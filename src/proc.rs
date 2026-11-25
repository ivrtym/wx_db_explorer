//! 微信进程与 `/proc/<pid>/mem` 只读扫描。

use anyhow::{anyhow, Result};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;

const SKIP_MAPS: [&str; 3] = ["[vdso]", "[vsyscall]", "[vvar]"];
const SKIP_PREFIXES: [&str; 5] = [
    "/usr/lib/",
    "/lib/",
    "/usr/share/",
    "/usr/lib64/",
    "/lib64/",
];
const MAX_REGION: u64 = 768 * 1024 * 1024;

fn exe_of(pid: i32) -> Option<PathBuf> {
    fs::read_link(format!("/proc/{pid}/exe")).ok()
}

/// 微信相关进程（wechat/weixin/WeChatAppEx），按 RSS 降序。
pub fn find_pids() -> Vec<i32> {
    let mut out: Vec<(u64, i32)> = Vec::new();
    let Ok(rd) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    for e in rd.flatten() {
        let Some(name) = e.file_name().to_str().map(|s| s.to_string()) else {
            continue;
        };
        let Ok(pid) = name.parse::<i32>() else {
            continue;
        };
        if pid == std::process::id() as i32 {
            continue;
        }
        let Some(exe) = exe_of(pid) else { continue };
        let base = exe
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if !matches!(base.as_str(), "wechat" | "weixin" | "wechatappex") {
            continue;
        }
        let rss = fs::read_to_string(format!("/proc/{pid}/statm"))
            .ok()
            .and_then(|s| {
                s.split_whitespace()
                    .nth(1)
                    .and_then(|v| v.parse::<u64>().ok())
            })
            .unwrap_or(0)
            * 4096;
        out.push((rss, pid));
    }
    out.sort_by(|a, b| b.0.cmp(&a.0));
    out.into_iter().map(|(_, p)| p).collect()
}

/// 可读内存区间 (start, end)。
pub fn readable_regions(pid: i32) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    let Ok(text) = fs::read_to_string(format!("/proc/{pid}/maps")) else {
        return out;
    };
    for line in text.lines() {
        let mut it = line.split_whitespace();
        let Some(range) = it.next() else { continue };
        let Some(perms) = it.next() else { continue };
        if !perms.starts_with('r') {
            continue;
        }
        let path = it.nth(3).unwrap_or(""); // dev inode [path]
        if SKIP_MAPS.contains(&path) || SKIP_PREFIXES.iter().any(|p| path.starts_with(p)) {
            continue;
        }
        let Some((s, e)) = range.split_once('-') else {
            continue;
        };
        let (Ok(s), Ok(e)) = (u64::from_str_radix(s, 16), u64::from_str_radix(e, 16)) else {
            continue;
        };
        if e <= s {
            continue;
        }
        let end = e.min(s + MAX_REGION);
        out.push((s, end));
    }
    out
}

fn open_mem(pid: i32) -> Result<File> {
    File::open(format!("/proc/{pid}/mem"))
        .map_err(|e| anyhow!("无法打开 /proc/{pid}/mem：{e}（需要 root 或 ptrace_scope=0）"))
}

pub fn read_at(f: &mut File, addr: u64, len: usize) -> Option<Vec<u8>> {
    f.seek(SeekFrom::Start(addr)).ok()?;
    let mut buf = vec![0u8; len];
    match f.read_exact(&mut buf) {
        Ok(()) => Some(buf),
        Err(_) => None,
    }
}

/// 在进程可读内存里找 needle，返回所有命中地址。
pub fn find_all(pid: i32, needle: &[u8]) -> Result<Vec<u64>> {
    if needle.is_empty() {
        return Ok(Vec::new());
    }
    let mut f = open_mem(pid)?;
    let mut hits = Vec::new();
    const CHUNK: usize = 8 * 1024 * 1024;
    let overlap = needle.len().saturating_sub(1);
    for (start, end) in readable_regions(pid) {
        let mut addr = start;
        let mut carry: Vec<u8> = Vec::new();
        while addr < end {
            let want = CHUNK.min((end - addr) as usize);
            let Some(buf) = read_at(&mut f, addr, want) else {
                addr += want as u64;
                carry.clear();
                continue;
            };
            let mut data = Vec::with_capacity(carry.len() + buf.len());
            data.extend_from_slice(&carry);
            data.extend_from_slice(&buf);
            let base = addr - carry.len() as u64;
            for i in memchr::memmem::find_iter(&data, needle) {
                hits.push(base + i as u64);
            }
            carry = if data.len() > overlap {
                data[data.len() - overlap..].to_vec()
            } else {
                data
            };
            addr += want as u64;
        }
    }
    Ok(hits)
}
