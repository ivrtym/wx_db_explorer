//! 数据库密钥提取（Linux 4.1+）。
//!
//! 链路：
//! ```text
//! 内存里搜 "com.Tencent.WCDB.Config.Cipher"        -> A
//! 搜 16 字节配对 (u64 A, u64 30)                    -> Q
//! node = Q - 0x10；node[0x10]==A，node[0x18]==30
//! cfg  = u64 @ (node + 0x28)
//! blob = read(cfg + 0x98)，兼容 +0x88
//! plain = blob XOR 固定 32 字节掩码
//! x'<64hex key><32hex salt>' = 从 plain 里扫出来
//! 按库文件页 1 的 salt 匹配 + 页 1 HMAC 验真
//! ```

use crate::crypto::{verify_key, PAGE_SZ};
use crate::paths::{cache_root, DbFile};
use crate::proc;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

const ANCHOR: &[u8] = b"com.Tencent.WCDB.Config.Cipher";
const MASK: [u8; 32] = [
    0xd2, 0xc7, 0x44, 0x24, 0x58, 0x02, 0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x50, 0x48, 0x8b,
    0x45, 0x00, 0x48, 0x84, 0x4c, 0x24, 0x48, 0x48, 0x89, 0x44, 0x25, 0x40, 0x48, 0x58, 0x4c, 0x24,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeySpec {
    pub key: [u8; 32],
    pub salt: [u8; 16],
}

fn u64_at(b: &[u8], off: usize) -> Option<u64> {
    b.get(off..off + 8)
        .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
}

/// 从一段十六进制文本扫 `x'<96hex>'`；一个长串里可能有多把 key，按 32 hex 滑动。
fn scan_specs(plain: &[u8]) -> Vec<KeySpec> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 2 < plain.len() {
        if &plain[i..i + 2] != b"x'" {
            i += 1;
            continue;
        }
        let start = i + 2;
        let mut end = start;
        while end < plain.len() && (plain[end] as char).is_ascii_hexdigit() {
            end += 1;
        }
        if end > start && plain.get(end) == Some(&b'\'') {
            let run = &plain[start..end];
            let mut s = 0;
            while s + 96 <= run.len() {
                let key_hex = &run[s..s + 64];
                let salt_hex = &run[s + 64..s + 96];
                if let (Ok(k), Ok(sa)) = (hex::decode(key_hex), hex::decode(salt_hex)) {
                    if k.len() == 32 && sa.len() == 16 {
                        let mut key = [0u8; 32];
                        key.copy_from_slice(&k);
                        let mut salt = [0u8; 16];
                        salt.copy_from_slice(&sa);
                        let spec = KeySpec { key, salt };
                        if !out.contains(&spec) {
                            out.push(spec);
                        }
                    }
                }
                s += 32;
            }
        }
        i = end.max(i + 1);
    }
    out
}

/// 一次扫描的产物：库密钥 + 图片密钥派生源（cfg+0x40 的 DWORD）。
#[derive(Default)]
pub struct Extracted {
    pub specs: Vec<KeySpec>,
    pub cfg_dwords: Vec<u32>,
    /// Config 对象地址（媒体密钥派生时在附近暴力找偏移）
    pub cfgs: Vec<u64>,
}

/// 从某个 pid 提取 keyspec 与 cfg_dword。
pub fn extract(pid: i32) -> Result<Extracted> {
    let anchors = proc::find_all(pid, ANCHOR)?;
    if anchors.is_empty() {
        return Ok(Extracted::default());
    }
    let mut specs: Vec<KeySpec> = Vec::new();
    let mut cfg_dwords: Vec<u32> = Vec::new();
    let mut cfgs: Vec<u64> = Vec::new();
    for a in anchors {
        let mut pair = Vec::with_capacity(16);
        pair.extend_from_slice(&a.to_le_bytes());
        pair.extend_from_slice(&(ANCHOR.len() as u64).to_le_bytes());
        for q in proc::find_all(pid, &pair)? {
            let Some(node_addr) = q.checked_sub(0x10) else {
                continue;
            };
            let mut mem = match File::open(format!("/proc/{pid}/mem")) {
                Ok(f) => f,
                Err(_) => continue,
            };
            let Some(node) = proc::read_at(&mut mem, node_addr, 0x50) else {
                continue;
            };
            if node.len() < 0x30 {
                continue;
            }
            if u64_at(&node, 0x10) != Some(a) || u64_at(&node, 0x18) != Some(ANCHOR.len() as u64) {
                continue;
            }
            let Some(cfg) = u64_at(&node, 0x28) else {
                continue;
            };
            if cfg < 0x10000 {
                continue;
            }
            if !cfgs.contains(&cfg) {
                cfgs.push(cfg);
            }
            // cfg+0x40 = cfgDword：图片密钥 = MD5(str(cfgDword) + wxid)[:16]，xor = cfgDword & 0xFF
            if let Some(dw) = proc::read_at(&mut mem, cfg + 0x40, 4) {
                let v = u32::from_le_bytes(dw[..4].try_into().unwrap());
                if v != 0 && !cfg_dwords.contains(&v) {
                    cfg_dwords.push(v);
                }
            }
            for off in [0x98u64, 0x88] {
                let Some(head) = proc::read_at(&mut mem, cfg + off, 0x10) else {
                    continue;
                };
                let (Some(ptr), Some(len)) = (u64_at(&head, 0), u64_at(&head, 8)) else {
                    continue;
                };
                if len == 0 || len > 4096 {
                    continue;
                }
                let Some(blob) = proc::read_at(&mut mem, ptr, len as usize) else {
                    continue;
                };
                let mut plain = vec![0u8; blob.len()];
                for (i, v) in blob.iter().enumerate() {
                    plain[i] = v ^ MASK[i % MASK.len()];
                }
                for spec in scan_specs(&plain) {
                    if !specs.contains(&spec) {
                        specs.push(spec);
                    }
                }
            }
        }
    }
    Ok(Extracted {
        specs,
        cfg_dwords,
        cfgs,
    })
}

fn read_page1(path: &Path) -> Option<Vec<u8>> {
    let mut f = File::open(path).ok()?;
    let mut buf = vec![0u8; PAGE_SZ];
    use std::io::Read;
    f.read_exact(&mut buf).ok()?;
    Some(buf)
}

/// 用 keyspec 匹配库文件：按页 1 的 salt，命中后必须过 HMAC。
pub fn match_keys(specs: &[KeySpec], dbs: &[DbFile]) -> HashMap<String, [u8; 32]> {
    let mut out = HashMap::new();
    for db in dbs {
        let Some(p1) = read_page1(&db.path) else {
            continue;
        };
        let salt = &p1[..16];
        let Some(spec) = specs.iter().find(|s| s.salt == salt) else {
            continue;
        };
        if verify_key(&spec.key, &p1) {
            out.insert(db.rel.clone(), spec.key);
        }
    }
    out
}

#[derive(Serialize, Deserialize, Default)]
struct KeyCache {
    version: u32,
    keys: HashMap<String, String>,
    #[serde(default)]
    cfg_dwords: Vec<u32>,
}

pub fn cache_file() -> std::path::PathBuf {
    cache_root().join("keys.json")
}

fn load_cache(path: &Path) -> (HashMap<String, [u8; 32]>, Vec<u32>) {
    // 兼容旧版缓存目录（首次以 wx_db_explorer 运行时不必重新扫内存）
    let legacy = crate::paths::legacy_cache_root().join("keys.json");
    let path = if path.exists() {
        path.to_path_buf()
    } else {
        legacy
    };
    let mut out = HashMap::new();
    let Ok(text) = fs::read_to_string(&path) else {
        return (out, Vec::new());
    };
    let Ok(cache) = serde_json::from_str::<KeyCache>(&text) else {
        return (out, Vec::new());
    };
    let dwords = cache.cfg_dwords.clone();
    for (rel, hexkey) in cache.keys {
        if let Ok(k) = hex::decode(&hexkey) {
            if k.len() == 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&k);
                out.insert(rel, key);
            }
        }
    }
    (out, dwords)
}

fn save_cache(path: &Path, keys: &HashMap<String, [u8; 32]>, dwords: &[u32]) {
    let cache = KeyCache {
        version: 1,
        keys: keys
            .iter()
            .map(|(k, v)| (k.clone(), hex::encode(v)))
            .collect(),
        cfg_dwords: dwords.to_vec(),
    };
    if let Some(dir) = path.parent() {
        let _ = fs::create_dir_all(dir);
    }
    let tmp = path.with_extension("json.tmp");
    if let Ok(mut f) = File::create(&tmp) {
        let _ = f.write_all(
            serde_json::to_string_pretty(&cache)
                .unwrap_or_default()
                .as_bytes(),
        );
        let _ = f.flush();
        let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));
        let _ = fs::rename(&tmp, path);
    }
}

/// 缓存优先；缺库才扫描进程内存。返回 (可用密钥, 失败原因)。
pub fn load_or_extract(
    dbs: &[DbFile],
    cache_path: &Path,
) -> Result<(HashMap<String, [u8; 32]>, Vec<u32>, Option<String>)> {
    let mut keys = HashMap::new();
    let (cached, mut dwords) = load_cache(cache_path);
    for (rel, key) in cached {
        // 只保留仍能通过页 1 HMAC 的条目
        if let Some(db) = dbs.iter().find(|d| d.rel == rel) {
            if let Some(p1) = read_page1(&db.path) {
                if verify_key(&key, &p1) {
                    keys.insert(rel, key);
                }
            }
        }
    }

    let missing: Vec<&DbFile> = dbs.iter().filter(|d| !keys.contains_key(&d.rel)).collect();
    if missing.is_empty() {
        return Ok((keys, dwords, None));
    }

    let pids = proc::find_pids();
    if pids.is_empty() {
        return Ok((
            keys,
            dwords,
            Some("未检测到微信进程，请先登录微信".to_string()),
        ));
    }
    let mut last_err = None;
    for pid in pids {
        match extract(pid) {
            Ok(ex) => {
                for d in ex.cfg_dwords {
                    if !dwords.contains(&d) {
                        dwords.push(d);
                    }
                }
                if ex.specs.is_empty() {
                    continue;
                }
                let matched = match_keys(&ex.specs, dbs);
                keys.extend(matched);
                if dbs.iter().all(|d| keys.contains_key(&d.rel)) {
                    break;
                }
            }
            Err(e) => last_err = Some(e.to_string()),
        }
    }
    if !keys.is_empty() || !dwords.is_empty() {
        save_cache(cache_path, &keys, &dwords);
    }
    Ok((keys, dwords, last_err))
}

/// 用显式十六进制密钥（32 字节）验真单个库。
#[allow(dead_code)]
pub fn key_from_hex(s: &str) -> Result<[u8; 32]> {
    let raw = hex::decode(s.trim()).map_err(|e| anyhow!("密钥不是十六进制：{e}"))?;
    if raw.len() != 32 {
        return Err(anyhow!("密钥长度必须是 32 字节，实际 {}", raw.len()));
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&raw);
    Ok(k)
}
