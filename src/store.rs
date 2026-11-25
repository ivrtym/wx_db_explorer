//! 解密缓存：stamp 命中直接复用；否则解密主库 + 合并 `-wal`（salt 帧过滤）。

use crate::crypto::{decrypt_file, merge_wal, KEY_SZ, PAGE_SZ, WAL_HEADER_SZ};
use crate::paths::cache_root;
use anyhow::{anyhow, Result};
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize)]
struct Stamp {
    version: u32,
    mtime: u64,
    size: u64,
    wal_mtime: u64,
    wal_size: u64,
    /// 合并的 WAL 帧数；-1 = 本轮 WAL 合并失败，仅用主库
    applied: i64,
}

const STAMP_VERSION: u32 = 2;

fn mtime_of(p: &Path) -> u64 {
    fs::metadata(p)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn size_of(p: &Path) -> u64 {
    fs::metadata(p).map(|m| m.len()).unwrap_or(0)
}

pub struct Store {
    dir: PathBuf,
}

impl Store {
    pub fn new(account: &str) -> Self {
        Store {
            dir: cache_root().join("db").join(account),
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn stamped_path(&self, rel: &str) -> PathBuf {
        self.dir.join(rel.replace('/', "__"))
    }

    fn temp_name(&self, dst: &Path, tag: &str) -> PathBuf {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        dst.with_extension(format!("{}.{}.{}.tmp", std::process::id(), n, tag))
    }

    /// 确保库已解密（并尽力合并 WAL），返回可读路径。
    pub fn ensure(&self, src: &Path, rel: &str, key: &[u8; KEY_SZ]) -> Result<PathBuf> {
        fs::create_dir_all(&self.dir)?;
        let dst = self.stamped_path(rel);
        let stamp_path = append_suffix(&dst, ".stamp");
        let wal = crate::paths::wal_sidecar(src);
        let mtime = mtime_of(src);
        let size = size_of(src);
        let wal_mtime = if wal.exists() { mtime_of(&wal) } else { 0 };
        let wal_size = if wal.exists() { size_of(&wal) } else { 0 };

        if dst.exists() {
            if let Ok(text) = fs::read_to_string(&stamp_path) {
                if let Ok(st) = serde_json::from_str::<Stamp>(&text) {
                    if st.version == STAMP_VERSION
                        && st.mtime == mtime
                        && st.size == size
                        && st.wal_mtime == wal_mtime
                        && st.wal_size == wal_size
                    {
                        return Ok(dst);
                    }
                }
            }
        }

        // 清掉 10 分钟前的陈旧中间产物（包括 SQLite 生成的 -shm/-wal）
        if let Ok(rd) = fs::read_dir(&self.dir) {
            for e in rd.flatten() {
                let p = e.path();
                let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
                if name.contains(".tmp")
                    && p.metadata()
                        .ok()
                        .and_then(|m| m.modified().ok())
                        .and_then(|t| t.elapsed().ok())
                        .map(|d| d.as_secs() > 600)
                        .unwrap_or(false)
                {
                    let _ = fs::remove_file(&p);
                }
            }
        }
        let tmp = self.temp_name(&dst, "main");
        let mut last_err = None;
        for _ in 0..4 {
            match decrypt_file(src, &tmp, key) {
                Ok(()) => match quick_check(&tmp) {
                    Ok(true) => {
                        let (best, applied) = self.try_merge_wal(&tmp, &wal, key);
                        let final_path = dst.clone();
                        if best != tmp {
                            fs::rename(&best, &dst)?;
                            let _ = fs::remove_file(&tmp);
                            cleanup_sidecars(&best);
                        } else {
                            fs::rename(&tmp, &dst)?;
                        }
                        cleanup_sidecars(&tmp);
                        let st = Stamp {
                            version: STAMP_VERSION,
                            mtime,
                            size,
                            wal_mtime,
                            wal_size,
                            applied,
                        };
                        let _ =
                            fs::write(&stamp_path, serde_json::to_string(&st).unwrap_or_default());
                        return Ok(final_path);
                    }
                    Ok(false) => last_err = Some("解密结果 quick_check 失败".to_string()),
                    Err(e) => last_err = Some(e.to_string()),
                },
                Err(e) => last_err = Some(e.to_string()),
            }
            let _ = fs::remove_file(&tmp);
            std::thread::sleep(std::time::Duration::from_millis(350));
        }
        if dst.exists() && quick_check(&dst).unwrap_or(false) {
            return Ok(dst);
        }
        Err(anyhow!(
            "数据库解密失败（{}）：{}",
            rel,
            last_err.unwrap_or_else(|| "未知原因".into())
        ))
    }

    /// 合并 WAL；失败则退回主库快照（可能缺最近几条）。
    fn try_merge_wal(&self, main: &Path, wal: &Path, key: &[u8; KEY_SZ]) -> (PathBuf, i64) {
        if !wal.exists() || size_of(wal) <= WAL_HEADER_SZ {
            return (main.to_path_buf(), 0);
        }
        let merged = self.temp_name(main, "merged");
        let snap = self.temp_name(main, "walsrc");
        if fs::copy(main, &merged).is_err() || fs::copy(wal, &snap).is_err() {
            let _ = fs::remove_file(&merged);
            let _ = fs::remove_file(&snap);
            return (main.to_path_buf(), -1);
        }
        let mut applied = -1i64;
        for _ in 0..3 {
            // 上一轮可能已部分写入，重试前恢复主库快照
            if fs::copy(main, &merged).is_err() {
                break;
            }
            match merge_wal(&merged, &snap, key, 0) {
                Ok(frames) => {
                    if quick_check(&merged).unwrap_or(false) {
                        applied = frames as i64;
                        break;
                    }
                }
                Err(_) => {}
            }
            std::thread::sleep(std::time::Duration::from_millis(300));
        }
        let _ = fs::remove_file(&snap);
        if applied >= 0 {
            (merged, applied)
        } else {
            let _ = fs::remove_file(&merged);
            (main.to_path_buf(), -1)
        }
    }
}

/// 只读打开（immutable=1）：不会在缓存目录生成 `-shm`/`-wal` 旁挂文件。
pub fn open_ro(path: &Path) -> Result<Connection> {
    let mut uri = String::from("file:");
    for ch in path.to_string_lossy().chars() {
        match ch {
            '%' => uri.push_str("%25"),
            '?' => uri.push_str("%3F"),
            '#' => uri.push_str("%23"),
            ' ' => uri.push_str("%20"),
            c => uri.push(c),
        }
    }
    uri.push_str("?immutable=1");
    Ok(Connection::open_with_flags(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )?)
}

pub fn append_suffix(p: &Path, suffix: &str) -> PathBuf {
    let mut s = p.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
}

/// `PRAGMA quick_check`；容忍 checkpoint 期间的 `Page N: never used`。
pub fn quick_check(path: &Path) -> Result<bool> {
    let conn = open_ro(path)?;
    let mut stmt = conn.prepare("PRAGMA quick_check")?;
    let mut rows = stmt.query([])?;
    let mut ok = true;
    while let Some(row) = rows.next()? {
        let line: String = row.get(0)?;
        for part in line.lines() {
            let p = part.trim();
            if p.is_empty() || p == "ok" || p == "*** in database main ***" {
                continue;
            }
            if p.starts_with("Page ") && p.ends_with(": never used") {
                continue;
            }
            ok = false;
        }
    }
    Ok(ok)
}

#[allow(dead_code)]
pub fn page_count(p: &Path) -> u64 {
    size_of(p) / PAGE_SZ as u64
}

fn cleanup_sidecars(base: &Path) {
    for suf in ["-shm", "-wal", ".tmp-shm", ".tmp-wal"] {
        let _ = fs::remove_file(append_suffix(base, suf));
    }
}
