//! 解密缓存：stamp 命中直接复用，否则重新解密（失败重试，原子替换）。

use crate::crypto::{decrypt_file, KEY_SZ};
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

    /// 确保库已解密，返回可读路径。
    pub fn ensure(&self, src: &Path, rel: &str, key: &[u8; KEY_SZ]) -> Result<PathBuf> {
        fs::create_dir_all(&self.dir)?;
        let dst = self.stamped_path(rel);
        let stamp_path = dst.with_extension("stamp");
        let md = fs::metadata(src)?;
        let mtime = md
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let size = md.len();

        if dst.exists() {
            if let Ok(text) = fs::read_to_string(&stamp_path) {
                if let Ok(st) = serde_json::from_str::<Stamp>(&text) {
                    if st.version == 1 && st.mtime == mtime && st.size == size {
                        return Ok(dst);
                    }
                }
            }
        }

        let tmp = dst.with_extension(format!("{}.tmp", std::process::id()));
        let mut last_err = None;
        for _ in 0..4 {
            match decrypt_file(
                src.to_str().ok_or_else(|| anyhow!("路径非 UTF-8"))?,
                tmp.to_str().expect("tmp utf8"),
                key,
            ) {
                Ok(()) => match quick_check(&tmp) {
                    Ok(true) => {
                        fs::rename(&tmp, &dst)?;
                        let st = Stamp {
                            version: 1,
                            mtime,
                            size,
                        };
                        let _ =
                            fs::write(&stamp_path, serde_json::to_string(&st).unwrap_or_default());
                        return Ok(dst);
                    }
                    Ok(false) => last_err = Some("解密结果 quick_check 失败".to_string()),
                    Err(e) => last_err = Some(e.to_string()),
                },
                Err(e) => last_err = Some(e.to_string()),
            }
            let _ = fs::remove_file(&tmp);
            std::thread::sleep(std::time::Duration::from_millis(350));
        }
        // 退而求其次：旧的已验证副本
        if dst.exists() && quick_check(&dst).unwrap_or(false) {
            return Ok(dst);
        }
        Err(anyhow!(
            "数据库解密失败（{}）：{}",
            rel,
            last_err.unwrap_or_else(|| "未知原因".into())
        ))
    }
}

/// `PRAGMA quick_check`；容忍 checkpoint 期间的 `Page N: never used`。
pub fn quick_check(path: &Path) -> Result<bool> {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
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
