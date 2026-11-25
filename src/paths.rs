//! 微信数据目录探测（Linux / Windows 通用）。
//!
//! Linux：`~/文档/xwechat_files`（或 `~/Documents/xwechat_files`），
//! `~/.xwechat/config/*.ini` 里的 `MyDocument:` 优先。
//! 账号目录 = 含 `db_storage` 子目录的目录。

use anyhow::{anyhow, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

pub fn user_home() -> PathBuf {
    if let Some(h) = std::env::var_os("HOME") {
        return PathBuf::from(h);
    }
    PathBuf::from(".")
}

fn read_text(p: &Path) -> Option<String> {
    fs::read(p)
        .ok()
        .map(|b| String::from_utf8_lossy(&b).to_string())
}

/// 从 `~/.xwechat/config/*.ini` 读 `MyDocument:`。
fn root_from_config() -> Vec<PathBuf> {
    let dir = user_home().join(".xwechat").join("config");
    let mut out = Vec::new();
    let Ok(rd) = fs::read_dir(&dir) else {
        return out;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.extension().and_then(|s| s.to_str()) != Some("ini") {
            continue;
        }
        let Some(text) = read_text(&p) else { continue };
        for line in text.lines() {
            let line = line.trim();
            if let Some(v) = line.strip_prefix("MyDocument:") {
                let v = v.trim();
                if !v.is_empty() {
                    out.push(PathBuf::from(v).join("xwechat_files"));
                }
            }
        }
    }
    out
}

/// 定位 `xwechat_files` 根目录。
pub fn detect_root(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        return if p.is_dir() {
            Some(p.to_path_buf())
        } else {
            None
        };
    }
    let home = user_home();
    let mut cands = root_from_config();
    cands.push(home.join("文档").join("xwechat_files"));
    cands.push(home.join("Documents").join("xwechat_files"));
    cands.push(home.join(".xwechat").join("xwechat_files"));
    cands.into_iter().find(|p| p.is_dir())
}

/// 所有含 `db_storage` 的账号目录，按最新库 mtime 倒序。
pub fn account_dirs(root: &Path) -> Vec<PathBuf> {
    let mut out: Vec<(u64, PathBuf)> = Vec::new();
    let Ok(rd) = fs::read_dir(root) else {
        return Vec::new();
    };
    for e in rd.flatten() {
        let p = e.path();
        if !p.is_dir() || !p.join("db_storage").is_dir() {
            continue;
        }
        let latest = newest_mtime(&p.join("db_storage"));
        out.push((latest, p));
    }
    out.sort_by(|a, b| b.0.cmp(&a.0));
    out.into_iter().map(|(_, p)| p).collect()
}

fn newest_mtime(dir: &Path) -> u64 {
    let mut best = 0u64;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            if p.extension().and_then(|s| s.to_str()) != Some("db") {
                continue;
            }
            if let Ok(md) = p.metadata() {
                if let Ok(t) = md.modified() {
                    if let Ok(dur) = t.duration_since(std::time::UNIX_EPOCH) {
                        best = best.max(dur.as_secs());
                    }
                }
            }
        }
    }
    best
}

#[allow(dead_code)]
pub struct DbFile {
    pub rel: String, // "contact/contact.db"
    pub path: PathBuf,
    pub size: u64,
}

/// 收集库文件：跳过 migrate 目录、`-wal/-shm`、`*_fts.db`（自定义分词器，读不了也用不上）。
pub fn db_files(account_dir: &Path) -> Vec<DbFile> {
    let base = account_dir.join("db_storage");
    let mut out = Vec::new();
    walk_collect(&base, &base, &mut out);
    out.sort_by(|a, b| a.rel.cmp(&b.rel));
    out
}

fn walk_collect(base: &Path, dir: &Path, out: &mut Vec<DbFile>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if name == "migrate" {
                continue;
            }
            walk_collect(base, &p, out);
            continue;
        }
        let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if !name.ends_with(".db") || name.ends_with("-wal") || name.ends_with("-shm") {
            continue;
        }
        if name.ends_with("_fts.db") {
            continue; // WCDB 自定义分词器，系统 sqlite 打不开；它是索引不是数据
        }
        let rel = p
            .strip_prefix(base)
            .unwrap_or(&p)
            .to_string_lossy()
            .replace('\\', "/");
        let size = p.metadata().map(|m| m.len()).unwrap_or(0);
        out.push(DbFile { rel, path: p, size });
    }
}

pub struct Account {
    #[allow(dead_code)]
    pub root: PathBuf,
    pub account: String,
    pub dir: PathBuf,
}

pub fn pick_account(root: &Path, want: Option<&str>) -> Result<Account> {
    let dirs = account_dirs(root);
    if dirs.is_empty() {
        return Err(anyhow!("{} 下没有含 db_storage 的账号目录", root.display()));
    }
    let dir = match want {
        Some(w) => dirs
            .iter()
            .find(|d| d.file_name().and_then(|s| s.to_str()) == Some(w))
            .or_else(|| {
                dirs.iter().find(|d| {
                    d.file_name()
                        .and_then(|s| s.to_str())
                        .map(|n| n.starts_with(w))
                        .unwrap_or(false)
                })
            })
            .ok_or_else(|| anyhow!("找不到账号目录：{w}"))?
            .clone(),
        None => dirs[0].clone(),
    };
    let account = dir
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_string();
    Ok(Account {
        root: root.to_path_buf(),
        account,
        dir,
    })
}

impl Account {
    /// 目录名去掉末尾 4 位哈希，得到 wxid。
    pub fn wxid(&self) -> String {
        let n = &self.account;
        if n.len() > 5 && n.as_bytes()[n.len() - 5] == b'_' {
            n[..n.len() - 5].to_string()
        } else {
            n.clone()
        }
    }
}

pub fn cache_root() -> PathBuf {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| user_home().join(".local").join("share"));
    base.join("wx_db_rs")
}

#[allow(dead_code)]
pub fn exists(p: &Path) -> bool {
    p.exists()
}

#[allow(dead_code)]
pub fn context_msg<T>(r: Result<T>, msg: &str) -> Result<T> {
    r.with_context(|| msg.to_string())
}
