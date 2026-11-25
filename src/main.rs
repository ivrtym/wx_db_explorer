//! wx_db_rs —— 微信 4.x 本地数据库读取器（Rust）。
//!
//! 覆盖：路径探测 → 密钥提取（/proc/<pid>/mem）→ SQLCipher4 解密（页级）
//! → 会话 / 消息（跨分片）/ 联系人 / 群 / 成员 / 标签 / 导出。
//!
//! 尚未移植：WAL 合并、媒体解密、朋友圈、监听。详见 README。

mod crypto;
mod keys;
mod model;
mod paths;
mod proc;
mod query;
mod store;

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use query::Ctx;
use std::io::Write;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "wx_db_rs",
    version,
    about = "微信 4.x 本地数据库读取器（Rust）"
)]
struct Cli {
    /// 显式指定 xwechat_files 根目录
    #[arg(long, global = true)]
    db_dir: Option<PathBuf>,
    /// 账号目录名（默认取最新的）
    #[arg(long, global = true)]
    account: Option<String>,
    /// 密钥缓存文件（默认 ~/.local/share/wx_db_rs/keys.json）
    #[arg(long, global = true)]
    keys_file: Option<PathBuf>,
    /// 输出 JSON
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// 环境自检：账号 / 库数量 / 可用密钥 / 缺失项
    Doctor,
    /// 会话列表
    Sessions {
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// 某个会话的消息（跨分片）
    Messages {
        chat: String,
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// 搜索联系人（空串 = 全部，最多 limit 条）
    Contacts {
        #[arg(long, default_value = "")]
        search: String,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// 群列表
    Groups,
    /// 群成员（传群 wxid，如 xxx@chatroom）
    Members { group: String },
    /// 标签列表
    Labels,
    /// 导出某个会话的消息为 JSON
    Export {
        chat: String,
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long, default_value_t = 1000)]
        limit: usize,
    },
}

fn fmt_ts(sec: i64) -> String {
    let dt = chrono::DateTime::<chrono::Local>::from(
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(sec.max(0) as u64),
    );
    dt.format("%Y-%m-%d %H:%M").to_string()
}

fn load_ctx(cli: &Cli) -> Result<Ctx> {
    let root = paths::detect_root(cli.db_dir.as_deref())
        .ok_or_else(|| anyhow!("没找到 xwechat_files（可传 --db-dir）"))?;
    let acct = paths::pick_account(&root, cli.account.as_deref())?;
    let dbs = paths::db_files(&acct.dir);
    let cache = cli.keys_file.clone().unwrap_or_else(keys::cache_file);
    let (keys, err) = keys::load_or_extract(&dbs, &cache)?;
    if let Some(e) = err {
        eprintln!("[wx_db_rs] 密钥提示：{e}");
    }
    Ok(Ctx {
        account: acct.account.clone(),
        wxid: acct.wxid(),
        dbs,
        keys,
        store: store::Store::new(&acct.account),
    })
}

fn print_json<T: serde::Serialize>(v: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}

fn main() {
    // 让 `| head` 这类管道正常结束，而不是 println! panic
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    if let Err(e) = run() {
        eprintln!("错误：{e}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let ctx = load_ctx(&cli)?;

    match &cli.cmd {
        Cmd::Doctor => {
            println!("account : {}", ctx.account);
            println!("wxid    : {}", ctx.wxid);
            println!("db_files: {}", ctx.dbs.len());
            println!("keys_ok : {}/{}", ctx.available(), ctx.dbs.len());
            let wal_n = ctx
                .dbs
                .iter()
                .filter(|d| paths::wal_sidecar(&d.path).exists())
                .count();
            println!("wal     : {} 个库有 -wal（启动时合并）", wal_n);
            println!("cache   : {}", ctx.store.dir().display());
            let missing: Vec<&str> = ctx
                .dbs
                .iter()
                .filter(|d| !ctx.keys.contains_key(&d.rel))
                .map(|d| d.rel.as_str())
                .collect();
            if missing.is_empty() {
                println!("missing : (无)");
            } else {
                println!("missing : {}/{}", missing.len(), ctx.dbs.len());
                for m in missing.iter().take(10) {
                    println!("  - {m}");
                }
            }
            if cli.json {
                let v = serde_json::json!({
                    "account": ctx.account,
                    "wxid": ctx.wxid,
                    "db_files": ctx.dbs.len(),
                    "keys_ok": ctx.available(),
                    "missing": missing,
                });
                print_json(&v)?;
            }
        }
        Cmd::Sessions { limit } => {
            let rows = query::sessions(&ctx, *limit)?;
            if cli.json {
                print_json(&rows)?;
            } else {
                for s in &rows {
                    println!(
                        "{:<40} unread={:<4} {}  {}",
                        trunc(&s.username, 40),
                        s.unread,
                        fmt_ts(s.last_time),
                        trunc(&s.summary, 40)
                    );
                }
                println!("共 {} 个会话", rows.len());
            }
        }
        Cmd::Messages { chat, limit } => {
            let rows = query::messages(&ctx, chat, *limit)?;
            if cli.json {
                print_json(&rows)?;
            } else {
                for m in &rows {
                    println!(
                        "[{}] {} {}: {}",
                        m.kind,
                        fmt_ts(m.create_time),
                        trunc(&m.sender, 20),
                        trunc(&m.content, 100)
                    );
                }
                println!("{} 共 {} 条（截断到 {}）", chat, rows.len(), limit);
            }
        }
        Cmd::Contacts { search, limit } => {
            let rows = query::contacts(&ctx, Some(search), *limit)?;
            if cli.json {
                print_json(&rows)?;
            } else {
                for c in &rows {
                    println!(
                        "{:<40} {:<24} {}",
                        c.username,
                        trunc(&c.nick_name, 24),
                        c.remark
                    );
                }
                println!("共 {} 人", rows.len());
            }
        }
        Cmd::Groups => {
            let rows = query::groups(&ctx)?;
            if cli.json {
                print_json(&rows)?;
            } else {
                for g in &rows {
                    println!(
                        "{:<30} {:<40} owner={} members={}",
                        g.username,
                        trunc(&g.name, 40),
                        g.owner,
                        g.member_count
                    );
                }
                println!("共 {} 个群", rows.len());
            }
        }
        Cmd::Members { group } => {
            let rows = query::group_members(&ctx, group)?;
            if cli.json {
                print_json(&rows)?;
            } else {
                for m in &rows {
                    println!(
                        "{:<40} {:<24} {}{}",
                        m.username,
                        trunc(&m.nick_name, 24),
                        m.remark,
                        if m.is_owner { "  [群主]" } else { "" }
                    );
                }
                println!("{} 共 {} 人", group, rows.len());
            }
        }
        Cmd::Labels => {
            let rows = query::labels(&ctx)?;
            if cli.json {
                print_json(&rows)?;
            } else {
                for l in &rows {
                    println!("{:>4}  {}", l.label_id, l.name);
                }
                println!("共 {} 个标签", rows.len());
            }
        }
        Cmd::Export { chat, out, limit } => {
            let rows = query::messages(&ctx, chat, *limit)?;
            match out {
                Some(p) => {
                    let mut f = std::fs::File::create(p)?;
                    write!(f, "{}", serde_json::to_string_pretty(&rows)?)?;
                    println!("已导出 {} 条 → {}", rows.len(), p.display());
                }
                None => print_json(&rows)?,
            }
        }
    }
    Ok(())
}

fn trunc(s: &str, n: usize) -> String {
    let t: String = s.chars().take(n).collect();
    if s.chars().count() > n {
        format!("{t}…")
    } else {
        t
    }
}
