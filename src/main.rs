//! wx_db_rs —— 微信 4.x 本地数据库读取器（Rust）。
//!
//! 覆盖：路径探测 → 密钥提取（/proc/<pid>/mem）→ SQLCipher4 解密（页级）
//! → 会话 / 消息（跨分片）/ 联系人 / 群 / 成员 / 标签 / 导出。
//!
//! 尚未移植：WAL 合并、媒体解密、朋友圈、监听。详见 README。

mod crypto;
mod keys;
mod media;
mod model;
mod moment;
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
    /// 朋友圈时间线
    Moments {
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long)]
        me: bool,
        #[arg(long)]
        keyword: Option<String>,
    },
    /// 朋友圈互动通知（他人对我的赞/评论）
    Interactions {
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long)]
        unread: bool,
    },
    /// 导出一条朋友圈的本地缓存媒体
    MomentMedia {
        #[arg(allow_hyphen_values = true)]
        tid: i64,
        #[arg(long)]
        out: Option<PathBuf>,
        /// all | image | video
        #[arg(long, default_value = "all")]
        kind: String,
    },
    /// 导出语音/视频/文件（按消息类型分发）
    Media {
        chat: String,
        #[arg(long, default_value_t = 50)]
        limit: usize,
        #[arg(long)]
        out: Option<PathBuf>,
        /// all | voice | video | file
        #[arg(long, default_value = "all")]
        kind: String,
    },
    /// 直接解密一个本地 .dat（不依赖消息库）
    DecryptDat {
        path: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// 检测/刷新图片密钥（需要先在本机打开过一张图片）
    ImageKey {
        #[arg(long)]
        refresh: bool,
    },
    /// 解密并导出某个会话的图片
    Images {
        chat: String,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long)]
        out: Option<PathBuf>,
        /// best | original | mid | thumb
        #[arg(long, default_value = "best")]
        tier: String,
    },
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
    let (keys, cfg_dwords, err) = keys::load_or_extract(&dbs, &cache)?;
    if let Some(e) = err {
        eprintln!("[wx_db_rs] 密钥提示：{e}");
    }
    Ok(Ctx {
        account: acct.account.clone(),
        account_dir: acct.dir.clone(),
        cfg_dwords,
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
            println!("cfg_dw  : {} 个图片密钥派生候选", ctx.cfg_dwords.len());
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
        Cmd::Moments { limit, me, keyword } => {
            let rows = moment::moments(&ctx, *limit, 0, *me, keyword.as_deref())?;
            if cli.json {
                print_json(&rows)?;
            } else {
                for m in &rows {
                    println!(
                        "[{}] {} {}  图{} 视{} 赞{} 评{}  {}",
                        m.tid,
                        fmt_ts(m.create_time),
                        m.nickname,
                        m.images.len(),
                        m.videos.len(),
                        m.likes.len(),
                        m.comments.len(),
                        trunc(&m.text, 50)
                    );
                    for c in &m.comments {
                        println!("    评论 {}: {}", c.nickname, trunc(&c.content, 60));
                    }
                }
                println!("共 {} 条朋友圈", rows.len());
            }
        }
        Cmd::Interactions { limit, unread } => {
            let rows = moment::interactions(&ctx, *limit, *unread)?;
            if cli.json {
                print_json(&rows)?;
            } else {
                for i in &rows {
                    println!(
                        "[{}] {} {} -> {} {} {}",
                        i.local_id,
                        fmt_ts(i.create_time),
                        i.from_nickname,
                        i.to_nickname,
                        trunc(&i.content, 40),
                        if i.unread { "(未读)" } else { "" }
                    );
                }
                println!(
                    "共 {} 条互动（未读 {}）",
                    rows.len(),
                    moment::unread_count(&ctx)?
                );
            }
        }
        Cmd::MomentMedia { tid, out, kind } => {
            let Some(m) = moment::moment(&ctx, *tid)? else {
                println!("没有 tid={tid} 的朋友圈");
                return Ok(());
            };
            let out_dir = out.clone().unwrap_or_else(|| {
                paths::cache_root()
                    .join("media")
                    .join(&ctx.account)
                    .join("moments")
            });
            std::fs::create_dir_all(&out_dir)?;
            let key = media::load_cached_key().and_then(|k| media::ascii_key(&k.aes_key));
            let mut ok = 0usize;
            let mut miss = 0usize;
            let groups: [(&Vec<moment::MediaItem>, &str); 2] =
                [(&m.images, "image"), (&m.videos, "video")];
            for (items, k) in groups {
                if kind != "all" && kind != k {
                    continue;
                }
                for (idx, it) in items.iter().enumerate() {
                    let Some(p) = moment::local_media_path(&ctx.account_dir, &it.md5, k) else {
                        println!(
                            "[miss] {} #{} md5={} 无本地缓存",
                            k,
                            idx,
                            &it.md5[..it.md5.len().min(8)]
                        );
                        miss += 1;
                        continue;
                    };
                    let data = std::fs::read(&p)?;
                    let bytes = if data.starts_with(&[0x07, 0x08]) {
                        match media::decrypt_dat(&data, key.as_ref(), None) {
                            Ok(b) => b,
                            Err(e) => {
                                println!("[fail] {} #{} 解密失败：{e}", k, idx);
                                miss += 1;
                                continue;
                            }
                        }
                    } else {
                        data
                    };
                    let ext = media::container_ext(&bytes);
                    let dst = out_dir.join(format!("{}_{}_{}.{}", m.tid, k, idx, ext));
                    std::fs::write(&dst, &bytes)?;
                    println!(
                        "[ok] {} #{} -> {}（{} 字节）",
                        k,
                        idx,
                        dst.display(),
                        bytes.len()
                    );
                    ok += 1;
                }
            }
            println!("完成：导出 {ok}，未找到 {miss} -> {}", out_dir.display());
        }
        Cmd::Media {
            chat,
            limit,
            out,
            kind,
        } => {
            let out_dir = out
                .clone()
                .unwrap_or_else(|| paths::cache_root().join("media").join(&ctx.account));
            std::fs::create_dir_all(&out_dir)?;
            let rows = query::messages(&ctx, chat, 2000)?;
            let want = |k: &str| match kind.as_str() {
                "voice" => k == "语音",
                "video" => k == "视频",
                "file" => k == "文件/链接/卡片",
                _ => matches!(k, "语音" | "视频" | "文件/链接/卡片"),
            };
            let mut picked: Vec<&model::Message> =
                rows.iter().filter(|m| want(&m.kind)).take(*limit).collect();
            picked.reverse();
            if picked.is_empty() {
                println!("{} 最近 2000 条里没有匹配的媒体消息（kind={}）", chat, kind);
            }
            let (mut ok, mut miss) = (0usize, 0usize);
            for m in picked {
                let Some(row) =
                    media::find_media_row(&ctx.store, &ctx.keys, &ctx.dbs, chat, m.local_id)
                else {
                    println!("[skip] {} 找不到原始行", m.local_id);
                    continue;
                };
                match crate::query::type_name(row.local_type).as_str() {
                    "语音" => match media::export_voice(
                        &ctx.store, &ctx.keys, &ctx.dbs, chat, &row, &out_dir,
                    ) {
                        Some(p) => {
                            println!(
                                "[ok] 语音 {} -> {}（{} 字节）",
                                m.local_id,
                                p.display(),
                                std::fs::metadata(&p).map(|x| x.len()).unwrap_or(0)
                            );
                            ok += 1;
                        }
                        None => {
                            println!(
                                "[miss] 语音 {} 无本地音频（未在微信播放/接收过）",
                                m.local_id
                            );
                            miss += 1;
                        }
                    },
                    "视频" => match media::export_video(&ctx.account_dir, chat, &row, &out_dir) {
                        Some(p) => {
                            println!(
                                "[ok] 视频 {} -> {}（{} 字节）",
                                m.local_id,
                                p.display(),
                                std::fs::metadata(&p).map(|x| x.len()).unwrap_or(0)
                            );
                            ok += 1;
                        }
                        None => {
                            println!(
                                "[miss] 视频 {} 本机没有 mp4（只有缩略图或未下载）",
                                m.local_id
                            );
                            miss += 1;
                        }
                    },
                    _ => match media::export_file(&ctx.account_dir, chat, &row, &out_dir) {
                        Some(p) => {
                            println!(
                                "[ok] 文件 {} -> {}（{} 字节）",
                                m.local_id,
                                p.display(),
                                std::fs::metadata(&p).map(|x| x.len()).unwrap_or(0)
                            );
                            ok += 1;
                        }
                        None => {
                            println!(
                                "[miss] 文件 {} 在 msg/file 下找不到匹配（原名/长度）",
                                m.local_id
                            );
                            miss += 1;
                        }
                    },
                }
            }
            println!("完成：导出 {ok}，未找到 {miss} -> {}", out_dir.display());
        }
        Cmd::DecryptDat { path, out } => {
            let data = std::fs::read(path)?;
            let key = if media::find_probe(&ctx.account_dir).is_some() {
                media::resolve_key(&ctx.cfg_dwords, &ctx.wxid, path)
            } else {
                None
            };
            let aes = key.as_ref().and_then(|k| media::ascii_key(&k.aes_key));
            let bytes =
                media::decrypt_dat(&data, aes.as_ref(), key.as_ref().and_then(|k| k.xor_key))?;
            let ext = media::image_ext(&bytes);
            match out {
                Some(p) => {
                    std::fs::write(p, &bytes)?;
                    println!(
                        "已解密 {} → {}（{} 字节，{}）",
                        path.display(),
                        p.display(),
                        bytes.len(),
                        ext
                    );
                }
                None => println!(
                    "格式={} 字节={} 头部={:02x?}",
                    ext,
                    bytes.len(),
                    &bytes[..bytes.len().min(8)]
                ),
            }
        }
        Cmd::ImageKey { refresh } => {
            let probe = media::find_probe(&ctx.account_dir)
                .ok_or_else(|| anyhow!("没有 V2 图片样本：请先在微信里点开任意一张图片"))?;
            println!("probe   : {}", probe.display());
            let mut k = media::resolve_key(&ctx.cfg_dwords, &ctx.wxid, &probe);
            if k.is_none() {
                println!("缓存未命中，尝试在 Config 对象附近反推 cfgDword…");
                k = media::scan_cfg_dword(&probe, &ctx.wxid, &ctx.account);
            }
            if k.is_none() {
                println!("cfgDword 反推未命中，扫描内存字符串候选（首次可能十几秒）…");
                k = media::detect_image_key(&probe, *refresh);
            }
            let k =
                k.ok_or_else(|| anyhow!("未找到可用的图片密钥（先在微信里打开任意一张图片再试）"))?;
            println!("aes_key : {}", k.aes_key);
            println!("xor_key : {:?}", k.xor_key);
            println!("cache   : {}", media::key_cache_file().display());
            if cli.json {
                print_json(&k)?;
            }
        }
        Cmd::Images {
            chat,
            limit,
            out,
            tier,
        } => {
            let out_dir = out
                .clone()
                .unwrap_or_else(|| paths::cache_root().join("media").join(&ctx.account));
            std::fs::create_dir_all(&out_dir)?;
            let probe = media::find_probe(&ctx.account_dir)
                .ok_or_else(|| anyhow!("没有 V2 图片样本：请先在微信里点开任意一张图片"))?;
            let key = media::resolve_key(&ctx.cfg_dwords, &ctx.wxid, &probe);
            if key.is_none() {
                println!("提示：没有可用的图片密钥，本次只列本机副本。");
                println!("      先在微信里打开任意一张图片，再跑 `wx_db_rs image-key`。");
            }
            let aes = key.as_ref().and_then(|k| media::ascii_key(&k.aes_key));
            let rows = query::messages(&ctx, chat, 2000)?;
            let mut wanted: Vec<&model::Message> = rows
                .iter()
                .filter(|m| m.kind == "图片")
                .take(*limit)
                .collect();
            wanted.reverse(); // 从旧到新
            if wanted.is_empty() {
                println!("{} 最近 2000 条里没有图片消息", chat);
            }
            let mut ok = 0usize;
            for m in wanted {
                let Some(md5) = media::extract_md5(&m.content) else {
                    println!("[skip] {} 无 md5", m.local_id);
                    continue;
                };
                let files = media::image_files(&ctx.account_dir, chat, &md5);
                let order: Vec<&str> = if tier == "best" {
                    media::TIER_ORDER.to_vec()
                } else {
                    vec![tier.as_str()]
                };
                let chosen = order.iter().find_map(|t| {
                    files
                        .get(t)
                        .filter(|(_, sz)| *sz > 0)
                        .map(|(p, sz)| (*t, p.clone(), *sz))
                });
                let Some((t, path, sz)) = chosen else {
                    println!(
                        "[skip] {} {} 本机没有该档副本（有：{}）",
                        m.local_id,
                        &md5[..8],
                        files.keys().cloned().collect::<Vec<_>>().join(",")
                    );
                    continue;
                };
                if key.is_none() {
                    println!(
                        "[list] {} {} tiers={}",
                        m.local_id,
                        &md5[..8],
                        files.keys().cloned().collect::<Vec<_>>().join(",")
                    );
                    continue;
                }
                let data = std::fs::read(&path)?;
                match media::decrypt_dat(&data, aes.as_ref(), key.as_ref().and_then(|k| k.xor_key))
                {
                    Ok(bytes) => {
                        let ext = media::image_ext(&bytes);
                        let dst = out_dir.join(format!("{}_{}.{}", m.local_id, &md5[..8], ext));
                        std::fs::write(&dst, &bytes)?;
                        println!(
                            "[ok] {} {} tier={} {}B -> {}",
                            m.local_id,
                            &md5[..8],
                            t,
                            sz,
                            dst.display()
                        );
                        ok += 1;
                    }
                    Err(e) => println!("[fail] {} {}：{e}", m.local_id, &md5[..8]),
                }
            }
            println!("完成：{ok} 张 -> {}", out_dir.display());
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
