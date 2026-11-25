//! 采集（Collector）与监听（Tailer）。
//!
//! 设计见 `docs/READ_API_V2.md`：
//! - 游标 `(chat, sort_seq, shard, local_id)`：唯一且单调，续采不重不漏；
//! - 检查点整体原子落盘（tmp + rename），崩溃后从上次位置继续；
//! - 投递语义 **at-least-once**，消费方按自然键去重；
//! - 同一会话内严格按 `sort_seq` 升序，跨会话不保证全局顺序。

use crate::query::{self, Ctx};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Cursor {
    pub chat: String,
    pub sort_seq: i64,
    pub shard: String,
    pub local_id: i64,
}

#[derive(Serialize, Deserialize, Default)]
pub struct Checkpoint {
    pub version: u32,
    pub epoch: u64,
    pub cursors: HashMap<String, Cursor>,
    pub updated_at: i64,
}

impl Checkpoint {
    pub fn load(path: &Path) -> Self {
        let Ok(text) = std::fs::read_to_string(path) else {
            return Checkpoint {
                version: 1,
                ..Default::default()
            };
        };
        serde_json::from_str(&text).unwrap_or(Checkpoint {
            version: 1,
            ..Default::default()
        })
    }

    pub fn save(&mut self, path: &Path) -> Result<()> {
        self.version = 1;
        self.updated_at = now_secs();
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("json.tmp");
        let text = serde_json::to_string_pretty(self)?;
        std::fs::write(&tmp, text)?;
        std::fs::rename(&tmp, path).context("checkpoint 落盘失败")?;
        Ok(())
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 解密快照代次：所有源库 mtime 的最大值。
pub fn epoch_of(ctx: &Ctx) -> u64 {
    ctx.dbs
        .iter()
        .filter_map(|d| d.path.metadata().ok()?.modified().ok())
        .filter_map(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .max()
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Sink
// ---------------------------------------------------------------------------

pub trait Sink {
    fn write(&mut self, dataset: &str, key: &str, payload: &serde_json::Value) -> Result<()>;
    fn flush(&mut self) -> Result<()>;
}

/// 流式 JSONL：每行 `{"schema":1,"dataset":..,"key":..,"payload":..}`。
pub struct JsonlSink {
    w: BufWriter<std::fs::File>,
    pub rows: usize,
}

impl JsonlSink {
    pub fn create(path: &Path) -> Result<Self> {
        if let Some(d) = path.parent() {
            std::fs::create_dir_all(d)?;
        }
        // 追加写：增量采集不能把上一次的结果覆盖掉
        let f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(JsonlSink {
            w: BufWriter::new(f),
            rows: 0,
        })
    }
}

impl Sink for JsonlSink {
    fn write(&mut self, dataset: &str, key: &str, payload: &serde_json::Value) -> Result<()> {
        let rec = serde_json::json!({
            "schema": 1, "dataset": dataset, "key": key, "payload": payload
        });
        writeln!(self.w, "{}", serde_json::to_string(&rec)?)?;
        self.rows += 1;
        Ok(())
    }
    fn flush(&mut self) -> Result<()> {
        self.w.flush()?;
        Ok(())
    }
}

/// SQLite sink：按 `(dataset, key)` 幂等 upsert。
pub struct SqliteSink {
    conn: rusqlite::Connection,
    pub rows: usize,
}

impl SqliteSink {
    pub fn create(path: &Path) -> Result<Self> {
        if let Some(d) = path.parent() {
            std::fs::create_dir_all(d)?;
        }
        let conn = rusqlite::Connection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS rows(
                 dataset TEXT NOT NULL,
                 key TEXT NOT NULL,
                 payload TEXT NOT NULL,
                 PRIMARY KEY(dataset, key));",
        )?;
        Ok(SqliteSink { conn, rows: 0 })
    }
}

impl Sink for SqliteSink {
    fn write(&mut self, dataset: &str, key: &str, payload: &serde_json::Value) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO rows(dataset,key,payload) VALUES(?1,?2,?3)",
            rusqlite::params![dataset, key, serde_json::to_string(payload)?],
        )?;
        self.rows += 1;
        Ok(())
    }
    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 采集
// ---------------------------------------------------------------------------

pub struct CollectOpts {
    pub chats: Option<Vec<String>>,
    pub kinds: Option<HashSet<String>>,
    pub since: Option<i64>,
    pub until: Option<i64>,
    pub batch: usize,
    pub full: bool,
}

pub struct CollectReport {
    pub rows: usize,
    pub chats: usize,
    pub epoch: u64,
}

fn message_key(m: &crate::model::Message) -> String {
    format!(
        "{}:{}",
        m.chat,
        if m.server_id != 0 {
            m.server_id.to_string()
        } else {
            format!("{}/{}", m.shard, m.local_id)
        }
    )
}

pub fn collect_messages(
    ctx: &Ctx,
    sink: &mut dyn Sink,
    state: &Path,
    opts: &CollectOpts,
) -> Result<CollectReport> {
    let chats = match &opts.chats {
        Some(c) => c.clone(),
        None => query::sessions(ctx, 500)?
            .into_iter()
            .map(|s| s.username)
            .collect(),
    };
    let index = query::shard_index(ctx, &chats);
    let mut cp = Checkpoint::load(state);
    cp.epoch = epoch_of(ctx);
    let mut report = CollectReport {
        rows: 0,
        chats: 0,
        epoch: cp.epoch,
    };

    for chat in &chats {
        let shards = match index.get(chat) {
            Some(v) if !v.is_empty() => v.clone(),
            _ => continue,
        };
        let mut after = if opts.full {
            0
        } else {
            cp.cursors.get(chat).map(|c| c.sort_seq).unwrap_or(0)
        };
        report.chats += 1;
        loop {
            let rows = query::messages_after(
                ctx,
                chat,
                &shards,
                after,
                opts.batch,
                opts.kinds.as_ref(),
                opts.since,
                opts.until,
            )?;
            if rows.is_empty() {
                break;
            }
            for m in &rows {
                let payload = serde_json::to_value(m)?;
                sink.write("messages", &message_key(m), &payload)?;
                report.rows += 1;
            }
            if let Some(last) = rows.last() {
                after = last.sort_seq;
                cp.cursors.insert(
                    chat.clone(),
                    Cursor {
                        chat: chat.clone(),
                        sort_seq: last.sort_seq,
                        shard: last.shard.clone(),
                        local_id: last.local_id,
                    },
                );
            }
            cp.save(state)?;
            if rows.len() < opts.batch {
                break;
            }
        }
        sink.flush()?;
    }
    cp.save(state)?;
    Ok(report)
}

/// 维度数据一次性导出（联系人/群/成员/标签/会话）。
pub fn collect_dimension(ctx: &Ctx, dataset: &str, sink: &mut dyn Sink) -> Result<usize> {
    let mut n = 0usize;
    match dataset {
        "contacts" => {
            for c in query::contacts(ctx, Some(""), 100000)? {
                sink.write("contacts", &c.username, &serde_json::to_value(&c)?)?;
                n += 1;
            }
        }
        "groups" => {
            for g in query::groups(ctx)? {
                sink.write("groups", &g.username, &serde_json::to_value(&g)?)?;
                n += 1;
            }
        }
        "members" => {
            for g in query::groups(ctx)? {
                for m in query::group_members(ctx, &g.username)? {
                    let key = format!("{}:{}", g.username, m.username);
                    let mut v = serde_json::to_value(&m)?;
                    if let Some(o) = v.as_object_mut() {
                        o.insert("chat".into(), serde_json::json!(g.username));
                    }
                    sink.write("members", &key, &v)?;
                    n += 1;
                }
            }
        }
        "labels" => {
            for l in query::labels(ctx)? {
                sink.write(
                    "labels",
                    &l.label_id.to_string(),
                    &serde_json::to_value(&l)?,
                )?;
                n += 1;
            }
        }
        "sessions" => {
            for s in query::sessions(ctx, 5000)? {
                sink.write("sessions", &s.username, &serde_json::to_value(&s)?)?;
                n += 1;
            }
        }
        other => anyhow::bail!("未知 dataset：{other}"),
    }
    sink.flush()?;
    Ok(n)
}

// ---------------------------------------------------------------------------
// 监听
// ---------------------------------------------------------------------------

/// 缺口启发式：相邻两条消息的 `sort_seq` 间隔超过 5 分钟就当一次可疑缺口。
///
/// `sort_seq` 是毫秒时间戳，群静默很久本来就是空档，所以这里只**报告**，
/// 不阻断；真正的判据应由消费方按业务容忍度决定。
pub const GAP_MS: i64 = 5 * 60 * 1000;

pub fn is_gap(prev: i64, next: i64) -> bool {
    prev > 0 && next > prev && next - prev > GAP_MS
}

pub struct TailOpts {
    pub chats: Option<Vec<String>>,
    pub kinds: Option<HashSet<String>>,
    pub interval: f64,
    pub once: bool,
    pub limit: usize,
}

pub fn tail<F>(ctx: &Ctx, state: &Path, opts: &TailOpts, mut on_event: F) -> Result<()>
where
    F: FnMut(&serde_json::Value) -> Result<()>,
{
    let chats = match &opts.chats {
        Some(c) => c.clone(),
        None => query::sessions(ctx, 500)?
            .into_iter()
            .map(|s| s.username)
            .collect(),
    };
    let index = query::shard_index(ctx, &chats);
    let mut cp = Checkpoint::load(state);
    cp.epoch = epoch_of(ctx);

    loop {
        let mut emitted = 0usize;
        for chat in &chats {
            let shards = match index.get(chat) {
                Some(v) if !v.is_empty() => v.clone(),
                _ => continue,
            };
            let after = cp.cursors.get(chat).map(|c| c.sort_seq).unwrap_or(0);
            let rows = query::messages_after(
                ctx,
                chat,
                &shards,
                after,
                opts.limit,
                opts.kinds.as_ref(),
                None,
                None,
            )?;
            if rows.is_empty() {
                continue;
            }
            if let Some(first) = rows.first() {
                if is_gap(after, first.sort_seq) {
                    on_event(&serde_json::json!({
                        "kind": "gap", "at": now_secs(), "chat": chat,
                        "prev_sort_seq": after, "next_sort_seq": first.sort_seq,
                        "skipped_ms": first.sort_seq - after,
                    }))?;
                }
            }
            for m in &rows {
                let ev = serde_json::json!({
                    "kind": "message",
                    "at": now_secs(),
                    "chat": chat,
                    "cursor": {"sort_seq": m.sort_seq, "shard": m.shard, "local_id": m.local_id},
                    "payload": serde_json::to_value(m)?,
                });
                on_event(&ev)?;
                emitted += 1;
            }
            if let Some(last) = rows.last() {
                cp.cursors.insert(
                    chat.clone(),
                    Cursor {
                        chat: chat.clone(),
                        sort_seq: last.sort_seq,
                        shard: last.shard.clone(),
                        local_id: last.local_id,
                    },
                );
            }
        }
        if emitted > 0 || opts.once {
            cp.save(state)?;
        }
        if opts.once {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_secs_f64(opts.interval.max(0.2)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkpoint_roundtrip() {
        let dir = std::env::temp_dir().join(format!("wx_db_rs_cp_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("cp.json");
        let mut cp = Checkpoint::default();
        cp.cursors.insert(
            "a@chatroom".into(),
            Cursor {
                chat: "a@chatroom".into(),
                sort_seq: 123,
                shard: "s".into(),
                local_id: 7,
            },
        );
        cp.save(&p).unwrap();
        let got = Checkpoint::load(&p);
        assert_eq!(got.cursors["a@chatroom"].sort_seq, 123);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn gap_heuristic() {
        assert!(!is_gap(0, 1000));
        assert!(!is_gap(1000, 2000));
        assert!(is_gap(1000, 1000 + GAP_MS + 1));
        assert!(!is_gap(1000, 900));
    }
}
