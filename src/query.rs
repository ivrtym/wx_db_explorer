//! 查询层：会话 / 消息（跨分片）/ 联系人 / 群 / 成员 / 标签。

use crate::model::{Contact, Group, GroupMember, Label, Message, Session};
use crate::paths::DbFile;
use crate::store::Store;
use anyhow::{anyhow, Result};
use md5::{Digest, Md5};
use rusqlite::{types::ValueRef, Connection};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub struct Ctx {
    pub account: String,
    pub account_dir: PathBuf,
    pub cfg_dwords: Vec<u32>,
    pub wxid: String,
    pub dbs: Vec<DbFile>,
    pub keys: HashMap<String, [u8; 32]>,
    pub store: Store,
}

/// 消息类型码 → 中文名（兼容 4.x 复合码：低 32 位才是真实类型）。
pub fn type_name(t: i64) -> String {
    fn base_name(t: i64) -> Option<&'static str> {
        Some(match t {
            1 => "文本",
            3 => "图片",
            34 => "语音",
            42 => "名片",
            43 => "视频",
            47 => "动画表情",
            48 => "位置",
            49 => "文件/链接/卡片",
            50 => "音视频通话",
            10000 => "系统消息",
            11000 => "动画表情",
            8594229559345 => "红包",
            _ => return None,
        })
    }
    if let Some(n) = base_name(t) {
        return n.to_string();
    }
    if t > 0xFFFF {
        let base = t & 0xFFFF_FFFF;
        if let Some(n) = base_name(base) {
            return n.to_string();
        }
        if let Some(n) = base_name(base & 0xFF) {
            return n.to_string();
        }
    }
    t.to_string()
}

/// 正文归一化：文本 / zstd 长文本 / 二进制占位。
pub(crate) fn friendly_content(v: ValueRef<'_>, kind: &str) -> String {
    let placeholder = format!("[{kind}]");
    let bytes: Option<&[u8]> = match v {
        ValueRef::Text(b) | ValueRef::Blob(b) => Some(b),
        _ => None,
    };
    let Some(b) = bytes else { return placeholder };
    if b.is_empty() {
        return placeholder;
    }
    if let Ok(s) = std::str::from_utf8(b) {
        let s = s.trim();
        return if s.is_empty() {
            placeholder
        } else {
            s.to_string()
        };
    }
    // zstd 压缩的长文本帧
    if b.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        if let Ok(out) = zstd::stream::decode_all(std::io::Cursor::new(b)) {
            if let Ok(s) = std::str::from_utf8(&out) {
                let s = s.trim();
                if !s.is_empty() {
                    return s.to_string();
                }
            }
        }
    }
    placeholder
}

fn table_exists(conn: &Connection, name: &str) -> Result<bool> {
    let mut stmt =
        conn.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1 LIMIT 1")?;
    Ok(stmt.exists([name])?)
}

fn name2id_map(conn: &Connection) -> Result<HashMap<i64, String>> {
    let mut out = HashMap::new();
    let mut stmt = conn.prepare("SELECT rowid, user_name FROM Name2Id")?;
    let mut rows = stmt.query([])?;
    while let Some(r) = rows.next()? {
        let id: i64 = r.get(0)?;
        let name: String = r.get(1)?;
        out.insert(id, name);
    }
    Ok(out)
}

impl Ctx {
    fn open(&self, rel: &str) -> Result<Connection> {
        let db = self
            .dbs
            .iter()
            .find(|d| d.rel == rel)
            .ok_or_else(|| anyhow!("找不到库：{rel}"))?;
        let key = self
            .keys
            .get(rel)
            .ok_or_else(|| anyhow!("没有 {rel} 的可用密钥"))?;
        let path = self.store.ensure(&db.path, &db.rel, key)?;
        crate::store::open_ro(&path)
    }

    pub fn available(&self) -> usize {
        self.dbs
            .iter()
            .filter(|d| self.keys.contains_key(&d.rel))
            .count()
    }
}

pub fn sessions(ctx: &Ctx, limit: usize) -> Result<Vec<Session>> {
    let conn = ctx.open("session/session.db")?;
    let mut stmt = conn.prepare(
        "SELECT username, unread_count, summary, last_timestamp, \
         COALESCE(last_sender_display_name, last_msg_sender, '') \
         FROM SessionTable WHERE is_hidden=0 ORDER BY sort_timestamp DESC LIMIT ?1",
    )?;
    let mut rows = stmt.query([limit as i64])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        out.push(Session {
            username: r.get(0)?,
            unread: r.get::<_, Option<i64>>(1)?.unwrap_or(0),
            summary: r.get::<_, Option<String>>(2)?.unwrap_or_default(),
            last_time: r.get::<_, Option<i64>>(3)?.unwrap_or(0),
            last_sender: r.get::<_, Option<String>>(4)?.unwrap_or_default(),
        });
    }
    Ok(out)
}

/// 跨分片读消息：表名 = `Msg_<md5(username)>`。
pub fn messages(ctx: &Ctx, chat: &str, limit: usize) -> Result<Vec<Message>> {
    let table = format!("Msg_{:x}", Md5::digest(chat.as_bytes()));
    let mut out: Vec<Message> = Vec::new();
    for db in &ctx.dbs {
        // 只看普通消息分片，排除 biz_message_*（公众号）
        let base = db.rel.rsplit('/').next().unwrap_or("");
        if !db.rel.starts_with("message/") || !base.starts_with("message_") {
            continue;
        }
        let Ok(conn) = ctx.open(&db.rel) else {
            continue;
        };
        if !table_exists(&conn, &table)? {
            continue;
        }
        let senders = name2id_map(&conn).unwrap_or_default();
        let sql = format!(
            "SELECT local_id, local_type, sort_seq, real_sender_id, create_time, \
             message_content FROM \"{table}\" ORDER BY sort_seq DESC LIMIT ?1"
        );
        let mut stmt = conn.prepare(&sql)?;
        let mut rows = stmt.query([limit as i64])?;
        while let Some(r) = rows.next()? {
            let type_code: i64 = r.get(1)?;
            let kind = type_name(type_code);
            let sender_id: i64 = r.get::<_, Option<i64>>(3)?.unwrap_or(0);
            let sender = senders.get(&sender_id).cloned().unwrap_or_default();
            let mut content = friendly_content(r.get_ref(5)?, &kind);
            // 群消息正文带「发送者:\n」前缀，显示时去掉
            if !sender.is_empty() {
                if let Some(rest) = content.strip_prefix(&format!("{sender}:\n")) {
                    content = rest.trim_start().to_string();
                } else if let Some(rest) = content.strip_prefix(&format!("{sender}:")) {
                    content = rest.trim_start().to_string();
                }
            }
            out.push(Message {
                local_id: r.get(0)?,
                kind,
                type_code,
                sender_id,
                sender,
                create_time: r.get::<_, Option<i64>>(4)?.unwrap_or(0),
                sort_seq: r.get::<_, Option<i64>>(2)?.unwrap_or(0),
                content,
                shard: db.rel.clone(),
            });
        }
    }
    out.sort_by(|a, b| b.sort_seq.cmp(&a.sort_seq));
    out.truncate(limit);
    Ok(out)
}

pub fn contacts(ctx: &Ctx, search: Option<&str>, limit: usize) -> Result<Vec<Contact>> {
    let conn = ctx.open("contact/contact.db")?;
    let kw = format!("%{}%", search.unwrap_or(""));
    let mut stmt = conn.prepare(
        "SELECT username, nick_name, remark FROM contact \
         WHERE nick_name LIKE ?1 OR remark LIKE ?1 OR username LIKE ?1 OR alias LIKE ?1 \
         LIMIT ?2",
    )?;
    let mut rows = stmt.query(rusqlite::params![kw, limit as i64])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        out.push(Contact {
            username: r.get(0)?,
            nick_name: r.get::<_, Option<String>>(1)?.unwrap_or_default(),
            remark: r.get::<_, Option<String>>(2)?.unwrap_or_default(),
        });
    }
    Ok(out)
}

pub fn groups(ctx: &Ctx) -> Result<Vec<Group>> {
    let conn = ctx.open("contact/contact.db")?;
    let mut stmt = conn.prepare(
        "SELECT r.username, COALESCE(c.nick_name, r.username) AS name, r.owner, \
         (SELECT COUNT(*) FROM chatroom_member m WHERE m.room_id = r.id) AS cnt \
         FROM chat_room r LEFT JOIN contact c ON c.username = r.username ORDER BY cnt DESC",
    )?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        out.push(Group {
            username: r.get(0)?,
            name: r.get(1)?,
            owner: r.get::<_, Option<String>>(2)?.unwrap_or_default(),
            member_count: r.get::<_, Option<i64>>(3)?.unwrap_or(0),
        });
    }
    Ok(out)
}

pub fn group_members(ctx: &Ctx, group: &str) -> Result<Vec<GroupMember>> {
    let conn = ctx.open("contact/contact.db")?;
    let mut stmt = conn.prepare(
        "SELECT c.username, c.nick_name, c.remark, (c.username = r.owner) \
         FROM chat_room r \
         JOIN chatroom_member m ON m.room_id = r.id \
         JOIN contact c ON c.id = m.member_id \
         WHERE r.username = ?1 ORDER BY c.username",
    )?;
    let mut rows = stmt.query([group])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        out.push(GroupMember {
            username: r.get(0)?,
            nick_name: r.get::<_, Option<String>>(1)?.unwrap_or_default(),
            remark: r.get::<_, Option<String>>(2)?.unwrap_or_default(),
            is_owner: r.get::<_, i64>(3)? != 0,
        });
    }
    Ok(out)
}

pub fn labels(ctx: &Ctx) -> Result<Vec<Label>> {
    let conn = ctx.open("contact/contact.db")?;
    let mut stmt =
        conn.prepare("SELECT label_id_, label_name_, sort_order_ FROM contact_label ORDER BY sort_order_, label_id_")?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        out.push(Label {
            label_id: r.get(0)?,
            name: r.get::<_, Option<String>>(1)?.unwrap_or_default(),
            sort_order: r.get::<_, Option<i64>>(2)?.unwrap_or(0),
        });
    }
    Ok(out)
}

#[allow(dead_code)]
pub fn shard_of(path: &Path) -> String {
    path.file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_string()
}
