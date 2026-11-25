//! 对外数据结构（与 wechatauto 的 dict 字段保持一致，便于对照）。

use serde::Serialize;

#[derive(Serialize, Debug, Clone)]
pub struct Session {
    pub username: String,
    pub unread: i64,
    pub summary: String,
    pub last_time: i64,
    pub last_sender: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct Message {
    pub chat: String,
    pub server_id: i64,
    pub local_id: i64,
    pub kind: String,
    pub type_code: i64,
    pub sender_id: i64,
    pub sender: String,
    pub create_time: i64,
    pub sort_seq: i64,
    pub content: String,
    pub shard: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct Contact {
    pub username: String,
    pub nick_name: String,
    pub remark: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct Group {
    pub username: String,
    pub name: String,
    pub owner: String,
    pub member_count: i64,
}

#[derive(Serialize, Debug, Clone)]
pub struct GroupMember {
    pub username: String,
    pub nick_name: String,
    pub remark: String,
    pub is_owner: bool,
}

#[derive(Serialize, Debug, Clone)]
pub struct Label {
    pub label_id: i64,
    pub name: String,
    pub sort_order: i64,
}
