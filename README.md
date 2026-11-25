# wx_db_rs

微信 4.x **本地数据库读取器**的 Rust 实现——`wechatauto` 读库部分的独立重写。
只读、不注入、不改微信进程；不需要界面，不需要登录窗口。

> 当前状态：**M1 完成**（密钥 → 解密 → 会话/消息/联系人/群/成员/标签/导出）。
> 媒体、朋友圈、WAL 合并、监听与采集引擎见路线图。

---

## 已实现

| 能力 | 说明 |
|---|---|
| 目录探测 | `~/.xwechat/config/*.ini` 的 `MyDocument:`，回退 `~/文档/xwechat_files` |
| 密钥提取 | 扫 `/proc/<pid>/mem` 的 `com.Tencent.WCDB.Config.Cipher`，XOR 掩码还原 keyspec |
| 密钥缓存 | `~/.local/share/wx_db_rs/keys.json`（0600），按 salt 匹配 + 页 1 HMAC 验真 |
| 库解密 | SQLCipher4 页级 AES-256-CBC，页 1 明文头，`PRAGMA quick_check` 校验 |
| 解密缓存 | `~/.local/share/wx_db_rs/db/<account>/`，stamp 命中直接复用 |
| 会话 | `SessionTable`（未读、摘要、最后时间、最后发送者） |
| 消息 | 跨分片按 `Msg_<md5(chat)>` 查询，`Name2Id` 解析发送者，支持复合类型码 |
| 联系人 | 昵称/备注/微信号模糊搜索（**无 50 条上限**） |
| 群 / 成员 / 标签 | 一条 SQL join，493 人群不产生 N+1 |
| 导出 | JSON |

**跳过** `*_fts.db`：WCDB 自定义分词器 `MMFtsTokenizer`，系统 SQLite 打不开，
且它是检索索引不是数据源。

## 未实现（路线图）

| 阶段 | 内容 |
|---|---|
| M2 | WAL 合并（salt 帧过滤，取最新增量） |
| M3 | 媒体：图片 key 派生、`.dat` V1/V2 解密、语音/视频/文件定位 |
| M4 | 朋友圈（`sns.db` 时间线 + 互动通知 + 缓存媒体） |
| M5 | Collector / Tailer（按 `docs/READ_API_V2.md` 的游标与检查点设计） |

## 用法

```bash
cargo build --release
B=./target/release/wx_db_rs

$B doctor                       # 账号 / 库数量 / 可用密钥 / 缺失项
$B sessions --limit 20
$B messages 52764254929@chatroom --limit 20
$B messages 52764254929@chatroom --limit 5 --json
$B contacts --search 明珠 --limit 10
$B groups
$B members 57412811169@chatroom
$B labels
$B export 52764254929@chatroom --out chat.json --limit 1000
```

全局参数：`--db-dir <xwechat_files>`、`--account <目录名>`、`--keys-file <path>`、`--json`。

## 架构

```
src/
├── main.rs    CLI（clap）
├── paths.rs   数据目录 / 账号 / 库文件收集（跳过 migrate 与 *_fts.db）
├── proc.rs    /proc/<pid>/mem 只读扫描（memchr 加速）
├── keys.rs    keyspec 提取、salt 匹配、缓存
├── crypto.rs  页解密 + 页 1 HMAC
├── store.rs   解密缓存 + stamp + quick_check
├── query.rs   会话/消息/联系人/群/成员/标签
└── model.rs   对外结构（serde）
```

关键不变量（与 Python 版一致）：

1. 每库独立密钥，按**页 1 的 salt**匹配，必须过 HMAC；
2. `local_id` 只在分片内唯一；`sender` 用**本分片**的 `Name2Id` 解析；
3. 解密产物先落 tmp，校验通过才原子替换；
4. 任何中间结果失败都退回上一份可用副本，不产生半成品。

## 与 Python 实现的对照（实测）

| 项 | Python | Rust |
|---|---|---|
| doctor | `19/19`（3 个 FTS 报错） | `16/16`（跳过 FTS） |
| 会话 | 50 | 50 |
| 消息（special_trader） | 1000 | 1000，字段逐条一致 |
| 联系人搜索 | 上限 50 | 无上限 |
| 群消息正文 | 保留 `sender:\n` 前缀 | 已剥离 |
| 首跑取密钥 | ~数秒 | ~14 秒（SIMD 搜索后） |
| 后续启动 | 走缓存 | 走缓存（<1s） |

## 运行要求

- Linux（用到 `/proc/<pid>/mem` 与 Unix 权限位）；Windows 端待补。
- 首次取密钥需要 root 或 `CAP_SYS_PTRACE`（或 `ptrace_scope=0`），之后走缓存。
- 只读：不 `WriteProcessMemory`、不写微信目录。

## 许可

Apache-2.0（与上游 `wechatauto-replica` 一致）。
