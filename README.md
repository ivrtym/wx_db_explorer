# wx_db_rs

微信 4.x **本地数据库读取器**的 Rust 实现——`wechatauto` 读库部分的独立重写。
只读、不注入、不改微信进程；不需要界面，不需要登录窗口。

> 当前状态：**M3.5 完成**——密钥 → 解密 → WAL 合并 → 会话/消息/联系人/群/成员/标签
> → 图片/语音/视频/文件导出。朋友圈、监听与采集引擎见路线图。

---

## 已实现

| 能力 | 说明 |
|---|---|
| 目录探测 | `~/.xwechat/config/*.ini` 的 `MyDocument:`，回退 `~/文档/xwechat_files` |
| 密钥提取 | 扫 `/proc/<pid>/mem` 的 `com.Tencent.WCDB.Config.Cipher`，XOR 掩码还原 keyspec |
| 密钥缓存 | `~/.local/share/wx_db_rs/keys.json`（0600），按 salt 匹配 + 页 1 HMAC 验真 |
| 库解密 | SQLCipher4 页级 AES-256-CBC，页 1 明文头，`PRAGMA quick_check` 校验 |
| **WAL 合并** | 按 salt 过滤帧、逐页解密覆盖、修正页 1 页数；失败退回主库快照 |
| 解密缓存 | `~/.local/share/wx_db_rs/db/<account>/`，stamp 记录 mtime/size/wal/applied |
| 会话 | `SessionTable`（未读、摘要、最后时间、最后发送者） |
| 消息 | 跨分片按 `Msg_<md5(chat)>` 查询，`Name2Id` 解析发送者，支持复合类型码 |
| 联系人 | 昵称/备注/微信号模糊搜索（**无 50 条上限**） |
| 群 / 成员 / 标签 | 一条 SQL join，493 人群不产生 N+1 |
| **图片** | `cfgDword` 派生密钥（在 Config 对象附近暴力定位偏移）→ V2/V1 解密 → 三档副本定位 → 导出 |
| 直接解 `.dat` | `decrypt-dat <file>`，不依赖消息库 |
| 语音 | `media_*.db` 的 `VoiceInfo.voice_data` → `.silk`（SILK 头校验） |
| 视频 | `packed_info` 里的 id → `msg/video/<id>.mp4`（没有就明确报缺失） |
| 文件 | 按 XML 原名 + 长度在 `msg/file` 下匹配（含 `(n)` 副本） |
| 导出 | JSON |

**跳过** `*_fts.db`：WCDB 自定义分词器 `MMFtsTokenizer`，系统 SQLite 打不开，
且它是检索索引不是数据源。

## 未实现（路线图）

| 阶段 | 内容 |
|---|---|
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
$B image-key                     # 派生/检测图片密钥（cfgDword，不需要打开图片）
$B images 52764254929@chatroom --limit 20 --out ./imgs
$B decrypt-dat ~/文档/xwechat_files/.../Img/xxx_t.dat --out one.jpg
$B media wxid_xxx --limit 20 --out ./media            # 语音/视频/文件
$B media wxid_xxx --kind voice --out ./voice
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
| WAL 合并 | 有 | 有（message_0 实测 722 帧） |
| 联系人/会话/群/成员 | 1668 / 101 / 13 / 493 | **1668 / 101 / 13 / 493** |
| 图片解密 | 有（key 需打开图片后抓） | 有（**cfgDword 派生，无需打开图片**）；与 Python 逐字节一致 |
| 语音导出 | 有 | 有（SILK，与 Python 逐字节一致） |
| 视频导出 | 有（缺文件返回 None） | 有（同样如实返回缺失） |

## 图片密钥是怎么拿到的

Linux 的 Config 布局与 Windows 不同（cipher 在 `cfg+0x98`，Windows 是 `cfg+0x2B8`），
所以不能沿用 Windows 的 `cfg+0x40`。做法：在 Config 对象后 1KB 窗口里逐 4 字节
尝试 `MD5(str(dword) + wxid)[:16]`，用一张 V2 图片的首块解出 JPEG/PNG 魔数来验证。
失败才回落到"扫描内存 ASCII 串"（需要先在微信里打开一张图片）。

## 运行要求

- Linux（用到 `/proc/<pid>/mem` 与 Unix 权限位）；Windows 端待补。
- 首次取密钥需要 root 或 `CAP_SYS_PTRACE`（或 `ptrace_scope=0`），之后走缓存。
- 只读：不 `WriteProcessMemory`、不写微信目录。

## 许可

Apache-2.0（与上游 `wechatauto-replica` 一致）。
