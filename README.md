# wx_db_explorer

微信 4.x **本地数据库读取器**的 Rust 实现——`wechatauto` 读库部分的独立重写。
只读、不注入、不改微信进程；不需要界面，不需要登录窗口。

> 当前状态：**M7 完成**——读 + 媒体 + 朋友圈 + 增量采集 / 准实时监听 + 维度变更检测。
> 后续只剩工程化增强（见路线图）。

---

## 已实现

| 能力 | 说明 |
|---|---|
| 目录探测 | `~/.xwechat/config/*.ini` 的 `MyDocument:`，回退 `~/文档/xwechat_files` |
| 密钥提取 | 扫 `/proc/<pid>/mem` 的 `com.Tencent.WCDB.Config.Cipher`，XOR 掩码还原 keyspec |
| 密钥缓存 | `~/.local/share/wx_db_explorer/keys.json`（0600），按 salt 匹配 + 页 1 HMAC 验真 |
| 库解密 | SQLCipher4 页级 AES-256-CBC，页 1 明文头，`PRAGMA quick_check` 校验 |
| **WAL 合并** | 按 salt 过滤帧、逐页解密覆盖、修正页 1 页数；失败退回主库快照 |
| 解密缓存 | `~/.local/share/wx_db_explorer/db/<account>/`，stamp 记录 mtime/size/wal/applied |
| 会话 | `SessionTable`（未读、摘要、最后时间、最后发送者） |
| 消息 | 跨分片按 `Msg_<md5(chat)>` 查询，`Name2Id` 解析发送者，支持复合类型码 |
| 联系人 | 昵称/备注/微信号模糊搜索（**无 50 条上限**） |
| 群 / 成员 / 标签 | 一条 SQL join，493 人群不产生 N+1 |
| **图片** | `cfgDword` 派生密钥（在 Config 对象附近暴力定位偏移）→ V2/V1 解密 → 三档副本定位 → 导出 |
| 直接解 `.dat` | `decrypt-dat <file>`，不依赖消息库 |
| 语音 | `media_*.db` 的 `VoiceInfo.voice_data` → `.silk`（SILK 头校验） |
| 视频 | `packed_info` 里的 id → `msg/video/<id>.mp4`（**需先在微信里播放过一次**；否则明确报缺失） |
| 文件 | 按 XML 原名 + 长度在 `msg/file` 下匹配（含 `(n)` 副本） |
| 朋友圈 | `sns.db` 时间线解析（正文/图片/视频/点赞/评论） |
| 朋友圈媒体 | Sns 缓存文件名是不透明 key，按**宽高精确匹配 + 明文尺寸消歧**（歧义拒绝），解密后导出 |
| 远端兜底 | `moment-media --fetch` 带微信 UA + Referer 拉 URL；CDN 多数情况只返回「暂时无法查看」占位图或 400，代码会**识别并报错**，不会保存占位图 |
| 互动通知 | `SnsMessage_tmp3`（他人对我的赞/评论，含未读数） |
| 采集 Collector | `collect messages` 增量续采（游标 + 检查点）、维度快照；JSONL / SQLite sink |
| 监听 Tailer | `tail --chat/--all`，JSONL 事件、检查点续传、缺口启发式 |
| 朋友圈增量 | `collect moments|interactions` 按 `tid` / `local_id` 游标续采 |
| 维度 diff | `collect diff`：联系人/群/成员/标签/会话的**逐键哈希变更**（+/-/~） |
| 导出 | JSON |

**跳过** `*_fts.db`：WCDB 自定义分词器 `MMFtsTokenizer`，系统 SQLite 打不开，
且它是检索索引不是数据源。

## 未实现（路线图）

| 阶段 | 内容 |
|---|---|
| M9 | 打包发布：README 示例、Release 二进制、CI |
| — | 远端媒体：已验证需会话态/签名，直连只能拿到占位图；不再投入 |

## 安装 / 分发

预编译包在 GitHub Releases：<https://github.com/ivrtym/wx_db_explorer/releases>

```bash
tar -xzf wx_db_explorer-0.9.1-x86_64-unknown-linux-gnu.tar.gz
./wx_db_explorer-0.9.1-x86_64-unknown-linux-gnu/wx_db_explorer doctor
```

- 单文件二进制（已 strip，约 5.8 MB）；SQLite 静态编入，**不依赖系统 libsqlite3**
- 仅支持 Linux；其它平台会明确报 `compile_error!`
- 动态链接 glibc；需要完全静态版可
  `cargo build --release --target x86_64-unknown-linux-musl`
- 重新打包：`sh scripts/release.sh` → `dist/wx_db_explorer-<ver>-<target>.tar.gz`
  （含 README 与 LICENSE，附 sha256）

## 用法

```bash
cargo build --release
B=./target/release/wx_db_explorer

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
$B moments --limit 20                 # 朋友圈时间线
$B moments --me --json                # 只看自己（JSON）
$B interactions --unread              # 未读赞/评论
$B moment-media -3384355768585342428 --out ./sns          # 本地缓存（推荐）
$B moment-media -3384355768585342428 --fetch --out ./sns  # 缓存缺失时尝试远端

# 增量采集（断点续采；--full 从头重采）
$B collect messages --all --out msgs.jsonl --state state.json
$B collect messages --chat 52764254929@chatroom --since 1795500000 --out one.jsonl
$B collect contacts --out contacts.jsonl
$B collect moments --out moments.jsonl        # 按 tid 增量
$B collect interactions --out it.jsonl        # 按 local_id 增量
$B collect messages --all --out msgs.db        # 按后缀选 SQLite sink（幂等 upsert）
$B collect diff --state dim.json               # 看维度变更（+新增 -删除 ~修改）
$B collect diff --state dim.json --update      # 写回基线

# 准实时监听（JSONL 事件；Ctrl+C 退出，检查点每轮落盘）
$B tail --chat 52764254929@chatroom --state tail.json
$B tail --all --interval 2 --state tail.json
$B tail --all --once --limit 5                 # 只轮询一次（调试/回放）
```

**投递语义**：at-least-once；同一会话内按 `sort_seq` 严格升序；跨会话不保证全局序。
检查点记录 `(chat, sort_seq, shard, local_id)` 与解密快照 `epoch`，崩溃后从上次位置继续。

> 朋友圈图片缓存的文件名与 feed 的 md5 **没有代数关系**，只能按
> `<size width height>` 精确匹配；同尺寸多张时用明文字节数消歧，
> 仍歧义则拒绝（不拿无关图冒充）。

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
| 语音导出 | 有 | 有（2928B SILK，sha256 一致） |
| 视频导出 | 有（未播放时返回 None） | 有（播放后 494KB HEVC/AAC，sha256 一致） |
| 文件导出 | 有 | 有（按原名+长度，32B 文本） |
| 朋友圈 | 13 条 | 13 条，8 个字段逐条一致（含图片 md5） |
| 朋友圈图片 | 需显式传 key 才能解 | 5 条动态的图片导出成功；与 Python 选中的缓存文件 **sha256 相同** |
| 朋友圈远端 | 支持 URL 拉取 | 实测：`shmmsns` 返回 120x120「暂时无法查看」占位图；`wxapp`/视频 CDN 返回 400 |
| 互动通知 | 2 条 | 2 条一致 |

## 图片密钥是怎么拿到的

Linux 的 Config 布局与 Windows 不同（cipher 在 `cfg+0x98`，Windows 是 `cfg+0x2B8`），
所以不能沿用 Windows 的 `cfg+0x40`。做法：在 Config 对象后 1KB 窗口里逐 4 字节
尝试 `MD5(str(dword) + wxid)[:16]`，用一张 V2 图片的首块解出 JPEG/PNG 魔数来验证。
失败才回落到"扫描内存 ASCII 串"（需要先在微信里打开一张图片）。

## 运行要求

- **仅 Linux**（`/proc/<pid>/mem` + Unix 权限位）。在 Windows/macOS 上会直接触发
  `compile_error!` 并说明原因，而不是编译出一堆无关错误。
- 首次取密钥需要 root 或 `CAP_SYS_PTRACE`（或 `ptrace_scope=0`），之后走缓存。
- 只读：不 `WriteProcessMemory`、不写微信目录。

## 许可

Apache-2.0（与上游 `wechatauto-replica` 一致）。
