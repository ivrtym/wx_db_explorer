//! 本地媒体：图片 key 发现、`.dat` 解密、三档副本定位。
//!
//! 图片密钥是**账号级**的，不是消息 XML 里的 CDN aeskey：
//!
//! ```text
//! aes = MD5(str(uin) + wxid)[:16]   # 16 字节 ASCII
//! xor = uin & 0xFF
//! ```
//!
//! 本机拿不到 uin 时走"内存候选 + V2 探针验证"：扫描内存里的 16 位十六进制串，
//! 用 AES-128-ECB 解一张 V2 图片的首块，命中 JPEG/PNG/GIF/RIFF/wxgf 魔数即采用。
//!
//! `.dat` 格式：
//! - V2：`魔数(6) + aes_size(u32le) + xor_size(u32le) + pad(5)`，
//!   从 15 开始是 `align16(aes_size)` 的 AES-ECB 密文，中间是明文，末尾
//!   `xor_size` 字节逐字节异或。
//! - V1：`魔数(6) + key(16) + 异或体`。

use anyhow::{anyhow, Result};
use md5::Digest;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

pub const V1_MAGIC: [u8; 6] = [0x07, 0x08, 0x05, 0x56, 0x02, 0x05];
pub const V2_MAGIC: [u8; 6] = [0x07, 0x08, 0x56, 0x32, 0x08, 0x07];
const FOOTER_MAX: usize = 64;

/// 三档副本的优先级：原件 > 微信下发的那份 > 预览图。
pub const TIER_ORDER: [&str; 3] = ["original", "mid", "thumb"];

fn align16(n: u32) -> usize {
    if n % 16 == 0 {
        n as usize + 16
    } else {
        ((n as usize + 15) / 16) * 16
    }
}

/// 从文件尾部反推单字节 XOR key（JPEG 以 `FF D9` 结尾；允许尾部有页脚）。
pub fn derive_xor_from_tail(data: &[u8]) -> Option<u8> {
    if data.len() < 2 {
        return None;
    }
    let tail = &data[data.len().saturating_sub(2 + FOOTER_MAX)..];
    for off in 0..tail.len().saturating_sub(1) {
        let a = tail[tail.len() - 2 - off];
        let b = tail[tail.len() - 1 - off];
        let key = a ^ 0xFF;
        if b ^ key == 0xD9 {
            return Some(key);
        }
    }
    None
}

/// AES-128-ECB 解密（NoPadding），返回全部明文块。
fn aes_ecb_decrypt(key: &[u8; 16], enc: &[u8]) -> Result<Vec<u8>> {
    use aes::cipher::{BlockDecrypt, KeyInit};
    let cipher = aes::Aes128::new_from_slice(key).map_err(|e| anyhow!("AES key: {e}"))?;
    let mut out = Vec::with_capacity(enc.len());
    for chunk in enc.chunks_exact(16) {
        let mut block = aes::cipher::Block::<aes::Aes128>::clone_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        out.extend_from_slice(&block);
    }
    Ok(out)
}

fn unpad_pkcs7(mut v: Vec<u8>) -> Vec<u8> {
    if let Some(&pad) = v.last() {
        let p = pad as usize;
        if (1..=16).contains(&p) && v.len() >= p && v[v.len() - p..].iter().all(|&b| b == pad) {
            v.truncate(v.len() - p);
        }
    }
    v
}

fn image_magic_ok(b: &[u8]) -> bool {
    b.starts_with(&[0xFF, 0xD8, 0xFF])
        || b.starts_with(b"\x89PNG")
        || b.starts_with(b"GIF8")
        || b.starts_with(b"RIFF")
        || b.starts_with(b"wxgf")
}

/// 解密 V2 `.dat`。
pub fn decrypt_v2(data: &[u8], aes: &[u8; 16], xor: u8) -> Result<Vec<u8>> {
    if data.len() < 31 {
        return Err(anyhow!("V2 文件过短"));
    }
    let aes_size = u32::from_le_bytes(data[6..10].try_into().unwrap());
    let xor_size = u32::from_le_bytes(data[10..14].try_into().unwrap()) as usize;
    let blk = align16(aes_size);
    let off = 15;
    if off + blk > data.len() {
        return Err(anyhow!("V2 AES 段越界"));
    }
    let head = aes_ecb_decrypt(aes, &data[off..off + blk])?;
    let head = unpad_pkcs7(head);
    let mid_end = data.len().saturating_sub(xor_size);
    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(&head);
    if mid_end > off + blk {
        out.extend_from_slice(&data[off + blk..mid_end]);
    }
    if xor_size > 0 && xor_size <= data.len() {
        for b in &data[mid_end..] {
            out.push(b ^ xor);
        }
    }
    Ok(trim_footer(out))
}

/// 按图片结束标记裁掉尾部页脚（JPEG / PNG / GIF）。
pub fn trim_footer(mut v: Vec<u8>) -> Vec<u8> {
    let end: &[u8] = if v.starts_with(&[0xFF, 0xD8, 0xFF]) {
        &[0xFF, 0xD9]
    } else if v.starts_with(b"\x89PNG") {
        &[0xAE, 0x42, 0x60, 0x82]
    } else if v.starts_with(b"GIF8") {
        b";"
    } else {
        return v;
    };
    if v.ends_with(end) {
        return v;
    }
    if let Some(pos) = v.windows(end.len()).rposition(|w| w == end) {
        let cut = pos + end.len();
        if v.len() - cut <= FOOTER_MAX {
            v.truncate(cut);
        }
    }
    v
}

/// 缓存容器（朋友圈 Sns）可能是图片也可能是 mp4。
pub fn container_ext(bytes: &[u8]) -> &'static str {
    if bytes.len() >= 12 && &bytes[4..8] == b"ftyp" {
        return "mp4";
    }
    image_ext(bytes)
}

pub fn image_ext(bytes: &[u8]) -> &'static str {
    if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        "jpg"
    } else if bytes.starts_with(b"\x89PNG") {
        "png"
    } else if bytes.starts_with(b"GIF8") {
        "gif"
    } else if bytes.starts_with(b"RIFF") {
        "webp"
    } else {
        "bin"
    }
}

/// 解密任意 `.dat`（V2 / V1 / 早期纯异或）。
pub fn decrypt_dat(data: &[u8], aes: Option<&[u8; 16]>, xor: Option<u8>) -> Result<Vec<u8>> {
    if data.len() > 6 && data[..6] == V2_MAGIC {
        let key = aes.ok_or_else(|| anyhow!("缺少图片 AES key"))?;
        let x = xor
            .or_else(|| derive_xor_from_tail(data))
            .ok_or_else(|| anyhow!("无法从尾部反推 XOR key"))?;
        return decrypt_v2(data, key, x);
    }
    if data.len() > 22 && data[..6] == V1_MAGIC {
        let x = xor
            .or_else(|| derive_xor_from_tail(data))
            .ok_or_else(|| anyhow!("无法从尾部反推 XOR key"))?;
        let body = &data[22..];
        let mut out = Vec::with_capacity(body.len());
        for b in body {
            out.push(b ^ x);
        }
        return Ok(trim_footer(out));
    }
    // 早期纯异或（无签名）
    for cand in [0x88u8, 0x30, 0xFF, 0xE9] {
        let out: Vec<u8> = data.iter().map(|b| b ^ cand).collect();
        if image_magic_ok(&out) {
            return Ok(trim_footer(out));
        }
    }
    Err(anyhow!("无法识别的图片加密格式"))
}

/// 找一张 V2 样本（用于验证候选密钥）。
pub fn find_probe(account_dir: &Path) -> Option<PathBuf> {
    let base = account_dir.join("msg").join("attach");
    let mut stack = vec![base];
    while let Some(d) = stack.pop() {
        let Ok(rd) = fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            if p.extension().and_then(|s| s.to_str()) != Some("dat") {
                continue;
            }
            if let Ok(head) = read_head(&p, 31) {
                if head.len() >= 31 && head[..6] == V2_MAGIC {
                    let aes_size = u32::from_le_bytes(head[6..10].try_into().unwrap());
                    if aes_size >= 16 {
                        return Some(p);
                    }
                }
            }
        }
    }
    None
}

fn read_head(p: &Path, n: usize) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut f = fs::File::open(p)?;
    let mut buf = vec![0u8; n];
    let got = f.read(&mut buf)?;
    buf.truncate(got);
    Ok(buf)
}

/// 用候选 key 试解探针首块，命中图片魔数即通过。
pub fn key_matches(key: &[u8; 16], dat: &Path) -> bool {
    let Ok(head) = read_head(dat, 64) else {
        return false;
    };
    if head.len() < 31 || head[..6] != V2_MAGIC {
        return false;
    }
    let aes_size = u32::from_le_bytes(head[6..10].try_into().unwrap());
    let blk = align16(aes_size);
    let Some(enc) = head.get(15..15 + blk.min(64 - 15)) else {
        return false;
    };
    if enc.len() < 16 {
        return false;
    }
    let enc = &enc[..enc.len() - enc.len() % 16];
    match aes_ecb_decrypt(key, enc) {
        Ok(pt) => image_magic_ok(&pt),
        Err(_) => false,
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct ImageKey {
    pub aes_key: String,
    pub xor_key: Option<u8>,
}

pub fn key_cache_file() -> PathBuf {
    crate::paths::cache_root().join("image_key.json")
}

pub fn load_cached_key() -> Option<ImageKey> {
    for p in [
        key_cache_file(),
        crate::paths::legacy_cache_root().join("image_key.json"),
        crate::paths::user_home().join(".local/share/wechatauto/image_key.json"),
    ] {
        let Ok(text) = fs::read_to_string(&p) else {
            continue;
        };
        if let Ok(k) = serde_json::from_str::<ImageKey>(&text) {
            if k.aes_key.len() >= 16 {
                return Some(k);
            }
        }
    }
    None
}

pub fn save_cached_key(k: &ImageKey) {
    let p = key_cache_file();
    if let Some(d) = p.parent() {
        let _ = fs::create_dir_all(d);
    }
    if let Ok(text) = serde_json::to_string_pretty(k) {
        let tmp = p.with_extension("json.tmp");
        if fs::write(&tmp, text).is_ok() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));
            }
            let _ = fs::rename(&tmp, &p);
        }
    }
}

/// 内存里扫描 16 位十六进制串，用探针验证出图片 AES key。
pub fn scan_key(probe: &Path) -> Option<[u8; 16]> {
    let pids = crate::proc::find_pids();
    let mut seen: std::collections::HashSet<[u8; 16]> = std::collections::HashSet::new();
    for pid in pids {
        let regions = crate::proc::readable_regions(pid);
        let mut mem = match std::fs::File::open(format!("/proc/{pid}/mem")) {
            Ok(f) => f,
            Err(_) => continue,
        };
        for (start, end) in regions {
            let mut addr = start;
            const CHUNK: usize = 8 * 1024 * 1024;
            while addr < end {
                let want = CHUNK.min((end - addr) as usize);
                let Some(buf) = crate::proc::read_at(&mut mem, addr, want) else {
                    addr += want as u64;
                    continue;
                };
                // 找 16~32 长度的十六进制串（密钥是 MD5 前 16 位）
                let mut i = 0;
                while i < buf.len() {
                    if !buf[i].is_ascii_hexdigit() {
                        i += 1;
                        continue;
                    }
                    let s = i;
                    while i < buf.len() && buf[i].is_ascii_hexdigit() {
                        i += 1;
                    }
                    let run = &buf[s..i];
                    if run.len() >= 16 {
                        for w in run.windows(16) {
                            let mut key = [0u8; 16];
                            key.copy_from_slice(w);
                            if !seen.insert(key) {
                                continue;
                            }
                            if key_matches(&key, probe) {
                                return Some(key);
                            }
                            if seen.len() > 400_000 {
                                return None;
                            }
                        }
                    }
                }
                addr += want as u64;
            }
        }
    }
    None
}

/// 解析图片 key：显式 → 缓存（含 Python 版缓存）→ 内存扫描。
pub fn detect_image_key(probe: &Path, refresh: bool) -> Option<ImageKey> {
    if !refresh {
        if let Some(k) = load_cached_key() {
            let aes = ascii_key(&k.aes_key)?;
            if key_matches(&aes, probe) {
                return Some(k);
            }
        }
    }
    let aes = scan_key(probe)?;
    let xor = fs::read(probe).ok().and_then(|d| derive_xor_from_tail(&d));
    let k = ImageKey {
        aes_key: String::from_utf8_lossy(&aes).to_string(),
        xor_key: xor,
    };
    save_cached_key(&k);
    Some(k)
}

/// 由 cfgDword 派生图片密钥（Windows 侧同源算法）：
/// `aes = MD5(str(cfgDword) + wxid)[:16]`，`xor = cfgDword & 0xFF`。
pub fn derive_from_cfg_dword(cfg_dword: u32, wxid: &str) -> ([u8; 16], u8) {
    let seed = format!("{}{}", cfg_dword, wxid);
    let hex = format!("{:x}", md5::Md5::digest(seed.as_bytes()));
    let mut aes = [0u8; 16];
    aes.copy_from_slice(&hex.as_bytes()[..16]);
    (aes, (cfg_dword & 0xFF) as u8)
}

/// 解析图片密钥：缓存 → cfgDword 派生（不需要打开图片）。扫描内存由 image-key 负责。
pub fn resolve_key(cfg_dwords: &[u32], wxid: &str, probe: &Path) -> Option<ImageKey> {
    if let Some(k) = load_cached_key() {
        if let Some(a) = ascii_key(&k.aes_key) {
            if key_matches(&a, probe) {
                return Some(k);
            }
        }
    }
    for d in cfg_dwords {
        let (aes, xor) = derive_from_cfg_dword(*d, wxid);
        if key_matches(&aes, probe) {
            let k = ImageKey {
                aes_key: String::from_utf8_lossy(&aes).to_string(),
                xor_key: Some(xor),
            };
            save_cached_key(&k);
            return Some(k);
        }
    }
    None
}

/// 在 Config 对象附近暴力找 cfgDword：读 1KB 窗口，逐 4 字节尝试派生并用探针验证。
///
/// Linux 的 Config 布局与 Windows 不同（cipher 在 cfg+0x98 而非 +0x2B8），
/// 所以不能沿用 `cfg+0x40`；这里用"派生正确性"反推偏移。
pub fn scan_cfg_dword(probe: &Path, wxid: &str, account: &str) -> Option<ImageKey> {
    use std::fs::File;
    for pid in crate::proc::find_pids() {
        let Ok(ex) = crate::keys::extract(pid) else {
            continue;
        };
        let Ok(mut mem) = File::open(format!("/proc/{pid}/mem")) else {
            continue;
        };
        for cfg in ex.cfgs {
            let Some(win) = crate::proc::read_at(&mut mem, cfg, 0x400) else {
                continue;
            };
            for off in (0..win.len().saturating_sub(4)).step_by(4) {
                let d = u32::from_le_bytes(win[off..off + 4].try_into().unwrap());
                if d == 0 {
                    continue;
                }
                for who in [wxid, account] {
                    let (aes, xor) = derive_from_cfg_dword(d, who);
                    if key_matches(&aes, probe) {
                        let k = ImageKey {
                            aes_key: String::from_utf8_lossy(&aes).to_string(),
                            xor_key: Some(xor),
                        };
                        save_cached_key(&k);
                        return Some(k);
                    }
                }
            }
        }
    }
    None
}

pub fn ascii_key(s: &str) -> Option<[u8; 16]> {
    let b = s.as_bytes();
    if b.len() != 16 {
        return None;
    }
    let mut k = [0u8; 16];
    k.copy_from_slice(b);
    Some(k)
}

/// 三档副本：`{tier: (path, size)}`。
pub fn image_files(
    account_dir: &Path,
    chat: &str,
    md5: &str,
) -> BTreeMap<&'static str, (PathBuf, u64)> {
    let chat_md5 = format!("{:x}", md5::Md5::digest(chat.as_bytes()));
    let base = account_dir.join("msg").join("attach").join(chat_md5);
    let want: [(&str, String); 3] = [
        ("original", format!("{md5}_h.dat")),
        ("mid", format!("{md5}.dat")),
        ("thumb", format!("{md5}_t.dat")),
    ];
    let mut out = BTreeMap::new();
    let mut stack = vec![base];
    while let Some(d) = stack.pop() {
        let Ok(rd) = fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
            for (tier, target) in &want {
                if name == target && !out.contains_key(tier) {
                    let size = p.metadata().map(|m| m.len()).unwrap_or(0);
                    out.insert(*tier, (p.clone(), size));
                }
            }
        }
    }
    out
}

/// 从消息 XML 里取图片 md5。
pub fn extract_md5(content: &str) -> Option<String> {
    let idx = content.find("md5=\"")?;
    let rest = &content[idx + 5..];
    let end = rest.find('"')?;
    let md5 = &rest[..end];
    if md5.len() == 32 && md5.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(md5.to_ascii_lowercase())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn align_rules() {
        assert_eq!(align16(16), 32);
        assert_eq!(align16(17), 32);
        assert_eq!(align16(31), 32);
        assert_eq!(align16(32), 48);
    }

    #[test]
    fn xor_from_jpeg_tail() {
        // 明文尾部 FF D9，异或 0x12 后反推
        let mut data = vec![0u8; 40];
        data[38] = 0xFF ^ 0x12;
        data[39] = 0xD9 ^ 0x12;
        assert_eq!(derive_xor_from_tail(&data), Some(0x12));
    }

    #[test]
    fn v2_roundtrip() {
        use aes::cipher::{BlockEncrypt, KeyInit};
        let key = [0x11u8; 16];
        let aes_size: u32 = 16;
        let xor: u8 = 0x5A;
        // 明文头部 16 字节 + PKCS7 补到 32
        let mut head = vec![0xFF, 0xD8, 0xFF, 0xE0];
        head.extend_from_slice(&[0u8; 12]);
        head.extend_from_slice(&[0x10u8; 16]); // pad
        let cipher = aes::Aes128::new_from_slice(&key).unwrap();
        let mut enc = Vec::new();
        for chunk in head.chunks_exact(16) {
            let mut b = aes::cipher::Block::<aes::Aes128>::clone_from_slice(chunk);
            cipher.encrypt_block(&mut b);
            enc.extend_from_slice(&b);
        }
        let mid = b"MIDDLE-RAW".to_vec();
        let tail_plain = b"TAIL-FFD9".to_vec();
        let tail: Vec<u8> = tail_plain.iter().map(|b| b ^ xor).collect();

        let mut dat = Vec::new();
        dat.extend_from_slice(&V2_MAGIC);
        dat.extend_from_slice(&aes_size.to_le_bytes());
        dat.extend_from_slice(&(tail.len() as u32).to_le_bytes());
        dat.push(0x01); // 14 -> 15 的填充字节
        dat.extend_from_slice(&enc);
        dat.extend_from_slice(&mid);
        dat.extend_from_slice(&tail);

        let out = decrypt_v2(&dat, &key, xor).unwrap();
        assert!(out.starts_with(&[0xFF, 0xD8, 0xFF]));
        assert!(out.windows(10).any(|w| w == b"MIDDLE-RAW"));
        assert!(out.ends_with(b"TAIL-FFD9"));
    }

    #[test]
    fn extract_md5_from_xml() {
        let xml = r#"<msg><img aeskey="ab" md5="0123456789abcdef0123456789abcdef" /></msg>"#;
        assert_eq!(
            extract_md5(xml).as_deref(),
            Some("0123456789abcdef0123456789abcdef")
        );
        assert!(extract_md5("<msg/>").is_none());
    }
}

// ---------------------------------------------------------------------------
// 语音 / 视频 / 文件
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct MediaRow {
    pub local_id: i64,
    pub local_type: i64,
    pub server_id: i64,
    pub create_time: i64,
    pub content: String,
    pub packed_info: Vec<u8>,
}

/// 按 (chat, local_id) 在消息分片里找回原始行（含 server_id / packed_info）。
pub fn find_media_row(
    store: &crate::store::Store,
    keys: &std::collections::HashMap<String, [u8; 32]>,
    dbs: &[crate::paths::DbFile],
    chat: &str,
    local_id: i64,
) -> Option<MediaRow> {
    use rusqlite::OptionalExtension;
    let table = format!("Msg_{:x}", md5::Md5::digest(chat.as_bytes()));
    for db in dbs {
        let base = db.rel.rsplit('/').next().unwrap_or("");
        if !db.rel.starts_with("message/") || !base.starts_with("message_") {
            continue;
        }
        let Some(key) = keys.get(&db.rel) else {
            continue;
        };
        let Ok(path) = store.ensure(&db.path, &db.rel, key) else {
            continue;
        };
        let Ok(conn) = crate::store::open_ro(&path) else {
            continue;
        };
        let sql = format!(
            "SELECT local_id, local_type, server_id, create_time, message_content, packed_info_data \
             FROM \"{table}\" WHERE local_id=?1 LIMIT 1"
        );
        let row: Option<(i64, i64, i64, i64, rusqlite::types::Value, Vec<u8>)> = conn
            .query_row(&sql, [local_id], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get::<_, Option<i64>>(2)?.unwrap_or(0),
                    r.get::<_, Option<i64>>(3)?.unwrap_or(0),
                    r.get(4)?,
                    r.get::<_, Option<Vec<u8>>>(5)?.unwrap_or_default(),
                ))
            })
            .optional()
            .ok()?;
        if let Some((lid, lt, sid, ct, content, packed)) = row {
            let kind = crate::query::type_name(lt);
            let text = match content {
                rusqlite::types::Value::Blob(b) => {
                    crate::query::friendly_content(rusqlite::types::ValueRef::Blob(&b), &kind)
                }
                rusqlite::types::Value::Text(t) => crate::query::friendly_content(
                    rusqlite::types::ValueRef::Text(t.as_bytes()),
                    &kind,
                ),
                _ => String::new(),
            };
            return Some(MediaRow {
                local_id: lid,
                local_type: lt,
                server_id: sid,
                create_time: ct,
                content: text,
                packed_info: packed,
            });
        }
    }
    None
}

/// 语音：`media_*.db` 的 `VoiceInfo.voice_data`（SILK），落盘 `.silk`。
///
/// 只有**在界面播放/接收过**的语音才会写进 VoiceInfo；拿不到不是读库坏了。
pub fn export_voice(
    store: &crate::store::Store,
    keys: &std::collections::HashMap<String, [u8; 32]>,
    dbs: &[crate::paths::DbFile],
    chat: &str,
    row: &MediaRow,
    out_dir: &Path,
) -> Option<PathBuf> {
    use rusqlite::OptionalExtension;
    if row.server_id == 0 {
        return None;
    }
    for db in dbs {
        let base = db.rel.rsplit('/').next().unwrap_or("");
        if !base.starts_with("media_") {
            continue;
        }
        let Some(key) = keys.get(&db.rel) else {
            continue;
        };
        let Ok(path) = store.ensure(&db.path, &db.rel, key) else {
            continue;
        };
        let Ok(conn) = crate::store::open_ro(&path) else {
            continue;
        };
        let chat_id: Option<i64> = conn
            .query_row(
                "SELECT rowid FROM Name2Id WHERE user_name=?1",
                [chat],
                |r| r.get(0),
            )
            .optional()
            .ok()?;
        let Some(cid) = chat_id else { continue };
        let data: Option<Vec<u8>> = conn
            .query_row(
                "SELECT voice_data FROM VoiceInfo WHERE chat_name_id=?1 AND svr_id=?2 \
                 ORDER BY create_time DESC LIMIT 1",
                rusqlite::params![cid, row.server_id],
                |r| r.get(0),
            )
            .optional()
            .ok()?;
        if let Some(b) = data {
            if b.is_empty() {
                continue;
            }
            let _ = std::fs::create_dir_all(out_dir);
            let dst = out_dir.join(format!("{}_{}.silk", chat, row.local_id));
            std::fs::write(&dst, &b).ok()?;
            return Some(dst);
        }
    }
    None
}

/// 从 `packed_info` 里取 32 位十六进制 id（视频文件名）。
pub fn extract_hex32(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 32 {
        return None;
    }
    for w in bytes.windows(32) {
        if w.iter().all(|b| b.is_ascii_hexdigit()) {
            return Some(String::from_utf8_lossy(w).to_string().to_ascii_lowercase());
        }
    }
    None
}

fn find_in_tree(root: &Path, pred: impl Fn(&str) -> bool) -> Option<PathBuf> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if pred(name) {
                return Some(p);
            }
        }
    }
    None
}

/// 视频：按 packed_info 里的 id 在 `msg/video` 下找 `<id>.mp4`。
pub fn export_video(
    account_dir: &Path,
    chat: &str,
    row: &MediaRow,
    out_dir: &Path,
) -> Option<PathBuf> {
    let vid = extract_hex32(&row.packed_info)?;
    let target = format!("{vid}.mp4");
    let src = find_in_tree(&account_dir.join("msg").join("video"), |n| n == target)?;
    let _ = std::fs::create_dir_all(out_dir);
    let dst = out_dir.join(format!("{}_{}.mp4", chat, row.local_id));
    std::fs::copy(&src, &dst).ok()?;
    Some(dst)
}

/// 从文件消息 XML 里取 `<title>`（原名）与 `<totallen>`（长度）。
pub fn file_meta(content: &str) -> Option<(String, Option<u64>)> {
    fn tag<'a>(s: &'a str, name: &str) -> Option<&'a str> {
        let open = format!("<{name}>");
        let close = format!("</{name}>");
        let i = s.find(&open)? + open.len();
        let j = s[i..].find(&close)? + i;
        Some(&s[i..j])
    }
    let title = tag(content, "title")?.trim().to_string();
    if title.is_empty() {
        return None;
    }
    let size = tag(content, "totallen").and_then(|v| v.trim().parse::<u64>().ok());
    Some((title, size))
}

/// 文件：`msg/file/<YYYY-MM>/<原名>`；同名带 `(n)` 后缀的也算，长度能对上优先。
pub fn export_file(
    account_dir: &Path,
    chat: &str,
    row: &MediaRow,
    out_dir: &Path,
) -> Option<PathBuf> {
    let (name, want_size) = file_meta(&row.content)?;
    let stem_ext: Vec<&str> = name.rsplitn(2, '.').collect();
    let (stem, ext) = if stem_ext.len() == 2 {
        (stem_ext[1], stem_ext[0])
    } else {
        (name.as_str(), "")
    };
    let family = |n: &str| -> bool {
        if n == name {
            return true;
        }
        let prefix = format!("{stem}(");
        let suffix = if ext.is_empty() {
            ")".to_string()
        } else {
            format!(").{ext}")
        };
        n.starts_with(&prefix) && n.ends_with(&suffix)
    };
    let base = account_dir.join("msg").join("file");
    let mut stack = vec![base];
    let mut candidates = Vec::new();
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            let n = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if family(n) {
                let sz = p.metadata().map(|m| m.len()).unwrap_or(0);
                candidates.push((p, sz));
            }
        }
    }
    let chosen = match want_size {
        Some(w) => candidates.into_iter().find(|(_, sz)| *sz == w),
        None => {
            if candidates.len() == 1 {
                candidates.pop()
            } else {
                None
            }
        }
    }?;
    let _ = std::fs::create_dir_all(out_dir);
    let dst = out_dir.join(format!("{}_{}_{}", chat, row.local_id, name));
    std::fs::copy(&chosen.0, &dst).ok()?;
    Some(dst)
}

#[cfg(test)]
mod media_tests {
    use super::*;

    #[test]
    fn hex32_from_packed_info() {
        let mut pi = vec![0x08, 0x47, 0x10, 0x06, 0x22, 0x22, 0x42, 0x20];
        pi.extend_from_slice(b"548641f67d05e39da14dd4a41ca4c55f");
        assert_eq!(
            extract_hex32(&pi).as_deref(),
            Some("548641f67d05e39da14dd4a41ca4c55f")
        );
        assert!(extract_hex32(b"short").is_none());
    }

    #[test]
    fn file_meta_parses_title_and_size() {
        let xml = "<msg><appmsg><title>报告.pdf</title><totallen>1234</totallen></appmsg></msg>";
        assert_eq!(file_meta(xml), Some(("报告.pdf".to_string(), Some(1234))));
        assert!(file_meta("<msg></msg>").is_none());
    }
}
