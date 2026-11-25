//! 朋友圈：`sns.db` 时间线与互动通知。
//!
//! 时间线正文是 `<SnsDataItem>` XML；图片/视频在 `<mediaList>` 里，
//! 点赞/评论在 `<like_user_list>` / `<comment_user_list>` 里。
//!
//! 本地缓存：`cache/<YYYY-MM>/Sns/{Img,Video}/<md5 前 2 位>/<md5 后 30 位>`，
//! 也是 V2 加密容器，密钥与聊天图片相同。

use crate::query::Ctx;
use anyhow::Result;
use serde::Serialize;

#[derive(Serialize, Debug, Clone)]
pub struct MediaItem {
    pub md5: String,
    pub url: String,
    pub size: u64,
    pub width: u32,
    pub height: u32,
}

#[derive(Serialize, Debug, Clone)]
pub struct UserComment {
    pub username: String,
    pub nickname: String,
    pub content: String,
    pub create_time: i64,
    pub kind: i64,
    pub comment_id: String,
    pub ref_comment_id: String,
    pub deleted: bool,
}

#[derive(Serialize, Debug, Clone)]
pub struct Moment {
    pub tid: i64,
    pub id: String,
    pub username: String,
    pub nickname: String,
    pub text: String,
    pub location: Option<(String, String)>,
    pub create_time: i64,
    pub images: Vec<MediaItem>,
    pub videos: Vec<MediaItem>,
    pub likes: Vec<UserComment>,
    pub comments: Vec<UserComment>,
}

#[derive(Serialize, Debug, Clone)]
pub struct Interaction {
    pub local_id: i64,
    pub create_time: i64,
    pub kind: i64,
    pub feed_id: i64,
    pub from_username: String,
    pub from_nickname: String,
    pub to_username: String,
    pub to_nickname: String,
    pub content: String,
    pub comment_id: i64,
    pub deleted: bool,
    pub relative_me: bool,
    pub unread: bool,
}

// ---------------------------------------------------------------------------
// XML 小工具（不引 regex，保持依赖最小）
// ---------------------------------------------------------------------------

fn tag<'a>(s: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let i = s.find(&open)? + open.len();
    let j = s[i..].find(&close)? + i;
    Some(&s[i..j])
}

/// 允许开标签带属性：`<url ...>text</url>`。
fn tag_with_attrs<'a>(s: &'a str, name: &str) -> Option<&'a str> {
    let pat = format!("<{name}");
    let mut from = 0;
    while let Some(i) = s[from..].find(&pat) {
        let start = from + i;
        let Some(gt) = s[start..].find('>') else {
            return None;
        };
        let body_start = start + gt + 1;
        let close = format!("</{name}>");
        if let Some(j) = s[body_start..].find(&close) {
            return Some(&s[body_start..body_start + j]);
        }
        from = body_start;
    }
    None
}

fn attr<'a>(s: &'a str, name: &str) -> Option<&'a str> {
    let pat = format!("{name}=\"");
    let i = s.find(&pat)? + pat.len();
    let j = s[i..].find('"')? + i;
    Some(&s[i..j])
}

fn blocks<'a>(s: &'a str, open: &str, close: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(i) = s[from..].find(open) {
        let start = from + i + open.len();
        let Some(j) = s[start..].find(close) else {
            break;
        };
        out.push(&s[start..start + j]);
        from = start + j + close.len();
    }
    out
}

fn parse_user_comment(block: &str) -> UserComment {
    UserComment {
        username: tag(block, "username").unwrap_or("").trim().to_string(),
        nickname: tag(block, "nickname").unwrap_or("").trim().to_string(),
        content: tag(block, "content").unwrap_or("").trim().to_string(),
        create_time: tag(block, "create_time")
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0),
        kind: tag(block, "type")
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0),
        comment_id: tag(block, "comment_id").unwrap_or("").trim().to_string(),
        ref_comment_id: tag(block, "ref_comment_id")
            .unwrap_or("")
            .trim()
            .to_string(),
        deleted: tag(block, "b_deleted")
            .map(|v| v.trim() == "1")
            .unwrap_or(false),
    }
}

fn parse_media(block: &str) -> MediaItem {
    let url = tag_with_attrs(block, "url")
        .unwrap_or("")
        .trim()
        .to_string();
    let md5 = attr(block, "videomd5")
        .or_else(|| attr(block, "md5"))
        .unwrap_or("")
        .to_ascii_lowercase();
    let (mut width, mut height, mut size) = (0u32, 0u32, 0u64);
    if let Some(i) = block.find("<size") {
        if let Some(gt) = block[i..].find('>') {
            let t = &block[i..i + gt];
            width = attr(t, "width").and_then(|v| v.parse().ok()).unwrap_or(0);
            height = attr(t, "height").and_then(|v| v.parse().ok()).unwrap_or(0);
            size = attr(t, "totalSize")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
        }
    }
    MediaItem {
        md5,
        url,
        size,
        width,
        height,
    }
}

fn is_video(block: &str, item: &MediaItem) -> bool {
    let u = item.url.to_ascii_lowercase();
    u.ends_with(".mp4")
        || u.ends_with(".mov")
        || u.ends_with(".avi")
        || attr(block, "videomd5").is_some()
        || tag(block, "videoDuration")
            .map(|v| v.trim().parse::<u32>().unwrap_or(0) > 0)
            .unwrap_or(false)
        || tag(block, "type").map(|v| v.trim() == "6").unwrap_or(false)
}

pub fn parse_feed(xml: &str) -> Moment {
    let id = tag(xml, "id").unwrap_or("").to_string();
    let username = tag(xml, "username").unwrap_or("").to_string();
    let create_time = tag(xml, "createTime")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let text = html_unescape(tag(xml, "contentDesc").unwrap_or(""));
    let location = match (attr(xml, "latitude"), attr(xml, "longitude")) {
        (Some(la), Some(lo)) => Some((la.to_string(), lo.to_string())),
        _ => None,
    };
    let mut images = Vec::new();
    let mut videos = Vec::new();
    for block in blocks(xml, "<media>", "</media>") {
        let item = parse_media(block);
        if is_video(block, &item) {
            videos.push(item);
        } else {
            images.push(item);
        }
    }
    let mut likes = Vec::new();
    if let Some(l) = blocks_one(xml, "<like_user_list>", "</like_user_list>") {
        for b in blocks(l, "<user_comment>", "</user_comment>") {
            let c = parse_user_comment(b);
            if !c.username.is_empty() {
                likes.push(c);
            }
        }
    }
    let mut comments = Vec::new();
    if let Some(c) = blocks_one(xml, "<comment_user_list>", "</comment_user_list>") {
        for b in blocks(c, "<user_comment>", "</user_comment>") {
            let c = parse_user_comment(b);
            if !c.username.is_empty() && !c.deleted {
                comments.push(c);
            }
        }
    }
    Moment {
        tid: 0, // 由调用方填充
        id,
        username,
        nickname: String::new(), // 由调用方补
        text,
        location,
        create_time,
        images,
        videos,
        likes,
        comments,
    }
}

fn blocks_one<'a>(s: &'a str, open: &str, close: &str) -> Option<&'a str> {
    let i = s.find(open)? + open.len();
    let j = s[i..].find(close)? + i;
    Some(&s[i..j])
}

fn html_unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

// ---------------------------------------------------------------------------
// 查询
// ---------------------------------------------------------------------------

fn nickname_of(ctx: &Ctx, username: &str) -> String {
    if username.is_empty() {
        return String::new();
    }
    if let Ok(conn) = ctx.open_public("contact/contact.db") {
        if let Ok(n) = conn.query_row(
            "SELECT COALESCE(NULLIF(remark,''), NULLIF(nick_name,''), username) FROM contact WHERE username=?1",
            [username],
            |r| r.get::<_, String>(0),
        ) {
            return n;
        }
    }
    username.to_string()
}

pub fn moments(
    ctx: &Ctx,
    limit: usize,
    offset: usize,
    only_me: bool,
    keyword: Option<&str>,
) -> Result<Vec<Moment>> {
    let conn = ctx.open_public("sns/sns.db")?;
    let mut stmt = conn.prepare(
        "SELECT tid, user_name, content FROM SnsTimeLine ORDER BY tid DESC LIMIT ?1 OFFSET ?2",
    )?;
    let mut rows = stmt.query(rusqlite::params![limit as i64, offset as i64])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        let tid: i64 = r.get(0)?;
        let owner: String = r.get::<_, Option<String>>(1)?.unwrap_or_default();
        let xml: String = r.get::<_, Option<String>>(2)?.unwrap_or_default();
        let mut m = parse_feed(&xml);
        m.tid = tid;
        if m.username.is_empty() {
            m.username = owner;
        }
        if only_me && m.username != ctx.wxid {
            continue;
        }
        if let Some(kw) = keyword {
            if !m.text.contains(kw) {
                continue;
            }
        }
        m.nickname = nickname_of(ctx, &m.username);
        out.push(m);
    }
    Ok(out)
}

pub fn moment(ctx: &Ctx, tid: i64) -> Result<Option<Moment>> {
    let conn = ctx.open_public("sns/sns.db")?;
    let row: Option<(i64, String)> = conn
        .query_row(
            "SELECT tid, content FROM SnsTimeLine WHERE tid=?1",
            [tid],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                ))
            },
        )
        .ok();
    Ok(row.map(|(t, xml)| {
        let mut m = parse_feed(&xml);
        m.tid = t;
        m.nickname = nickname_of(ctx, &m.username);
        m
    }))
}

pub fn interactions(ctx: &Ctx, limit: usize, only_unread: bool) -> Result<Vec<Interaction>> {
    let conn = ctx.open_public("sns/sns.db")?;
    let sql = format!(
        "SELECT local_id, create_time, type, feed_id, from_username, from_nickname, \
         to_username, to_nickname, content, comment_id, del_status, is_relative_me, is_unread \
         FROM SnsMessage_tmp3 {} ORDER BY create_time DESC, local_id DESC LIMIT ?1",
        if only_unread { "WHERE is_unread=1" } else { "" }
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query([limit as i64])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        out.push(Interaction {
            local_id: r.get(0)?,
            create_time: r.get::<_, Option<i64>>(1)?.unwrap_or(0),
            kind: r.get::<_, Option<i64>>(2)?.unwrap_or(0),
            feed_id: r.get::<_, Option<i64>>(3)?.unwrap_or(0),
            from_username: r.get::<_, Option<String>>(4)?.unwrap_or_default(),
            from_nickname: r.get::<_, Option<String>>(5)?.unwrap_or_default(),
            to_username: r.get::<_, Option<String>>(6)?.unwrap_or_default(),
            to_nickname: r.get::<_, Option<String>>(7)?.unwrap_or_default(),
            content: r.get::<_, Option<String>>(8)?.unwrap_or_default(),
            comment_id: r.get::<_, Option<i64>>(9)?.unwrap_or(0),
            deleted: r.get::<_, Option<i64>>(10)?.unwrap_or(0) != 0,
            relative_me: r.get::<_, Option<i64>>(11)?.unwrap_or(0) != 0,
            unread: r.get::<_, Option<i64>>(12)?.unwrap_or(0) != 0,
        });
    }
    Ok(out)
}

pub fn unread_count(ctx: &Ctx) -> Result<i64> {
    let conn = ctx.open_public("sns/sns.db")?;
    Ok(conn.query_row(
        "SELECT COUNT(*) FROM SnsMessage_tmp3 WHERE is_unread=1",
        [],
        |r| r.get(0),
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;

    const XML: &str = r#"<SnsDataItem><TimelineObject><id>123</id><username>ivrtym</username>
<createTime>1794410394</createTime><contentDesc>人生救护车初体验</contentDesc>
<location latitude="0" longitude="0"/>
<ContentObject><mediaList><media><id>1</id><type>2</type>
<url type="1" md5="de2b26c010ef68acd18207989e768a22">http://x/a</url>
<size width="1080" height="1684" totalSize="63907"/></media></mediaList></ContentObject>
<like_user_list><user_comment><username>u1</username><nickname>甲</nickname></user_comment></like_user_list>
<comment_user_list><user_comment><username>u2</username><nickname>乙</nickname>
<content>这是怎么啦</content><create_time>1791635938</create_time><type>2</type>
<comment_id>1</comment_id><ref_comment_id>0</ref_comment_id><b_deleted>0</b_deleted>
</user_comment></comment_user_list></TimelineObject></SnsDataItem>"#;

    #[test]
    fn parse_feed_fields() {
        let m = parse_feed(XML);
        assert_eq!(m.id, "123");
        assert_eq!(m.username, "ivrtym");
        assert_eq!(m.text, "人生救护车初体验");
        assert_eq!(m.create_time, 1794410394);
        assert_eq!(m.images.len(), 1);
        assert_eq!(m.images[0].md5, "de2b26c010ef68acd18207989e768a22");
        assert_eq!(m.images[0].width, 1080);
        assert_eq!(m.images[0].size, 63907);
        assert!(m.videos.is_empty());
        assert_eq!(m.likes.len(), 1);
        assert_eq!(m.comments.len(), 1);
        assert_eq!(m.comments[0].content, "这是怎么啦");
    }

    #[test]
    fn video_detected_by_type() {
        let xml = r#"<media><type>6</type><url md5="aa">http://x/v</url>
<videomd5>bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb</videomd5></media>"#;
        let m = parse_feed(xml);
        assert_eq!(m.videos.len(), 1, "{:?}", m.images);
    }
}

// ---------------------------------------------------------------------------
// Sns 缓存匹配（文件名是不透明 key，只能按内容特征匹配）
// ---------------------------------------------------------------------------

/// 从图片字节里读宽高（JPEG SOF / PNG IHDR / GIF）。
pub fn image_dims(b: &[u8]) -> Option<(u32, u32)> {
    if b.starts_with(&[0xFF, 0xD8]) {
        let mut i = 2usize;
        while i + 9 < b.len() {
            if b[i] != 0xFF {
                i += 1;
                continue;
            }
            let marker = b[i + 1];
            if marker == 0xD8 || marker == 0x01 || (0xD0..=0xD7).contains(&marker) {
                i += 2;
                continue;
            }
            if i + 4 > b.len() {
                return None;
            }
            let len = u16::from_be_bytes([b[i + 2], b[i + 3]]) as usize;
            if matches!(
                marker,
                0xC0..=0xC3 | 0xC5..=0xC7 | 0xC9..=0xCB | 0xCD..=0xCF
            ) {
                if i + 9 > b.len() {
                    return None;
                }
                let h = u16::from_be_bytes([b[i + 5], b[i + 6]]) as u32;
                let w = u16::from_be_bytes([b[i + 7], b[i + 8]]) as u32;
                return Some((w, h));
            }
            i += 2 + len.max(2);
        }
        None
    } else if b.starts_with(b"\x89PNG") && b.len() > 24 {
        let w = u32::from_be_bytes(b[16..20].try_into().ok()?);
        let h = u32::from_be_bytes(b[20..24].try_into().ok()?);
        Some((w, h))
    } else if b.starts_with(b"GIF8") && b.len() > 10 {
        let w = u16::from_le_bytes([b[6], b[7]]) as u32;
        let h = u16::from_le_bytes([b[8], b[9]]) as u32;
        Some((w, h))
    } else {
        None
    }
}

pub struct CachedImage {
    #[allow(dead_code)]
    pub path: std::path::PathBuf,
    pub w: u32,
    pub h: u32,
    pub plain_size: usize,
    pub bytes: Vec<u8>,
}

fn sns_files(account_dir: &std::path::Path, sub: &str) -> Vec<std::path::PathBuf> {
    let base = account_dir.join("cache");
    let mut out = Vec::new();
    let Ok(months) = std::fs::read_dir(&base) else {
        return out;
    };
    for mon in months.flatten() {
        let Ok(buckets) = std::fs::read_dir(mon.path().join("Sns").join(sub)) else {
            continue;
        };
        for b in buckets.flatten() {
            let Ok(files) = std::fs::read_dir(b.path()) else {
                continue;
            };
            for f in files.flatten() {
                if f.path().is_file() {
                    out.push(f.path());
                }
            }
        }
    }
    out
}

/// 扫描并解密 Sns 图片缓存，得到 (宽, 高, 明文字节数)。
pub fn scan_cached_images(
    account_dir: &std::path::Path,
    aes: Option<&[u8; 16]>,
    xor: Option<u8>,
) -> Vec<CachedImage> {
    let mut out = Vec::new();
    for p in sns_files(account_dir, "Img") {
        let Ok(data) = std::fs::read(&p) else {
            continue;
        };
        let plain = if data.starts_with(&[0x07, 0x08]) {
            match crate::media::decrypt_dat(&data, aes, xor) {
                Ok(b) => b,
                Err(_) => continue,
            }
        } else {
            data
        };
        if let Some((w, h)) = image_dims(&plain) {
            out.push(CachedImage {
                path: p,
                w,
                h,
                plain_size: plain.len(),
                bytes: plain,
            });
        }
    }
    out
}

/// 按宽高精确匹配；同尺寸多张时用明文尺寸偏差消歧（≤512B 或 10%），歧义则拒绝。
pub fn match_cached_image<'a>(
    index: &'a [CachedImage],
    w: u32,
    h: u32,
    size: u64,
) -> Option<&'a CachedImage> {
    let mut hits: Vec<&CachedImage> = index.iter().filter(|c| c.w == w && c.h == h).collect();
    if hits.is_empty() {
        return None;
    }
    if hits.len() == 1 {
        return hits.pop();
    }
    let tol = std::cmp::max(512i64, (size as i64) / 10);
    let mut scored: Vec<(i64, &CachedImage)> = hits
        .into_iter()
        .map(|c| ((c.plain_size as i64 - size as i64).abs(), c))
        .filter(|(d, _)| *d <= tol)
        .collect();
    scored.sort_by_key(|(d, _)| *d);
    match scored.len() {
        1 => Some(scored[0].1),
        n if n > 1 && scored[0].0 < scored[1].0 => Some(scored[0].1),
        _ => None,
    }
}

/// 视频缓存按字节数匹配：明文（fsz==size）或 V2 容器（fsz==size+31），容差 8。
pub fn match_cached_video(account_dir: &std::path::Path, size: u64) -> Option<std::path::PathBuf> {
    if size == 0 {
        return None;
    }
    let mut plain: Option<(i64, std::path::PathBuf)> = None;
    let mut container: Option<(i64, std::path::PathBuf)> = None;
    for p in sns_files(account_dir, "Video") {
        let Ok(fsz) = std::fs::metadata(&p).map(|m| m.len()) else {
            continue;
        };
        let d_plain = (fsz as i64 - size as i64).abs();
        let d_cont = (fsz as i64 - size as i64 - 31).abs();
        if d_plain <= 8 && plain.as_ref().map(|(d, _)| d_plain < *d).unwrap_or(true) {
            plain = Some((d_plain, p.clone()));
        }
        if d_cont <= 8 && container.as_ref().map(|(d, _)| d_cont < *d).unwrap_or(true) {
            container = Some((d_cont, p));
        }
    }
    plain.or(container).map(|(_, p)| p)
}

#[cfg(test)]
mod cache_tests {
    use super::*;

    #[test]
    fn dims_from_png_header() {
        let mut png = vec![0u8; 33];
        png[..8].copy_from_slice(b"\x89PNG\r\n\x1a\n");
        png[16..20].copy_from_slice(&1080u32.to_be_bytes());
        png[20..24].copy_from_slice(&1684u32.to_be_bytes());
        assert_eq!(image_dims(&png), Some((1080, 1684)));
    }

    #[test]
    fn dims_from_jpeg_sof0() {
        let mut j = vec![0xFF, 0xD8, 0xFF, 0xC0, 0x00, 0x11, 0x08];
        j.extend_from_slice(&(667u16).to_be_bytes()); // height
        j.extend_from_slice(&(375u16).to_be_bytes()); // width
        j.extend_from_slice(&[0u8; 16]);
        assert_eq!(image_dims(&j), Some((375, 667)));
    }

    #[test]
    fn size_disambiguation() {
        let mk = |w, h, size| CachedImage {
            path: std::path::PathBuf::from("x"),
            w,
            h,
            plain_size: size,
            bytes: Vec::new(),
        };
        let idx = vec![mk(100, 200, 1000), mk(100, 200, 5000), mk(1, 1, 1000)];
        assert_eq!(
            match_cached_image(&idx, 100, 200, 1020).map(|c| c.plain_size),
            Some(1000)
        );
        assert!(
            match_cached_image(&idx, 100, 200, 3000).is_none(),
            "两候选偏差相同应拒绝"
        );
        assert!(match_cached_image(&idx, 7, 7, 1000).is_none());
    }
}
