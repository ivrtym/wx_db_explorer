//! SQLCipher4 页解密与页 1 HMAC 校验。
//!
//! 布局（页 4096，reserve 80 = IV 16 + HMAC 64）：
//! - 页 1：`[16B 明文 salt][4000B 密文][16B IV][64B HMAC]`
//! - 其他页：`[4016B 密文][16B IV][64B HMAC]`
//!
//! HMAC：`PBKDF2-HMAC-SHA512(key, salt^0x3A, 2 轮, 32B)` 作 mac_key，
//! 数据 = 页 1 的 `[16 .. 4032]`，再追加 `u32le(1)`。

use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
use anyhow::{bail, Result};
use hmac::{Hmac, Mac};
use sha2::Sha512;
use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::os::unix::fs::FileExt;
use std::path::Path;

pub const WAL_HEADER_SZ: u64 = 32;
pub const WAL_FRAME_HDR_SZ: u64 = 24;
pub const WAL_FRAME_SZ: u64 = WAL_FRAME_HDR_SZ + PAGE_SZ as u64;

pub const PAGE_SZ: usize = 4096;
pub const RESERVE_SZ: usize = 80;
pub const SALT_SZ: usize = 16;
pub const KEY_SZ: usize = 32;

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type HmacSha512 = Hmac<Sha512>;

/// 用页 1 的 HMAC 验真 32 字节裸密钥。
pub fn verify_key(key: &[u8; KEY_SZ], page1: &[u8]) -> bool {
    if page1.len() < PAGE_SZ {
        return false;
    }
    let salt = &page1[..SALT_SZ];
    let mut mac_salt = [0u8; SALT_SZ];
    for i in 0..SALT_SZ {
        mac_salt[i] = salt[i] ^ 0x3A;
    }
    let mut mac_key = [0u8; KEY_SZ];
    pbkdf2::pbkdf2_hmac::<Sha512>(key, &mac_salt, 2, &mut mac_key);

    let mut mac = <HmacSha512 as Mac>::new_from_slice(&mac_key).expect("hmac key");
    mac.update(&page1[16..PAGE_SZ - RESERVE_SZ + 16]);
    mac.update(&1u32.to_le_bytes());
    let tag = mac.finalize().into_bytes();
    tag[..] == page1[PAGE_SZ - 64..PAGE_SZ]
}

/// 解一页，返回 4096 字节明文页（尾部 reserve 填 0）。
pub fn decrypt_page(key: &[u8; KEY_SZ], page: &[u8], pgno: u32) -> Result<Vec<u8>> {
    if page.len() < PAGE_SZ {
        bail!("页长度不足：{}", page.len());
    }
    let iv = &page[PAGE_SZ - RESERVE_SZ..PAGE_SZ - RESERVE_SZ + 16];
    let enc = if pgno == 1 {
        &page[16..PAGE_SZ - RESERVE_SZ]
    } else {
        &page[..PAGE_SZ - RESERVE_SZ]
    };
    let mut buf = enc.to_vec();
    let dec = Aes256CbcDec::new(key.into(), iv.into())
        .decrypt_padded_mut::<NoPadding>(&mut buf)
        .map_err(|e| anyhow::anyhow!("AES 解密失败：{e}"))?;
    let mut out = Vec::with_capacity(PAGE_SZ);
    if pgno == 1 {
        out.extend_from_slice(b"SQLite format 3\0");
    }
    out.extend_from_slice(dec);
    out.extend(std::iter::repeat(0u8).take(RESERVE_SZ));
    debug_assert_eq!(out.len(), PAGE_SZ);
    Ok(out)
}

/// 整库解密（不合并 WAL）。
pub fn decrypt_file(src: &Path, dst: &Path, key: &[u8; KEY_SZ]) -> Result<()> {
    let mut f = File::open(src)?;
    let out = File::create(dst)?;
    let mut w = BufWriter::new(out);
    let mut page = vec![0u8; PAGE_SZ];
    let mut pgno: u32 = 1;
    loop {
        let mut got = 0usize;
        while got < PAGE_SZ {
            let n = f.read(&mut page[got..])?;
            if n == 0 {
                break;
            }
            got += n;
        }
        if got == 0 {
            break;
        }
        if got < PAGE_SZ {
            // 尾部不足一页：SQLite 正常不会出现，补零继续
            for b in page[got..].iter_mut() {
                *b = 0;
            }
        }
        let plain = decrypt_page(key, &page, pgno)?;
        w.write_all(&plain)?;
        pgno += 1;
    }
    w.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_roundtrip_length() {
        let key = [7u8; KEY_SZ];
        let page = vec![0u8; PAGE_SZ];
        // 全零页是合法长度的输入，解密后必须仍是 4096 且带 SQLite 头
        let out = decrypt_page(&key, &page, 1).unwrap();
        assert_eq!(out.len(), PAGE_SZ);
        assert_eq!(&out[..16], b"SQLite format 3\0");
    }

    #[test]
    fn verify_rejects_short_page() {
        let key = [0u8; KEY_SZ];
        assert!(!verify_key(&key, &[0u8; 100]));
    }
}

/// 把 `-wal` 里的加密帧覆盖进已解密的库文件，返回处理到的帧序号。
///
/// 帧结构（WCDB，大端）：`[0:4] 页号`、`[4:8] 提交标记`、`[8:16] salt`、
/// `[16:24] 校验`，随后 4096 字节页。
///
/// 只合并 salt 与 WAL 头一致的帧：微信 checkpoint 会重置 WAL（salt 递增），
/// 旧世代帧若被合并会用过期页覆盖新数据，直接毁库。
pub fn merge_wal(db: &Path, wal: &Path, key: &[u8; KEY_SZ], from_frame: usize) -> Result<usize> {
    let db_f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(db)?;
    let wal_f = File::open(wal)?;
    let wal_len = wal_f.metadata()?.len();
    if wal_len < WAL_HEADER_SZ + WAL_FRAME_SZ {
        return Ok(from_frame);
    }
    let mut header = [0u8; WAL_HEADER_SZ as usize];
    wal_f.read_exact_at(&mut header, 0)?;
    let salt = &header[16..24];

    let frames = ((wal_len - WAL_HEADER_SZ) / WAL_FRAME_SZ) as usize;
    let mut last = from_frame;
    let mut max_pgno: u32 = 0;
    let mut fh = [0u8; WAL_FRAME_HDR_SZ as usize];
    let mut page = vec![0u8; PAGE_SZ];

    for i in from_frame..frames {
        let off = WAL_HEADER_SZ + i as u64 * WAL_FRAME_SZ;
        if wal_f.read_exact_at(&mut fh, off).is_err()
            || wal_f
                .read_exact_at(&mut page, off + WAL_FRAME_HDR_SZ)
                .is_err()
        {
            break;
        }
        let pgno = u32::from_be_bytes(fh[0..4].try_into().unwrap());
        last = i + 1;
        if &fh[8..16] != salt || pgno == 0 {
            continue;
        }
        let pt = decrypt_page(key, &page, pgno)?;
        if pgno == 1 {
            if &pt[..16] != b"SQLite format 3\0" {
                continue;
            }
        } else if !matches!(pt[0], 0 | 2 | 5 | 10 | 13) {
            continue;
        }
        db_f.write_all_at(&pt, (pgno as u64 - 1) * PAGE_SZ as u64)?;
        max_pgno = max_pgno.max(pgno);
    }

    // 合并后修正页 1 的页数（偏移 28..32，大端）
    let len = db_f.metadata()?.len();
    let db_pages = ((len + PAGE_SZ as u64 - 1) / PAGE_SZ as u64) as u32;
    let mut p1 = vec![0u8; PAGE_SZ];
    if db_f.read_exact_at(&mut p1, 0).is_ok() {
        let hdr_pages = u32::from_be_bytes(p1[28..32].try_into().unwrap());
        let new_pages = hdr_pages.max(max_pgno).max(db_pages);
        if new_pages != hdr_pages {
            p1[28..32].copy_from_slice(&new_pages.to_be_bytes());
            db_f.write_all_at(&p1, 0)?;
        }
    }
    db_f.sync_all()?;
    Ok(last)
}

#[cfg(test)]
fn encrypt_page_for_test(key: &[u8; KEY_SZ], plain: &[u8], pgno: u32) -> Vec<u8> {
    use aes::cipher::BlockEncryptMut;
    type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
    let iv = [3u8; 16];
    let start = if pgno == 1 { 16 } else { 0 };
    let mut buf = plain[start..PAGE_SZ - RESERVE_SZ].to_vec();
    let n = buf.len();
    let enc = Aes256CbcEnc::new(key.into(), (&iv).into())
        .encrypt_padded_mut::<NoPadding>(&mut buf, n)
        .unwrap();
    let mut out = Vec::with_capacity(PAGE_SZ);
    if pgno == 1 {
        out.extend_from_slice(&plain[..16]);
    }
    out.extend_from_slice(enc);
    out.extend_from_slice(&iv);
    out.extend(std::iter::repeat(0u8).take(64));
    out
}

#[cfg(test)]
mod wal_tests {
    use super::*;
    use std::io::Write as _;

    fn build_db(path: &std::path::Path) {
        let mut page1 = vec![0u8; PAGE_SZ];
        page1[..16].copy_from_slice(b"SQLite format 3\0");
        page1[28..32].copy_from_slice(&2u32.to_be_bytes());
        let mut page2 = vec![0u8; PAGE_SZ];
        page2[0] = 2;
        let mut f = File::create(path).unwrap();
        f.write_all(&page1).unwrap();
        f.write_all(&page2).unwrap();
    }

    #[test]
    fn merge_replaces_page_and_fixes_count() {
        let dir = std::env::temp_dir().join(format!("wx_db_rs_wal_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("t.db");
        let wal = dir.join("t.db-wal");
        build_db(&db);

        let key = [9u8; KEY_SZ];
        let salt = [7u8; 8];
        let mut plain5 = vec![0u8; PAGE_SZ];
        plain5[0] = 13;
        plain5[100..104].copy_from_slice(b"DATA");
        let frame_page = encrypt_page_for_test(&key, &plain5, 5);

        let mut w = File::create(&wal).unwrap();
        let mut wh = [0u8; WAL_HEADER_SZ as usize];
        wh[16..24].copy_from_slice(&salt);
        w.write_all(&wh).unwrap();
        let mut fh = [0u8; WAL_FRAME_HDR_SZ as usize];
        fh[0..4].copy_from_slice(&5u32.to_be_bytes());
        fh[8..16].copy_from_slice(&salt);
        w.write_all(&fh).unwrap();
        w.write_all(&frame_page).unwrap();
        drop(w);

        let got = merge_wal(&db, &wal, &key, 0).unwrap();
        assert_eq!(got, 1);
        let bytes = std::fs::read(&db).unwrap();
        assert_eq!(bytes.len(), PAGE_SZ * 5);
        assert_eq!(&bytes[4 * PAGE_SZ + 100..4 * PAGE_SZ + 104], b"DATA");
        let pages = u32::from_be_bytes(bytes[28..32].try_into().unwrap());
        assert_eq!(pages, 5);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn merge_skips_other_salt() {
        let dir = std::env::temp_dir().join(format!("wx_db_rs_wal2_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("t.db");
        let wal = dir.join("t.db-wal");
        build_db(&db);
        let key = [9u8; KEY_SZ];
        let mut plain = vec![0u8; PAGE_SZ];
        plain[0] = 13;
        let frame_page = encrypt_page_for_test(&key, &plain, 3);
        let mut w = File::create(&wal).unwrap();
        let mut wh = [0u8; WAL_HEADER_SZ as usize];
        wh[16..24].copy_from_slice(&[1u8; 8]);
        w.write_all(&wh).unwrap();
        let mut fh = [0u8; WAL_FRAME_HDR_SZ as usize];
        fh[0..4].copy_from_slice(&3u32.to_be_bytes());
        fh[8..16].copy_from_slice(&[2u8; 8]);
        w.write_all(&fh).unwrap();
        w.write_all(&frame_page).unwrap();
        drop(w);
        merge_wal(&db, &wal, &key, 0).unwrap();
        let bytes = std::fs::read(&db).unwrap();
        assert_eq!(bytes.len(), PAGE_SZ * 2, "异 salt 帧不应写入");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
