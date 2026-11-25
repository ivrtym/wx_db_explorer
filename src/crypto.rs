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
pub fn decrypt_file(src: &str, dst: &str, key: &[u8; KEY_SZ]) -> Result<()> {
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
