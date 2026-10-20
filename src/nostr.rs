//! Just enough Nostr for `ditto-policy ban`: events and their signatures
//! (NIP-01), NIP-44 v2 decryption, and decoding NIP-19 entities.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use secp256k1::{Parity, PublicKey, SECP256K1, SecretKey, XOnlyPublicKey, schnorr};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Event {
    pub id: String,
    pub pubkey: String,
    pub created_at: i64,
    pub kind: i64,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

impl Event {
    fn compute_id(&self) -> String {
        let canonical = serde_json::to_string(&(
            0,
            &self.pubkey,
            self.created_at,
            self.kind,
            &self.tags,
            &self.content,
        ))
        .unwrap_or_default();
        hex::encode(Sha256::digest(canonical.as_bytes()))
    }

    /// Whether the id is the hash of the event and the signature is its
    /// author's.
    pub fn verify(&self) -> bool {
        if self.compute_id() != self.id {
            return false;
        }
        let (Ok(id), Ok(pubkey), Ok(sig)) = (
            hex::decode(&self.id),
            hex::decode(&self.pubkey),
            hex::decode(&self.sig),
        ) else {
            return false;
        };
        let (Ok(pubkey), Ok(sig)) = (
            XOnlyPublicKey::from_slice(&pubkey),
            schnorr::Signature::from_slice(&sig),
        ) else {
            return false;
        };
        SECP256K1.verify_schnorr(&sig, &id, &pubkey).is_ok()
    }

    /// The value of the first tag named `name`.
    pub fn tag(&self, name: &str) -> Option<&str> {
        tag(&self.tags, name)
    }
}

/// The value of the first of `tags` named `name`.
pub fn tag<'a>(tags: &'a [Vec<String>], name: &str) -> Option<&'a str> {
    tags.iter()
        .find(|tag| tag.first().map(String::as_str) == Some(name))
        .and_then(|tag| tag.get(1))
        .map(String::as_str)
}

// NIP-44 v2.

/// The key two parties share.
pub fn conversation_key(secret: &SecretKey, pubkey: &XOnlyPublicKey) -> [u8; 32] {
    let point = secp256k1::ecdh::shared_secret_point(
        &PublicKey::from_x_only_public_key(*pubkey, Parity::Even),
        secret,
    );
    let (prk, _) = Hkdf::<Sha256>::extract(Some(b"nip44-v2"), &point[..32]);
    prk.into()
}

/// NIP-44's `calc_padded_len`.
fn padded_len(unpadded: usize) -> usize {
    if unpadded <= 32 {
        return 32;
    }
    let next_power = 1usize << (usize::BITS - (unpadded - 1).leading_zeros());
    let chunk = if next_power <= 256 {
        32
    } else {
        next_power / 8
    };
    chunk * ((unpadded - 1) / chunk + 1)
}

/// Decrypt a payload, or `None` if it isn't a valid v2 payload for this key.
pub fn decrypt(conversation_key: &[u8; 32], payload: &str) -> Option<String> {
    if payload.starts_with('#') {
        return None;
    }
    let bytes = STANDARD.decode(payload).ok()?;
    // Version, nonce, the shortest padded plaintext and its length, and MAC.
    if bytes.len() < 1 + 32 + 2 + 32 + 32 || bytes[0] != 2 {
        return None;
    }
    let nonce: [u8; 32] = bytes[1..33].try_into().unwrap();
    let (ciphertext, tag) = bytes[33..].split_at(bytes.len() - 33 - 32);

    let hkdf = Hkdf::<Sha256>::from_prk(conversation_key).ok()?;
    let mut keys = [0u8; 76];
    hkdf.expand(&nonce, &mut keys).ok()?;
    let (key, chacha_nonce, hmac_key) = (&keys[..32], &keys[32..44], &keys[44..]);

    let mut mac = Hmac::<Sha256>::new_from_slice(hmac_key).ok()?;
    mac.update(&nonce);
    mac.update(ciphertext);
    mac.verify_slice(tag).ok()?;

    let mut padded = ciphertext.to_vec();
    ChaCha20::new(key.into(), chacha_nonce.into()).apply_keystream(&mut padded);
    let len = u16::from_be_bytes([padded[0], padded[1]]) as usize;
    if len == 0 || padded.len() != 2 + padded_len(len) {
        return None;
    }
    String::from_utf8(padded[2..2 + len].to_vec()).ok()
}

// NIP-19. bech32 is decoded here rather than by a library, because nostr's
// TLV entities routinely run past the 90 characters BIP-173 allows.

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GENERATOR: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

#[derive(Debug, PartialEq, Eq)]
pub enum Decoded {
    Npub(String),
    Naddr {
        pubkey: String,
        kind: u32,
        identifier: String,
    },
}

pub fn nip19_decode(value: &str) -> Option<Decoded> {
    let (hrp, data) = bech32_decode(value)?;
    match hrp.as_str() {
        "npub" => Some(Decoded::Npub(key(&data)?)),
        "naddr" => {
            let tlv = parse_tlv(&data)?;
            let first = |kind: u8| tlv.iter().find(|(k, _)| *k == kind).map(|(_, v)| v);
            Some(Decoded::Naddr {
                identifier: String::from_utf8(first(0)?.to_vec()).ok()?,
                pubkey: key(first(2)?)?,
                kind: u32::from_be_bytes(first(3)?.as_slice().try_into().ok()?),
            })
        }
        _ => None,
    }
}

fn key(bytes: &[u8]) -> Option<String> {
    (bytes.len() == 32).then(|| hex::encode(bytes))
}

fn parse_tlv(mut data: &[u8]) -> Option<Vec<(u8, Vec<u8>)>> {
    let mut entries = Vec::new();
    while !data.is_empty() {
        let (&kind, rest) = data.split_first()?;
        let (&len, rest) = rest.split_first()?;
        let value = rest.get(..len as usize)?;
        entries.push((kind, value.to_vec()));
        data = &rest[len as usize..];
    }
    Some(entries)
}

fn polymod(values: impl IntoIterator<Item = u8>) -> u32 {
    let mut chk: u32 = 1;
    for value in values {
        let top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ u32::from(value);
        for (i, generator) in GENERATOR.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= generator;
            }
        }
    }
    chk
}

fn bech32_decode(value: &str) -> Option<(String, Vec<u8>)> {
    if value.len() > 5000 {
        return None;
    }
    let has_lower = value.bytes().any(|b| b.is_ascii_lowercase());
    let has_upper = value.bytes().any(|b| b.is_ascii_uppercase());
    if has_lower && has_upper {
        return None;
    }
    let value = value.to_ascii_lowercase();
    let separator = value.rfind('1')?;
    if separator == 0 || separator + 7 > value.len() {
        return None;
    }
    let hrp = &value[..separator];
    let words = value[separator + 1..]
        .bytes()
        .map(|c| CHARSET.iter().position(|&x| x == c).map(|i| i as u8))
        .collect::<Option<Vec<u8>>>()?;

    let mut values: Vec<u8> = hrp.bytes().map(|b| b >> 5).collect();
    values.push(0);
    values.extend(hrp.bytes().map(|b| b & 31));
    values.extend_from_slice(&words);
    if polymod(values) != 1 {
        return None;
    }

    // 5-bit words to bytes, refusing nonzero padding.
    let (mut acc, mut bits, mut data) = (0u32, 0u32, Vec::new());
    for &word in &words[..words.len() - 6] {
        acc = (acc << 5) | u32::from(word);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            data.push((acc >> bits) as u8);
        }
    }
    if bits >= 5 || (acc << (8 - bits)) & 0xff != 0 {
        return None;
    }
    Some((hrp.to_string(), data))
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use secp256k1::Keypair;

    /// Sign a new event with `secret` (hex).
    pub fn sign(secret: &str, kind: i64, tags: &[&[&str]], content: &str) -> Event {
        let event = Event {
            id: String::new(),
            pubkey: String::new(),
            created_at: 1_700_000_000,
            kind,
            tags: tags
                .iter()
                .map(|tag| tag.iter().map(|s| s.to_string()).collect())
                .collect(),
            content: content.into(),
            sig: String::new(),
        };
        resign(secret, event)
    }

    /// Sign `event` again, after a change to it.
    pub fn resign(secret: &str, mut event: Event) -> Event {
        let keypair = Keypair::from_seckey_str_global(secret).unwrap();
        event.pubkey = hex::encode(keypair.x_only_public_key().0.serialize());
        event.id = event.compute_id();
        let digest = hex::decode(&event.id).unwrap();
        event.sig = hex::encode(
            SECP256K1
                .sign_schnorr_no_aux_rand(&digest, &keypair)
                .to_byte_array(),
        );
        event
    }

    #[test]
    fn signs_and_verifies() {
        let event = sign(&"01".repeat(32), 1, &[&["t", "x\n\"y\""]], "héllo\u{1}");
        assert!(event.verify());
        let mut tampered = event.clone();
        tampered.content = "other".into();
        assert!(!tampered.verify());
    }

    /// From NIP-44's `nip44.vectors.json`.
    #[test]
    fn decrypts_the_spec_vectors() {
        let secret = |hex: &str| SecretKey::from_slice(&hex::decode(hex).unwrap()).unwrap();
        let (one, two) = (
            secret(&format!("{:064x}", 1)),
            secret(&format!("{:064x}", 2)),
        );
        let key = conversation_key(&one, &two.x_only_public_key(SECP256K1).0);
        assert_eq!(
            hex::encode(key),
            "c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d"
        );
        let payload = "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABee0G5VSK0/9YypIObAtDKfYEAjD35uVkHyB0F4DwrcNaCXlCWZKaArsGrY6M9wnuTMxWfp1RTN9Xga8no+kF5Vsb";
        assert_eq!(decrypt(&key, payload).as_deref(), Some("a"));
        assert_eq!(decrypt(&[1; 32], payload), None);
        assert_eq!(decrypt(&key, "not base64!"), None);
    }

    #[test]
    fn decodes_nip19() {
        let pubkey = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
        let npub = "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6";
        assert_eq!(nip19_decode(npub), Some(Decoded::Npub(pubkey.into())));
        assert_eq!(
            nip19_decode(&npub.to_uppercase()),
            Some(Decoded::Npub(pubkey.into()))
        );
        assert_eq!(
            nip19_decode(
                "naddr1qvzqqqpmrqpzqdjt6x8rz0hl2y8ja6ktmcd00mk8vjq87garcx74xz0yphknwmw4qqqqe6t958"
            ),
            Some(Decoded::Naddr {
                pubkey: "364bd18e313eff510f2eeacbde1af7eec764807f23a3c1bd5309e40ded376dd5".into(),
                kind: 15128,
                identifier: String::new(),
            })
        );
        let mut broken = npub.to_string();
        broken.pop();
        broken.push('q');
        assert_eq!(nip19_decode(&broken), None);
    }
}
