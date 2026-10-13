//! The banned pubkeys, in an LMDB of their own.
//!
//! LMDB takes readers and writers from more than one process, so
//! `ditto-policy ban` writes while the plugin runs, and the plugin refuses a
//! banned pubkey's events from the moment the ban commits.
//!
//! | table    | key    | value                                   |
//! |----------|--------|-----------------------------------------|
//! | `banned` | pubkey | community id ‖ time (u32 BE) ‖ [`Role`] |
//!
//! A ban whose bundle couldn't be found has an all-zero community id.

use std::path::Path;

use anyhow::{Context, Result};
use heed::types::Bytes;
use heed::{Database, Env, EnvOpenOptions, WithoutTls};

use crate::concord::{self, Bytes32};
use crate::policy::Event;

/// Address space reserved. A ban is 69 bytes.
const MAP_SIZE: usize = 1 << 30;

/// What a banned pubkey was to its Community.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// An address the Community publishes at, or one of its invite links.
    Community = 0,
    /// A person in it, banned with `--members`: their own key, for
    /// everything they post.
    Member = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ban {
    pub pubkey: Bytes32,
    pub community: Bytes32,
    pub at: u32,
    pub role: Role,
}

impl Ban {
    fn encode(&self) -> Vec<u8> {
        [
            &self.community[..],
            &self.at.to_be_bytes(),
            &[self.role as u8],
        ]
        .concat()
    }

    fn decode(pubkey: &[u8], value: &[u8]) -> Option<Ban> {
        let (community, rest) = value.split_first_chunk::<32>()?;
        let (at, rest) = rest.split_first_chunk::<4>()?;
        let role = match rest {
            [1] => Role::Member,
            _ => Role::Community,
        };
        Some(Ban {
            pubkey: pubkey.try_into().ok()?,
            community: *community,
            at: u32::from_be_bytes(*at),
            role,
        })
    }
}

pub struct Bans {
    env: Env<WithoutTls>,
    banned: Database<Bytes, Bytes>,
}

impl Bans {
    /// Open the database in `dir`, making it if it isn't there.
    pub fn open(dir: &Path) -> Result<Bans> {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("Could not make the directory {}", dir.display()))?;
        // SAFETY: the environment is opened once per process, and nothing
        // but LMDB writes to its files.
        let env = unsafe {
            EnvOpenOptions::new()
                .read_txn_without_tls()
                .map_size(MAP_SIZE)
                .max_dbs(1)
                .open(dir)
        }
        .with_context(|| format!("Could not open the database at {}", dir.display()))?;
        let mut txn = env.write_txn()?;
        let banned = env.create_database(&mut txn, Some("banned"))?;
        txn.commit()?;
        Ok(Bans { env, banned })
    }

    /// Whether an event is one a ban keeps out: signed by a banned pubkey,
    /// or announcing an invite link whose bundle's signer is banned.
    pub fn blocks(&self, event: &Event) -> Result<bool> {
        let txn = self.env.read_txn()?;
        let banned = |pubkey: &str| -> Result<bool> {
            Ok(match concord::bytes32(pubkey) {
                Some(pubkey) => self.banned.get(&txn, &pubkey)?.is_some(),
                None => false,
            })
        };
        if banned(&event.pubkey)? {
            return Ok(true);
        }
        if event.kind == concord::ANNOUNCEMENT
            && let Some(signer) = concord::link_signer(&event.content)
        {
            return banned(&signer);
        }
        Ok(false)
    }

    /// Ban `pubkeys` together, as `community`'s.
    pub fn ban(&self, pubkeys: &[(Bytes32, Role)], community: &Bytes32) -> Result<()> {
        let at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| {
                u32::try_from(since.as_secs()).unwrap_or(u32::MAX)
            });
        let mut txn = self.env.write_txn()?;
        for &(pubkey, role) in pubkeys {
            let ban = Ban {
                pubkey,
                community: *community,
                at,
                role,
            };
            self.banned.put(&mut txn, &pubkey, &ban.encode())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn get(&self, pubkey: &Bytes32) -> Result<Option<Ban>> {
        let txn = self.env.read_txn()?;
        Ok(self
            .banned
            .get(&txn, pubkey)?
            .and_then(|value| Ban::decode(pubkey, value)))
    }

    pub fn list(&self) -> Result<Vec<Ban>> {
        let txn = self.env.read_txn()?;
        let mut bans = Vec::new();
        for entry in self.banned.iter(&txn)? {
            let (pubkey, value) = entry?;
            bans.extend(Ban::decode(pubkey, value));
        }
        Ok(bans)
    }

    /// Lift the bans on `pubkeys`. Returns how many there were.
    pub fn unban(&self, pubkeys: &[Bytes32]) -> Result<usize> {
        let mut txn = self.env.write_txn()?;
        let mut lifted = 0;
        for pubkey in pubkeys {
            lifted += usize::from(self.banned.delete(&mut txn, pubkey)?);
        }
        txn.commit()?;
        Ok(lifted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(pubkey: &str, kind: u64, content: &str) -> Event {
        Event {
            id: "00".repeat(32),
            pubkey: pubkey.into(),
            created_at: 0,
            kind,
            tags: vec![],
            content: content.into(),
        }
    }

    #[test]
    fn bans_authors_and_their_links() {
        let dir = tempfile::tempdir().unwrap();
        let bans = Bans::open(dir.path()).unwrap();
        let v = concord::tests::vectors();
        let url = v["invite"]["url"].as_str().unwrap();
        let signer = v["invite"]["link_signer"].as_str().unwrap();
        let alice = "aa".repeat(32);

        assert!(!bans.blocks(&event(signer, 33301, "")).unwrap());
        assert!(
            !bans
                .blocks(&event(&alice, concord::ANNOUNCEMENT, url))
                .unwrap()
        );

        let community = [7; 32];
        bans.ban(
            &[(concord::bytes32(signer).unwrap(), Role::Community)],
            &community,
        )
        .unwrap();
        assert!(bans.blocks(&event(signer, 1059, "")).unwrap());
        assert!(
            bans.blocks(&event(&alice, concord::ANNOUNCEMENT, url))
                .unwrap()
        );
        assert!(!bans.blocks(&event(&alice, 1, url)).unwrap());
        assert!(!bans.blocks(&event(&alice, 1, "")).unwrap());

        let list = bans.list().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].community, community);
        assert_eq!(list[0].role, Role::Community);

        assert_eq!(bans.unban(&[concord::bytes32(signer).unwrap()]).unwrap(), 1);
        assert!(!bans.blocks(&event(signer, 1059, "")).unwrap());
        assert!(bans.list().unwrap().is_empty());
    }
}
