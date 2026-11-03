//! The banned pubkeys, in an LMDB of their own.
//!
//! LMDB takes readers and writers from more than one process, so
//! `ditto-policy ban` writes while the plugin runs, and the plugin refuses a
//! banned pubkey's events from the moment the ban commits.
//!
//! | table       | key        | value                                     |
//! |-------------|------------|-------------------------------------------|
//! | `banned`    | pubkey     | community id ‖ time (u32 BE) ‖ [`Role`]   |
//! | `blocklist` | entry hash | created_at (i64 BE) ‖ blocked (u8) ‖ id   |
//!
//! A ban whose bundle couldn't be found has an all-zero community id, as has
//! a person's banned on their own. A ban from the Armada blocklist has its
//! entry's hash in place of a community id. `blocklist` holds the newest
//! entry of each user the blocklist names (see [`crate::blocklist`]).

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
    /// A person banned on their own, with `--pubkey`: by no Community, so
    /// lifting one's bans leaves theirs.
    Person = 2,
    /// A person an Armada blocklist entry names, recognized here: lifting
    /// the entry lifts it.
    Blocklist = 3,
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
            [2] => Role::Person,
            [3] => Role::Blocklist,
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
    blocklist: Database<Bytes, Bytes>,
}

/// The newest blocklist entry for a user, as kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub created_at: i64,
    pub blocked: bool,
    pub id: Bytes32,
}

impl Entry {
    fn encode(&self) -> Vec<u8> {
        [
            &self.created_at.to_be_bytes()[..],
            &[u8::from(self.blocked)],
            &self.id[..],
        ]
        .concat()
    }

    fn decode(value: &[u8]) -> Option<Entry> {
        let (created_at, rest) = value.split_first_chunk::<8>()?;
        let (&blocked, id) = rest.split_first()?;
        Some(Entry {
            created_at: i64::from_be_bytes(*created_at),
            blocked: blocked == 1,
            id: id.try_into().ok()?,
        })
    }
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
                .max_dbs(2)
                .open(dir)
        }
        .with_context(|| format!("Could not open the database at {}", dir.display()))?;
        let mut txn = env.write_txn()?;
        let banned = env.create_database(&mut txn, Some("banned"))?;
        let blocklist = env.create_database(&mut txn, Some("blocklist"))?;
        txn.commit()?;
        Ok(Bans {
            env,
            banned,
            blocklist,
        })
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

    /// Ban `pubkeys` together, as `community`'s. A person already banned on
    /// their own, or by the blocklist, stays so.
    pub fn ban(&self, pubkeys: &[(Bytes32, Role)], community: &Bytes32) -> Result<()> {
        let at = now();
        let mut txn = self.env.write_txn()?;
        for &(pubkey, role) in pubkeys {
            let own = self
                .banned
                .get(&txn, &pubkey)?
                .and_then(|value| Ban::decode(&pubkey, value))
                .is_some_and(|ban| matches!(ban.role, Role::Person | Role::Blocklist));
            if own && role != Role::Person {
                continue;
            }
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

    /// Every blocklist entry kept, by its hash.
    pub fn entries(&self) -> Result<Vec<(Bytes32, Entry)>> {
        let txn = self.env.read_txn()?;
        let mut entries = Vec::new();
        for entry in self.blocklist.iter(&txn)? {
            let (hash, value) = entry?;
            if let (Ok(hash), Some(entry)) = (hash.try_into(), Entry::decode(value)) {
                entries.push((hash, entry));
            }
        }
        Ok(entries)
    }

    /// Keep `entry` as the newest for `hash`.
    pub fn put_entry(&self, hash: &Bytes32, entry: &Entry) -> Result<()> {
        let mut txn = self.env.write_txn()?;
        self.blocklist.put(&mut txn, hash, &entry.encode())?;
        txn.commit()?;
        Ok(())
    }

    /// Ban `pubkey` as the user blocklist entry `hash` names, unless it's
    /// banned already. Whether it was banned now.
    pub fn ban_blocklisted(&self, pubkey: &Bytes32, hash: &Bytes32) -> Result<bool> {
        let mut txn = self.env.write_txn()?;
        if self.banned.get(&txn, pubkey)?.is_some() {
            return Ok(false);
        }
        let ban = Ban {
            pubkey: *pubkey,
            community: *hash,
            at: now(),
            role: Role::Blocklist,
        };
        self.banned.put(&mut txn, pubkey, &ban.encode())?;
        txn.commit()?;
        Ok(true)
    }

    /// Lift the bans entry `hash` made. Returns the pubkeys lifted.
    pub fn unban_blocklisted(&self, hash: &Bytes32) -> Result<Vec<Bytes32>> {
        let lifted: Vec<Bytes32> = self
            .list()?
            .into_iter()
            .filter(|ban| ban.role == Role::Blocklist && ban.community == *hash)
            .map(|ban| ban.pubkey)
            .collect();
        self.unban(&lifted)?;
        Ok(lifted)
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

fn now() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| {
            u32::try_from(since.as_secs()).unwrap_or(u32::MAX)
        })
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

    #[test]
    fn a_community_ban_leaves_a_persons_own() {
        let dir = tempfile::tempdir().unwrap();
        let bans = Bans::open(dir.path()).unwrap();
        let alice = [0xaa; 32];
        bans.ban(&[(alice, Role::Person)], &[0; 32]).unwrap();
        bans.ban(&[(alice, Role::Member)], &[7; 32]).unwrap();
        let ban = bans.get(&alice).unwrap().unwrap();
        assert_eq!((ban.role, ban.community), (Role::Person, [0; 32]));

        let bob = [0xbb; 32];
        bans.ban(&[(bob, Role::Member)], &[7; 32]).unwrap();
        bans.ban(&[(bob, Role::Person)], &[0; 32]).unwrap();
        assert_eq!(bans.get(&bob).unwrap().unwrap().role, Role::Person);
    }
}
