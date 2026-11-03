//! Armada's blocklist, applied here: kind-37307 entries signed by moderation
//! keys the config names (see [`crate::config`]), as `armada-blocklist`
//! publishes them. Off unless some are named.
//!
//! A user's entry names only a hash of their pubkey,
//!
//! ```text
//! entry hash = sha256(utf8("armada/blocklist/user/v1") || 0x00 || pubkey[32])
//! ```
//!
//! so a ban is recognized on meeting the pubkey: as an event's author, or in
//! one of its `p` tags (a follow, a reply, a gift wrap to them). From then on
//! it's banned like any other, and what it stored here is deleted, by the
//! configured command (`ditto-relay delete` by default). Lifting the entry
//! lifts the ban; what was deleted stays deleted. `ditto-policy unban` lifts
//! it only until the pubkey is next met.
//!
//! Entries come in two ways: as they're published here, through the plugin,
//! and from the configured relays, read when the plugin starts and every
//! `refresh_minutes` after. Community entries name a hash of a community id,
//! which can't be told from anything the relay sees, so they're left to
//! `ditto-policy ban <link>`.

use std::collections::{HashMap, HashSet};
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use anyhow::Result;
use sha2::{Digest, Sha256};

use crate::bans::{Bans, Entry};
use crate::concord::{Bytes32, bytes32};
use crate::config::BlocklistConfig;
use crate::fetch::{self, Filter};
use crate::{nostr, policy};

pub const KIND: u64 = 37307;
const LABEL: &[u8] = b"armada/blocklist/user/v1";
/// Pubkeys known not to be banned kept at most, before starting over.
const MAX_CLEAR: usize = 100_000;

/// The entry hash a user's pubkey is listed under.
pub fn hash(pubkey: &Bytes32) -> Bytes32 {
    let mut hasher = Sha256::new();
    hasher.update(LABEL);
    hasher.update([0]);
    hasher.update(pubkey);
    hasher.finalize().into()
}

/// A user's entry, as an event carries it.
struct Parsed {
    hash: Bytes32,
    entry: Entry,
}

fn parse(
    authors: &[String],
    pubkey: &str,
    kind: u64,
    id: &str,
    created_at: i64,
    tags: &[Vec<String>],
) -> Option<Parsed> {
    if kind != KIND || !authors.iter().any(|author| author == pubkey) {
        return None;
    }
    let tag = |name: &str| nostr::tag(tags, name);
    if tag("scope") != Some("user") || tag("v") != Some("1") {
        return None;
    }
    let blocked = match tag("status")? {
        "blocked" => true,
        "lifted" => false,
        _ => return None,
    };
    Some(Parsed {
        hash: bytes32(tag("d")?)?,
        entry: Entry {
            created_at,
            blocked,
            id: bytes32(id)?,
        },
    })
}

/// Whether `new` replaces `old`: newer, or as new with the lower id.
fn newer(new: &Entry, old: &Entry) -> bool {
    new.created_at > old.created_at || (new.created_at == old.created_at && new.id < old.id)
}

pub struct Blocklist {
    authors: Vec<String>,
    delete_command: Vec<String>,
    entries: HashMap<Bytes32, Entry>,
    blocked: HashSet<Bytes32>,
    /// Pubkeys met that no entry bans, so they aren't hashed again.
    clear: HashSet<String>,
    /// Pubkeys whose stored events this process has had deleted.
    deleted: HashSet<Bytes32>,
    fetched: Option<Receiver<Vec<nostr::Event>>>,
}

impl Blocklist {
    /// The blocklist the config asks for, with the entries `bans` keeps, and
    /// a thread reading the configured relays. None if no authors are named.
    pub fn start(config: &BlocklistConfig, bans: &Bans) -> Result<Option<Blocklist>> {
        if config.authors.is_empty() {
            return Ok(None);
        }
        let mut blocklist = Blocklist::new(config.authors.clone(), config.delete_command.clone());
        for (hash, entry) in bans.entries()? {
            blocklist.entries.insert(hash, entry);
        }
        blocklist.blocked = blocklist.blocked_hashes();
        if !config.relays.is_empty() {
            let (tx, rx) = mpsc::channel();
            let filter = Filter {
                kinds: vec![KIND as i64],
                authors: config.authors.clone(),
                d: None,
            };
            let relays = config.relays.clone();
            let every = Duration::from_secs(config.refresh_minutes.max(1) * 60);
            thread::spawn(move || {
                loop {
                    if tx.send(fetch::query(&relays, &filter)).is_err() {
                        return;
                    }
                    thread::sleep(every);
                }
            });
            blocklist.fetched = Some(rx);
        }
        eprintln!(
            "ditto-policy: applying the Armada blocklist of {} key(s), {} user(s) blocked",
            blocklist.authors.len(),
            blocklist.blocked.len()
        );
        Ok(Some(blocklist))
    }

    fn new(authors: Vec<String>, delete_command: Vec<String>) -> Blocklist {
        Blocklist {
            authors,
            delete_command,
            entries: HashMap::new(),
            blocked: HashSet::new(),
            clear: HashSet::new(),
            deleted: HashSet::new(),
            fetched: None,
        }
    }

    fn blocked_hashes(&self) -> HashSet<Bytes32> {
        self.entries
            .iter()
            .filter(|(_, entry)| entry.blocked)
            .map(|(hash, _)| *hash)
            .collect()
    }

    /// Take in what's come from the relays and `event`, then ban whichever
    /// pubkey `event` names that an entry blocks. Call before judging it.
    pub fn observe(&mut self, bans: &Bans, event: &policy::Event) -> Result<()> {
        let fetched: Vec<nostr::Event> = self
            .fetched
            .as_ref()
            .map(|rx| rx.try_iter().flatten().collect())
            .unwrap_or_default();
        let mut changed = false;
        for event in &fetched {
            let parsed = parse(
                &self.authors,
                &event.pubkey,
                event.kind as u64,
                &event.id,
                event.created_at,
                &event.tags,
            );
            changed |= self.absorb(bans, parsed)?;
        }
        // The relay checked its signature before asking.
        let parsed = parse(
            &self.authors,
            &event.pubkey,
            event.kind,
            &event.id,
            event.created_at as i64,
            &event.tags,
        );
        changed |= self.absorb(bans, parsed)?;
        if changed {
            self.blocked = self.blocked_hashes();
            self.clear.clear();
        }
        if self.blocked.is_empty() {
            return Ok(());
        }
        let named = std::iter::once(event.pubkey.as_str()).chain(
            event
                .tags
                .iter()
                .filter(|tag| tag.first().is_some_and(|name| name == "p"))
                .filter_map(|tag| tag.get(1).map(String::as_str)),
        );
        for pubkey in named {
            if self.clear.contains(pubkey) {
                continue;
            }
            let Some(key) = bytes32(pubkey) else { continue };
            let hash = hash(&key);
            if !self.blocked.contains(&hash) {
                if self.clear.len() >= MAX_CLEAR {
                    self.clear.clear();
                }
                self.clear.insert(pubkey.to_string());
                continue;
            }
            if bans.ban_blocklisted(&key, &hash)? {
                eprintln!(
                    "ditto-policy: banned {pubkey}, whom blocklist entry {} names",
                    hex::encode(hash)
                );
            }
            self.delete(key);
        }
        Ok(())
    }

    /// Keep `parsed` if it's newer than what's kept; a lift lifts the bans
    /// its entry made. Whether anything changed.
    fn absorb(&mut self, bans: &Bans, parsed: Option<Parsed>) -> Result<bool> {
        let Some(Parsed { hash, entry }) = parsed else {
            return Ok(false);
        };
        if self
            .entries
            .get(&hash)
            .is_some_and(|old| !newer(&entry, old))
        {
            return Ok(false);
        }
        bans.put_entry(&hash, &entry)?;
        if !entry.blocked {
            for pubkey in bans.unban_blocklisted(&hash)? {
                self.deleted.remove(&pubkey);
                eprintln!(
                    "ditto-policy: lifted the ban on {}, as blocklist entry {} was",
                    hex::encode(pubkey),
                    hex::encode(hash)
                );
            }
        }
        self.entries.insert(hash, entry);
        Ok(true)
    }

    /// Have the relay delete what `pubkey` stored, once a process. In the
    /// background: the relay is waiting on the plugin's answers.
    fn delete(&mut self, pubkey: Bytes32) {
        if self.delete_command.is_empty() || !self.deleted.insert(pubkey) {
            return;
        }
        let filter = format!(r#"{{"authors":["{}"]}}"#, hex::encode(pubkey));
        let (program, args) = (
            self.delete_command[0].clone(),
            self.delete_command[1..].to_vec(),
        );
        thread::spawn(move || {
            // Never its stdout: that's the plugin's answers.
            let status = Command::new(&program)
                .args(&args)
                .arg(&filter)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .status();
            match status {
                Ok(status) if status.success() => {
                    eprintln!("ditto-policy: asked {program} to delete {filter}")
                }
                Ok(status) => eprintln!("ditto-policy: {program} deleting {filter}: {status}"),
                Err(error) => eprintln!("ditto-policy: could not run {program}: {error}"),
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bans::Role;

    const MODERATOR: &str = "0d";

    fn moderator() -> String {
        MODERATOR.repeat(32)
    }

    fn entry(pubkey: &Bytes32, status: &str, created_at: u64, author: &str) -> policy::Event {
        policy::Event {
            id: format!("{created_at:064x}"),
            pubkey: author.into(),
            created_at,
            kind: KIND,
            tags: vec![
                vec!["d".into(), hex::encode(hash(pubkey))],
                vec!["scope".into(), "user".into()],
                vec!["status".into(), status.into()],
                vec!["v".into(), "1".into()],
            ],
            content: String::new(),
        }
    }

    fn note(pubkey: &str, p: &[&str]) -> policy::Event {
        policy::Event {
            id: "00".repeat(32),
            pubkey: pubkey.into(),
            created_at: 1,
            kind: 1,
            tags: p.iter().map(|p| vec!["p".into(), (*p).into()]).collect(),
            content: String::new(),
        }
    }

    #[test]
    fn matches_armada_blocklists_user_test_vector() {
        assert_eq!(
            hex::encode(hash(&[0; 32])),
            "5651d56b6e1741880b2c3822dfe70dbf1d14ed6497ef26ea5e82b81c29cc1856"
        );
    }

    #[test]
    fn bans_whom_an_entry_names_once_met_and_lifts_with_it() {
        let dir = tempfile::tempdir().unwrap();
        let bans = Bans::open(dir.path()).unwrap();
        let log = dir.path().join("deleted");
        let delete = vec![
            "sh".into(),
            "-c".into(),
            format!("printf '%s\\n' \"$1\" >> {}", log.display()),
            "sh".into(),
        ];
        let mut list = Blocklist::new(vec![moderator()], delete);
        let (alice, bob) = ([0xaa; 32], [0xbb; 32]);
        let (alice_hex, bob_hex) = (hex::encode(alice), hex::encode(bob));

        // Not by a moderation key: nothing.
        list.observe(&bans, &entry(&alice, "blocked", 1, &"ee".repeat(32)))
            .unwrap();
        list.observe(&bans, &note(&alice_hex, &[])).unwrap();
        assert!(bans.list().unwrap().is_empty());

        list.observe(&bans, &entry(&alice, "blocked", 2, &moderator()))
            .unwrap();
        assert!(bans.list().unwrap().is_empty(), "not banned until met");
        // Met in someone else's p tag.
        list.observe(&bans, &note(&bob_hex, &[&alice_hex])).unwrap();
        let ban = bans.get(&alice).unwrap().unwrap();
        assert_eq!((ban.role, ban.community), (Role::Blocklist, hash(&alice)));
        assert!(bans.get(&bob).unwrap().is_none());
        assert!(bans.blocks(&note(&alice_hex, &[])).unwrap());
        // Deleted once, in the background.
        list.observe(&bans, &note(&alice_hex, &[])).unwrap();
        for _ in 0..100 {
            if log.exists() {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        thread::sleep(Duration::from_millis(50));
        let deleted = std::fs::read_to_string(&log).unwrap();
        assert_eq!(deleted, format!("{{\"authors\":[\"{alice_hex}\"]}}\n"));

        // An older lift changes nothing; a newer one lifts the ban.
        list.observe(&bans, &entry(&alice, "lifted", 1, &moderator()))
            .unwrap();
        assert!(bans.get(&alice).unwrap().is_some());
        list.observe(&bans, &entry(&alice, "lifted", 3, &moderator()))
            .unwrap();
        assert!(bans.get(&alice).unwrap().is_none());
        list.observe(&bans, &note(&alice_hex, &[])).unwrap();
        assert!(bans.get(&alice).unwrap().is_none());
    }

    #[test]
    fn leaves_other_bans_as_they_are() {
        let dir = tempfile::tempdir().unwrap();
        let bans = Bans::open(dir.path()).unwrap();
        let mut list = Blocklist::new(vec![moderator()], vec![]);
        let alice = [0xaa; 32];
        bans.ban(&[(alice, Role::Person)], &[0; 32]).unwrap();
        list.observe(&bans, &entry(&alice, "blocked", 2, &moderator()))
            .unwrap();
        list.observe(&bans, &note(&hex::encode(alice), &[]))
            .unwrap();
        assert_eq!(bans.get(&alice).unwrap().unwrap().role, Role::Person);
        list.observe(&bans, &entry(&alice, "lifted", 3, &moderator()))
            .unwrap();
        assert_eq!(bans.get(&alice).unwrap().unwrap().role, Role::Person);
    }

    #[test]
    fn keeps_its_entries_across_restarts() {
        let dir = tempfile::tempdir().unwrap();
        let bans = Bans::open(dir.path()).unwrap();
        let alice = [0xaa; 32];
        let config = BlocklistConfig {
            authors: vec![moderator()],
            relays: vec![],
            delete_command: vec![],
            ..Default::default()
        };
        let mut list = Blocklist::start(&config, &bans).unwrap().unwrap();
        list.observe(&bans, &entry(&alice, "blocked", 2, &moderator()))
            .unwrap();
        drop(list);

        let mut list = Blocklist::start(&config, &bans).unwrap().unwrap();
        list.observe(&bans, &note(&hex::encode(alice), &[]))
            .unwrap();
        assert!(bans.get(&alice).unwrap().is_some());
        assert!(
            Blocklist::start(&BlocklistConfig::default(), &bans)
                .unwrap()
                .is_none(),
            "off with no authors"
        );
    }
}
