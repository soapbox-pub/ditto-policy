//! `ditto-policy ban`, `ditto-policy ban --list`, and `ditto-policy unban`:
//! keep a Concord Community off the relay, given one of its invite links.
//!
//! The link opens the Community's bundle, whose keys give every address the
//! Community publishes at in its current epoch: its Control Plane, its
//! Guestbook, each Channel's Chat Plane, where its next Refounding and
//! rekeys would go, and where its dissolution would. The Control Plane names
//! its Channels and its other invite links. Every one of those pubkeys is
//! banned, and so is any Discover announcement of the links.
//!
//! With `--members`, so is everyone in the Community, by their own keys:
//! the Guestbook coalesced, with everyone seen publishing on its planes,
//! less anyone its Banlist names. That bans them from posting anything here,
//! not only to the Community.
//!
//! Earlier epochs are out of reach: no key in the bundle derives them. And
//! the plugin only refuses new events: what's already stored stays until
//! it's deleted.
//!
//! Everything is read from the link's relays, the Community's, and any
//! given with `--relay`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

use anyhow::{Result, anyhow, bail};

use crate::bans::{Ban, Bans, Role};
use crate::concord::{self, Bytes32, bytes32};
use crate::fetch::{self, Filter};
use crate::nostr::{self, Decoded, Event};

/// A pubkey to ban, and what it is to the Community.
struct Target {
    pubkey: Bytes32,
    role: Role,
    what: String,
}

impl Target {
    fn new(pubkey: &str, role: Role, what: impl Into<String>) -> Option<Target> {
        Some(Target {
            pubkey: bytes32(pubkey)?,
            role,
            what: what.into(),
        })
    }
}

/// `ditto-policy ban <link>`.
pub fn ban(
    db: &Path,
    link: &str,
    members: bool,
    extra_relays: &[String],
    dry_run: bool,
) -> Result<()> {
    ban_with(
        &Bans::open(db)?,
        link,
        members,
        extra_relays,
        dry_run,
        fetch::query,
    )
}

/// [`ban`], reading events with `query`.
fn ban_with(
    bans: &Bans,
    link: &str,
    members: bool,
    extra_relays: &[String],
    dry_run: bool,
    query: impl Fn(&[String], &Filter) -> Vec<Event>,
) -> Result<()> {
    let link = concord::parse_link(link).map_err(|error| anyhow!(error))?;
    let mut relays: Vec<String> = link.relays.iter().chain(extra_relays).cloned().collect();

    let mut targets =
        vec![Target::new(&link.link_signer, Role::Community, "this invite link").unwrap()];
    let mut community = [0; 32];

    let filter = Filter {
        kinds: vec![concord::INVITE_BUNDLE],
        authors: vec![link.link_signer.clone()],
        d: Some(vec![String::new()]),
    };
    let found = query(&relays, &filter)
        .into_iter()
        .filter(concord::is_bundle)
        .max_by_key(|event| event.created_at);
    let bundle = match found {
        None => {
            println!(
                "No invite bundle for this link was found on its relays. Banning the link alone."
            );
            None
        }
        Some(event) => match concord::open_bundle(&event, &link).map_err(|error| anyhow!(error))? {
            None => {
                println!(
                    "This invite link has been revoked, so it holds no keys. Banning the link alone."
                );
                None
            }
            Some(bundle) => Some(bundle),
        },
    };

    if let Some(bundle) = &bundle {
        let (id, root, epoch) = (bundle.id(), bundle.root(), bundle.root_epoch);
        community = id;
        relays.extend(bundle.relays.iter().cloned());

        let read = concord::control_key(&root, &id, epoch);
        let mut control_plane = vec![read.pk.clone()];
        control_plane.extend(
            bundle
                .control_pk
                .iter()
                .map(|pk| pk.to_lowercase())
                .filter(|pk| bytes32(pk).is_some()),
        );
        let wraps = query(&relays, &wraps_by(control_plane));
        let control = concord::read_control(&wraps, &read.conv_key);
        let name = control.name.as_deref().unwrap_or(&bundle.name);
        println!("Community: {name} ({})", bundle.community_id);
        if epoch > 0 {
            println!(
                "It's at epoch {epoch}. Epochs before it can't be reached from this link: no key in it derives them."
            );
        }

        if let Some(pk) = &bundle.control_pk {
            targets.extend(Target::new(pk, Role::Community, "Control Plane"));
        }
        targets.extend(Target::new(
            &read.pk,
            Role::Community,
            "Control Plane, at its pre-split address",
        ));
        let guestbook = concord::guestbook_key(&root, &id, epoch);
        targets.extend(Target::new(&guestbook.pk, Role::Community, "Guestbook"));
        targets.extend(Target::new(
            &concord::base_rekey_key(&root, &id, epoch + 1).pk,
            Role::Community,
            "its next Refounding",
        ));
        targets.extend(Target::new(
            &concord::dissolved_key(&id).pk,
            Role::Community,
            "its dissolution",
        ));

        // Each Chat Plane's address, and the key that opens it.
        let mut chats = Vec::new();
        for (channel, channel_name) in &control.channels {
            let key = concord::channel_key(&root, channel, epoch);
            targets.extend(Target::new(
                &key.pk,
                Role::Community,
                format!("#{}", display_name(channel_name, channel)),
            ));
            chats.push(key);
        }
        for channel in &bundle.channels {
            let (Some(channel_id), Some(key)) = (bytes32(&channel.id), bytes32(&channel.key))
            else {
                continue;
            };
            let name = display_name(
                control
                    .channels
                    .get(&channel_id)
                    .filter(|name| !name.is_empty())
                    .unwrap_or(&channel.name),
                &channel_id,
            );
            let key = concord::channel_key(&key, &channel_id, channel.epoch);
            targets.extend(Target::new(
                &key.pk,
                Role::Community,
                format!("#{name}, private"),
            ));
            targets.extend(Target::new(
                &concord::channel_rekey_key(&root, &channel_id, channel.epoch + 1).pk,
                Role::Community,
                format!("#{name}'s next key"),
            ));
            chats.push(key);
        }

        // A Registry is a member's word for which pubkeys are invite links,
        // so it could name anyone's: only one that has published an invite
        // bundle is taken as one.
        let others: Vec<String> = control
            .link_signers
            .iter()
            .filter(|other| **other != link.link_signer)
            .cloned()
            .collect();
        if !others.is_empty() {
            let filter = Filter {
                kinds: vec![concord::INVITE_BUNDLE],
                authors: others.clone(),
                d: Some(vec![String::new()]),
            };
            let signers: BTreeSet<String> = query(&relays, &filter)
                .into_iter()
                .filter(concord::is_bundle)
                .map(|event| event.pubkey)
                .collect();
            for other in &others {
                if signers.contains(other) {
                    targets.extend(Target::new(
                        other,
                        Role::Community,
                        "another of its invite links",
                    ));
                } else {
                    println!(
                        "  Not banning {other}: its Registry names it as an invite link, but no bundle of it was found."
                    );
                }
            }
        }

        if members {
            let mut planes = vec![guestbook.pk.clone()];
            planes.extend(chats.iter().map(|key| key.pk.clone()));
            let mut by_plane: BTreeMap<String, Vec<Event>> = BTreeMap::new();
            for wrap in query(&relays, &wraps_by(planes)) {
                by_plane.entry(wrap.pubkey.clone()).or_default().push(wrap);
            }
            let wraps_at = |pk: &str| by_plane.get(pk).map_or(&[][..], Vec::as_slice);

            let mut authors = control.authors.clone();
            for key in &chats {
                for (author, last) in concord::authors(wraps_at(&key.pk), &key.conv_key) {
                    let seen = authors.entry(author).or_insert(i64::MIN);
                    *seen = (*seen).max(last);
                }
            }
            // The owner is in it, whether or not they've been seen.
            authors
                .entry(bundle.owner.to_lowercase())
                .or_insert(i64::MIN);
            let guestbook = concord::read_guestbook(wraps_at(&guestbook.pk), &guestbook.conv_key);
            let found = concord::members(&guestbook, &authors, &control.banned);
            if !control.banned.is_empty() {
                println!(
                    "  Not banning the {} people its own Banlist names.",
                    control.banned.len()
                );
            }
            for member in &found {
                let what = if *member == bundle.owner.to_lowercase() {
                    "its owner"
                } else {
                    "a member"
                };
                targets.extend(Target::new(member, Role::Member, what));
            }
        }
    }

    let mut seen = BTreeSet::new();
    targets.retain(|target| seen.insert(target.pubkey));

    println!(
        "{} {} pubkeys:",
        if dry_run { "Would ban" } else { "Banning" },
        targets.len()
    );
    for target in &targets {
        println!("  {}  {}", hex::encode(target.pubkey), target.what);
    }
    if dry_run {
        return Ok(());
    }
    let pubkeys: Vec<(Bytes32, Role)> = targets
        .iter()
        .map(|target| (target.pubkey, target.role))
        .collect();
    bans.ban(&pubkeys, &community)?;
    println!("Banned. Events already stored are left as they are.");
    Ok(())
}

/// `ditto-policy ban --list`.
pub fn list(db: &Path) -> Result<()> {
    let mut bans = Bans::open(db)?.list()?;
    if bans.is_empty() {
        println!("Nothing is banned.");
        return Ok(());
    }
    bans.sort_by_key(|ban| (ban.community, ban.role as u8, ban.at, ban.pubkey));
    let mut community = None;
    for ban in bans {
        if community != Some(ban.community) {
            community = Some(ban.community);
            if ban.community == [0; 32] {
                println!("Invite links whose bundles weren't found:");
            } else {
                println!("Community {}:", hex::encode(ban.community));
            }
        }
        let role = match ban.role {
            Role::Community => "",
            Role::Member => "  member",
        };
        println!(
            "  {}  banned {}{role}",
            hex::encode(ban.pubkey),
            date(ban.at)
        );
    }
    Ok(())
}

/// `ditto-policy unban <target>`: an invite link or community id lifts its
/// Community's bans, its members' included; a pubkey just its own.
pub fn unban(db: &Path, target: &str) -> Result<()> {
    let lifted = unban_from(&Bans::open(db)?, target)?;
    println!("Lifted {lifted} bans.");
    Ok(())
}

fn unban_from(bans: &Bans, target: &str) -> Result<usize> {
    let all = bans.list()?;
    let of_community = |community: Bytes32| -> Vec<Bytes32> {
        all.iter()
            .filter(|ban| ban.community == community)
            .map(|ban| ban.pubkey)
            .collect()
    };
    let pubkeys = if let Some(signer) = concord::link_signer(target) {
        let signer = bytes32(&signer).unwrap();
        match bans.get(&signer)? {
            Some(Ban { community, .. }) if community != [0; 32] => of_community(community),
            _ => vec![signer],
        }
    } else {
        let hex = match nostr::nip19_decode(target.trim()) {
            Some(Decoded::Npub(pubkey)) => pubkey,
            _ => target.trim().to_lowercase(),
        };
        let Some(key) = bytes32(&hex) else {
            bail!("Not an invite link, community id, or pubkey: {target}")
        };
        match of_community(key) {
            community if !community.is_empty() => community,
            _ => vec![key],
        }
    };
    bans.unban(&pubkeys)
}

fn wraps_by(authors: Vec<String>) -> Filter {
    Filter {
        kinds: vec![concord::WRAP],
        authors,
        d: None,
    }
}

fn display_name(name: &str, id: &Bytes32) -> String {
    if name.is_empty() {
        hex::encode(&id[..4])
    } else {
        name.to_string()
    }
}

/// A Unix time as a UTC date, `2026-10-20`.
fn date(at: u32) -> String {
    let days = (UNIX_EPOCH + Duration::from_secs(at.into()))
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / 86400;
    // Howard Hinnant's civil_from_days.
    let z = days as i64 + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::concord::tests::{event, vectors};
    use crate::policy;

    /// A relay holding the vectors' bundle, Control Plane, Guestbook, and a
    /// chat message.
    fn relay(_: &[String], filter: &Filter) -> Vec<Event> {
        let v = vectors();
        let mut events = vec![
            event(&v["invite"]["bundle_event"]),
            event(&v["guestbook"]["wrap"]),
            event(&v["chat_wrap"]["wrap"]),
        ];
        events.extend(v["control"]["wraps"].as_array().unwrap().iter().map(event));
        events
            .into_iter()
            .filter(|event| {
                filter.kinds.contains(&event.kind) && filter.authors.contains(&event.pubkey)
            })
            .collect()
    }

    fn by(pubkey: &str) -> policy::Event {
        policy::Event {
            id: "00".repeat(32),
            pubkey: pubkey.into(),
            kind: 1,
            tags: vec![],
            content: String::new(),
        }
    }

    #[test]
    fn bans_a_community_by_its_invite_link() {
        let v = vectors();
        let dir = tempfile::tempdir().unwrap();
        let bans = Bans::open(dir.path()).unwrap();
        let url = v["invite"]["url"].as_str().unwrap();

        ban_with(&bans, url, false, &[], true, relay).unwrap();
        assert!(bans.list().unwrap().is_empty(), "a dry run changes nothing");

        ban_with(&bans, url, false, &[], false, relay).unwrap();
        let list = bans.list().unwrap();
        let community = bytes32(v["keys"]["community_id"].as_str().unwrap()).unwrap();
        assert!(
            list.iter()
                .all(|ban| ban.community == community && ban.role == Role::Community)
        );
        // The link, Control Plane at both addresses, Guestbook, next
        // Refounding, dissolution, two public Channels, and the private one
        // and its next key.
        assert_eq!(list.len(), 10);
        assert!(
            bans.blocks(&by(v["control"]["control_pk"].as_str().unwrap()))
                .unwrap()
        );
        assert!(
            bans.blocks(&by(v["invite"]["link_signer"].as_str().unwrap()))
                .unwrap()
        );
        assert!(
            !bans
                .blocks(&by(v["keys"]["alice"].as_str().unwrap()))
                .unwrap()
        );

        bans.unban(&list.iter().map(|ban| ban.pubkey).collect::<Vec<_>>())
            .unwrap();
        ban_with(&bans, url, true, &[], false, relay).unwrap();
        let members: BTreeSet<String> = bans
            .list()
            .unwrap()
            .iter()
            .filter(|ban| ban.role == Role::Member)
            .map(|ban| hex::encode(ban.pubkey))
            .collect();
        let k = &v["keys"];
        // The owner and Alice, who wrote in a Channel; not Bob, whom the
        // Community itself banned.
        assert!(members.contains(k["owner"].as_str().unwrap()));
        assert!(members.contains(k["alice"].as_str().unwrap()));
        assert!(!members.contains(k["bob"].as_str().unwrap()));
        assert!(bans.blocks(&by(k["alice"].as_str().unwrap())).unwrap());

        // The link lifts the whole Community, members and all.
        let total = bans.list().unwrap().len();
        assert_eq!(unban_from(&bans, url).unwrap(), total);
        assert!(bans.list().unwrap().is_empty());
    }

    #[test]
    fn formats_dates() {
        assert_eq!(date(0), "1970-01-01");
        assert_eq!(date(1_792_454_400), "2026-10-20");
        assert_eq!(date(951_782_400), "2000-02-29");
    }
}
