//! A write policy plugin for strfry and Ditto Relay: each event comes in as
//! a line of JSON on stdin, and whether to take it goes out as a line of
//! JSON on stdout.
//!
//! Ditto Relay pipelines its requests, writing a batch before reading any
//! answers, so answers are flushed whenever there's nothing more to read
//! rather than held back until stdin closes.
//!
//! Its subcommands ban Concord Communities: see [`ban`]. The plugin refuses
//! what the bans in its database cover.

mod ban;
mod bans;
mod concord;
mod fetch;
mod labels;
mod nostr;
mod policy;

use std::io::{self, BufRead, Write};
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

use bans::Bans;
use policy::{Input, Verdict};

#[derive(Parser)]
#[command(about, long_about = None)]
struct Cli {
    /// Where the bans are kept.
    #[arg(
        long,
        env = "DITTO_POLICY_DB",
        default_value = "/var/lib/ditto-policy",
        global = true
    )]
    db: PathBuf,
    /// Without one, run as the plugin.
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Ban a Concord Community, given one of its invite links.
    Ban {
        /// An invite link: …/invite/<naddr>#<fragment>.
        #[arg(required_unless_present = "list")]
        link: Option<String>,
        /// Ban everyone in the Community too, from posting anything.
        #[arg(long)]
        members: bool,
        /// Another relay to read the Community from, besides the link's and
        /// its own. Repeatable.
        #[arg(long = "relay", value_name = "URL")]
        relays: Vec<String>,
        /// Show what would be banned, and ban nothing.
        #[arg(long)]
        dry_run: bool,
        /// List the bans instead.
        #[arg(long, conflicts_with_all = ["link", "members", "relays", "dry_run"])]
        list: bool,
    },
    /// Lift bans: an invite link's or community id's Community's, members
    /// and all, or a single pubkey's.
    Unban {
        /// An invite link, community id, pubkey, or npub.
        target: String,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        None => {
            let mut plugin = Plugin {
                db: cli.db,
                bans: None,
                failed: false,
            };
            run(io::stdin().lock(), io::stdout().lock(), &mut |event| {
                plugin.banned(event)
            })?;
        }
        Some(Command::Ban { list: true, .. }) => ban::list(&cli.db)?,
        Some(Command::Ban {
            link,
            members,
            relays,
            dry_run,
            ..
        }) => ban::ban(
            &cli.db,
            &link.unwrap_or_default(),
            members,
            &relays,
            dry_run,
        )?,
        Some(Command::Unban { target }) => ban::unban(&cli.db, &target)?,
    }
    Ok(())
}

/// The plugin's hold on the bans. The database is opened once there is
/// one, so a relay started before the first ban picks it up.
struct Plugin {
    db: PathBuf,
    bans: Option<Bans>,
    failed: bool,
}

impl Plugin {
    fn banned(&mut self, event: &policy::Event) -> bool {
        if self.bans.is_none() && !self.failed && self.db.join("data.mdb").exists() {
            match Bans::open(&self.db) {
                Ok(bans) => self.bans = Some(bans),
                Err(err) => {
                    eprintln!("ditto-policy: bans not enforced: {err:#}");
                    self.failed = true;
                }
            }
        }
        let Some(bans) = &self.bans else { return false };
        bans.blocks(event).unwrap_or_else(|err| {
            eprintln!("ditto-policy: could not read the bans: {err:#}");
            false
        })
    }
}

fn run(
    mut input: impl BufRead,
    mut output: impl Write,
    banned: &mut impl FnMut(&policy::Event) -> bool,
) -> io::Result<()> {
    let mut line = String::new();
    loop {
        line.clear();
        if input.read_line(&mut line)? == 0 {
            return output.flush();
        }
        if let Some(answer) = answer(line.trim_end(), banned) {
            serde_json::to_writer(&mut output, &answer)?;
            output.write_all(b"\n")?;
        }
        if input.fill_buf()?.is_empty() {
            output.flush()?;
        }
    }
}

/// strfry's output message.
#[derive(Debug, Serialize)]
struct Output {
    id: String,
    action: &'static str,
    #[serde(skip_serializing_if = "String::is_empty")]
    msg: String,
}

fn answer(line: &str, banned: &mut impl FnMut(&policy::Event) -> bool) -> Option<Output> {
    if line.is_empty() {
        return None;
    }
    let input = match serde_json::from_str::<Input>(line) {
        Ok(input) => input,
        Err(err) => {
            eprintln!("ditto-policy: unparseable input ({err}): {line}");
            // Refused, if there's an id to refuse, rather than left to time out.
            #[derive(Deserialize)]
            struct Id {
                event: IdOnly,
            }
            #[derive(Deserialize)]
            struct IdOnly {
                id: String,
            }
            let id = serde_json::from_str::<Id>(line).ok()?.event.id;
            return Some(Output {
                id,
                action: "reject",
                msg: "error: internal error".into(),
            });
        }
    };
    let verdict = if banned(&input.event) {
        Verdict::Reject("blocked: banned by this relay's operator".into())
    } else {
        policy::judge(&input)
    };
    let (action, msg) = match verdict {
        Verdict::Accept => ("accept", String::new()),
        Verdict::Reject(msg) => ("reject", msg),
    };
    Some(Output {
        id: input.event.id,
        action,
        msg,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_lines(input: &str) -> Vec<serde_json::Value> {
        let mut out = Vec::new();
        let banned = "dd".repeat(32);
        run(input.as_bytes(), &mut out, &mut |event: &policy::Event| {
            event.pubkey == banned
        })
        .unwrap();
        String::from_utf8(out)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn request(id: &str, kind: u64) -> String {
        format!(
            r#"{{"type":"new","event":{{"id":"{id}","pubkey":"{pk}","created_at":1,"kind":{kind},"tags":[],"content":"","sig":"{sig}"}},"receivedAt":1,"sourceType":"IP4","sourceInfo":"1.2.3.4"}}"#,
            pk = "b".repeat(64),
            sig = "c".repeat(128),
        ) + "\n"
    }

    #[test]
    fn answers_each_event_by_id() {
        let a = "a".repeat(64);
        let d = "d".repeat(64);
        let out = run_lines(&(request(&a, 1) + &request(&d, 42)));
        assert_eq!(out.len(), 2);
        assert_eq!(out[0]["id"], a.as_str());
        assert_eq!(out[0]["action"], "accept");
        assert!(out[0].get("msg").is_none());
        assert_eq!(out[1]["id"], d.as_str());
        assert_eq!(out[1]["action"], "reject");
        assert_eq!(out[1]["msg"], "blocked: public chat is not allowed");
    }

    #[test]
    fn refuses_banned_pubkeys() {
        let request = request(&"a".repeat(64), 1).replace(&"b".repeat(64), &"d".repeat(64));
        let out = run_lines(&request);
        assert_eq!(out[0]["action"], "reject");
        assert_eq!(out[0]["msg"], "blocked: banned by this relay's operator");
    }

    #[test]
    fn refuses_what_it_cant_read_if_it_can() {
        let a = "a".repeat(64);
        let input = format!(
            "{{\"event\":{{\"id\":\"{a}\",\"kind\":\"one\"}}}}\nnonsense\n\n{}",
            request(&a, 1)
        );
        let out = run_lines(&input);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0]["action"], "reject");
        assert_eq!(out[0]["msg"], "error: internal error");
        assert_eq!(out[1]["action"], "accept");
    }
}
