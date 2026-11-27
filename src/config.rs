//! The plugin's config file, TOML, read when it starts. Without one, or
//! without a setting, it does what it did before there was one: see
//! `ditto-policy.example.toml`.
//!
//! A file rather than flags, so the relay's `write_policy_plugin` can stay a
//! bare path, which Ditto Relay restarts the plugin for when it changes.
//!
//! The spam domains are read again whenever the file changes (see
//! [`Watched`]), so a new one is refused within seconds of being added,
//! without restarting anything. The rest is read once, at the start.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::concord::bytes32;
use crate::nostr::{self, Decoded};

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub blocklist: BlocklistConfig,
    pub spam: SpamConfig,
}

/// Spam that's refused by what it says.
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SpamConfig {
    /// Domains that only spam links to, refused in any event's content.
    /// Subdomains count. Read lowercase, without a leading `*.` or `.`.
    pub domains: Vec<String>,
}

/// Applying Armada's blocklist: see [`crate::blocklist`].
#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BlocklistConfig {
    /// The moderation keys whose entries count, hex or npub. None, and the
    /// blocklist isn't applied.
    pub authors: Vec<String>,
    /// Relays to read entries from as the plugin starts, and every
    /// `refresh_minutes` after. Entries published here are seen as they
    /// arrive whatever this says.
    pub relays: Vec<String>,
    pub refresh_minutes: u64,
    /// Run with a filter naming a banned user's pubkey appended, to delete
    /// what they stored. Empty doesn't delete.
    pub delete_command: Vec<String>,
}

impl Default for BlocklistConfig {
    fn default() -> Self {
        BlocklistConfig {
            authors: Vec::new(),
            relays: Vec::new(),
            refresh_minutes: 30,
            delete_command: ["ditto-relay", "delete", "--filter"]
                .map(String::from)
                .to_vec(),
        }
    }
}

impl Config {
    /// The config at `path`, or the defaults if there's no file there.
    pub fn load(path: &Path) -> Result<Config> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Config::default());
            }
            Err(error) => {
                return Err(error).with_context(|| format!("Could not read {}", path.display()));
            }
        };
        Config::parse(&text).with_context(|| format!("In {}", path.display()))
    }

    pub(crate) fn parse(text: &str) -> Result<Config> {
        let mut config: Config = toml::from_str(text)?;
        let mut authors = Vec::new();
        for author in &config.blocklist.authors {
            let hex = match nostr::nip19_decode(author.trim()) {
                Some(Decoded::Npub(pubkey)) => pubkey,
                _ => author.trim().to_lowercase(),
            };
            if bytes32(&hex).is_none() {
                bail!("blocklist.authors: not a pubkey or npub: {author}");
            }
            authors.push(hex);
        }
        config.blocklist.authors = authors;
        let mut domains = Vec::new();
        for domain in &config.spam.domains {
            let name = domain
                .trim()
                .trim_start_matches("*.")
                .trim_start_matches('.')
                .trim_end_matches('.')
                .to_ascii_lowercase();
            if name.is_empty()
                || !name.contains('.')
                || !name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
            {
                bail!("spam.domains: not a domain: {domain:?}");
            }
            domains.push(name);
        }
        config.spam.domains = domains;
        Ok(config)
    }
}

/// How often [`Watched::refresh`] looks at the file.
const CHECK_EVERY: Duration = Duration::from_secs(5);

/// The config, read again when its file changes.
pub struct Watched {
    path: PathBuf,
    modified: Option<SystemTime>,
    checked: Instant,
    pub config: Config,
}

impl Watched {
    /// The config at `path`. A bad one is reported, and the defaults used.
    pub fn load(path: &Path) -> Watched {
        let modified = modified(path);
        let config = Config::load(path).unwrap_or_else(|err| {
            eprintln!("ditto-policy: config not applied: {err:#}");
            Config::default()
        });
        Watched {
            path: path.to_owned(),
            modified,
            checked: Instant::now(),
            config,
        }
    }

    /// Read the file again if it has changed since it was last read, and
    /// it's been [`CHECK_EVERY`] since the last look. Only the spam domains
    /// are taken from it. A bad file is reported, and what was read before
    /// is kept.
    pub fn refresh(&mut self) {
        if self.checked.elapsed() < CHECK_EVERY {
            return;
        }
        self.checked = Instant::now();
        let modified = modified(&self.path);
        if modified == self.modified {
            return;
        }
        self.modified = modified;
        match Config::load(&self.path) {
            Ok(config) => {
                eprintln!(
                    "ditto-policy: {} changed: {} spam domains",
                    self.path.display(),
                    config.spam.domains.len()
                );
                self.config.spam = config.spam;
            }
            Err(err) => eprintln!("ditto-policy: config change not applied: {err:#}"),
        }
    }

    #[cfg(test)]
    fn check_now(&mut self) {
        self.checked -= CHECK_EVERY;
    }
}

/// When the file at `path` was last changed, if it's there.
fn modified(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_off() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config::load(&dir.path().join("missing.toml")).unwrap();
        assert!(config.blocklist.authors.is_empty());
        assert_eq!(config.blocklist.refresh_minutes, 30);
    }

    #[test]
    fn reads_spam_domains() {
        let config = Config::parse(
            r#"
            [spam]
            domains = ["Evmverse.CC", "*.solhub.cc", ".gweiportal.top."]
            "#,
        )
        .unwrap();
        assert_eq!(
            config.spam.domains,
            ["evmverse.cc", "solhub.cc", "gweiportal.top"]
        );
        for bad in ["", "localhost", "https://evmverse.cc/", "evm verse.cc"] {
            assert!(
                Config::parse(&format!("[spam]\ndomains = [{bad:?}]")).is_err(),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn rereads_spam_domains_when_the_file_changes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ditto-policy.toml");
        std::fs::write(&path, "[spam]\ndomains = [\"evmverse.cc\"]\n").unwrap();
        let mut watched = Watched::load(&path);
        assert_eq!(watched.config.spam.domains, ["evmverse.cc"]);

        let write = |text: &str, age: u64| {
            std::fs::write(&path, text).unwrap();
            // Set a time apart from the last write's, which may share its tick.
            let time = SystemTime::now() - Duration::from_secs(age);
            std::fs::File::options()
                .write(true)
                .open(&path)
                .unwrap()
                .set_modified(time)
                .unwrap();
        };
        write("[spam]\ndomains = [\"evmverse.cc\", \"solhub.cc\"]\n", 60);
        watched.refresh();
        assert_eq!(watched.config.spam.domains.len(), 1, "not looked at yet");
        watched.check_now();
        watched.refresh();
        assert_eq!(watched.config.spam.domains, ["evmverse.cc", "solhub.cc"]);

        write("[spam]\ndomains = [\"not a domain\"]\n", 30);
        watched.check_now();
        watched.refresh();
        assert_eq!(
            watched.config.spam.domains,
            ["evmverse.cc", "solhub.cc"],
            "a bad file keeps what was read"
        );
    }

    #[test]
    fn reads_authors_as_hex_or_npub() {
        let config = Config::parse(
            r#"
            [blocklist]
            authors = ["npub1ph0kcd0kr6cyqvtdq8mgmm2d8z6hnst5y0fxw90afzgst2vpjy9qfz24jj", "AA"]
            "#,
        );
        assert!(config.is_err(), "AA isn't a pubkey");
        let config = Config::parse(
            r#"
            [blocklist]
            authors = ["npub1ph0kcd0kr6cyqvtdq8mgmm2d8z6hnst5y0fxw90afzgst2vpjy9qfz24jj"]
            relays = ["ws://127.0.0.1:13131"]
            delete_command = []
            "#,
        )
        .unwrap();
        assert_eq!(
            config.blocklist.authors,
            ["0ddf6c35f61eb040316d01f68ded4d38b579c17423d26715fd489105a981910a"]
        );
        assert!(config.blocklist.delete_command.is_empty());
        assert!(
            Config::parse("[blocklist]\nauthor = []").is_err(),
            "a typo is caught"
        );
    }
}
