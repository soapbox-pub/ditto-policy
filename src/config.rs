//! The plugin's config file, TOML, read when it starts. Without one, or
//! without a setting, it does what it did before there was one: see
//! `ditto-policy.example.toml`.
//!
//! A file rather than flags, so the relay's `write_policy_plugin` can stay a
//! bare path, which Ditto Relay restarts the plugin for when it changes.

use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::concord::bytes32;
use crate::nostr::{self, Decoded};

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub blocklist: BlocklistConfig,
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

    fn parse(text: &str) -> Result<Config> {
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
        Ok(config)
    }
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
