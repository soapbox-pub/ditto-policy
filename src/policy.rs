//! What's let in and what isn't.

use serde::Deserialize;

/// strfry's input message. Only what the policy looks at is read.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Input {
    pub event: Event,
}

#[derive(Debug, Deserialize)]
pub struct Event {
    pub id: String,
    pub kind: u64,
    pub content: String,
}

/// What's made of an event.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    /// Refused, with what to tell the client.
    Reject(String),
}

/// NIP-28 public chat: channel creation, metadata, messages, hiding
/// messages, and muting users.
const NIP_28: std::ops::RangeInclusive<u64> = 40..=44;

/// aéPiot's domains. Its accounts post nothing but notes that hashtag every
/// word and link each phrase here, by the thousand a day from a rotating set
/// of keys, and the hashtag pages they create draw headless browsers. It
/// links through generated subdomains too, so those count.
const SPAM_DOMAINS: [&str; 4] = [
    "aepiot.com",
    "aepiot.ro",
    "allgraph.ro",
    "headlines-world.com",
];

pub fn judge(input: &Input) -> Verdict {
    if NIP_28.contains(&input.event.kind) {
        return Verdict::Reject("blocked: public chat is not allowed".into());
    }
    if names_spam_domain(&input.event.content) {
        return Verdict::Reject("blocked: links to aéPiot are not allowed".into());
    }
    Verdict::Accept
}

/// Whether `text` names a spam domain or a subdomain of one, as a whole
/// hostname: `x.aepiot.com` does, `notaepiot.com` doesn't.
fn names_spam_domain(text: &str) -> bool {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '-'))
        .map(|host| host.trim_end_matches('.').to_ascii_lowercase())
        .any(|host| {
            SPAM_DOMAINS.iter().any(|domain| {
                host.strip_suffix(domain)
                    .is_some_and(|rest| rest.is_empty() || rest.ends_with('.'))
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(kind: u64, content: &str) -> Input {
        Input {
            event: Event {
                id: "00".repeat(32),
                kind,
                content: content.into(),
            },
        }
    }

    #[test]
    fn blocks_nip_28() {
        for k in 40..=44 {
            assert!(
                matches!(judge(&event(k, "")), Verdict::Reject(_)),
                "kind {k}"
            );
        }
    }

    #[test]
    fn accepts_the_rest() {
        for k in [0, 1, 3, 7, 39, 45, 1040, 10040, 30040] {
            assert_eq!(judge(&event(k, "")), Verdict::Accept, "kind {k}");
        }
    }

    #[test]
    fn blocks_aepiot_links() {
        for content in [
            "#LOWELL #BAILEY\nhttps://aepiot.com/related-search.html?reports=LOWELL%20BAILEY",
            "https://headlines-world.com/?q=DILMA%20ROUSSEFF",
            "see https://allgraph.ro.",
            "HTTPS://AEPIOT.RO/search.html?lang=es",
            "https://2026-18-10-24-57-59-06xdf6I6.aepiot.com/backlink.html",
            r#"{"name":"aéPiot","website":"https://aepiot.com"}"#,
        ] {
            assert!(
                matches!(judge(&event(1, content)), Verdict::Reject(_)),
                "{content}"
            );
        }
    }

    #[test]
    fn accepts_lookalikes() {
        for content in [
            "https://notaepiot.com/",
            "https://aepiot.com.example.org/",
            "https://example.com/?u=aepiot-com",
            "allgraph.romania",
        ] {
            assert_eq!(judge(&event(1, content)), Verdict::Accept, "{content}");
        }
    }
}
