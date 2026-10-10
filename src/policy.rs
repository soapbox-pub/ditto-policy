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

pub fn judge(input: &Input) -> Verdict {
    if NIP_28.contains(&input.event.kind) {
        return Verdict::Reject("blocked: public chat is not allowed".into());
    }
    Verdict::Accept
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kind(kind: u64) -> Input {
        Input {
            event: Event {
                id: "00".repeat(32),
                kind,
            },
        }
    }

    #[test]
    fn blocks_nip_28() {
        for k in 40..=44 {
            assert!(matches!(judge(&kind(k)), Verdict::Reject(_)), "kind {k}");
        }
    }

    #[test]
    fn accepts_the_rest() {
        for k in [0, 1, 3, 7, 39, 45, 1040, 10040, 30040] {
            assert_eq!(judge(&kind(k)), Verdict::Accept, "kind {k}");
        }
    }
}
