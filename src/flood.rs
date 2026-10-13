//! Floods of root kind 1 notes from many accounts at once, ported from the
//! OpenSearch-backed Ditto relay.
//!
//! A note's features are the pubkeys it mentions (`p` tags, `nostr:npub` and
//! `nostr:nprofile`) and the links it has (`r` tags and URLs in its content,
//! as lowercase host and path). Prose and hashtags don't count. Within the
//! window, a note is a flood when:
//!
//! - [`Rule::Similar`]: enough other pubkeys posted a note sharing at least
//!   half its features (Jaccard similarity), or
//! - [`Rule::Mentions`]: a pubkey it mentions was mentioned by enough other
//!   pubkeys, which catches campaigns that rotate their targets.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::LazyLock;

use regex::{Captures, Regex};

use crate::policy::Event;

/// Which rule took a note for a flood.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rule {
    Similar,
    Mentions,
}

impl Rule {
    /// Why the note is refused, as the old relay said it.
    pub fn reason(self) -> &'static str {
        match self {
            Rule::Similar => "note matches a flood of similar notes from other accounts",
            Rule::Mentions => "note mentions an account being flooded by other accounts",
        }
    }
}

/// How a [`Detector`] judges. `0` turns a rule off.
#[derive(Clone, Debug)]
pub struct Options {
    /// Other authors with a similar note needed to flag one.
    pub similar_authors: usize,
    /// Other authors mentioning the same pubkey needed to flag a note.
    pub mention_authors: usize,
    pub window_ms: u64,
    pub min_similarity: f64,
    /// Notes with fewer features aren't judged by [`Rule::Similar`].
    pub min_features: usize,
    /// The newest notes kept per feature, which bounds the work per note.
    pub max_postings: usize,
    pub max_entries: usize,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            similar_authors: 3,
            mention_authors: 10,
            window_ms: 10 * 60_000,
            min_similarity: 0.5,
            min_features: 2,
            max_postings: 256,
            max_entries: 20_000,
        }
    }
}

const MAX_FEATURES: usize = 32;
/// Tags and content matches looked at per note.
const MAX_CANDIDATES: usize = 128;
/// Postings visited per check, newest first.
const MAX_SCAN: usize = 2048;

static HEX64: LazyLock<Regex> = LazyLock::new(|| Regex::new("^[0-9a-f]{64}$").unwrap());
static MENTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("nostr:(npub1[02-9ac-hj-np-z]+|nprofile1[02-9ac-hj-np-z]+)").unwrap()
});
/// A URL's host (group 1) and path (group 2).
const URL: &str = r#"(?:https?|wss?)://([^\s<>"'`)\]/?#]+)([^\s<>"'`)\]?#]*)"#;
static CONTENT_URL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&format!(r"(?i)(?-u:\b){URL}")).unwrap());
static R_TAG_URL: LazyLock<Regex> = LazyLock::new(|| Regex::new(&format!("(?i)^{URL}")).unwrap());

/// Whether the event is a root kind 1 note, the only kind judged.
pub fn is_candidate(event: &Event) -> bool {
    event.kind == 1
        && !event
            .tags
            .iter()
            .any(|tag| tag.first().is_some_and(|name| name == "e" || name == "q"))
}

fn url_feature(captures: &Captures) -> String {
    let url = format!("{}{}", &captures[1], &captures[2]).to_lowercase();
    format!("u:{}", url.trim_end_matches('/'))
}

/// The pubkey a `nostr:npub` or `nostr:nprofile` names.
fn mentioned_pubkey(bech32: &str) -> Option<String> {
    let (hrp, data) = bech32::decode(bech32).ok()?;
    let pubkey = match hrp.as_str() {
        "npub" => data.get(..32).filter(|_| data.len() == 32)?,
        // TLV, of which type 0 is the pubkey.
        "nprofile" => {
            let mut rest = data.as_slice();
            loop {
                let [kind, len, tail @ ..] = rest else {
                    return None;
                };
                let value = tail.get(..usize::from(*len))?;
                if *kind == 0 && value.len() == 32 {
                    break value;
                }
                rest = &tail[value.len()..];
            }
        }
        _ => return None,
    };
    Some(pubkey.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// A note's features, at most [`MAX_FEATURES`] of them from at most
/// [`MAX_CANDIDATES`] tags and matches.
pub fn features(event: &Event) -> HashSet<String> {
    let mut features = HashSet::new();
    let mut budget = MAX_CANDIDATES;
    let mut full = |features: &HashSet<String>| {
        if features.len() >= MAX_FEATURES || budget == 0 {
            return true;
        }
        budget -= 1;
        false
    };

    for tag in &event.tags {
        let (Some(name), Some(value)) = (tag.first(), tag.get(1)) else {
            continue;
        };
        if name != "p" && name != "r" {
            continue;
        }
        if full(&features) {
            return features;
        }
        if name == "p" {
            if HEX64.is_match(value) {
                features.insert(format!("p:{value}"));
            }
        } else if let Some(captures) = R_TAG_URL.captures(value) {
            features.insert(url_feature(&captures));
        }
    }
    for captures in MENTION.captures_iter(&event.content) {
        if full(&features) {
            return features;
        }
        if let Some(pubkey) = mentioned_pubkey(&captures[1]) {
            features.insert(format!("p:{pubkey}"));
        }
    }
    for captures in CONTENT_URL.captures_iter(&event.content) {
        if full(&features) {
            return features;
        }
        features.insert(url_feature(&captures));
    }
    features
}

/// FNV-1a. Features are kept hashed: as strings they'd take many times the
/// memory at the entry cap.
fn hash(feature: &str) -> u64 {
    feature.bytes().fold(0xcbf2_9ce4_8422_2325, |h, byte| {
        (h ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
    })
}

struct Entry {
    id: String,
    pubkey: String,
    features: Vec<u64>,
    at: u64,
    flood: Option<Rule>,
}

/// The notes of the last window, for judging the next.
pub struct Detector {
    options: Options,
    /// Oldest first. The front's sequence number is `first`.
    entries: VecDeque<Entry>,
    first: u64,
    by_id: HashMap<String, u64>,
    /// Feature hash to the sequence numbers of the notes with it, oldest
    /// first.
    postings: HashMap<u64, VecDeque<u64>>,
}

impl Detector {
    pub fn new(options: Options) -> Self {
        Detector {
            options,
            entries: VecDeque::new(),
            first: 0,
            by_id: HashMap::new(),
            postings: HashMap::new(),
        }
    }

    /// How many notes are remembered.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    fn entry(&self, seq: u64) -> Option<&Entry> {
        self.entries
            .get(usize::try_from(seq.checked_sub(self.first)?).ok()?)
    }

    /// Remember a note, received at `now` in milliseconds, and say which
    /// rule takes it for a flood, if any. A note seen before gets the same
    /// answer as the first time.
    pub fn check(&mut self, event: &Event, now: u64) -> Option<Rule> {
        if !is_candidate(event) {
            return None;
        }
        self.expire(now.saturating_sub(self.options.window_ms));
        if let Some(&seq) = self.by_id.get(&event.id) {
            return self.entry(seq).and_then(|entry| entry.flood);
        }

        let mut names = features(event);
        names.remove(&format!("p:{}", event.pubkey));
        let mut features = Vec::with_capacity(names.len());
        let mut mentions = Vec::new();
        for name in &names {
            let hash = hash(name);
            features.push(hash);
            if name.starts_with("p:") {
                mentions.push(hash);
            }
        }
        let similar = features.len() >= self.options.min_features;
        // A note mentioning just one pubkey still counts toward Mentions.
        if !similar && mentions.is_empty() {
            return None;
        }

        let flood = if self.options.mention_authors > 0 && self.mentioned(&event.pubkey, &mentions)
        {
            Some(Rule::Mentions)
        } else if self.options.similar_authors > 0
            && similar
            && self.similar(&event.pubkey, &features)
        {
            Some(Rule::Similar)
        } else {
            None
        };
        self.record(Entry {
            id: event.id.clone(),
            pubkey: event.pubkey.clone(),
            features,
            at: now,
            flood,
        });
        flood
    }

    /// Whether a mention was already mentioned by enough other authors.
    fn mentioned(&self, pubkey: &str, mentions: &[u64]) -> bool {
        let mut scan = MAX_SCAN;
        for mention in mentions {
            let Some(list) = self.postings.get(mention) else {
                continue;
            };
            if list.len() < self.options.mention_authors {
                continue;
            }
            let mut authors = HashSet::new();
            for &seq in list.iter().rev() {
                if scan == 0 {
                    break;
                }
                scan -= 1;
                let Some(other) = self.entry(seq) else {
                    continue;
                };
                if other.pubkey == pubkey {
                    continue;
                }
                authors.insert(other.pubkey.as_str());
                if authors.len() >= self.options.mention_authors {
                    return true;
                }
            }
        }
        false
    }

    /// Whether enough other authors posted a note similar enough.
    fn similar(&self, pubkey: &str, features: &[u64]) -> bool {
        let mut overlap: HashMap<u64, usize> = HashMap::new();
        let mut scan = MAX_SCAN;
        for feature in features {
            let Some(list) = self.postings.get(feature) else {
                continue;
            };
            for &seq in list.iter().rev() {
                if scan == 0 {
                    break;
                }
                scan -= 1;
                let Some(other) = self.entry(seq) else {
                    continue;
                };
                if other.pubkey == pubkey || other.features.len() < self.options.min_features {
                    continue;
                }
                *overlap.entry(seq).or_default() += 1;
            }
        }

        let mut authors = HashSet::new();
        for (seq, shared) in overlap {
            let Some(other) = self.entry(seq) else {
                continue;
            };
            let union = features.len() + other.features.len() - shared;
            if (shared as f64) / (union as f64) < self.options.min_similarity {
                continue;
            }
            authors.insert(other.pubkey.as_str());
            if authors.len() >= self.options.similar_authors {
                return true;
            }
        }
        false
    }

    fn record(&mut self, entry: Entry) {
        let seq = self.first + self.entries.len() as u64;
        self.by_id.insert(entry.id.clone(), seq);
        for feature in &entry.features {
            let list = self.postings.entry(*feature).or_default();
            list.push_back(seq);
            if list.len() > self.options.max_postings {
                list.pop_front();
            }
        }
        self.entries.push_back(entry);
        if self.entries.len() > self.options.max_entries {
            self.evict();
        }
    }

    fn expire(&mut self, cutoff: u64) {
        while self
            .entries
            .front()
            .is_some_and(|oldest| oldest.at < cutoff)
        {
            self.evict();
        }
    }

    /// Forget the oldest note, which heads each postings list it's still in.
    fn evict(&mut self) {
        let Some(entry) = self.entries.pop_front() else {
            return;
        };
        let seq = self.first;
        self.first += 1;
        self.by_id.remove(&entry.id);
        for feature in &entry.features {
            let Some(list) = self.postings.get_mut(feature) else {
                continue;
            };
            if list.front() == Some(&seq) {
                list.pop_front();
            }
            if list.is_empty() {
                self.postings.remove(feature);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const D: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    const E: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

    thread_local!(static COUNTER: Cell<u64> = const { Cell::new(0) });

    fn next() -> u64 {
        COUNTER.with(|c| {
            c.set(c.get() + 1);
            c.get()
        })
    }

    fn note(pubkey: Option<&str>, tags: &[&[&str]], content: &str) -> Event {
        let n = next();
        Event {
            id: format!("{n:064x}"),
            pubkey: pubkey.map_or_else(|| format!("{n:f>64x}"), str::to_string),
            created_at: 0,
            kind: 1,
            tags: tags
                .iter()
                .map(|tag| tag.iter().map(|s| s.to_string()).collect())
                .collect(),
            content: content.into(),
        }
    }

    fn mentioning(pubkeys: &[&str]) -> Event {
        let tags: Vec<[&str; 2]> = pubkeys.iter().map(|pk| ["p", *pk]).collect();
        let tags: Vec<&[&str]> = tags.iter().map(|tag| tag.as_slice()).collect();
        note(None, &tags, "")
    }

    fn npub(hex: &str) -> String {
        let bytes: Vec<u8> = (0..32)
            .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
            .collect();
        bech32::encode::<bech32::Bech32>(bech32::Hrp::parse("npub").unwrap(), &bytes).unwrap()
    }

    fn nprofile(hex: &str, relay: &str) -> String {
        let mut tlv = vec![0, 32];
        tlv.extend((0..32).map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap()));
        tlv.extend([1, relay.len() as u8]);
        tlv.extend(relay.bytes());
        bech32::encode::<bech32::Bech32>(bech32::Hrp::parse("nprofile").unwrap(), &tlv).unwrap()
    }

    /// A campaign note: a fixed skeleton, gibberish of its own, and a new
    /// author unless one's given.
    fn campaign(pubkey: Option<&str>) -> Event {
        let content = format!(
            "{:x} nostr:{} wss://relay.example.com",
            next() * 7919,
            npub(C)
        );
        note(
            pubkey,
            &[&["r", "https://www.reddit.com/"], &["p", A], &["p", B]],
            &content,
        )
    }

    fn detector(similar_authors: usize, mention_authors: usize) -> Detector {
        Detector::new(Options {
            similar_authors,
            mention_authors,
            ..Options::default()
        })
    }

    fn sorted(set: HashSet<String>) -> Vec<String> {
        let mut v: Vec<_> = set.into_iter().collect();
        v.sort();
        v
    }

    #[test]
    fn judges_root_notes_only() {
        assert!(is_candidate(&note(None, &[&["p", A]], "")));
        assert!(!is_candidate(&note(None, &[&["e", A]], "")));
        assert!(!is_candidate(&note(None, &[&["q", A]], "")));
        let mut comment = note(None, &[], "");
        comment.kind = 1111;
        assert!(!is_candidate(&comment));
    }

    #[test]
    fn merges_p_tags_with_npub_and_nprofile_mentions() {
        let content = format!(
            "hi nostr:{} and nostr:{}",
            npub(A),
            nprofile(B, "wss://x.com")
        );
        let ev = note(None, &[&["p", A]], &content);
        assert_eq!(sorted(features(&ev)), [format!("p:{A}"), format!("p:{B}")]);
    }

    #[test]
    fn normalizes_links_to_host_and_path() {
        let ev = note(
            None,
            &[&["r", "https://www.Reddit.com/"]],
            "see https://example.com/a/b/?utm=1#x and wss://relay.ditto.pub",
        );
        assert_eq!(
            sorted(features(&ev)),
            ["u:example.com/a/b", "u:relay.ditto.pub", "u:www.reddit.com"]
        );
    }

    #[test]
    fn ignores_hashtags_references_and_malformed_p_tags() {
        let ev = note(
            None,
            &[&["t", "nostr"], &["a", "30023:x:y"], &["p", "not-hex"]],
            "plain words",
        );
        assert!(features(&ev).is_empty());
    }

    #[test]
    fn flags_a_skeleton_enough_other_authors_posted() {
        let mut d = detector(3, 0);
        for _ in 0..3 {
            assert_eq!(d.check(&campaign(None), 0), None);
        }
        assert_eq!(d.check(&campaign(None), 0), Some(Rule::Similar));
        assert_eq!(d.check(&campaign(None), 0), Some(Rule::Similar));
    }

    #[test]
    fn doesnt_count_the_notes_own_author() {
        let mut d = detector(2, 2);
        for _ in 0..10 {
            assert_eq!(d.check(&campaign(Some(D)), 0), None);
        }
    }

    #[test]
    fn ignores_notes_with_no_mention_and_too_few_features() {
        let mut d = detector(1, 1);
        for _ in 0..5 {
            assert_eq!(
                d.check(&note(None, &[], "gm https://example.com/x"), 0),
                None
            );
        }
        assert_eq!(d.len(), 0);
    }

    #[test]
    fn needs_similarity_at_the_threshold() {
        let mut d = detector(1, 0);
        d.check(&mentioning(&[A, B, C]), 0);
        // 1 shared of 5.
        assert_eq!(d.check(&mentioning(&[A, D, E]), 0), None);
        // 2 shared of 4.
        assert_eq!(d.check(&mentioning(&[A, B, D]), 0), Some(Rule::Similar));
    }

    #[test]
    fn flags_a_target_enough_other_authors_mention() {
        let mut d = detector(0, 3);
        // Targets rotate, so no two notes are alike; only A repeats.
        let rotating = || {
            let other = format!("{:064x}", next() * 104_729);
            mentioning(&[A, &other])
        };
        for _ in 0..3 {
            assert_eq!(d.check(&rotating(), 0), None);
        }
        assert_eq!(d.check(&rotating(), 0), Some(Rule::Mentions));
    }

    #[test]
    fn counts_single_mentions_toward_mention_floods() {
        let mut d = detector(3, 2);
        assert_eq!(d.check(&mentioning(&[A]), 0), None);
        assert_eq!(d.check(&mentioning(&[A]), 0), None);
        assert_eq!(d.check(&mentioning(&[A]), 0), Some(Rule::Mentions));
    }

    #[test]
    fn ignores_self_mentions() {
        let mut d = detector(0, 1);
        d.check(&note(Some(A), &[&["p", A]], ""), 0);
        assert_eq!(d.check(&note(Some(B), &[&["p", B]], ""), 0), None);
    }

    #[test]
    fn forgets_notes_that_age_out() {
        let mut d = detector(2, 2);
        d.check(&campaign(None), 0);
        d.check(&campaign(None), 0);
        assert_eq!(d.check(&campaign(None), 10 * 60_000 + 1), None);
        assert_eq!(d.len(), 1);
    }

    #[test]
    fn answers_a_resubmitted_note_the_same() {
        let mut d = detector(1, 0);
        let first = campaign(None);
        assert_eq!(d.check(&first, 0), None);
        assert_eq!(d.check(&first, 0), None);
        let second = campaign(None);
        assert_eq!(d.check(&second, 0), Some(Rule::Similar));
        assert_eq!(d.check(&second, 0), Some(Rule::Similar));
        assert_eq!(d.len(), 2);
    }

    #[test]
    fn never_remembers_replies() {
        let mut d = detector(1, 1);
        for _ in 0..5 {
            assert_eq!(
                d.check(&note(None, &[&["e", A], &["p", B], &["p", C]], ""), 0),
                None
            );
        }
        assert_eq!(d.len(), 0);
    }

    #[test]
    fn caps_memory() {
        let mut d = Detector::new(Options {
            max_entries: 10,
            ..Options::default()
        });
        for _ in 0..50 {
            d.check(&campaign(None), 0);
        }
        assert_eq!(d.len(), 10);
    }
}
