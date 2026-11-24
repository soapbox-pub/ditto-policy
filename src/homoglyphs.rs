//! Refuses text written in disguise: Latin words with letters from other
//! alphabets swapped in that look the same, as in `FrᎬe cryРto hЕre`, so
//! word filters, searches and similarity checks miss them.
//!
//! People do it too, a word or two at a time, to get past other sites'
//! filters (`kіІІеd`), and decorate names and captions with it, so it takes
//! a text that's mostly Latin, with at least [`MIN_WORDS`] disguised words
//! making up at least [`MIN_SHARE`] of its words, URLs aside. A disguised
//! word has a lowercase Latin letter: all-caps stylings (`ΤΗΞ LΛЅΤ ΤRΛΙΝ`)
//! and Cyrillic words with a Latin capital (`ПольшаU`) aren't counted.
//! Profiles aren't judged, since fancy-lettered names are common there.

/// What's judged: text notes, comments, and long-form articles.
const KINDS: [u64; 3] = [1, 1111, 30023];
const MIN_WORDS: usize = 2;
/// The share of words, as a fraction, that must be disguised.
const MIN_SHARE: (usize, usize) = (2, 5);

pub fn disguised(kind: u64, text: &str) -> bool {
    if !KINDS.contains(&kind) {
        return false;
    }
    let mut latin = 0;
    let mut other = 0;
    let mut words = 0;
    let mut disguised = 0;
    for word in text
        .split_whitespace()
        .filter(|token| !token.contains("://") && !token.starts_with("nostr:"))
        .flat_map(|token| token.split(|c: char| !(c.is_alphabetic() || c == '\'' || c == '’')))
    {
        for c in word.chars().filter(|c| c.is_alphabetic()) {
            if c.is_ascii() {
                latin += 1;
            } else {
                other += 1;
            }
        }
        if word.chars().any(|c| c.is_ascii_alphabetic()) {
            words += 1;
            if word.chars().any(|c| c.is_ascii_lowercase()) && word.chars().any(is_lookalike) {
                disguised += 1;
            }
        }
    }
    latin >= other && disguised >= MIN_WORDS && disguised * MIN_SHARE.1 >= words * MIN_SHARE.0
}

/// Whether `c`, not being Latin, looks like a Latin letter. Every Cherokee
/// letter counts: its syllabary borrowed Latin shapes.
fn is_lookalike(c: char) -> bool {
    matches!(c,
        // Cyrillic
        'А' | 'В' | 'Е' | 'К' | 'М' | 'Н' | 'О' | 'Р' | 'С' | 'Т' | 'Х' | 'Ѕ' | 'І' | 'Ј' | 'Ү'
        | 'Ԛ' | 'Ԝ' | 'Ӏ' | 'а' | 'е' | 'о' | 'р' | 'с' | 'у' | 'х' | 'ѕ' | 'і' | 'ј' | 'ԁ'
        | 'ԛ' | 'ԝ' | 'һ' | 'ӏ'
        // Greek
        | 'Α' | 'Β' | 'Ε' | 'Ζ' | 'Η' | 'Ι' | 'Κ' | 'Μ' | 'Ν' | 'Ο' | 'Ρ' | 'Τ' | 'Υ' | 'Χ'
        | 'ο' | 'ν'
        // Armenian
        | 'Օ' | 'օ' | 'ս' | 'հ' | 'ո'
        // Cherokee, and its lowercase
        | '\u{13A0}'..='\u{13F5}' | '\u{AB70}'..='\u{ABBF}'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_disguised_text() {
        for text in [
            "💰 FrᎬe cryРto hЕre: https://one.evmverse.cc/?ref=msiv42\n⚡️ ᎻurrΥ uᏢ!",
            "🚨 1 ETH claim now: https://one.evmverse.cc/?ref=qswqib\n🪂 AirdrОР seАЅΟn iᏚ hЕrЕ.",
            "🔥 DОn'Т Мiss 1 EᎢН: https://one.evmverse.cc/?ref=vklctj\n🪂 AirdrОp ЅЕaЅΟn iᏚ hᎬre.",
            "Ꮯlaim yoսr օwn tokens",
        ] {
            assert!(disguised(1, text), "{text}");
        }
    }

    #[test]
    fn lets_other_writing_through() {
        for text in [
            "gm",
            "Привет, как дела? I'm fine, спасибо.",
            "Ελληνικά και English μαζί, ΟΚ",
            "ᏣᎳᎩ ᎦᏬᏂᎯᏍᏗ is written in Cherokee",
            "Հայերեն and English",
            "10 μg of caffeine in 5 μs",
            "Grüße aus Köln, ça va? Ñandú, Łódź, ǅemal",
            "𝐅𝐫𝐞𝐞 fancy letters",
            // A few words disguised against other sites' filters.
            "72 people were kіІІеd in a russian аttack on Komyshuvakha, in the Zaporizhzhia region.",
            "russiа is committing gеnocіde in Ukraine.",
            // All-caps stylings.
            "ΤΗΞ LΛЅΤ ΤRΛΙΝ ΗΛD ΛLЯΞΛDΥ LΞҒΤ.\nhttps://example.com/a.jpg",
            // Cyrillic, with Latin slips.
            "Польша U20 – Германия U20: прогноз на матч",
            "Типаodu, сегодня в Одессе погода такая: сunny, как моя улыбка",
        ] {
            assert!(!disguised(1, text), "{text}");
        }
    }

    #[test]
    fn judges_only_writing() {
        let name = r#"{"name":"ѕнαу тнє fαитαвℓισυѕ","about":"FrᎬe cryРto hЕre"}"#;
        assert!(!disguised(0, name));
        assert!(disguised(1111, "FrᎬe cryРto hЕre"));
        assert!(disguised(30023, "FrᎬe cryРto hЕre"));
    }
}
