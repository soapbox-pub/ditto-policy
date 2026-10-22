//! Refuses events whose labels (emoji shortcodes, titles, descriptions) hold
//! a word from [`FIRST`] and one from [`SECOND`], or whose labels or
//! hashtags hold a word from [`ALONE`]. Content isn't read. Words are kept
//! as sorted SHA-256 hashes of their lowercase form.

use sha2::{Digest, Sha256};

use crate::policy::Event;

const LABELS: [&str; 8] = [
    "emoji",
    "title",
    "name",
    "about",
    "alt",
    "summary",
    "description",
    "d",
];

const FIRST: [&str; 18] = [
    "10910087de24bfcabe854fda62b5023a61fe531705043b9979fdf00f12c4c0ec",
    "14e65d98b3a1603432d20f2e1f2399ac3a767cd889409a4456bd6d6bd3447684",
    "1b3703ad4f7400a2f145e470fe0dea3ed6a0fe7954434a6f4e8d11475475810d",
    "2ad442533965a212f2506b172cf5950d0266e7a9b31d942ac5ccb098c14c1716",
    "2ec716e4dc4329cdd25b5714267892d55d4c035f82418b32226be31278cbef79",
    "393e5f17f6430ce360bef801c3e58b5876c2f963717e9a4ea8abd1a291748255",
    "586f4c7e53cf84c2ebbd4d2bf00288ec96972b129bff83bc4e8e5ff72a0ec7ff",
    "5c77d7fd8f51ed0c2a913e46326ff6d2ea2e95c8ecf1667c72eb72ccc3fc2b46",
    "67556cd0dda76ca333bc2aa39ae597067177eec967ac4f1143f644f5825feba2",
    "794b25a56df17fff2ca47b0fdbc35ba76ab6dfa562e57ed1d4df6833bfb8428d",
    "82e695c9e75f5bc67deea8c67acb1c7bce3f633d533f9785804b500206348b89",
    "99ec68fed53dd6fc0363b9734f4761298e44cdb08ca44f9897d92dbedfaacc80",
    "c0d86b61decf26d2fdbd002c534b14daeb7cff5f406ec570a2189a73e7a29823",
    "c81409883fdefbb3fffab99f37740b68280f21146319cb56caa3148ea307c7eb",
    "cb95e6357074b4b7bb6c5c59044db5ca096f70ce52ba2ac4449448b8cad9fe52",
    "d142bda3c12cdab2d45d2cf47617ec425ded55cd82b20a80d1f32089e3d4019a",
    "d3c75401b551ed8d6d0bcb2e0e0fd89fed7a3c4d4cd85a122df90f9f5dbfdbf8",
    "ddc9e669194254cef019a29d3619a2c16592e5d52e1a81e98b01bd52319149a3",
];

const SECOND: [&str; 20] = [
    "0033728f0fbc83a0f0226d91bb063540d6d0158c0bbfa1620ae5b95b10f82932",
    "0f28c4960d96647e77e7ab6d13b85bd16c7ca56f45df802cdc763a5e5c0c7863",
    "12a667c9be6ff8f665d2e9163f3b96422e8025ef238817ec8101c17a23f1a4c3",
    "1dba4b3306b4de8e5bc487aa42333ae61b1e16186ced18a3ac6bdd1623bb1d5b",
    "4140197ec7959b1c0674de1ee3c6d3f542c371276e2518427e0ad89e5c30f804",
    "4bb60e47e119588e2082815ed6c8bebd6a3536305a43ea7df6b3c927b7b638ff",
    "594810adcbee20bd1d6f8e4cee51efdf1a235691e9d08fe96ce944d7fde34fd6",
    "652742992acbaf9a5a3fbef60f7a51e853a93534fac251e375c662d6a5cd8d01",
    "6537c1117b2647b03f737d146ce8b91e644c698507cd7808c45e48f133016c46",
    "6577be77529947bf04c41fca275a6405b66698659cbb7889c0b5f97ecded21b0",
    "665cb762e3bc03d078dea6bd624f49ac355ed3389d977f6e320792111961421d",
    "6ccffa4977d4246ed9de8ad27693e9802b50d105aae43730d06f1dc840ca6df5",
    "7e85c676fd97d370e2309003a5681bc4388306979b7db04c37c6fb0672891b6a",
    "7f5a9ba14cb89dc20e9001e41ba6f98fc1d4d71752a7407bcd082d52bb63465c",
    "8c5c04391361cbf4afd74c5ed8101ea4af881c4ee3b3df1d5b3716a19b1a834d",
    "9552989330645df8d6e44af9814d287efc4afc8a1a89d58303b5d48048f776b7",
    "c2c3b68b48832afd9a4dbdd474c1b6c81c8baecdb71446f9947dac72dd0fe93d",
    "cd2eb0837c9b4c962c22d2ff8b5441b7b45805887f051d39bf133b583baf6860",
    "d92f4cf1e2d7e8129d7536dda13e3b1898da728ee64e2f9566cb7c86619bbda5",
    "e7282d82ac6c9ebf6968111f5d11bea6f9234d56952fbd615c7a14d04c3900c3",
];

const ALONE: [&str; 8] = [
    "3272065f6d7a331f8f642b2a50e2d418d75b150e97ffcd27e5acee7a64c8cb24",
    "6593198799afe0cfe2bf1c45a354af5bc7a99b1ced1e12e6d8740a63ffc75739",
    "869cc28dd25de48206a5ab275b14aef421691897269bd82483c1671ba5644d29",
    "8edb4fc92b919c7e21992b0ebe0e6acc6bdb5b8394a52f689b86d5d00c3d7b5f",
    "9e508bbc832ead5fd3ba0b99710965166f77a4413bf73b724f856d77e4858265",
    "b0195b413bb0a1e73f61c67f03a2071ec715f07dd762834e23f6c76656c22c1e",
    "c164a49dc160b0fba7ca0e569bfff1b5932160aaa8855fbb887c1e4a8a814c8d",
    "dbc9305b71fb2d8d47347cedcabf344439219480f3faeb791d0fcca1b71f7e40",
];

pub fn flagged(event: &Event) -> bool {
    matches(event, &ALONE, &FIRST, &SECOND)
}

fn matches(event: &Event, alone: &[&str], first: &[&str], second: &[&str]) -> bool {
    let listed = |list: &[&str], hash: &str| list.binary_search(&hash).is_ok();
    if words(event, &["t"]).any(|word| listed(alone, &hash(&word))) {
        return true;
    }
    let (mut a, mut b) = (false, false);
    for word in words(event, &LABELS) {
        let hash = hash(&word);
        if listed(alone, &hash) {
            return true;
        }
        a |= under_18(&word) || listed(first, &hash);
        b |= listed(second, &hash);
        if a && b {
            return true;
        }
    }
    false
}

fn hash(word: &str) -> String {
    hex::encode(Sha256::digest(word.as_bytes()))
}

fn words<'a>(event: &'a Event, names: &'a [&str]) -> impl Iterator<Item = String> + 'a {
    event
        .tags
        .iter()
        .filter(|tag| {
            tag.first()
                .is_some_and(|name| names.contains(&name.as_str()))
        })
        .filter_map(|tag| tag.get(1))
        .flat_map(|value| value.split(|c: char| !c.is_alphanumeric()))
        .filter(|word| !word.is_empty())
        .map(str::to_lowercase)
}

fn under_18(word: &str) -> bool {
    word.strip_suffix("yo")
        .filter(|n| n.len() <= 2)
        .and_then(|n| n.parse::<u8>().ok())
        .is_some_and(|age| age < 18)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flagged(tags: &[&[&str]]) -> bool {
        let (alone, a, b) = (hash("cherry"), hash("apple"), hash("banana"));
        let event = Event {
            id: "00".repeat(32),
            pubkey: "bb".repeat(32),
            kind: 30030,
            tags: tags
                .iter()
                .map(|t| t.iter().map(|s| s.to_string()).collect())
                .collect(),
            content: "apple banana cherry".into(),
        };
        matches(&event, &[&alone], &[&a], &[&b])
    }

    #[test]
    fn flags_a_pair_across_labels() {
        assert!(flagged(&[&[
            "emoji",
            "Apple_Banana",
            "https://example.com/a.png"
        ]]));
        assert!(flagged(&[&["title", "apple"], &["about", "a banana"]]));
        assert!(flagged(&[&["d", "banana-12yo"]]));
    }

    #[test]
    fn flags_a_word_alone() {
        assert!(flagged(&[&[
            "emoji",
            "cherry_1",
            "https://example.com/a.png"
        ]]));
        assert!(flagged(&[&["t", "Cherry"]]));
    }

    #[test]
    fn passes_the_rest() {
        assert!(!flagged(&[]));
        assert!(!flagged(&[&[]]));
        assert!(!flagged(&[&["title", "apple apple"]]));
        assert!(!flagged(&[&["title", "banana 18yo"]]));
        assert!(!flagged(&[&["t", "apple"], &["t", "banana"]]));
        assert!(!flagged(&[&["p", "cherry"], &["title", "cherrypie"]]));
    }

    #[test]
    fn lists_are_sorted() {
        assert!(ALONE.is_sorted() && FIRST.is_sorted() && SECOND.is_sorted());
    }
}
