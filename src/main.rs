//! A write policy plugin for strfry and Ditto Relay: each event comes in as
//! a line of JSON on stdin, and whether to take it goes out as a line of
//! JSON on stdout.
//!
//! Ditto Relay pipelines its requests, writing a batch before reading any
//! answers, so answers are flushed whenever there's nothing more to read
//! rather than held back until stdin closes.

mod policy;

use std::io::{self, BufRead, Write};

use serde::{Deserialize, Serialize};

use policy::{Input, Verdict};

fn main() -> io::Result<()> {
    run(io::stdin().lock(), io::stdout().lock())
}

fn run(mut input: impl BufRead, mut output: impl Write) -> io::Result<()> {
    let mut line = String::new();
    loop {
        line.clear();
        if input.read_line(&mut line)? == 0 {
            return output.flush();
        }
        if let Some(answer) = answer(line.trim_end()) {
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

fn answer(line: &str) -> Option<Output> {
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
    let (action, msg) = match policy::judge(&input) {
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
        run(input.as_bytes(), &mut out).unwrap();
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
