//! Reading events from relays, for `ditto-policy ban`: a thread a relay,
//! each paging back through everything that matches.

use std::collections::BTreeMap;
use std::io;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use serde::Serialize;
use serde_json::{Value, json};
use tungstenite::client::IntoClientRequest;
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Message, WebSocket};

use crate::nostr::Event;

/// How long a relay gets to connect, and to send each message after.
const TIMEOUT: Duration = Duration::from_secs(15);
/// Events asked for a page.
const PAGE: usize = 500;
/// Pages asked for at most, from each relay.
const MAX_PAGES: usize = 200;

#[derive(Debug, Clone, Default, Serialize)]
pub struct Filter {
    pub kinds: Vec<i64>,
    pub authors: Vec<String>,
    #[serde(rename = "#d", skip_serializing_if = "Option::is_none")]
    pub d: Option<Vec<String>>,
}

impl Filter {
    /// Whether an event is one this asked for: a relay may send anything.
    fn matches(&self, event: &Event) -> bool {
        self.kinds.contains(&event.kind)
            && self.authors.contains(&event.pubkey)
            && self
                .d
                .as_ref()
                .is_none_or(|d| d.iter().any(|d| event.tag("d").unwrap_or_default() == d))
    }
}

/// Every event matching `filter` that any of `relays` has, each checked
/// against its signature. Relays that fail are reported and passed over.
pub fn query(relays: &[String], filter: &Filter) -> Vec<Event> {
    let mut relays: Vec<String> = relays
        .iter()
        .map(|relay| relay.trim_end_matches('/').to_string())
        .filter(|relay| !is_onion(relay))
        .collect();
    relays.sort();
    relays.dedup();
    if filter.authors.is_empty() {
        return Vec::new();
    }

    let (tx, rx) = mpsc::channel();
    for relay in relays {
        let (tx, filter) = (tx.clone(), filter.clone());
        thread::spawn(move || {
            let events = query_one(&relay, &filter).unwrap_or_else(|(events, error)| {
                eprintln!("{relay}: {error}");
                events
            });
            let _ = tx.send(events);
        });
    }
    drop(tx);

    let mut events = BTreeMap::new();
    for event in rx.into_iter().flatten() {
        if !events.contains_key(&event.id) && filter.matches(&event) && event.verify() {
            events.insert(event.id.clone(), event);
        }
    }
    events.into_values().collect()
}

/// What one relay has, or what it gave before failing and why.
fn query_one(url: &str, filter: &Filter) -> Result<Vec<Event>, (Vec<Event>, String)> {
    let mut socket = connect(url).map_err(|error| (Vec::new(), error))?;
    let mut events: BTreeMap<String, Event> = BTreeMap::new();
    let mut until = None;
    for page in 0..MAX_PAGES {
        let mut request = serde_json::to_value(filter).unwrap();
        request["limit"] = PAGE.into();
        if let Some(until) = until {
            request["until"] = json!(until);
        }
        let id = format!("ban{page}");
        let mut new = 0;
        let mut oldest = None;
        let result = (|| -> Result<(), String> {
            send(&mut socket, json!(["REQ", id, request]))?;
            loop {
                let message = match socket.read().map_err(|error| error.to_string())? {
                    Message::Text(text) => text,
                    Message::Close(_) => return Err("closed the connection".into()),
                    _ => continue,
                };
                let Ok(Value::Array(message)) = serde_json::from_str(message.as_str()) else {
                    continue;
                };
                match message.as_slice() {
                    [kind, sub, event] if kind == "EVENT" && *sub == id => {
                        if let Ok(event) = serde_json::from_value::<Event>(event.clone())
                            && !events.contains_key(&event.id)
                        {
                            new += 1;
                            oldest = Some(oldest.unwrap_or(i64::MAX).min(event.created_at));
                            events.insert(event.id.clone(), event);
                        }
                    }
                    [kind, sub, ..] if (kind == "EOSE" || kind == "CLOSED") && *sub == id => {
                        return send(&mut socket, json!(["CLOSE", id]));
                    }
                    _ => {}
                }
            }
        })();
        if let Err(error) = result {
            return Err((events.into_values().collect(), error));
        }
        // `until` takes in its own second, so a page with nothing new is
        // the last.
        if new == 0 {
            break;
        }
        until = oldest;
    }
    let _ = socket.close(None);
    Ok(events.into_values().collect())
}

fn send(socket: &mut WebSocket<MaybeTlsStream<TcpStream>>, message: Value) -> Result<(), String> {
    socket
        .send(Message::text(message.to_string()))
        .map_err(|error| error.to_string())
}

fn connect(url: &str) -> Result<WebSocket<MaybeTlsStream<TcpStream>>, String> {
    let request = url
        .into_client_request()
        .map_err(|error| error.to_string())?;
    let uri = request.uri();
    let host = uri.host().ok_or("no host")?;
    let port = uri.port_u16().unwrap_or(if uri.scheme_str() == Some("ws") {
        80
    } else {
        443
    });
    let stream = (host, port)
        .to_socket_addrs()
        .map_err(|error| error.to_string())?
        .find_map(|addr| TcpStream::connect_timeout(&addr, TIMEOUT).ok())
        .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut).to_string())?;
    stream
        .set_read_timeout(Some(TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(TIMEOUT)))
        .map_err(|error| error.to_string())?;
    let (socket, _) =
        tungstenite::client_tls(request, stream).map_err(|error| error.to_string())?;
    Ok(socket)
}

/// Tor isn't to hand here.
fn is_onion(url: &str) -> bool {
    url.into_client_request()
        .ok()
        .and_then(|request| request.uri().host().map(|host| host.ends_with(".onion")))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nostr::tests::{resign, sign};
    use std::net::TcpListener;

    #[test]
    fn pages_through_a_relay_and_checks_what_it_sends() {
        let alice = sign(&"11".repeat(32), 1059, &[], "one");
        let mut older = sign(&"11".repeat(32), 1059, &[], "two");
        older.created_at -= 1;
        let older = resign(&"11".repeat(32), older);
        let stranger = sign(&"22".repeat(32), 1059, &[], "not asked for");
        let mut forged = sign(&"11".repeat(32), 1059, &[], "three");
        forged.content = "tampered".into();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let served = [alice.clone(), stranger, forged];
        let server = {
            let older = older.clone();
            thread::spawn(move || {
                let mut socket = tungstenite::accept(listener.accept().unwrap().0).unwrap();
                let mut requests = Vec::new();
                while let Ok(message) = socket.read() {
                    let Message::Text(text) = message else {
                        continue;
                    };
                    let message: Value = serde_json::from_str(text.as_str()).unwrap();
                    if message[0] != "REQ" {
                        continue;
                    }
                    let sub = message[1].clone();
                    let page: Vec<&Event> = match message[2].get("until") {
                        None => served.iter().collect(),
                        Some(_) => vec![&older],
                    };
                    for event in page {
                        socket
                            .send(Message::text(json!(["EVENT", sub, event]).to_string()))
                            .unwrap();
                    }
                    socket
                        .send(Message::text(json!(["EOSE", sub]).to_string()))
                        .unwrap();
                    requests.push(message[2].clone());
                }
                requests
            })
        };

        let filter = Filter {
            kinds: vec![1059],
            authors: vec![alice.pubkey.clone()],
            d: None,
        };
        let mut ids: Vec<String> = query(&[url], &filter)
            .into_iter()
            .map(|event| event.id)
            .collect();
        ids.sort();
        let mut want = vec![alice.id.clone(), older.id.clone()];
        want.sort();
        assert_eq!(ids, want);

        let requests = server.join().unwrap();
        // The first page, the second from the oldest of it, and the third,
        // which brought nothing new.
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0]["authors"], json!([alice.pubkey]));
        assert_eq!(requests[1]["until"], json!(alice.created_at));
        assert_eq!(requests[2]["until"], json!(older.created_at));
    }
}
