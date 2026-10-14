//! How clients take decryption, by host, so that an application can tell
//! which hosts likely pin their certificates and should be left out:
//! handshakes the client refused, connections it closed after the
//! handshake without a request, and the requests it sent.

use std::{
    collections::HashMap,
    sync::{LazyLock, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Serialize;

/// Hosts kept; the least recent goes first.
const HOSTS: usize = 200;

#[derive(Clone, Debug, Default, Serialize)]
pub struct ClientVerdict {
    pub host: String,
    /// Handshakes the client refused (our certificate).
    pub refused: u32,
    /// Connections closed after the handshake without a request.
    pub silent: u32,
    /// Requests sent.
    pub requests: u32,
    /// When the last of these happened, in Unix milliseconds.
    pub last: u64,
}

static VERDICTS: LazyLock<Mutex<HashMap<String, ClientVerdict>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub(crate) fn note(host: &str, refused: u32, silent: u32, requests: u32) {
    let last = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);
    let mut verdicts = VERDICTS.lock().unwrap();
    if !verdicts.contains_key(host)
        && verdicts.len() >= HOSTS
        && let Some(oldest) = verdicts
            .values()
            .min_by_key(|v| v.last)
            .map(|v| v.host.clone())
    {
        verdicts.remove(&oldest);
    }
    let v = verdicts
        .entry(host.to_owned())
        .or_insert_with(|| ClientVerdict {
            host: host.to_owned(),
            ..Default::default()
        });
    v.refused += refused;
    v.silent += silent;
    v.requests += requests;
    v.last = last;
}

/// The hosts decrypted since the start or the last clearing, most recent
/// first.
pub fn client_verdicts() -> Vec<ClientVerdict> {
    let mut list: Vec<ClientVerdict> =
        VERDICTS.lock().unwrap().values().cloned().collect();
    list.sort_by(|a, b| b.last.cmp(&a.last));
    list
}

pub fn clear_client_verdicts() {
    VERDICTS.lock().unwrap().clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdicts_add_up_by_host() {
        note("pinned.verdict.test", 1, 0, 0);
        note("pinned.verdict.test", 0, 1, 0);
        note("fine.verdict.test", 0, 0, 3);
        let list = client_verdicts();
        let pinned = list
            .iter()
            .find(|v| v.host == "pinned.verdict.test")
            .unwrap();
        assert_eq!((pinned.refused, pinned.silent, pinned.requests), (1, 1, 0));
        let fine = list.iter().find(|v| v.host == "fine.verdict.test").unwrap();
        assert_eq!(fine.requests, 3);
    }
}
