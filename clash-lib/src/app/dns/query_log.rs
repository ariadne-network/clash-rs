//! The resolver's recent lookups, for the API: what was asked, the
//! answers, whether they came from the cache or which server gave them,
//! and how long it took.

use std::{
    cell::RefCell,
    collections::VecDeque,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use hickory_proto::{op, rr};
use serde::Serialize;

/// Lookups kept, oldest dropped first.
const CAPACITY: usize = 300;
/// Answers kept of a lookup.
const MAX_ANSWERS: usize = 8;

#[derive(Clone, Debug, Serialize)]
pub struct QueryRecord {
    /// When it was asked, in Unix milliseconds.
    pub at: u64,
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    /// "1.2.3.4", or the record type and data ("CNAME a.example.").
    pub answers: Vec<String>,
    /// The answers' lowest TTL, in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
    /// The server that answered (its client id); empty from the cache.
    pub server: String,
    pub cached: bool,
    pub millis: f64,
    /// The response code ("NoError", "NXDomain"…), or the error.
    pub result: String,
}

static LOG: Mutex<VecDeque<QueryRecord>> = Mutex::new(VecDeque::new());

tokio::task_local! {
    /// The client whose answer a lookup used (`batch_exchange`).
    pub(crate) static ANSWERED_BY: RefCell<Option<String>>;
}

/// Notes the client that answered, inside a lookup.
pub(crate) fn answered_by(id: String) {
    let _ = ANSWERED_BY.try_with(|s| *s.borrow_mut() = Some(id));
}

pub(crate) fn record(
    query: &op::Query,
    result: &anyhow::Result<op::Message>,
    server: String,
    cached: bool,
    started: std::time::Instant,
) {
    let (answers, ttl, result) = match result {
        Ok(m) => {
            let answers = m
                .answers
                .iter()
                .take(MAX_ANSWERS)
                .map(|r| match &r.data {
                    rr::RData::A(v4) => v4.to_string(),
                    rr::RData::AAAA(v6) => v6.to_string(),
                    data => format!("{} {data}", r.record_type()),
                })
                .collect();
            let ttl = m.answers.iter().map(|r| r.ttl).min();
            (answers, ttl, format!("{:?}", m.metadata.response_code))
        }
        Err(e) => (Vec::new(), None, e.to_string()),
    };
    let record = QueryRecord {
        at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64),
        name: query.name().to_ascii().trim_end_matches('.').to_owned(),
        kind: query.query_type().to_string(),
        answers,
        ttl,
        server,
        cached,
        millis: started.elapsed().as_secs_f64() * 1000.0,
        result,
    };
    let mut log = LOG.lock().unwrap();
    if log.len() == CAPACITY {
        log.pop_front();
    }
    log.push_back(record);
}

/// The recent lookups, newest first.
pub fn recent() -> Vec<QueryRecord> {
    LOG.lock().unwrap().iter().rev().cloned().collect()
}

pub fn clear() {
    LOG.lock().unwrap().clear();
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use hickory_proto::{op, rr};

    use super::*;

    #[tokio::test]
    async fn records_answers_and_the_server() {
        let name = rr::Name::from_str("a.example.").unwrap();
        let query = op::Query::query(name.clone(), rr::RecordType::A);
        let mut reply = op::Message::query();
        reply.add_answer(rr::Record::from_rdata(
            name.clone(),
            60,
            rr::RData::A(rr::rdata::A::new(1, 2, 3, 4)),
        ));
        reply.add_answer(rr::Record::from_rdata(
            name,
            30,
            rr::RData::CNAME(rr::rdata::CNAME(
                rr::Name::from_str("b.example.").unwrap(),
            )),
        ));
        let server = ANSWERED_BY
            .scope(Default::default(), async {
                answered_by("DoH#dns.example:443".into());
                ANSWERED_BY.with(|s| s.borrow_mut().take())
            })
            .await
            .unwrap();
        record(&query, &Ok(reply), server, false, std::time::Instant::now());
        record(
            &query,
            &Err(anyhow::anyhow!("timeout")),
            String::new(),
            false,
            std::time::Instant::now(),
        );
        // Other tests' lookups may be logged meanwhile.
        let recent: Vec<_> = recent()
            .into_iter()
            .filter(|r| r.name == "a.example")
            .collect();
        let last = &recent[1];
        assert_eq!((last.name.as_str(), last.kind.as_str()), ("a.example", "A"));
        assert_eq!(last.answers, ["1.2.3.4", "CNAME b.example."]);
        assert_eq!(
            (last.ttl, last.server.as_str()),
            (Some(30), "DoH#dns.example:443")
        );
        assert_eq!(last.result, "NoError");
        assert_eq!(recent[0].result, "timeout");
    }
}
