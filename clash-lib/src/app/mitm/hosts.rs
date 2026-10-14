//! Which hosts a set of URL patterns may apply to, for decrypting only the
//! hosts something uses (`only-used-hosts`). A pattern bound to one
//! literal host (`rewrite::bound_host`) applies to that host. The other
//! patterns anchored at the URL's start run as one lazy DFA: a host is
//! used when, after `https://host/`, a pattern can still match. A pattern
//! not anchored, or one the DFA cannot take (look-around), may apply to
//! any host. Answers are kept by host.
//!
//! For this, a "." (and "\S") between the scheme and the first "/" of a
//! pattern stands for any character but "/": `^https?:\/\/.+\.ads\.cn\/`
//! is written for hosts ending in .ads.cn, though as written it also
//! matches `https://a.test/x.ads.cn/`. Rewrites still match as written.

use std::{
    collections::{HashMap, HashSet},
    sync::Mutex,
};

use regex_automata::{
    Anchored, Input,
    hybrid::dfa::{Cache, DFA},
    util::syntax,
};

use super::rewrite::bound_host;

/// Hosts' answers kept; the list starts over past it.
const KEPT: usize = 4096;

pub struct PatternHosts {
    bound: HashSet<String>,
    unbound: Option<(DFA, Mutex<Cache>)>,
    /// Some pattern may apply to any host.
    any: bool,
    answers: Mutex<HashMap<(String, u16), bool>>,
}

impl PatternHosts {
    pub fn new<'a>(patterns: impl IntoIterator<Item = &'a str>) -> Self {
        let mut bound = HashSet::new();
        let mut anchored = Vec::new();
        let mut any = false;
        let syntax = syntax::Config::new().unicode(false).utf8(false);
        for p in patterns {
            if let Some(host) = bound_host(p) {
                bound.insert(host);
                continue;
            }
            let start = p.strip_prefix("(?i)").unwrap_or(p);
            let p = host_bounded(p);
            if start.starts_with('^') && syntax::parse_with(&p, &syntax).is_ok() {
                anchored.push(p);
            } else {
                any = true;
            }
        }
        let unbound = (!any && !anchored.is_empty())
            .then(|| {
                DFA::builder()
                    .configure(DFA::config().cache_capacity(1 << 20))
                    .syntax(syntax)
                    .build_many(&anchored)
                    .ok()
            })
            .flatten()
            .map(|dfa| {
                let cache = dfa.create_cache();
                (dfa, Mutex::new(cache))
            });
        // Patterns the DFA could not take may match anything.
        let any = any || (!anchored.is_empty() && unbound.is_none());
        Self {
            bound,
            unbound,
            any,
            answers: Mutex::new(HashMap::new()),
        }
    }

    /// Whether some pattern may match a URL of `host` on `port`.
    pub fn may_apply(&self, host: &str, port: u16) -> bool {
        if self.any {
            return true;
        }
        let host = host.to_ascii_lowercase();
        if self.bound.contains(&host) {
            return true;
        }
        let Some((dfa, cache)) = &self.unbound else {
            return false;
        };
        let key = (host, port);
        if let Some(answer) = self.answers.lock().unwrap().get(&key) {
            return *answer;
        }
        let (host, port) = &key;
        let mut prefixes =
            vec![format!("https://{host}/"), format!("http://{host}/")];
        if *port != 443 && *port != 80 {
            prefixes.push(format!("https://{host}:{port}/"));
            prefixes.push(format!("http://{host}:{port}/"));
        }
        let answer = {
            let mut cache = cache.lock().unwrap();
            prefixes.iter().any(|p| reachable(dfa, &mut cache, p))
        };
        let mut answers = self.answers.lock().unwrap();
        if answers.len() >= KEPT {
            answers.clear();
        }
        answers.insert(key, answer);
        answer
    }
}

/// The pattern with "." and "\S" in its host part (after "://", before
/// the first "/") kept from crossing into the path.
fn host_bounded(p: &str) -> String {
    let start = [r":\/\/", "://"]
        .iter()
        .filter_map(|s| p.find(s).map(|i| i + s.len()))
        .min();
    let Some(start) = start else {
        return p.to_owned();
    };
    let mut out = String::from(&p[..start]);
    let mut chars = p[start..].chars().peekable();
    let mut class = false;
    let mut in_host = true;
    while let Some(c) = chars.next() {
        if !in_host {
            out.push(c);
            continue;
        }
        match c {
            '\\' => match chars.next() {
                Some('/') if !class => {
                    in_host = false;
                    out.push_str(r"\/");
                }
                Some('S') if !class => out.push_str(r"[^\/\s]"),
                Some(next) => {
                    out.push('\\');
                    out.push(next);
                }
                None => out.push('\\'),
            },
            '[' if !class => {
                class = true;
                out.push(c);
            }
            ']' if class => {
                class = false;
                out.push(c);
            }
            '/' if !class => {
                in_host = false;
                out.push(c);
            }
            '.' if !class => out.push_str(r"[^\/]"),
            _ => out.push(c),
        }
    }
    out
}

/// Whether, after `prefix`, some pattern can still match (or has).
fn reachable(dfa: &DFA, cache: &mut Cache, prefix: &str) -> bool {
    let input = Input::new(prefix).anchored(Anchored::Yes);
    let Ok(mut sid) = dfa.start_state_forward(cache, &input) else {
        return true;
    };
    for &b in prefix.as_bytes() {
        match dfa.next_state(cache, sid, b) {
            Ok(next) => sid = next,
            Err(_) => return true,
        }
        if sid.is_dead() {
            return false;
        }
        if sid.is_match() || sid.is_quit() {
            return true;
        }
    }
    !sid.is_dead()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_of_patterns() {
        let h = PatternHosts::new([
            r"^https?:\/\/api\.example\.com\/ad",
            r"^https?:\/\/(www|m)\.zhihu\.com\/api\/v4\/ads",
            r"^https:\/\/[\w-]+\.googlevideo\.com\/initplayback",
            r"(?i)^https?:\/\/.+\.adsrv\.cn\/",
            r"^https?:\/\/(?:\d+\.){3}\d+\/ad",
        ]);
        assert!(!h.any);
        for (host, used) in [
            ("api.example.com", true),
            ("www.zhihu.com", true),
            ("m.zhihu.com", true),
            ("zhihu.com", false),
            ("api.zhihu.com", false),
            ("rr3---sn-a5m.googlevideo.com", true),
            ("www.youtube.com", false),
            ("x.ADSRV.cn", true),
            ("adsrv.cn", false),
            ("203.0.113.9", true),
        ] {
            assert_eq!(h.may_apply(host, 443), used, "{host}");
        }
        // A pattern for any host's path applies to any host.
        assert!(
            PatternHosts::new([r"^https?:\/\/.+\/ads\/"]).may_apply("any.test", 443)
        );
        assert_eq!(
            host_bounded(r"^https?:\/\/(.+\.)?a\.cn\/x.y"),
            r"^https?:\/\/([^\/]+\.)?a\.cn\/x.y"
        );
        // A pattern not anchored at the start may match any host.
        assert!(PatternHosts::new([r"\/ads\/"]).may_apply("any.test", 443));
        // None: no host.
        assert!(!PatternHosts::new([]).may_apply("any.test", 443));
    }
}
