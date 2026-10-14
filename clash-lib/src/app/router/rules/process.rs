use std::{
    net::SocketAddr,
    sync::{Arc, RwLock},
};

use super::RuleMatcher;
use crate::session::{Network, Session};

/// Finds the executable (its path) of the local process that owns a
/// connection's source socket, UDP or TCP (our fork): the application
/// provides it, from the system's socket lists, in place of sock2proc.
pub type ProcessFinder =
    Arc<dyn Fn(bool, SocketAddr) -> Option<String> + Send + Sync>;

static FINDER: RwLock<Option<(ProcessFinder, bool)>> = RwLock::new(None);

/// Sets the process finder; `annotate`: also for every connection
/// tracked, listed as its `processPath`.
pub fn set_process_finder(finder: Option<ProcessFinder>, annotate: bool) {
    *FINDER.write().unwrap() = finder.map(|f| (f, annotate));
}

fn finder() -> Option<(ProcessFinder, bool)> {
    FINDER.read().unwrap().clone()
}

/// The process path of a connection to track, when the finder annotates.
pub(crate) fn process_of(sess: &Session) -> Option<String> {
    let (find, annotate) = finder()?;
    annotate
        .then(|| find(sess.network == Network::Udp, sess.source))
        .flatten()
}

/// Whether a PROCESS-NAME (`name_only`: the file name, or the path when
/// the pattern has a "/") or PROCESS-PATH pattern names the executable at
/// `path`; "*" and "?" are wildcards, and case does not matter.
fn names(pattern: &str, path: &str, name_only: bool) -> bool {
    let subject = if name_only && !pattern.contains('/') {
        path.rsplit('/').next().unwrap_or(path)
    } else {
        path
    };
    glob(
        &pattern.to_lowercase().chars().collect::<Vec<_>>(),
        &subject.to_lowercase().chars().collect::<Vec<_>>(),
    )
}

fn glob(pattern: &[char], text: &[char]) -> bool {
    let (mut p, mut t) = (0, 0);
    // The last "*" and where the text stood then.
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        match pattern.get(p) {
            Some('*') => {
                star = Some((p, t));
                p += 1;
            }
            Some(&c) if c == '?' || c == text[t] => {
                p += 1;
                t += 1;
            }
            _ => match star {
                Some((sp, st)) => {
                    p = sp + 1;
                    t = st + 1;
                    star = Some((sp, st + 1));
                }
                None => return false,
            },
        }
    }
    pattern[p..].iter().all(|&c| c == '*')
}

pub struct Process {
    pub name: String,
    pub target: String,
    #[allow(dead_code)]
    pub name_only: bool,
}

impl std::fmt::Display for Process {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} process {}", self.target, self.name)
    }
}

impl RuleMatcher for Process {
    fn apply(&self, sess: &crate::session::Session) -> bool {
        if let Some((find, _)) = finder() {
            return find(sess.network == Network::Udp, sess.source).is_some_and(
                |path| {
                    tracing::debug!("process {} for {}", path, sess);
                    names(&self.name, &path, self.name_only)
                },
            );
        }
        #[cfg(all(
            feature = "process-rules",
            any(target_os = "linux", target_os = "macos", target_os = "windows")
        ))]
        {
            use crate::session::Network;
            use tracing::debug;

            sock2proc::find_process_name(
                Some(sess.source),
                sess.destination.clone().try_into_socket_addr(),
                match sess.network {
                    Network::Tcp => sock2proc::NetworkProtocol::TCP,
                    Network::Udp => sock2proc::NetworkProtocol::UDP,
                },
            )
            .is_some_and(|proc| {
                debug!("Matching process name: {} with {}", proc, self.name);
                if self.name_only {
                    proc == self.name
                } else {
                    proc.contains(&self.name)
                }
            })
        }
        #[cfg(not(all(
            feature = "process-rules",
            any(target_os = "linux", target_os = "macos", target_os = "windows")
        )))]
        {
            // Our fork: debug, not info; it was a line for each connection
            // that reached the rule.
            tracing::debug!(
                "PROCESS-NAME not supported on this platform: {}",
                &sess
            );
            false
        }
    }

    fn target(&self) -> &str {
        &self.target
    }

    fn payload(&self) -> String {
        self.name.clone()
    }

    fn type_name(&self) -> &str {
        "Process"
    }
}

#[cfg(test)]
mod tests {
    use super::names;

    #[test]
    fn process_patterns() {
        let path = "/Applications/Telegram.app/Contents/MacOS/Telegram";
        assert!(names("Telegram", path, true));
        assert!(names("telegram", path, true));
        assert!(!names("Tele", path, true));
        assert!(names("Tele*", path, true));
        assert!(names("T?legram", path, true));
        assert!(names("/Applications/*.app/*", path, true));
        assert!(!names("Telegram", path, false));
        assert!(names(path, path, false));
        assert!(names("*/MacOS/Telegram", path, false));
        assert!(!names("*.exe", path, true));
    }
}
