use std::{collections::HashMap, net::SocketAddr, sync::Arc};

pub trait Authenticator {
    fn authenticate(&self, username: &str, password: &str) -> bool;
    fn users(&self) -> Vec<String>;
    fn enabled(&self) -> bool;

    /// Whether a client at `source` has to authenticate. Loopback clients
    /// are exempt, as with mihomo's default `skip-auth-prefixes`: the
    /// credentials protect a port opened to the LAN, while apps on the
    /// same machine reach it through the system proxy without any.
    fn required_for(&self, source: &SocketAddr) -> bool {
        self.enabled() && !source.ip().to_canonical().is_loopback()
    }
}

pub type ThreadSafeAuthenticator = Arc<dyn Authenticator + Send + Sync>;

pub struct User(String, String);

impl User {
    pub fn new(username: String, password: String) -> Self {
        Self(username, password)
    }
}

pub struct PlainAuthenticator {
    store: HashMap<String, String>,
    usernames: Vec<String>,
}

impl PlainAuthenticator {
    pub fn new(users: Vec<User>) -> Self {
        let mut store = HashMap::new();
        let mut usernames = Vec::new();
        for user in users {
            store.insert(user.0.clone(), user.1.clone());
            usernames.push(user.0.clone());
        }
        Self { store, usernames }
    }
}

impl Authenticator for PlainAuthenticator {
    fn authenticate(&self, username: &str, password: &str) -> bool {
        match self.store.get(username) {
            Some(p) => p == password,
            None => false,
        }
    }

    fn users(&self) -> Vec<String> {
        self.usernames.clone()
    }

    fn enabled(&self) -> bool {
        !self.usernames.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_clients_skip_authentication() {
        let auth = PlainAuthenticator::new(vec![User::new("u".into(), "p".into())]);
        for (source, required) in [
            ("127.0.0.1:1", false),
            ("[::1]:1", false),
            ("[::ffff:127.0.0.1]:1", false),
            ("192.168.1.2:1", true),
        ] {
            assert_eq!(
                auth.required_for(&source.parse().unwrap()),
                required,
                "{source}"
            );
        }
        assert!(
            !PlainAuthenticator::new(vec![])
                .required_for(&"192.168.1.2:1".parse().unwrap())
        );
    }
}
