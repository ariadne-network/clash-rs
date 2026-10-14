use std::{collections::HashMap, fmt::Display, sync::Arc, time::Duration};

use async_trait::async_trait;
use erased_serde::Serialize as ESerialize;
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use tracing::{debug, trace, warn};

use super::cidr_trie::CidrTrie;
use crate::{
    Error,
    app::{
        remote_content_manager::providers::{
            Provider, ProviderType, ProviderVehicleType, ThreadSafeProviderVehicle,
            fetcher::Fetcher,
        },
        router::{RuleMatcher, map_rule_type},
    },
    common::{
        errors::map_io_error, geodata::GeoDataLookup, mmdb::MmdbLookup, succinct_set,
    },
    config::internal::rule::{RuleKind, RuleType},
    session::Session,
};

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ProviderScheme {
    pub payload: Vec<String>,
}

#[derive(Deserialize, Serialize, Debug, Clone, Copy, Default)]
#[serde(rename_all = "lowercase")]
pub enum RuleSetFormat {
    #[default]
    Yaml,
    Text,
    Mrs,
}

impl Display for RuleSetFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleSetFormat::Yaml => write!(f, "yaml"),
            RuleSetFormat::Text => write!(f, "text"),
            RuleSetFormat::Mrs => write!(f, "mrs"),
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Clone, Copy, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RuleSetBehavior {
    /// Rule contents will be built into a DomainSet
    Domain,
    /// Rule contents will be built into a IpCidr Trie
    Ipcidr,
    /// Classical line based rules
    Classical,
}

impl Display for RuleSetBehavior {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleSetBehavior::Domain => write!(f, "Domain"),
            RuleSetBehavior::Ipcidr => write!(f, "IPCIDR"),
            RuleSetBehavior::Classical => write!(f, "Classical"),
        }
    }
}

pub enum RuleContent {
    // the left will converted into a right
    Domain(succinct_set::DomainSet),
    Ipcidr(Box<CidrTrie>),
    Classical(Box<FastClassicalRules>),
}

/// The API lists this many of a set's rules; only they are kept as text
/// (our fork: all were, about 50 bytes each).
const LISTED_RULES: usize = 500;

pub struct FastClassicalRules {
    /// It has IP rules that look a name up (our fork).
    resolves_ip: bool,
    raw_rules: Vec<String>,
    /// DOMAIN and DOMAIN-SUFFIX rules as a domain set (our fork): in a
    /// hash set and a radix trie they took about 300 bytes each, so a list
    /// of 100,000 left little of an iOS packet tunnel's 50 MiB. Those with
    /// wildcard characters, which the set reads as wildcards, stay in the
    /// two below.
    domains: succinct_set::DomainSet,
    exact_domains: std::collections::HashSet<String>,
    domain_suffix_trie: crate::common::domain_trie::DomainSuffixTrie<()>,
    domain_keywords_ac: Option<aho_corasick::AhoCorasick>,
    ip_cidr: CidrTrie,
    other_rules: Vec<Box<dyn RuleMatcher>>,
}

impl Default for FastClassicalRules {
    fn default() -> Self {
        Self::empty()
    }
}

impl FastClassicalRules {
    pub fn empty() -> Self {
        Self {
            resolves_ip: false,
            raw_rules: Vec::new(),
            domains: succinct_set::DomainSet::default(),
            exact_domains: std::collections::HashSet::new(),
            domain_suffix_trie: crate::common::domain_trie::DomainSuffixTrie::new(),
            domain_keywords_ac: None,
            ip_cidr: CidrTrie::new(),
            other_rules: Vec::new(),
        }
    }

    pub fn search(&self, sess: &Session) -> bool {
        if let Some(domain) = sess.destination.domain() {
            if self.domains.has(domain) {
                return true;
            }
            let domain_lower = domain.to_ascii_lowercase();
            if self.exact_domains.contains(&domain_lower) {
                return true;
            }
            if self.domain_suffix_trie.search(domain).is_some() {
                return true;
            }
            if let Some(ref ac) = self.domain_keywords_ac
                && ac.is_match(domain)
            {
                return true;
            }
        }

        if let Some(ip) = sess.resolved_ip.or(sess.destination.ip())
            && self.ip_cidr.contains(ip)
        {
            return true;
        }

        for rule in &self.other_rules {
            if rule.apply(sess) {
                return true;
            }
        }

        false
    }

    pub fn list_rules(&self, limit: usize) -> Vec<String> {
        self.raw_rules.iter().take(limit).cloned().collect()
    }
}

struct Inner {
    content: RuleContent,
}

#[async_trait]
pub trait RuleProvider: Provider {
    fn search(&self, sess: &Session) -> bool;
    /// Whether a name is looked up before searching (our fork): for IP
    /// rules.
    fn should_resolve_ip(&self) -> bool {
        false
    }
    fn behavior(&self) -> RuleSetBehavior;
    fn format(&self) -> RuleSetFormat;
    /// Returns up to `limit` rules as strings. Only Classical providers return
    /// non-empty results; Domain/IPCIDR data structures don't support
    /// enumeration.
    async fn list_rules(&self, limit: usize) -> Vec<String> {
        let _ = limit;
        vec![]
    }
}

pub type ThreadSafeRuleProvider = Arc<dyn RuleProvider + Send + Sync>;

type RuleUpdater =
    Box<dyn Fn(RuleContent) -> BoxFuture<'static, ()> + Send + Sync + 'static>;
type RuleParser =
    Box<dyn Fn(&[u8]) -> anyhow::Result<RuleContent> + Send + Sync + 'static>;

pub struct RuleProviderImpl {
    name: String,
    fetcher: Option<Fetcher<RuleUpdater, RuleParser>>,
    inner: Arc<tokio::sync::RwLock<Inner>>,
    behavior: RuleSetBehavior,
    format: RuleSetFormat,
    inline_rules: Option<Vec<String>>,

    mmdb: Option<MmdbLookup>,
    geodata: Option<GeoDataLookup>,
}

impl RuleProviderImpl {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: String,
        behavior: RuleSetBehavior,
        format: RuleSetFormat,
        // InlineRuleProvider doesn't have an interval and vehicle
        interval: Option<Duration>,
        vehicle: Option<ThreadSafeProviderVehicle>,
        mmdb: Option<MmdbLookup>,
        geodata: Option<GeoDataLookup>,
        inline_rules: Option<Vec<String>>,
    ) -> Self {
        let inner = Arc::new(tokio::sync::RwLock::new(Inner {
            content: match behavior {
                RuleSetBehavior::Domain => {
                    RuleContent::Domain(succinct_set::DomainSet::default())
                }
                RuleSetBehavior::Ipcidr => {
                    RuleContent::Ipcidr(Box::new(CidrTrie::new()))
                }
                RuleSetBehavior::Classical => RuleContent::Classical(Box::default()),
            },
        }));

        let inner_clone = inner.clone();

        let n = name.clone();
        let updater: RuleUpdater =
            Box::new(move |input: RuleContent| -> BoxFuture<'static, ()> {
                let n = n.clone(); // Clone name for the async block
                let inner: Arc<tokio::sync::RwLock<Inner>> = inner_clone.clone();
                Box::pin(async move {
                    let mut inner = inner.write().await;
                    trace!("updated rules for provider: {}", n);
                    inner.content = input;
                })
            });

        let n_parser = name.clone(); // Clone name specifically for the parser closure
        let current_behavior = behavior;
        let current_format = format;
        let inline_rules_clone = inline_rules.clone();
        let mmdb_clone = mmdb.clone();
        let geodata_clone = geodata.clone();
        let parser: RuleParser =
            Box::new(move |input: &[u8]| -> anyhow::Result<RuleContent> {
                match current_format {
                    RuleSetFormat::Yaml => {
                        let scheme: ProviderScheme = serde_yaml::from_slice(input)
                            .map_err(|x| {
                            Error::InvalidConfig(format!(
                                "rule provider parse error (yaml) {n_parser}: {x}"
                            ))
                        })?;

                        // Fn: we need to clone the values anyway to avoid
                        // moving `inline_rules` from
                        // the "Environment"
                        let mut payload =
                            inline_rules_clone.clone().unwrap_or_default();
                        payload.extend(scheme.payload);

                        // For Yaml, we still need to convert Vec<String> to
                        // RuleContent
                        make_rules(
                            current_behavior,
                            payload,
                            mmdb_clone.clone(),
                            geodata_clone.clone(),
                        )
                        .map_err(anyhow::Error::new)
                    }
                    RuleSetFormat::Text => {
                        let text = std::str::from_utf8(input).map_err(|e| {
                            Error::InvalidConfig(format!(
                                "invalid utf-8 in text rule provider {n_parser}: \
                                 {e}"
                            ))
                        })?;

                        let lines = text.lines().map(str::trim).filter(|line| {
                            !line.is_empty()
                                && !line.starts_with('#')
                                && !line.starts_with("//")
                        });
                        // A domain set straight from the lines (our fork),
                        // not through a string for each of them.
                        if matches!(current_behavior, RuleSetBehavior::Domain) {
                            return Ok(RuleContent::Domain(
                                match inline_rules_clone.as_deref() {
                                    None | Some([]) => {
                                        succinct_set::DomainSet::from_lines(text)
                                    }
                                    Some(inline) => {
                                        succinct_set::DomainSet::from_rules(
                                            lines.chain(
                                                inline.iter().map(String::as_str),
                                            ),
                                        )
                                    }
                                },
                            ));
                        }
                        let mut payload: Vec<String> =
                            lines.map(String::from).collect();

                        if let Some(inline) = inline_rules_clone.clone() {
                            payload.extend(inline);
                        }

                        // For Text, we also convert Vec<String> to RuleContent
                        make_rules(
                            current_behavior,
                            payload,
                            mmdb_clone.clone(),
                            geodata_clone.clone(),
                        )
                        .map_err(anyhow::Error::new)
                    }
                    RuleSetFormat::Mrs => {
                        if matches!(current_behavior, RuleSetBehavior::Classical) {
                            return Err(anyhow::Error::new(Error::InvalidConfig(
                                format!(
                                    "MRS format is not supported for classical \
                                     behavior in rule provider {n_parser}"
                                ),
                            )));
                        }
                        // Parse MRS format using the updated function
                        // signature. It directly
                        // returns the required RuleContent.
                        super::mrs::rules_mrs_parse(input, current_behavior)
                    }
                }
            });

        // A file/http vehicle always gets a fetcher so its content loads at
        // startup, regardless of `interval` (file providers also live-reload
        // via the watcher). Only inline providers (no vehicle) have none.
        let fetcher = vehicle.map(|vehicle| {
            Fetcher::new(
                name.clone(),
                interval.unwrap_or_default(),
                vehicle,
                parser,
                Some(updater),
            )
        });

        Self {
            name,
            fetcher,
            inner,
            behavior,
            format,
            inline_rules,

            mmdb,
            geodata,
        }
    }
}

#[async_trait]
impl RuleProvider for RuleProviderImpl {
    fn search(&self, sess: &Session) -> bool {
        let inner = self.inner.try_read();

        match inner {
            Ok(inner) => match &inner.content {
                RuleContent::Domain(set) => set.has(&sess.destination.host()),
                // The address looked up for a name too (our fork), and no
                // match without one: 0.0.0.0 matched sets with 0.0.0.0/8.
                RuleContent::Ipcidr(trie) => sess
                    .resolved_ip
                    .or(sess.destination.ip())
                    .is_some_and(|ip| trie.contains(ip)),
                RuleContent::Classical(fast) => fast.search(sess),
            },
            Err(_) => {
                debug!("rule provider {} is busy", self.name());
                false
            }
        }
    }

    fn should_resolve_ip(&self) -> bool {
        match self.behavior {
            RuleSetBehavior::Domain => false,
            RuleSetBehavior::Ipcidr => true,
            // While the content is being replaced: looking up costs a
            // query at most.
            RuleSetBehavior::Classical => match self.inner.try_read() {
                Ok(inner) => match &inner.content {
                    RuleContent::Classical(fast) => fast.resolves_ip,
                    _ => false,
                },
                Err(_) => true,
            },
        }
    }

    fn behavior(&self) -> RuleSetBehavior {
        self.behavior
    }

    fn format(&self) -> RuleSetFormat {
        self.format
    }

    async fn list_rules(&self, limit: usize) -> Vec<String> {
        let inner = self.inner.read().await;
        match &inner.content {
            RuleContent::Classical(fast) => fast.list_rules(limit),
            _ => vec![],
        }
    }
}

#[async_trait]
impl Provider for RuleProviderImpl {
    fn name(&self) -> &str {
        &self.name
    }

    fn vehicle_type(&self) -> ProviderVehicleType {
        if let Some(fetcher) = &self.fetcher {
            fetcher.vehicle_type()
        } else {
            ProviderVehicleType::Inline
        }
    }

    fn typ(&self) -> ProviderType {
        ProviderType::Rule
    }

    async fn initialize(&self) -> std::io::Result<()> {
        debug!("initializing rule provider {}", self.name());

        if let Some(fetcher) = &self.fetcher {
            trace!("initializing rule provider {} with fetcher", self.name());
            let ele = fetcher.initial().await.map_err(map_io_error)?;
            if let Some(updater) = fetcher.on_update.as_ref() {
                updater(ele).await; // Directly pass RuleContent
            }
            // Auto-watch local file providers. Best-effort: watcher setup can
            // fail (inotify limits, unsupported filesystems), so log and keep
            // serving the loaded rules instead of failing init.
            if let Err(e) = fetcher.start_watch().await {
                warn!(
                    "rule provider '{}': live file watching unavailable, falling \
                     back to interval polling: {}",
                    self.name(),
                    e
                );
            }
        } else {
            trace!("initializing inline rule provider {}", self.name());
            let rules = make_rules(
                self.behavior,
                self.inline_rules.clone().unwrap_or_default(),
                self.mmdb.clone(),
                self.geodata.clone(),
            );

            match rules {
                Ok(content) => {
                    let mut inner = self.inner.write().await;
                    inner.content = content;
                }
                Err(e) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "failed to initialize inline rule provider {}: {}",
                            self.name(),
                            e
                        ),
                    ));
                }
            }
        }
        Ok(())
    }

    async fn update(&self) -> std::io::Result<()> {
        if let Some(fetcher) = &self.fetcher {
            let (ele, same) = fetcher.update().await.map_err(map_io_error)?;
            debug!("rule provider {} updated. same? {}", self.name(), same);
            if !same && let Some(updater) = fetcher.on_update.as_ref() {
                updater(ele).await; // Directly pass RuleContent
            }
        } else {
            trace!("no fetcher for rule provider {}", self.name());
        }

        Ok(())
    }

    async fn as_map(&self) -> HashMap<String, Box<dyn ESerialize + Send>> {
        let mut m: HashMap<String, Box<dyn ESerialize + Send>> = HashMap::new();

        m.insert("name".to_owned(), Box::new(self.name().to_string()));
        m.insert("type".to_owned(), Box::new(self.typ().to_string()));
        m.insert(
            "vehicleType".to_owned(),
            Box::new(self.vehicle_type().to_string()),
        );

        if let Some(fetcher) = &self.fetcher {
            m.insert("updatedAt".to_owned(), Box::new(fetcher.updated_at().await));
        }

        m.insert("behavior".to_owned(), Box::new(self.behavior().to_string()));
        m.insert("format".to_owned(), Box::new(self.format().to_string()));

        m
    }
}

// --- make_rules is needed for Yaml and Text formats ---
fn make_rules(
    behavior: RuleSetBehavior,
    rules: Vec<String>, // Input is Vec<String> for Yaml/Text
    mmdb: Option<MmdbLookup>,
    geodata: Option<GeoDataLookup>,
) -> Result<RuleContent, Error> {
    match behavior {
        RuleSetBehavior::Domain => Ok(RuleContent::Domain(
            succinct_set::DomainSet::from_rules(rules.iter().map(String::as_str)),
        )),
        RuleSetBehavior::Ipcidr => {
            Ok(RuleContent::Ipcidr(Box::new(make_ip_cidr_rules(rules)?)))
        }
        RuleSetBehavior::Classical => Ok(RuleContent::Classical(Box::new(
            make_classical_rules(rules, mmdb, geodata)?,
        ))),
    }
}

fn make_ip_cidr_rules(rules: Vec<String>) -> Result<CidrTrie, Error> {
    let mut trie = CidrTrie::new();
    for rule in rules {
        trie.insert(&rule);
    }
    Ok(trie)
}

fn make_classical_rules(
    rules: Vec<String>,
    mmdb: Option<MmdbLookup>,
    geodata: Option<GeoDataLookup>,
) -> Result<FastClassicalRules, Error> {
    let mut raw_rules = Vec::new();
    let mut exact_domains = std::collections::HashSet::new();
    let mut domain_suffix_trie = crate::common::domain_trie::DomainSuffixTrie::new();
    let mut keywords = Vec::new();
    let mut ip_cidr = CidrTrie::new();
    let mut other_rules = Vec::new();
    let mut resolves_ip = false;
    // The domain set's rules, a line each.
    let mut names = String::new();
    let plain = |name: &str| !name.is_empty() && !name.contains(['*', '+', '\n']);

    for rule in rules {
        let parts = rule.split(',').map(str::trim).collect::<Vec<&str>>();

        // the rule inside RULE-SET is slightly different from the rule in
        // config the target is always empty as it's held in the
        // RULE-SET container let's parse it manually
        let rule_type = match parts.as_slice() {
            [proto, payload] => RuleType::new(proto, payload, "", None),
            [proto, payload, params @ ..] => {
                RuleType::new(proto, payload, "", Some(params.to_vec()))
            }
            _ => Err(Error::InvalidConfig(format!("invalid rule line: {rule}"))),
        }?;

        let options = rule_type.options();
        match rule_type.kind() {
            RuleKind::Domain { domain, .. } if plain(domain) => {
                names.push_str(domain);
                names.push('\n');
            }
            RuleKind::Domain { domain, .. } => {
                exact_domains.insert(domain.to_ascii_lowercase());
            }
            RuleKind::DomainSuffix { domain_suffix, .. } => {
                // As the trie takes it: without dots around.
                let suffix = domain_suffix
                    .trim()
                    .trim_start_matches('.')
                    .trim_end_matches('.');
                if plain(suffix) {
                    names.push_str("+.");
                    names.push_str(suffix);
                    names.push('\n');
                } else {
                    domain_suffix_trie.insert(domain_suffix, ());
                }
            }
            RuleKind::DomainKeyword { domain_keyword, .. } => {
                keywords.push(domain_keyword.clone());
            }
            RuleKind::IpCidr { ipnet, .. } if !options.no_resolve => {
                ip_cidr.insert(&ipnet.to_string());
                resolves_ip = true;
            }
            _ => {
                let rule_matcher =
                    map_rule_type(rule_type, mmdb.clone(), geodata.clone(), None);
                resolves_ip |= rule_matcher.should_resolve_ip();
                if raw_rules.len() < LISTED_RULES {
                    raw_rules.push(format!(
                        "{},{}",
                        rule_matcher.type_name(),
                        rule_matcher.payload()
                    ));
                }
                other_rules.push(rule_matcher);
                continue;
            }
        }

        if raw_rules.len() < LISTED_RULES {
            let rule_matcher =
                map_rule_type(rule_type, mmdb.clone(), geodata.clone(), None);
            raw_rules.push(format!(
                "{},{}",
                rule_matcher.type_name(),
                rule_matcher.payload()
            ));
        }
    }

    let domain_keywords_ac = if !keywords.is_empty() {
        aho_corasick::AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .build(&keywords)
            .ok()
    } else {
        None
    };

    Ok(FastClassicalRules {
        resolves_ip,
        raw_rules,
        domains: succinct_set::DomainSet::from_rules(names.lines()),
        exact_domains,
        domain_suffix_trie,
        domain_keywords_ac,
        ip_cidr,
        other_rules,
    })
}

#[cfg(test)]
mod tests {
    use crate::{
        app::remote_content_manager::providers::{
            MockProviderVehicle, Provider, ProviderVehicleType,
            rule_provider::{
                RuleProviderImpl, RuleSetBehavior, RuleSetFormat,
                provider::RuleProvider,
            },
        },
        common::{geodata::MockGeoDataLookupTrait, mmdb::MockMmdbLookupTrait},
        session::{Session, SocksAddr},
    };
    use std::{path::Path, sync::Arc, time::Duration};
    use tokio_test::assert_ok;

    #[tokio::test]
    async fn test_inline_provider() {
        let mock_mmdb = MockMmdbLookupTrait::new();
        let mock_geodata = MockGeoDataLookupTrait::new();

        let provider = RuleProviderImpl::new(
            "test".to_string(),
            RuleSetBehavior::Classical,
            RuleSetFormat::Text,
            None,
            None,
            Some(Arc::new(mock_mmdb)),
            Some(Arc::new(mock_geodata)),
            Some(vec!["DOMAIN-SUFFIX, google.com".to_owned()]),
        );

        assert_ok!(provider.initialize().await);

        let sess = Session {
            destination: SocksAddr::Domain("test.google.com".to_owned(), 443),
            ..Default::default()
        };
        assert!(provider.search(&sess));
    }

    #[tokio::test]
    async fn classical_domains_in_a_domain_set() {
        let provider = RuleProviderImpl::new(
            "test".to_string(),
            RuleSetBehavior::Classical,
            RuleSetFormat::Text,
            None,
            None,
            Some(Arc::new(MockMmdbLookupTrait::new())),
            Some(Arc::new(MockGeoDataLookupTrait::new())),
            Some(
                [
                    "DOMAIN,Exact.example",
                    "DOMAIN-SUFFIX,.suffix.example",
                    "DOMAIN-SUFFIX,*.wild.example",
                    "DOMAIN,a*.star.example",
                    "DOMAIN-KEYWORD,keyword",
                ]
                .iter()
                .map(|r| r.to_string())
                .collect(),
            ),
        );
        assert_ok!(provider.initialize().await);
        let matches = |host: &str| {
            provider.search(&Session {
                destination: SocksAddr::Domain(host.to_owned(), 443),
                ..Default::default()
            })
        };
        assert!(matches("exact.example") && !matches("www.exact.example"));
        assert!(matches("suffix.example") && matches("a.b.SUFFIX.example"));
        assert!(!matches("notsuffix.example"));
        // Wildcard characters as the trie and hash set take them: literally.
        assert!(matches("x.*.wild.example") && !matches("x.y.wild.example"));
        assert!(matches("a*.star.example") && !matches("ab.star.example"));
        assert!(matches("a.keyword.example"));
        assert!(!provider.list_rules(10).await.is_empty());
    }

    #[tokio::test]
    async fn rule_sets_with_ip_rules_look_names_up() {
        let provider = |behavior, rules: &[&str]| {
            RuleProviderImpl::new(
                "test".to_string(),
                behavior,
                RuleSetFormat::Text,
                None,
                None,
                Some(Arc::new(MockMmdbLookupTrait::new())),
                Some(Arc::new(MockGeoDataLookupTrait::new())),
                Some(rules.iter().map(|r| r.to_string()).collect()),
            )
        };
        let classical = provider(
            RuleSetBehavior::Classical,
            &["DOMAIN-SUFFIX,google.com", "IP-CIDR,1.2.3.0/24"],
        );
        assert_ok!(classical.initialize().await);
        assert!(classical.should_resolve_ip());
        let names = provider(
            RuleSetBehavior::Classical,
            &["DOMAIN-SUFFIX,google.com", "IP-CIDR,1.2.3.0/24,no-resolve"],
        );
        assert_ok!(names.initialize().await);
        assert!(!names.should_resolve_ip());
        // An IP range set matches the address looked up for a name, and
        // nothing without one.
        let ranges = provider(RuleSetBehavior::Ipcidr, &["1.2.3.0/24", "0.0.0.0/8"]);
        assert_ok!(ranges.initialize().await);
        assert!(ranges.should_resolve_ip());
        let mut sess = Session {
            destination: SocksAddr::Domain("example.com".to_owned(), 443),
            ..Default::default()
        };
        assert!(!ranges.search(&sess));
        sess.resolved_ip = Some("1.2.3.4".parse().unwrap());
        assert!(ranges.search(&sess));
    }

    #[tokio::test]
    async fn test_file_provider_with_inline_rules() {
        let mock_mmdb = MockMmdbLookupTrait::new();
        let mock_geodata = MockGeoDataLookupTrait::new();
        let mut mock_vehicle = MockProviderVehicle::new();

        let mock_file = std::env::temp_dir().join(format!(
            "{}-{}",
            "mock_provider_vehicle",
            uuid::Uuid::new_v4()
        ));
        if Path::new(mock_file.to_str().unwrap()).exists() {
            std::fs::remove_file(&mock_file).unwrap();
        }
        std::fs::write(&mock_file, "twitter.com").unwrap();

        mock_vehicle
            .expect_path()
            .return_const(mock_file.to_str().unwrap().to_owned());
        mock_vehicle
            .expect_read()
            .returning(|| Ok("twitter.com".into()));
        mock_vehicle
            .expect_typ()
            .return_const(ProviderVehicleType::File);

        let provider = RuleProviderImpl::new(
            "test".to_string(),
            RuleSetBehavior::Domain,
            RuleSetFormat::Text,
            Some(Duration::from_secs(5)),
            Some(Arc::new(mock_vehicle)),
            Some(Arc::new(mock_mmdb)),
            Some(Arc::new(mock_geodata)),
            Some(vec!["+.google.com".to_owned()]),
        );

        assert_ok!(provider.initialize().await);

        assert!(provider.search(&Session {
            destination: SocksAddr::Domain("test.google.com".to_owned(), 443),
            ..Default::default()
        }));
    }

    /// A local `type: file` provider is watched automatically (no config flag)
    /// and live-reloads on disk change.
    ///
    /// Linux-only: inotify delivers events promptly, whereas macOS (FSEvents)
    /// and Windows (ReadDirectoryChangesW) coalesce them with multi-second
    /// latency — fine for the real feature, but too flaky for a bounded test.
    /// The watcher code is platform-agnostic; only this timing check is gated.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_file_provider_watch() {
        let mock_mmdb = MockMmdbLookupTrait::new();
        let mock_geodata = MockGeoDataLookupTrait::new();

        // Write initial content to a temporary file.  Using `NamedTempFile`
        // ensures the file is removed even if the test panics.
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        use std::io::{Seek as _, Write as _};
        write!(tmp, "payload:\n  - twitter.com\n").unwrap();
        tmp.flush().unwrap();

        // Use the real file vehicle so that notify can watch the actual path.
        let vehicle = Arc::new(
            crate::app::remote_content_manager::providers::file_vehicle::Vehicle::new(
                tmp.path().to_str().unwrap(),
            ),
        );

        let provider = Arc::new(RuleProviderImpl::new(
            "watch-test".to_string(),
            RuleSetBehavior::Domain,
            RuleSetFormat::Yaml,
            None, // no polling interval — rely purely on file watching
            Some(vehicle),
            Some(Arc::new(mock_mmdb)),
            Some(Arc::new(mock_geodata)),
            None,
        ));

        assert_ok!(provider.initialize().await);

        // Initial content: twitter.com should match.
        let sess_twitter = Session {
            destination: SocksAddr::Domain("twitter.com".to_owned(), 443),
            ..Default::default()
        };
        assert!(
            provider.search(&sess_twitter),
            "twitter.com should match after initial load"
        );
        // google.com should NOT match yet.
        let sess_google = Session {
            destination: SocksAddr::Domain("google.com".to_owned(), 443),
            ..Default::default()
        };
        assert!(
            !provider.search(&sess_google),
            "google.com should NOT match before file update"
        );

        // Re-write on each iteration: this defeats the watcher-registration
        // race (the watch is set up asynchronously by `initialize()`) and keeps
        // nudging slow/coalescing backends until the reload is observed.
        let deadline =
            tokio::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            tmp.as_file_mut().set_len(0).expect("truncate tmp file");
            tmp.as_file_mut().seek(std::io::SeekFrom::Start(0)).unwrap();
            write!(tmp.as_file_mut(), "payload:\n  - google.com\n").unwrap();
            tmp.as_file_mut().sync_all().unwrap();

            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            if provider.search(&sess_google) {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                panic!("provider did not reload within 15 s after file change");
            }
        }

        // And the old rule is gone after the reload.
        assert!(
            !provider.search(&sess_twitter),
            "twitter.com should NOT match after file update"
        );
    }

    #[tokio::test]
    async fn test_classical_rule_provider() {
        let mock_mmdb = MockMmdbLookupTrait::new();
        let mock_geodata = MockGeoDataLookupTrait::new();

        let rules = vec![
            "DOMAIN,google.com".to_string(),
            "DOMAIN-SUFFIX,apple.com".to_string(),
            "DOMAIN-KEYWORD,twitter".to_string(),
            "IP-CIDR,192.168.1.0/24".to_string(),
        ];

        let provider = RuleProviderImpl::new(
            "classical-test".to_string(),
            RuleSetBehavior::Classical,
            RuleSetFormat::Yaml,
            None,
            None,
            Some(Arc::new(mock_mmdb)),
            Some(Arc::new(mock_geodata)),
            Some(rules),
        );

        assert_ok!(provider.initialize().await);

        // DOMAIN match
        assert!(provider.search(&Session {
            destination: SocksAddr::Domain("google.com".to_owned(), 443),
            ..Default::default()
        }));
        // DOMAIN should not match subdomain or prefix
        assert!(!provider.search(&Session {
            destination: SocksAddr::Domain("sub.google.com".to_owned(), 443),
            ..Default::default()
        }));

        // DOMAIN-SUFFIX match
        assert!(provider.search(&Session {
            destination: SocksAddr::Domain("apple.com".to_owned(), 443),
            ..Default::default()
        }));
        assert!(provider.search(&Session {
            destination: SocksAddr::Domain("store.apple.com".to_owned(), 443),
            ..Default::default()
        }));
        assert!(!provider.search(&Session {
            destination: SocksAddr::Domain("fakeapple.com".to_owned(), 443),
            ..Default::default()
        }));

        // DOMAIN-KEYWORD match
        assert!(provider.search(&Session {
            destination: SocksAddr::Domain("api.twitter.com".to_owned(), 443),
            ..Default::default()
        }));
        assert!(provider.search(&Session {
            destination: SocksAddr::Domain("mytwitter.org".to_owned(), 443),
            ..Default::default()
        }));

        // IP-CIDR match
        assert!(provider.search(&Session {
            destination: SocksAddr::Ip("192.168.1.50:80".parse().unwrap()),
            ..Default::default()
        }));
        assert!(!provider.search(&Session {
            destination: SocksAddr::Ip("192.168.2.1:80".parse().unwrap()),
            ..Default::default()
        }));

        // list_rules
        let listed = provider.list_rules(10).await;
        assert_eq!(listed.len(), 4);
    }
}
