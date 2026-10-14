use crate::{
    app::{
        remote_content_manager::providers::rule_provider::ThreadSafeRuleProvider,
        router::rules::RuleMatcher,
    },
    session::Session,
};

#[derive(Clone)]
pub struct RuleSet {
    pub rule_set: String,
    pub target: String,
    pub rule_provider: ThreadSafeRuleProvider,
    /// The set's IP rules go by the destination's address alone, a name
    /// is not looked up for them (our fork).
    pub no_resolve: bool,
}

impl RuleSet {
    pub fn new(
        rule_set: String,
        target: String,
        rule_provider: ThreadSafeRuleProvider,
        no_resolve: bool,
    ) -> Self {
        Self {
            rule_set,
            target,
            rule_provider,
            no_resolve,
        }
    }
}

impl std::fmt::Display for RuleSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} rule-set {}", self.target, self.rule_set)
    }
}

impl RuleMatcher for RuleSet {
    fn apply(&self, sess: &Session) -> bool {
        self.rule_provider.search(sess)
    }

    fn target(&self) -> &str {
        self.target.as_str()
    }

    fn payload(&self) -> String {
        self.rule_set.clone()
    }

    fn type_name(&self) -> &str {
        "RuleSet"
    }

    /// A set with IP rules looks the name up first, as an IP-CIDR rule does
    /// (our fork, as mihomo): GEOIP as an IP range set matched no request
    /// by name.
    fn should_resolve_ip(&self) -> bool {
        !self.no_resolve && self.rule_provider.should_resolve_ip()
    }
}
