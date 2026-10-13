use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use axum::{
    Router,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
};
use serde::Deserialize;

use crate::{
    RuntimeComponents,
    app::api::AppState,
    session::{Network, Session, SocksAddr},
};

#[derive(Clone)]
struct RuleState {
    components: Arc<RwLock<Arc<RuntimeComponents>>>,
}

pub fn routes(
    components: Arc<RwLock<Arc<RuntimeComponents>>>,
) -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(get_rules))
        .route("/match", get(match_rule))
        .with_state(RuleState { components })
}

async fn get_rules(State(state): State<RuleState>) -> impl IntoResponse {
    let comps = state.components.read().unwrap().clone();
    let rules = comps.router.get_all_rules();
    let mut r = HashMap::new();
    r.insert(
        "rules",
        rules.iter().map(|r| r.as_map()).collect::<Vec<_>>(),
    );
    axum::response::Json(r)
}

#[derive(Deserialize)]
struct MatchQuery {
    host: String,
    port: Option<u16>,
    /// "tcp" (default) or "udp".
    network: Option<String>,
}

/// The rule a connection to `host:port` would match and its target, as
/// the router decides it (rule mode): for testing rules. Domains are
/// resolved when a rule needs the IP, as for a real connection.
async fn match_rule(
    State(state): State<RuleState>,
    Query(q): Query<MatchQuery>,
) -> impl IntoResponse {
    let comps = state.components.read().unwrap().clone();
    let port = q.port.unwrap_or(443);
    let destination = match SocksAddr::try_from((q.host.clone(), port)) {
        Ok(d) => d,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    let mut sess = Session {
        network: if q.network.as_deref() == Some("udp") {
            Network::Udp
        } else {
            Network::Tcp
        },
        destination,
        ..Default::default()
    };
    let (target, rule) = comps.router.match_route(&mut sess).await;
    let mut r: HashMap<&str, serde_json::Value> = HashMap::new();
    r.insert("target", target.into());
    if let Some(rule) = rule {
        r.insert("rule", rule.matcher().type_name().into());
        r.insert("payload", rule.matcher().payload().into());
    }
    if let Some(ip) = sess.resolved_ip {
        r.insert("resolved_ip", ip.to_string().into());
    }
    axum::response::Json(r).into_response()
}
