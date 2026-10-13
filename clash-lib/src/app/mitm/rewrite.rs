//! Rewrites on decrypted and plain HTTP (our fork), as Surge has them: URL
//! rewrite (header, 302, 307, reject and Loon's reject variants), header
//! rewrite, body rewrite with regular expressions, and map local. In
//! Surge's order: request headers, URL, map local, request body; then
//! response headers and body. Patterns match the full URL; those the
//! `regex` crate takes go into sets, matched at once (a module may have
//! hundreds), the rest (look-around) one by one.

use std::{collections::HashMap, io::Read, sync::OnceLock};

use async_trait::async_trait;
use base64::Engine as _;
use bytes::{Bytes, BytesMut};
use futures::StreamExt;
use http::{
    HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri, header,
};
use http_body_util::{BodyExt, BodyStream, StreamBody};
use hyper::body::Frame;
use tracing::{debug, warn};

use super::{Body, HttpProcessor, RequestOutcome, full_body};
pub use crate::config::def::RewriteConfig;

const DEFAULT_MAX_BODY: usize = 1 << 20;

/// A rule list's patterns. Most of a module's patterns name one host
/// (`^https?:\/\/api\.example\.com\/...`): they are looked up by the URL's
/// host, and only the others are tried on every URL. Each is compiled on
/// first use: as bytes with ASCII classes and case folding where the
/// `regex` crate takes it (URLs are ASCII; the Unicode tables would cost
/// much memory for hundreds of case-insensitive patterns), else (look-
/// around) with fancy-regex.
struct Patterns {
    sources: Vec<String>,
    compiled: Vec<OnceLock<Compiled>>,
    by_host: HashMap<String, Vec<usize>>,
    /// The patterns not bound to a host, in order.
    unbound: Vec<usize>,
}

enum Compiled {
    Ascii(regex::bytes::Regex),
    Fancy(fancy_regex::Regex),
    Invalid,
}

impl Compiled {
    fn new(p: &str) -> Self {
        // URLs are short: a small lazy-DFA cache (2 MB by default, per
        // thread) does.
        if let Ok(re) = regex::bytes::RegexBuilder::new(p)
            .unicode(false)
            .dfa_size_limit(1 << 17)
            .build()
        {
            return Compiled::Ascii(re);
        }
        match fancy_regex::RegexBuilder::new(p)
            .backtrack_limit(100_000)
            .build()
        {
            Ok(re) => Compiled::Fancy(re),
            Err(e) => {
                warn!("rewrite: invalid pattern {p:?}: {e}");
                Compiled::Invalid
            }
        }
    }

    fn is_match(&self, text: &str) -> bool {
        match self {
            Compiled::Ascii(re) => re.is_match(text.as_bytes()),
            Compiled::Fancy(re) => re.is_match(text).unwrap_or(false),
            Compiled::Invalid => false,
        }
    }
}

impl Patterns {
    fn new<'a>(patterns: impl Iterator<Item = &'a str>) -> Self {
        let mut sources = Vec::new();
        let mut by_host: HashMap<String, Vec<usize>> = HashMap::new();
        let mut unbound = Vec::new();
        for (i, p) in patterns.enumerate() {
            match bound_host(p) {
                Some(host) => by_host.entry(host).or_default().push(i),
                None => unbound.push(i),
            }
            sources.push(p.to_owned());
        }
        let compiled = sources.iter().map(|_| OnceLock::new()).collect();
        Self {
            sources,
            compiled,
            by_host,
            unbound,
        }
    }

    fn compiled(&self, i: usize) -> &Compiled {
        self.compiled[i].get_or_init(|| Compiled::new(&self.sources[i]))
    }

    /// The patterns that may match `url`, in order.
    fn candidates(&self, url: &str) -> Vec<usize> {
        let mut out = self.unbound.clone();
        if let Some(bound) = self.by_host.get(&url_host(url)) {
            out.extend(bound);
            out.sort_unstable();
        }
        out
    }

    /// The indexes matching `url`, in order.
    fn matching(&self, url: &str) -> Vec<usize> {
        self.candidates(url)
            .into_iter()
            .filter(|i| self.compiled(*i).is_match(url))
            .collect()
    }

    fn first(&self, url: &str) -> Option<usize> {
        self.candidates(url)
            .into_iter()
            .find(|i| self.compiled(*i).is_match(url))
    }

    /// `text` with pattern i's match replaced ($1 and the like).
    fn replace(&self, i: usize, text: &str, template: &str) -> String {
        match self.compiled(i) {
            Compiled::Ascii(re) => String::from_utf8_lossy(
                &re.replace(text.as_bytes(), template.as_bytes()),
            )
            .into_owned(),
            Compiled::Fancy(re) => re.replace(text, template).into_owned(),
            Compiled::Invalid => template.to_owned(),
        }
    }
}

/// The URL's host, lower case.
fn url_host(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let end = rest.find(['/', '?', '#', ':']).unwrap_or(rest.len());
    rest[..end].to_ascii_lowercase()
}

/// The host a pattern can only match URLs of: one anchored at a scheme and
/// a literal host, followed by the path, port, query or `$`
/// (`^https?:\/\/api\.example\.com\/`), with no alternative at its top
/// level. An unescaped dot in the host is taken for a dot.
fn bound_host(p: &str) -> Option<String> {
    if top_level_alternation(p) {
        return None;
    }
    let q = p.strip_prefix("(?i)").unwrap_or(p).strip_prefix('^')?;
    let q = ["http(s)?", "http[s]?", "https?", "https", "http"]
        .iter()
        .find_map(|s| q.strip_prefix(s))?;
    let q = q.strip_prefix(r":\/\/").or_else(|| q.strip_prefix("://"))?;
    let chars: Vec<char> = q.chars().collect();
    let mut host = String::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let next = if c == '\\' && matches!(chars.get(i + 1), Some('.' | '-')) {
            i += 2;
            chars[i - 1]
        } else if c.is_ascii_alphanumeric() || c == '-' || c == '.' {
            i += 1;
            c
        } else {
            break;
        };
        // A quantified character: not one host.
        if matches!(chars.get(i), Some('?' | '*' | '+' | '{')) {
            return None;
        }
        host.push(next.to_ascii_lowercase());
    }
    // Where the host ends (a pattern that stops inside it matches longer
    // hosts too).
    let rest: String = chars[i..].iter().collect();
    let ends = [r"\/", "/", ":", "$", r"\?"]
        .iter()
        .any(|e| rest.starts_with(e));
    (!host.is_empty() && ends).then_some(host)
}

/// Whether a `|` stands outside every group and class.
fn top_level_alternation(p: &str) -> bool {
    let mut depth = 0i32;
    let mut class = false;
    let mut chars = p.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                chars.next();
            }
            '[' if !class => class = true,
            ']' if class => class = false,
            '(' if !class => depth += 1,
            ')' if !class => depth -= 1,
            '|' if !class && depth == 0 => return true,
            _ => {}
        }
    }
    false
}

pub struct Rewriter {
    config: RewriteConfig,
    url: Patterns,
    map_local: Patterns,
    header: Patterns,
    body: Patterns,
    /// Body regular expressions, per rule and pair.
    body_res: Vec<Vec<(Option<fancy_regex::Regex>, String)>>,
    header_res: Vec<Option<fancy_regex::Regex>>,
    max_body: usize,
}

impl Rewriter {
    pub fn new(config: RewriteConfig) -> Self {
        let body_res = config
            .body
            .iter()
            .map(|b| {
                b.pairs
                    .iter()
                    .map(|(re, rep)| {
                        (
                            fancy_regex::RegexBuilder::new(&format!("(?m){re}"))
                                .backtrack_limit(100_000)
                                .build()
                                .ok(),
                            rep.clone(),
                        )
                    })
                    .collect()
            })
            .collect();
        let header_res = config
            .header
            .iter()
            .map(|h| {
                (h.action == "replace-regex")
                    .then(|| fancy_regex::Regex::new(&h.value).ok())
                    .flatten()
            })
            .collect();
        Self {
            url: Patterns::new(config.url.iter().map(|r| r.pattern.as_str())),
            map_local: Patterns::new(
                config.map_local.iter().map(|r| r.pattern.as_str()),
            ),
            header: Patterns::new(config.header.iter().map(|r| r.pattern.as_str())),
            body: Patterns::new(config.body.iter().map(|r| r.pattern.as_str())),
            body_res,
            header_res,
            max_body: config.max_body_size.unwrap_or(DEFAULT_MAX_BODY),
            config,
        }
    }

    fn rewrite_headers(
        &self,
        url: &str,
        response: bool,
        headers: &mut http::HeaderMap,
    ) {
        for i in self.header.matching(url) {
            let rule = &self.config.header[i];
            if rule.response != response {
                continue;
            }
            let Ok(name) = HeaderName::from_bytes(rule.name.as_bytes()) else {
                continue;
            };
            // Framing stays as it is (Surge refuses such changes).
            if name == header::CONTENT_LENGTH || name == header::TRANSFER_ENCODING {
                continue;
            }
            match rule.action.as_str() {
                "add" => {
                    if let Ok(v) = HeaderValue::from_str(&rule.value) {
                        headers.append(name, v);
                    }
                }
                "del" => {
                    headers.remove(&name);
                }
                "replace" => {
                    if headers.contains_key(&name)
                        && let Ok(v) = HeaderValue::from_str(&rule.value)
                    {
                        headers.insert(name, v);
                    }
                }
                "replace-regex" => {
                    let (Some(re), Some(current)) = (
                        &self.header_res[i],
                        headers.get(&name).and_then(|v| v.to_str().ok()),
                    ) else {
                        continue;
                    };
                    let new = re
                        .replace_all(current, rule.replacement.as_str())
                        .into_owned();
                    if let Ok(v) = HeaderValue::from_str(&new) {
                        headers.insert(name, v);
                    }
                }
                _ => {}
            }
        }
    }

    /// The body rules for this URL and direction.
    fn body_rules(&self, url: &str, response: bool) -> Vec<usize> {
        self.body
            .matching(url)
            .into_iter()
            .filter(|i| self.config.body[*i].response == response)
            .collect()
    }

    fn rewrite_text(&self, rules: &[usize], text: &str) -> String {
        let mut text = text.to_owned();
        for i in rules {
            for (re, rep) in &self.body_res[*i] {
                if let Some(re) = re {
                    text = re.replace_all(&text, rep.as_str()).into_owned();
                }
            }
        }
        text
    }
}

/// A local answer: status and headers, and the body.
fn answer(
    status: u16,
    content_type: Option<&str>,
    body: impl Into<Bytes>,
) -> Response<Body> {
    let mut resp = Response::new(full_body(body));
    *resp.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
    if let Some(ct) = content_type.and_then(|c| HeaderValue::from_str(c).ok()) {
        resp.headers_mut().insert(header::CONTENT_TYPE, ct);
    }
    resp
}

/// A 1-pixel transparent GIF.
const TINY_GIF: &[u8] = b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;";

fn reject(kind: &str) -> Option<Response<Body>> {
    Some(match kind {
        "reject" => answer(404, None, Bytes::new()),
        "reject-200" => answer(200, None, Bytes::new()),
        "reject-img" | "reject-tinygif" => {
            answer(200, Some("image/gif"), Bytes::from_static(TINY_GIF))
        }
        "reject-dict" => {
            answer(200, Some("application/json"), Bytes::from_static(b"{}"))
        }
        "reject-array" => {
            answer(200, Some("application/json"), Bytes::from_static(b"[]"))
        }
        _ => return None,
    })
}

/// A body read whole, or one larger than the limit: what was read, then
/// the rest, as it comes.
enum Collected {
    Whole(Bytes),
    TooLarge(Body),
}

async fn collect(mut body: Body, limit: usize) -> Result<Collected, hyper::Error> {
    let mut buf = BytesMut::new();
    while let Some(frame) = body.frame().await {
        // Trailers are dropped: nothing rewritten carries any.
        let Ok(data) = frame?.into_data() else {
            continue;
        };
        buf.extend_from_slice(&data);
        if buf.len() > limit {
            let head =
                futures::stream::once(async move { Ok(Frame::data(buf.freeze())) });
            let rest = BodyStream::new(body);
            return Ok(Collected::TooLarge(BodyExt::boxed(StreamBody::new(
                head.chain(rest),
            ))));
        }
    }
    Ok(Collected::Whole(buf.freeze()))
}

fn decompress(encoding: &str, data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    match encoding {
        "gzip" | "x-gzip" => flate2::read::GzDecoder::new(data)
            .read_to_end(&mut out)
            .ok()?,
        "deflate" => flate2::read::ZlibDecoder::new(data)
            .read_to_end(&mut out)
            .ok()
            .or_else(|| {
                out.clear();
                flate2::read::DeflateDecoder::new(data)
                    .read_to_end(&mut out)
                    .ok()
            })?,
        "" | "identity" => return Some(data.to_vec()),
        _ => return None,
    };
    Some(out)
}

#[cfg(test)]
fn gzip(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut e =
        flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    let _ = e.write_all(data);
    e.finish().unwrap_or_default()
}

#[async_trait]
impl HttpProcessor for Rewriter {
    fn wants(&self, url: &str) -> bool {
        [&self.url, &self.map_local, &self.header, &self.body]
            .iter()
            .any(|p| p.first(url).is_some())
    }

    async fn request(&self, url: &str, mut req: Request<Body>) -> RequestOutcome {
        self.rewrite_headers(url, false, req.headers_mut());

        if let Some(i) = self.url.first(url) {
            let rule = &self.config.url[i];
            debug!("rewrite {url}: {} ({})", rule.kind, rule.pattern);
            if let Some(resp) = reject(&rule.kind) {
                return RequestOutcome::Respond(resp);
            }
            match rule.kind.as_str() {
                "reject-drop" => return RequestOutcome::Drop,
                "302" | "307" => {
                    let location = self.url.replace(i, url, &rule.replacement);
                    let mut resp = answer(
                        if rule.kind == "302" { 302 } else { 307 },
                        None,
                        Bytes::new(),
                    );
                    if let Ok(v) = HeaderValue::from_str(&location) {
                        resp.headers_mut().insert(header::LOCATION, v);
                    }
                    return RequestOutcome::Respond(resp);
                }
                "header" => {
                    let new = self.url.replace(i, url, &rule.replacement);
                    if let Ok(uri) = new.parse::<Uri>() {
                        let same_host = uri.authority().map(|a| a.as_str())
                            == url
                                .parse::<Uri>()
                                .ok()
                                .and_then(|u| {
                                    u.authority().map(|a| a.as_str().to_owned())
                                })
                                .as_deref();
                        if same_host {
                            // The path changes on this connection.
                            let absolute = req.uri().scheme().is_some();
                            *req.uri_mut() = if absolute {
                                uri
                            } else {
                                uri.path_and_query()
                                    .map(|p| p.as_str())
                                    .unwrap_or("/")
                                    .parse()
                                    .unwrap_or_default()
                            };
                        } else {
                            // Another host: a redirect, the server here is the
                            // old one.
                            let mut resp = answer(307, None, Bytes::new());
                            if let Ok(v) = HeaderValue::from_str(&new) {
                                resp.headers_mut().insert(header::LOCATION, v);
                            }
                            return RequestOutcome::Respond(resp);
                        }
                    }
                }
                _ => {}
            }
        }

        if let Some(i) = self.map_local.first(url) {
            let rule = &self.config.map_local[i];
            let body = base64::engine::general_purpose::STANDARD
                .decode(&rule.body)
                .unwrap_or_default();
            let mut resp = answer(
                rule.status_code.unwrap_or(200),
                rule.content_type.as_deref(),
                body,
            );
            for (k, v) in &rule.headers {
                if let (Ok(k), Ok(v)) = (
                    HeaderName::from_bytes(k.as_bytes()),
                    HeaderValue::from_str(v),
                ) {
                    resp.headers_mut().insert(k, v);
                }
            }
            return RequestOutcome::Respond(resp);
        }

        // A response body to rewrite comes in an encoding read here.
        if !self.body_rules(url, true).is_empty() {
            req.headers_mut().insert(
                header::ACCEPT_ENCODING,
                HeaderValue::from_static("gzip, deflate"),
            );
        }

        let rules = self.body_rules(url, false);
        if !rules.is_empty() {
            let (parts, body) = req.into_parts();
            let bytes = match collect(body, self.max_body).await {
                Ok(Collected::Whole(bytes)) => bytes,
                Ok(Collected::TooLarge(body)) => {
                    return RequestOutcome::Forward(Request::from_parts(
                        parts, body,
                    ));
                }
                Err(e) => {
                    debug!("rewrite {url}: request body: {e}");
                    return RequestOutcome::Drop;
                }
            };
            let new = match std::str::from_utf8(&bytes) {
                Ok(text) => Bytes::from(self.rewrite_text(&rules, text)),
                Err(_) => bytes,
            };
            let mut req = Request::from_parts(parts, full_body(new.clone()));
            req.headers_mut()
                .insert(header::CONTENT_LENGTH, HeaderValue::from(new.len()));
            return RequestOutcome::Forward(req);
        }
        RequestOutcome::Forward(req)
    }

    async fn response(
        &self,
        url: &str,
        _method: &Method,
        mut resp: Response<Body>,
    ) -> Response<Body> {
        self.rewrite_headers(url, true, resp.headers_mut());
        let rules = self.body_rules(url, true);
        if rules.is_empty() {
            return resp;
        }
        // Larger than the limit by its length: as it is.
        let length = resp
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok()?.parse::<usize>().ok());
        if length.is_some_and(|l| l > self.max_body) {
            return resp;
        }
        let encoding = resp
            .headers()
            .get(header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();
        let (mut parts, body) = resp.into_parts();
        let bytes = match collect(body, self.max_body).await {
            Ok(Collected::Whole(bytes)) => bytes,
            Ok(Collected::TooLarge(body)) => {
                debug!(
                    "rewrite {url}: response body larger than {} bytes; not rewritten",
                    self.max_body
                );
                return Response::from_parts(parts, body);
            }
            Err(e) => {
                warn!("rewrite {url}: response body: {e}");
                return answer(502, None, Bytes::new());
            }
        };
        let Some(plain) = decompress(&encoding, &bytes) else {
            parts
                .headers
                .insert(header::CONTENT_LENGTH, HeaderValue::from(bytes.len()));
            return Response::from_parts(parts, full_body(bytes));
        };
        let new = match std::str::from_utf8(&plain) {
            Ok(text) => Bytes::from(self.rewrite_text(&rules, text)),
            Err(_) => Bytes::from(plain),
        };
        parts.headers.remove(header::CONTENT_ENCODING);
        parts.headers.remove(header::TRANSFER_ENCODING);
        parts
            .headers
            .insert(header::CONTENT_LENGTH, HeaderValue::from(new.len()));
        Response::from_parts(parts, full_body(new))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::def::{BodyRewrite, HeaderRewrite, MapLocal, UrlRewrite};

    fn rewriter() -> Rewriter {
        Rewriter::new(RewriteConfig {
            url: vec![
                UrlRewrite {
                    pattern: r"(?i)\b\/ad\/".into(),
                    replacement: "-".into(),
                    kind: "reject".into(),
                },
                UrlRewrite {
                    pattern: r"^https?://(www\.)?google\.cn/(.*)".into(),
                    replacement: "https://www.google.com/$2".into(),
                    kind: "302".into(),
                },
                UrlRewrite {
                    pattern: r"^https://a\.test/dict(?=\?)".into(),
                    replacement: "-".into(),
                    kind: "reject-dict".into(),
                },
            ],
            map_local: vec![MapLocal {
                pattern: r"^https://a\.test/splash".into(),
                body: base64::engine::general_purpose::STANDARD
                    .encode("{\"ads\":[]}"),
                content_type: Some("application/json".into()),
                ..Default::default()
            }],
            header: vec![HeaderRewrite {
                pattern: "^https://a\\.test/".into(),
                action: "add".into(),
                name: "X-Test".into(),
                value: "1".into(),
                ..Default::default()
            }],
            body: vec![BodyRewrite {
                response: true,
                pattern: "^https://a\\.test/page".into(),
                pairs: vec![("\"ad\":true".into(), "\"ad\":false".into())],
            }],
            ..Default::default()
        })
    }

    async fn status(r: &Rewriter, url: &str) -> (u16, String, Option<String>) {
        let req = Request::get(url).body(full_body(Bytes::new())).unwrap();
        match r.request(url, req).await {
            RequestOutcome::Respond(resp) => {
                let status = resp.status().as_u16();
                let location = resp
                    .headers()
                    .get(header::LOCATION)
                    .map(|v| v.to_str().unwrap().to_owned());
                let body = resp.into_body().collect().await.unwrap().to_bytes();
                (
                    status,
                    String::from_utf8_lossy(&body).into_owned(),
                    location,
                )
            }
            RequestOutcome::Forward(req) => (
                0,
                req.headers()
                    .get("x-test")
                    .map(|v| v.to_str().unwrap().to_owned())
                    .unwrap_or_default(),
                None,
            ),
            RequestOutcome::Drop => (1, String::new(), None),
        }
    }

    #[tokio::test]
    async fn requests() {
        let r = rewriter();
        assert_eq!(status(&r, "https://x.test/AD/1.png").await.0, 404);
        assert_eq!(
            status(&r, "http://google.cn/search?q=1").await,
            (
                302,
                String::new(),
                Some("https://www.google.com/search?q=1".into())
            )
        );
        assert_eq!(
            status(&r, "https://a.test/dict?x").await,
            (200, "{}".into(), None)
        );
        assert_eq!(
            status(&r, "https://a.test/splash").await,
            (200, "{\"ads\":[]}".into(), None)
        );
        // Passes, with the header added.
        assert_eq!(
            status(&r, "https://a.test/other").await,
            (0, "1".into(), None)
        );
    }

    #[tokio::test]
    async fn response_bodies_compressed_or_not() {
        let r = rewriter();
        for gz in [false, true] {
            let body = b"{\"ad\":true,\"x\":1}";
            let mut resp = Response::new(full_body(if gz {
                gzip(body)
            } else {
                body.to_vec()
            }));
            if gz {
                resp.headers_mut().insert(
                    header::CONTENT_ENCODING,
                    HeaderValue::from_static("gzip"),
                );
            }
            let out = r.response("https://a.test/page", &Method::GET, resp).await;
            assert!(out.headers().get(header::CONTENT_ENCODING).is_none());
            let text = out.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(&text[..], b"{\"ad\":false,\"x\":1}");
        }
    }

    #[test]
    fn patterns_bound_to_a_host() {
        assert_eq!(
            bound_host(r"^https?:\/\/api\.example\.com\/ad"),
            Some("api.example.com".into())
        );
        assert_eq!(
            bound_host(r"(?i)^https://A.example.com:8443/"),
            Some("a.example.com".into())
        );
        assert_eq!(
            bound_host(r"^http(s)?://x-y.test$"),
            Some("x-y.test".into())
        );
        for unbound in [
            r"(?i)\b\/ad\/",
            r"^https?:\/\/ads?\.example\.com\/",
            r"^https?:\/\/(www\.)?example\.com\/",
            r"^https?:\/\/.*\.example\.com\/",
            r"^https?:\/\/a\.com\/x|^https?:\/\/b\.com\/",
            r"^https?:\/\/a\.com(\/|$)",
            r"^https?:\/\/api\.example\.co",
        ] {
            assert_eq!(bound_host(unbound), None, "{unbound}");
        }
        assert!(!top_level_alternation(r"^https?:\/\/a\.com\/(x|y)[|]\|"));
        // Looked up by host; the others on every URL, in order.
        let p = Patterns::new(
            [
                r"(?i)\/ad\/",
                r"^https?:\/\/a\.test\/x",
                r"^https?:\/\/b\.test\/",
            ]
            .into_iter(),
        );
        assert_eq!(p.matching("https://a.test/x/ad/"), [0, 1]);
        assert_eq!(p.first("https://A.test:8443/x"), None);
        assert_eq!(p.first("http://a.test/x?q"), Some(1));
        assert_eq!(p.replace(1, "http://a.test/x1", "$0!"), "http://a.test/x!1");
    }

    #[tokio::test]
    async fn larger_bodies_pass_unchanged() {
        let r = Rewriter::new(RewriteConfig {
            body: vec![BodyRewrite {
                response: true,
                pattern: "^https://a\\.test/".into(),
                pairs: vec![("a".into(), "b".into())],
            }],
            max_body_size: Some(8),
            ..Default::default()
        });
        // Its length unknown until read: in chunks, more than the limit.
        let chunks = futures::stream::iter(
            ["aaaaa", "aaaaa", "aaaaa"]
                .map(|c| Ok::<_, hyper::Error>(Frame::data(Bytes::from(c)))),
        );
        let resp = Response::new(BodyExt::boxed(StreamBody::new(chunks)));
        let out = r.response("https://a.test/x", &Method::GET, resp).await;
        assert_eq!(
            &out.into_body().collect().await.unwrap().to_bytes()[..],
            b"aaaaaaaaaaaaaaa"
        );
        // A request is dropped where a rule says so.
        let r = Rewriter::new(RewriteConfig {
            url: vec![UrlRewrite {
                pattern: "^https://a\\.test/drop".into(),
                kind: "reject-drop".into(),
                ..Default::default()
            }],
            ..Default::default()
        });
        assert_eq!(status(&r, "https://a.test/drop").await.0, 1);
    }
}
