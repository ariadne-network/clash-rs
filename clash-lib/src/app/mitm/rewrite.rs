//! Rewrites on decrypted and plain HTTP (our fork), as Surge has them: URL
//! rewrite (header, 302, 307, reject and Loon's reject variants), header
//! rewrite, body rewrite with regular expressions, and map local. In
//! Surge's order: request headers, URL, map local, request body; then
//! response headers and body. Patterns match the full URL; those the
//! `regex` crate takes go into sets, matched at once (a module may have
//! hundreds), the rest (look-around) one by one.

use std::io::Read;

use async_trait::async_trait;
use base64::Engine as _;
use bytes::{Bytes, BytesMut};
use futures::StreamExt;
use http::{
    HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri, header,
};
use http_body_util::{BodyExt, BodyStream, StreamBody};
use hyper::body::Frame;
use regex::RegexSet;
use tracing::{debug, warn};

use super::{Body, HttpProcessor, RequestOutcome, full_body};
pub use crate::config::def::RewriteConfig;

const DEFAULT_MAX_BODY: usize = 1 << 20;

/// Patterns matched at once where the `regex` crate takes them.
struct Patterns {
    set: RegexSet,
    /// The indexes `set` holds, in order.
    in_set: Vec<usize>,
    /// The others (look-around), by index.
    fancy: Vec<(usize, fancy_regex::Regex)>,
    /// Every pattern compiled for replacement (None: fancy only).
    each: Vec<Option<regex::Regex>>,
    fancy_each: Vec<Option<fancy_regex::Regex>>,
}

impl Patterns {
    fn new<'a>(patterns: impl Iterator<Item = &'a str>) -> Self {
        let mut in_set = Vec::new();
        let mut set_patterns = Vec::new();
        let mut fancy = Vec::new();
        let mut each = Vec::new();
        let mut fancy_each = Vec::new();
        for (i, p) in patterns.enumerate() {
            match regex::Regex::new(p) {
                Ok(re) => {
                    in_set.push(i);
                    set_patterns.push(p.to_owned());
                    each.push(Some(re));
                    fancy_each.push(None);
                }
                Err(_) => match fancy_regex::RegexBuilder::new(p)
                    .backtrack_limit(100_000)
                    .build()
                {
                    Ok(re) => {
                        fancy.push((i, re.clone()));
                        each.push(None);
                        fancy_each.push(Some(re));
                    }
                    Err(e) => {
                        warn!("rewrite: invalid pattern {p:?}: {e}");
                        each.push(None);
                        fancy_each.push(None);
                    }
                },
            }
        }
        let set = RegexSet::new(&set_patterns).unwrap_or_else(|_| RegexSet::empty());
        Self {
            set,
            in_set,
            fancy,
            each,
            fancy_each,
        }
    }

    /// The indexes matching `text`, in order.
    fn matching(&self, text: &str) -> Vec<usize> {
        let mut out: Vec<usize> = self
            .set
            .matches(text)
            .iter()
            .map(|i| self.in_set[i])
            .collect();
        out.extend(
            self.fancy
                .iter()
                .filter(|(_, re)| re.is_match(text).unwrap_or(false))
                .map(|(i, _)| *i),
        );
        out.sort_unstable();
        out
    }

    fn first(&self, text: &str) -> Option<usize> {
        self.matching(text).into_iter().next()
    }

    /// `text` with pattern i's match replaced ($1 and the like).
    fn replace(&self, i: usize, text: &str, template: &str) -> String {
        if let Some(Some(re)) = self.each.get(i) {
            return re.replace(text, template).into_owned();
        }
        if let Some(Some(re)) = self.fancy_each.get(i) {
            return re.replace(text, template).into_owned();
        }
        template.to_owned()
    }
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
                    return RequestOutcome::Forward(Request::from_parts(parts, body));
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
