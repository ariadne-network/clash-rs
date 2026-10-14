//! jq body rewrites (Surge's `http-request-jq` and `http-response-jq`),
//! with jaq: the body read as JSON, run through the filter, and its first
//! output written back. A filter is compiled once per thread: jaq's values
//! are not shared between threads.

use std::{cell::RefCell, collections::HashMap, rc::Rc};

use jaq_core::{
    Compiler, Ctx, Vars, data,
    load::{Arena, File, Loader},
    unwrap_valr,
};
use jaq_json::{Val, read};

type Filter = jaq_core::Filter<data::JustLut<Val>>;

thread_local! {
    /// Compiled filters by their code; None for one that does not compile.
    static FILTERS: RefCell<HashMap<String, Option<Rc<Filter>>>> =
        RefCell::new(HashMap::new());
}

fn compile(code: &str) -> Option<Filter> {
    let defs = jaq_core::defs()
        .chain(jaq_std::defs())
        .chain(jaq_json::defs());
    let funs = jaq_core::funs()
        .chain(jaq_std::funs())
        .chain(jaq_json::funs());
    let arena = Arena::default();
    let modules = Loader::new(defs)
        .load(&arena, File { code, path: () })
        .ok()?;
    Compiler::default().with_funs(funs).compile(modules).ok()
}

/// Whether `code` is a filter jaq compiles.
pub fn jq_compiles(code: &str) -> bool {
    compile(code).is_some()
}

/// The JSON `text` through the filter `code`: its first output; None when
/// the text is not JSON or the filter does not compile, fails or yields
/// nothing.
pub(crate) fn apply(code: &str, text: &str) -> Option<String> {
    let filter = FILTERS.with(|filters| {
        filters
            .borrow_mut()
            .entry(code.to_owned())
            .or_insert_with(|| compile(code).map(Rc::new))
            .clone()
    })?;
    let input = read::parse_single(text.as_bytes()).ok()?;
    let ctx = Ctx::<data::JustLut<Val>>::new(&filter.lut, Vars::new([]));
    let output = filter.id.run((ctx, input)).map(unwrap_valr).next()?.ok()?;
    Some(output.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_change_json() {
        let text = r#"{"data":{"ads":[1,2],"items":["a"]},"n":1}"#;
        let out = apply(".data.ads = [] | .n += 1", text).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["data"]["ads"], serde_json::json!([]));
        assert_eq!(v["data"]["items"], serde_json::json!(["a"]));
        assert_eq!(v["n"], 2);
        let out = apply(".data |= del(.ads)", text).unwrap();
        assert!(!out.contains("ads"));
        // Not JSON, or a filter that fails: no change.
        assert_eq!(apply(".a", "not json"), None);
        assert_eq!(apply("error(\"x\")", text), None);
        assert!(!jq_compiles(".data |="));
    }
}
