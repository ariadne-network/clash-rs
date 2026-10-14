//! idea: https://github.com/openacid/succinct
//! impl: https://github.com/MetaCubeX/mihomo/blob/Meta/component/trie/domain_set.go
//! I have no idea what's going on here, just copy the code from above link.

use super::trie::{StringTrie, valid_and_split_domain};

static COMPLEX_WILDCARD: u8 = b'+';
static WILDCARD: u8 = b'*';
static DOMAIN_STEP: u8 = b'.';

#[derive(Default)]
pub struct DomainSet {
    leaves: Vec<u64>,
    label_bit_map: Vec<u64>,
    labels: Vec<u8>,
    ranks: Vec<i32>,
    selects: Vec<i32>,
}

impl DomainSet {
    pub fn has(&self, key: &str) -> bool {
        let key = key
            .chars()
            .rev()
            .map(|x| x.to_ascii_lowercase())
            .collect::<Vec<_>>();
        let mut node_id = 0;
        let mut bm_idx = 0;

        struct Cursor {
            bm_idx: usize,
            index: usize,
        }

        let mut stack = vec![];

        #[derive(PartialEq)]
        enum State {
            Restart,
            Done,
        }

        let mut i: usize = 0;

        while i < key.len()
        // i++
        {
            let mut state = State::Restart;

            'ctrl: while state == State::Restart {
                state = State::Done;

                let c = key[i];
                loop
                // bm_idx++
                {
                    if get_bit(&self.label_bit_map, bm_idx) {
                        if !stack.is_empty() {
                            let cursor: Cursor = stack.pop().unwrap();
                            let next_node_id = count_zeros(
                                &self.label_bit_map,
                                &self.ranks,
                                cursor.bm_idx + 1,
                            );
                            let mut next_bm_idx = select_ith_one(
                                &self.label_bit_map,
                                &self.ranks,
                                &self.selects,
                                next_node_id - 1,
                            ) + 1;

                            let mut j = cursor.index;
                            while j < key.len() && key[j] != DOMAIN_STEP as char {
                                j += 1;
                            }
                            if j == key.len() {
                                if get_bit(&self.leaves, next_node_id as isize) {
                                    return true;
                                } else {
                                    state = State::Restart;
                                    continue 'ctrl;
                                }
                            }

                            while next_bm_idx - next_node_id < self.labels.len() {
                                if self.labels[next_bm_idx - next_node_id]
                                    == DOMAIN_STEP
                                {
                                    bm_idx = next_bm_idx as isize;
                                    node_id = next_node_id;
                                    i = j;

                                    state = State::Restart;
                                    continue 'ctrl;
                                }
                                next_bm_idx += 1;
                            }
                        }
                        return false;
                    }

                    if self.labels.is_empty() {
                        return false;
                    }

                    if self.labels[bm_idx as usize - node_id] == COMPLEX_WILDCARD {
                        return true;
                    } else if self.labels[bm_idx as usize - node_id] == WILDCARD {
                        let cursor = Cursor {
                            bm_idx: bm_idx as usize,
                            index: i,
                        };
                        stack.push(cursor);
                    } else if self.labels[bm_idx as usize - node_id] == c as u8 {
                        break;
                    }

                    bm_idx += 1;
                }

                node_id = count_zeros(
                    &self.label_bit_map,
                    &self.ranks,
                    bm_idx as usize + 1,
                );
                bm_idx = select_ith_one(
                    &self.label_bit_map,
                    &self.ranks,
                    &self.selects,
                    node_id - 1,
                ) as isize
                    + 1;

                i += 1;
            }
        }

        get_bit(&self.leaves, node_id as isize)
    }

    #[cfg(test)]
    pub fn traverse<F>(&self, mut f: F)
    where
        F: FnMut(&String) -> bool,
    {
        self.keys(|x| f(&x.chars().rev().collect::<String>()));
    }
}

impl DomainSet {
    pub(crate) fn from_mrs_parts(
        leaves: Vec<u64>,
        label_bit_map: Vec<u64>,
        labels: Vec<u8>,
    ) -> Self {
        let mut set = Self {
            leaves,
            label_bit_map,
            labels,
            ranks: Vec::new(),
            selects: Vec::new(),
        };
        set.init();
        set
    }

    fn init(&mut self) {
        self.ranks.clear(); // Ensure clean state
        self.selects.clear();

        self.ranks.push(0);
        for i in 0..self.label_bit_map.len() {
            let n = self.label_bit_map[i].count_ones();
            // Ensure ranks has enough capacity or handle potential panic if
            // last() is called on empty vec
            let last_rank = self.ranks.last().copied().unwrap_or(0);
            self.ranks.push(last_rank + n as i32);
        }

        let mut n: u64 = 0; // a bit counting
        let total_bits = self.label_bit_map.len() * 64;

        for i in 0..total_bits {
            let word_index = i >> 6;
            let bit_index = i & 63;

            if word_index >= self.label_bit_map.len() {
                break;
            }

            let is_set = (self.label_bit_map[word_index] >> bit_index) & 1;
            if is_set == 1 {
                if n & 63 == 0 {
                    // Check if it's the start of a select block (every 64th '1'
                    // bit)
                    self.selects.push(i as i32);
                }
                n += 1;
            }
        }
    }

    #[cfg(test)]
    fn keys<F>(&self, mut f: F)
    where
        F: FnMut(&String) -> bool,
    {
        let mut current_key = vec![];

        fn traverse<F>(
            this: &DomainSet,
            current_key: &mut Vec<char>,
            node_id: isize,
            bm_idx: isize,
            f: &mut F,
        ) -> bool
        where
            F: FnMut(&String) -> bool,
        {
            if get_bit(&this.leaves, node_id) && !f(&current_key.iter().collect()) {
                return false;
            }

            let mut bm_idx = bm_idx;

            loop {
                if get_bit(&this.label_bit_map, bm_idx) {
                    return true;
                }

                let next_label = this.labels[(bm_idx - node_id) as usize];
                current_key.push(next_label as char);
                let next_node_id = count_zeros(
                    &this.label_bit_map,
                    &this.ranks,
                    bm_idx as usize + 1,
                );
                let next_bm_idx = select_ith_one(
                    &this.label_bit_map,
                    &this.ranks,
                    &this.selects,
                    next_node_id - 1,
                ) + 1;

                if !traverse(
                    this,
                    current_key,
                    next_node_id as isize,
                    next_bm_idx as isize,
                    f,
                ) {
                    return false;
                }

                current_key.pop();

                bm_idx += 1;
            }
        }

        traverse(self, &mut current_key, 0, 0, &mut f);
    }
}

struct QElt {
    s: u32,
    e: u32,
    col: u32,
}

impl DomainSet {
    /// A set of domain rules ("example.com", "+.example.com" for it and its
    /// subdomains, ".example.com" for subdomains alone, "*" for one label),
    /// as `StringTrie` takes them, built without one (our fork): the trie of
    /// a list of 250,000 names took tens of MiB to build a set of four, and
    /// iOS ends a packet tunnel at about 50 MiB.
    pub fn from_rules<'a>(rules: impl IntoIterator<Item = &'a str>) -> Self {
        Self::build(rules, 0, 0)
    }

    /// The set of a list's lines. Its size sets aside what the build takes
    /// at once, which growing piecemeal left behind in the allocator.
    pub fn from_lines(text: &str) -> Self {
        let lines = text.bytes().filter(|b| *b == b'\n').count() + 1;
        Self::build(
            text.lines().map(str::trim).filter(|line| {
                !line.is_empty() && !line.starts_with('#') && !line.starts_with("//")
            }),
            text.len() * 2,
            lines * 2,
        )
    }

    fn build<'a>(
        rules: impl IntoIterator<Item = &'a str>,
        bytes_capacity: usize,
        keys_capacity: usize,
    ) -> Self {
        // The keys one after another, reversed, a byte per character in
        // lowercase as `has` reads them, with each one's start and length.
        let mut bytes: Vec<u8> = Vec::with_capacity(bytes_capacity);
        let mut spans: Vec<(u32, u32)> = Vec::with_capacity(keys_capacity);
        let mut add = |prefix: &str, name: &str| {
            let start = bytes.len();
            bytes.extend(
                name.chars()
                    .rev()
                    .chain(prefix.chars().rev())
                    .map(|c| c.to_ascii_lowercase() as u8),
            );
            spans.push((start as u32, (bytes.len() - start) as u32));
        };
        for rule in rules {
            let (Some(parts), true) = valid_and_split_domain(rule) else {
                continue;
            };
            match parts[0] {
                "+" if parts.len() > 1 => {
                    add("", &rule[2..]);
                    add("+.", &rule[2..]);
                }
                "+" => {}
                "" => add("+", rule),
                _ => add("", rule),
            }
        }
        let key = |&(start, len): &(u32, u32)| {
            &bytes[start as usize..start as usize + len as usize]
        };
        spans.sort_unstable_by(|a, b| key(a).cmp(key(b)));
        spans.dedup_by(|a, b| key(a) == key(b));
        Self::from_sorted(spans.len(), |i| key(&spans[i]))
    }

    /// The set of `len` keys, reversed, sorted and without duplicates.
    /// Nodes are numbered breadth first; the queue holds one level at a
    /// time (our fork: it kept an entry for every node, one per character
    /// of all keys).
    fn from_sorted<'a>(len: usize, key: impl Fn(usize) -> &'a [u8]) -> Self {
        let mut rv = DomainSet::default();
        if len == 0 {
            return rv;
        }
        // A label for each character that follows a key's longest common
        // prefix with the one before it, and a node for each label and the
        // root: the sizes, to allocate once.
        let labels = (0..len)
            .map(|i| {
                let k = key(i);
                let common = match i {
                    0 => 0,
                    _ => {
                        k.iter().zip(key(i - 1)).take_while(|(a, b)| a == b).count()
                    }
                };
                k.len() - common
            })
            .sum::<usize>();
        rv.labels.reserve_exact(labels);
        rv.label_bit_map
            .reserve_exact((2 * labels + 1).div_ceil(64) + 1);
        rv.leaves.reserve_exact((labels + 1).div_ceil(64) + 1);
        let at = |i: u32, col: u32| key(i as usize).get(col as usize).copied();
        let mut l_idx = 0;
        let mut queue = std::collections::VecDeque::from([QElt {
            s: 0,
            e: len as u32,
            col: 0,
        }]);
        let mut i = 0;
        while let Some(mut elt) = queue.pop_front() {
            if elt.col as usize == key(elt.s as usize).len() {
                elt.s += 1;
                set_bit(&mut rv.leaves, i, true);
            }

            let mut j = elt.s;
            while j < elt.e {
                let frm = j;
                while j < elt.e && at(j, elt.col) == at(frm, elt.col) {
                    j += 1;
                }

                queue.push_back(QElt {
                    s: frm,
                    e: j,
                    col: elt.col + 1,
                });
                if let Some(c) = at(frm, elt.col) {
                    rv.labels.push(c);
                    set_bit(&mut rv.label_bit_map, l_idx, false);
                    l_idx += 1;
                }
            }

            set_bit(&mut rv.label_bit_map, l_idx, true);
            l_idx += 1;
            i += 1;
        }

        rv.init();
        rv
    }
}

/// Convert a `StringTrie` to a `DomainSet`.
impl<T> From<StringTrie<T>> for DomainSet {
    fn from(value: StringTrie<T>) -> Self {
        let mut keys = vec![];
        value.traverse(|key, _| {
            keys.push(key.chars().rev().map(|c| c as u8).collect::<Vec<u8>>());
            true
        });
        keys.sort();
        keys.dedup();
        Self::from_sorted(keys.len(), |i| &keys[i])
    }
}

fn get_bit(bm: &[u64], i: isize) -> bool {
    if bm.is_empty() {
        return false;
    }
    bm[(i >> 6) as usize] & (1 << (i & 63) as usize) != 0
}

fn set_bit(bm: &mut Vec<u64>, i: usize, v: bool) {
    while i >> 6 >= (bm.len()) {
        bm.push(0);
    }
    bm[i >> 6] |= (v as u64) << (i & 63);
}

fn count_zeros(bm: &[u64], ranks: &[i32], i: usize) -> usize {
    i - ranks[i >> 6] as usize
        - (bm[i >> 6] & ((1 << (i & 63)) - 1)).count_ones() as usize
}

fn select_ith_one(bm: &[u64], ranks: &[i32], selects: &[i32], i: usize) -> usize {
    let base = selects[i >> 6] & !63;
    let mut find_ith_one = i as isize - ranks[base as usize >> 6] as isize;
    for (i, w) in bm.iter().enumerate().skip(base as usize >> 6) {
        let mut bit_idx = 0;
        let mut w = *w;
        while w > 0 {
            find_ith_one -= (w & 1) as isize;
            if find_ith_one < 0 {
                return (i << 6) + bit_idx;
            }

            let t0 = (w & !1).trailing_zeros();
            w = w.unbounded_shr(t0);
            bit_idx += t0 as usize;
        }
    }

    unreachable!("invalid data");
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    #[test]
    fn test_domain_set_complex_wildcard() {
        let mut tree = super::StringTrie::new();
        let domains = vec![
            "baidu.com",
            "google.com",
            "www.google.com",
            "test.a.net",
            "test.a.oc",
            "mijia cloud",
            ".qq.com",
            "+.cn",
        ];

        for d in domains {
            tree.insert(d, Arc::new(true));
        }

        let mut key_src = vec![];
        tree.traverse(|key, _| {
            key_src.push(key.to_owned());
            true
        });
        key_src.sort();

        let set = super::DomainSet::from(tree);
        assert!(set.has("test.cn"));
        assert!(set.has("cn"));
        assert!(set.has("mijia cloud"));
        assert!(set.has("test.a.net"));
        assert!(set.has("www.qq.com"));
        assert!(set.has("google.com"));
        assert!(!set.has("qq.com"));
        assert!(!set.has("www.baidu.com"));

        test_dump(&key_src, &set);
    }

    #[test]
    fn test_domain_set_wildcard() {
        let mut tree = super::StringTrie::new();
        let domains = vec![
            "*.*.*.baidu.com",
            "www.baidu.*",
            "stun.*.*",
            "*.*.qq.com",
            "test.*.baidu.com",
            "*.apple.com",
        ];

        for d in domains {
            tree.insert(d, Arc::new(true));
        }

        let mut key_src = vec![];
        tree.traverse(|key, _| {
            key_src.push(key.to_owned());
            true
        });
        key_src.sort();

        let set = super::DomainSet::from(tree);

        assert!(set.has("www.baidu.com"));
        assert!(set.has("test.test.baidu.com"));
        assert!(set.has("test.test.qq.com"));
        assert!(set.has("stun.ab.cd"));
        assert!(!set.has("test.baidu.com"));
        assert!(!set.has("www.google.com"));
        assert!(!set.has("a.www.google.com"));
        assert!(!set.has("test.qq.com"));
        assert!(!set.has("test.test.test.qq.com"));

        test_dump(&key_src, &set);
    }

    #[test]
    fn from_rules_as_through_the_trie() {
        let rules = [
            "baidu.com",
            "google.com",
            "www.google.com",
            ".qq.com",
            "+.cn",
            "+.example.org",
            "example.org",
            "*.*.qq.com",
            "stun.*.*",
            "www.baidu.*",
            "bad..name",
            "trailing.dot.",
            "",
        ];
        let mut tree = super::StringTrie::new();
        for d in rules {
            tree.insert(d, Arc::new(true));
        }
        let mut via_trie = vec![];
        super::DomainSet::from(tree).traverse(|key| {
            via_trie.push(key.to_owned());
            true
        });
        let mut direct = vec![];
        let set = super::DomainSet::from_rules(rules);
        set.traverse(|key| {
            direct.push(key.to_owned());
            true
        });
        assert_eq!(direct, via_trie);
        assert!(set.has("test.cn") && set.has("cn") && set.has("www.qq.com"));
        assert!(!set.has("qq.com") && !set.has("bad..name"));
        // Names in capitals match, as lookups are in lowercase.
        assert!(super::DomainSet::from_rules(["Example.COM"]).has("example.com"));
        assert!(!super::DomainSet::from_rules([]).has("example.com"));
    }

    fn test_dump(data_src: &Vec<String>, set: &super::DomainSet) {
        let mut data_set = vec![];
        set.traverse(|key| {
            data_set.push(key.to_owned());
            true
        });
        data_set.sort();

        assert_eq!(data_src, &data_set);
    }
}
