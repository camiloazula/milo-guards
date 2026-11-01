//! Runs every detector over a text and settles overlaps: the one place a
//! text is read.

use std::collections::BTreeMap;

use crate::mask::Mask;
use crate::reading::Reading;
use crate::{generic, pem, rows, Rule};

/// One thing found: the rule, the reason, where it is, and how a finding
/// about it is shown.
#[derive(Debug, Clone)]
pub(crate) struct Hit {
    pub(crate) rule: Rule,
    pub(crate) reason: &'static str,
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) mask: Mask,
}

/// What a text holds: it, read as it means, and every hit in that, in the
/// order it reads, none overlapping another. A hit's range is in the read
/// text; [`Reading::original`] carries it back.
pub(crate) struct Scan<'a> {
    pub(crate) reading: Reading<'a>,
    pub(crate) hits: Vec<Hit>,
}

/// Runs every detector over `text`.
///
/// Detectors run from the most specific to the least (a key block, a key of
/// a provider, a password in an address, a name assigned a value, then
/// personal data), and a hit that overlaps one already kept is dropped: a
/// GitHub token written after `token=` is a GitHub token, and an address
/// inside a password's URL is not found a second time.
pub(crate) fn scan(original: &str) -> Scan<'_> {
    let reading = Reading::new(original);
    let text = reading.text();
    // Only ASCII is folded, so a byte offset in `lower` is one in `text`.
    let lower = text.to_ascii_lowercase();
    let mut found = Vec::new();
    pem::scan(text, &lower, &mut found);
    let table = rows::table();
    rows::scan(&table.secrets, text, &lower, &mut found);
    generic::scan(text, &lower, &mut found);
    rows::scan(&table.personal, text, &lower, &mut found);
    let hits = settle(found);
    Scan { reading, hits }
}

/// Keeps the first of any hits that overlap, in the order they were found,
/// and returns them by position.
fn settle(found: Vec<Hit>) -> Vec<Hit> {
    let mut kept: BTreeMap<usize, Hit> = BTreeMap::new();
    for hit in found {
        if hit.start >= hit.end {
            continue;
        }
        let before = kept
            .range(..=hit.start)
            .next_back()
            .is_some_and(|(_, other)| other.end > hit.start);
        let after = kept
            .range(hit.start..)
            .next()
            .is_some_and(|(start, _)| *start < hit.end);
        if !before && !after {
            kept.insert(hit.start, hit);
        }
    }
    kept.into_values().collect()
}
