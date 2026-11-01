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

/// Runs every detector over `original`.
///
/// Detectors run from the most specific to the least (a key block, a key of
/// a provider, a password in an address, a name assigned a value, then
/// personal data). Hits that overlap become one hit that covers both, with
/// the rule of the more specific: a password written `password=Xy9!` and a
/// provider's key is one secret to a caller that scrubs it, and the span
/// that leaves a part of it behind is a leak.
pub(crate) fn scan(original: &str) -> Scan<'_> {
    let reading = Reading::new(original);
    let text = reading.text();
    // Only ASCII is folded, so a byte offset in `lower` is one in `text`.
    let lower = text.to_ascii_lowercase();
    let mut found = Vec::new();
    pem::scan(text, &lower, &mut found);
    let table = rows::table();
    rows::scan(&table.secrets, &reading, &lower, &mut found);
    generic::scan(&reading, &lower, &mut found);
    rows::scan(&table.personal, &reading, &lower, &mut found);
    let hits = settle(found);
    Scan { reading, hits }
}

/// Merges hits that overlap, in the order they were found (the more
/// specific first), and returns them by position.
fn settle(found: Vec<Hit>) -> Vec<Hit> {
    // Start of a kept hit, to the hit and the order it was found in.
    let mut kept: BTreeMap<usize, (usize, Hit)> = BTreeMap::new();
    for (order, hit) in found.into_iter().enumerate() {
        if hit.start >= hit.end {
            continue;
        }
        let (mut start, mut end) = (hit.start, hit.end);
        let mut winner = (order, hit);
        // The kept hits that overlap `start..end` are next to each other;
        // taking them widens the range, which may reach more.
        loop {
            let mut touching: Vec<usize> = kept
                .range(..=start)
                .next_back()
                .filter(|(_, (_, other))| other.end > start)
                .map(|(at, _)| *at)
                .into_iter()
                .collect();
            touching.extend(kept.range(start + 1..end).map(|(at, _)| *at));
            if touching.is_empty() {
                break;
            }
            for at in touching {
                if let Some((other_order, other)) = kept.remove(&at) {
                    start = start.min(other.start);
                    end = end.max(other.end);
                    if other_order < winner.0 {
                        winner = (other_order, other);
                    }
                }
            }
        }
        let (order, mut hit) = winner;
        // What a hit shows of its front is its own: a range that now begins
        // earlier begins with something else.
        if start != hit.start {
            hit.mask = Mask::Length;
        }
        hit.start = start;
        hit.end = end;
        kept.insert(start, (order, hit));
    }
    kept.into_values().map(|(_, hit)| hit).collect()
}
