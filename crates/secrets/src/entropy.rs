//! The entropy pass: shapeless secrets, found by how random they look.

use crate::{Rule, Span};

/// The shortest run read as a secret.
const MIN_LENGTH: usize = 20;

/// Spans of `text` that look random: each run of base64 and base64url
/// characters at least 20 long, with a letter and a digit in it, whose
/// Shannon entropy is at least `bits` per character.
pub(crate) fn find(text: &str, bits: f64) -> Vec<Span> {
    let bytes = text.as_bytes();
    let mut spans = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        if !is_token_byte(bytes[at]) {
            at += 1;
            continue;
        }
        let start = at;
        while bytes.get(at).copied().is_some_and(is_token_byte) {
            at += 1;
        }
        // Dashes, underscores, slashes and signs frame a token: option
        // names (`--flag`), paths and padding are not part of it.
        let token = &bytes[start..at];
        let lead = token.iter().take_while(|b| is_edge(**b)).count();
        let trail = token.iter().rev().take_while(|b| is_edge(**b)).count();
        if lead + trail >= token.len() {
            continue;
        }
        let (from, to) = (start + lead, at - trail);
        let token = &bytes[from..to];
        if token.len() >= MIN_LENGTH && is_candidate(token) && entropy(token) >= bits {
            spans.push(Span {
                rule: Rule::GenericSecret,
                start: from,
                end: to,
            });
        }
    }
    spans
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'_' | b'-')
}

fn is_edge(byte: u8) -> bool {
    matches!(byte, b'+' | b'/' | b'_' | b'-')
}

/// Whether the run has a letter and a digit and is none of the shapes known
/// to be safe: a hash (32, 40, 56, 64, 96 or 128 hex digits), a UUID, a
/// lockfile's integrity hash (`sha512-…`).
fn is_candidate(token: &[u8]) -> bool {
    let letter = token.iter().any(u8::is_ascii_alphabetic);
    let digit = token.iter().any(u8::is_ascii_digit);
    letter && digit && !is_hash(token) && !is_uuid(token) && !is_integrity(token)
}

fn is_hash(token: &[u8]) -> bool {
    matches!(token.len(), 32 | 40 | 56 | 64 | 96 | 128) && token.iter().all(u8::is_ascii_hexdigit)
}

fn is_uuid(token: &[u8]) -> bool {
    token.len() == 36
        && token.iter().enumerate().all(|(place, &byte)| {
            if matches!(place, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

fn is_integrity(token: &[u8]) -> bool {
    [&b"sha1-"[..], b"sha256-", b"sha384-", b"sha512-"]
        .iter()
        .any(|prefix| token.starts_with(prefix))
}

/// Shannon entropy of the bytes, in bits per byte.
#[allow(
    clippy::cast_precision_loss,
    reason = "counts of bytes, far below 2^52"
)]
fn entropy(token: &[u8]) -> f64 {
    let mut counts = [0usize; 256];
    for &byte in token {
        counts[usize::from(byte)] += 1;
    }
    let total = token.len() as f64;
    counts
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let share = count as f64 / total;
            -share * share.log2()
        })
        .sum()
}
