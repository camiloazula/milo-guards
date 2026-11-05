//! Whatever the text, reading it ends, never panics, and answers with spans
//! that are on character boundaries, in order and apart, a hostile text of a
//! megabyte among them. That such a text is read in time linear in its
//! length, because the table is built of regular expressions that never
//! backtrack and the hand loops do not rescan, is in `timing.rs`.

mod common;

use common::hostile::{hostile, HOSTILE};
use milo_guards_secrets::{find, find_high_entropy, find_spans, Span};

/// Pieces of what a table of secrets looks for, joined at random into text
/// no one expects: every prefix, name and separator it reads.
const PIECES: [&str; 74] = [
    "AKIA",
    "ASIA",
    "AIza",
    "ghp_",
    "gho_",
    "github_pat_",
    "glpat-",
    "xoxb-",
    "xapp-1-",
    "sk-",
    "sk-ant-",
    "sk-proj-",
    "sk_live_",
    "whsec_",
    "SG.",
    "npm_",
    "pypi-AgEI",
    "hf_",
    "cio",
    "shpat_",
    "eyJ",
    "eyJhbGciOiJIUzI1NiJ9.",
    "-----BEGIN PRIVATE KEY-----",
    "-----END PRIVATE KEY-----",
    "-----BEGIN ",
    "-----",
    "PRIVATE KEY",
    "Basic ",
    "Bearer ",
    "Authorization: ",
    "postgres://",
    "https://",
    "://",
    "user:pass@",
    "@",
    "password",
    "token",
    "secret",
    "api_key",
    "AccountKey=",
    "aws_secret_access_key",
    "=",
    ":",
    "\"",
    "'",
    "\\\"",
    "\\u0041",
    "%41",
    "&#65;",
    "\u{200b}",
    "\\n",
    "\n",
    "\r\n",
    " ",
    "\t",
    ".",
    "+",
    "-",
    "_",
    "/",
    "4111111111111111",
    "4111 1111",
    "123-45-6789",
    "8.8.8.8",
    "2606:4700::1111",
    "a@b.io",
    "+14155550132",
    "0",
    "9",
    "x",
    "Z",
    "é",
    "日本",
    "😀",
];

/// A small deterministic generator, so a failure names its seed.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> usize {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.0 >> 33) as usize
    }

    /// A number below `limit`.
    fn below(&mut self, limit: u32) -> u32 {
        u32::try_from(self.next() % usize::try_from(limit).unwrap_or(1)).unwrap_or(0)
    }
}

/// What every answer must hold: spans on boundaries, in order, apart, and one
/// finding for each.
fn check_answer(text: &str) {
    let spans = find_spans(text);
    let assessment = find(text);
    assert_eq!(spans.len(), assessment.findings().len(), "{text:?}");
    assert_eq!(assessment.is_safe(), spans.is_empty(), "{text:?}");
    let mut at = 0;
    for span in &spans {
        assert!(
            span.start >= at && span.start < span.end,
            "{text:?} {spans:?}"
        );
        assert!(span.end <= text.len(), "{text:?} {spans:?}");
        assert!(text.is_char_boundary(span.start), "{text:?} {spans:?}");
        assert!(text.is_char_boundary(span.end), "{text:?} {spans:?}");
        at = span.end;
    }
    for finding in assessment.findings() {
        let target = finding.target.as_deref().unwrap_or_default();
        assert!(!finding.reason.is_empty() && !target.is_empty(), "{text:?}");
    }
    check_entropy(text, &find_high_entropy(text, 3.0));
}

fn check_entropy(text: &str, spans: &[Span]) {
    let mut at = 0;
    for span in spans {
        assert!(span.start >= at && span.start < span.end && span.end <= text.len());
        assert!(text.is_char_boundary(span.start) && text.is_char_boundary(span.end));
        at = span.end;
    }
}

#[test]
fn random_text_never_panics() {
    let mut random = Lcg(7);
    for _ in 0..4_000 {
        let length = random.next() % 30;
        let text: String = (0..length)
            .map(|_| PIECES[random.next() % PIECES.len()])
            .collect();
        check_answer(&text);
    }
}

#[test]
fn random_characters_never_panic() {
    let mut random = Lcg(11);
    for _ in 0..2_000 {
        let length = random.next() % 80;
        let text: String = (0..length)
            .filter_map(|_| {
                // Mostly ASCII, with any character now and then.
                let code = if random.next().is_multiple_of(4) {
                    random.below(0x11_0000)
                } else {
                    random.below(0x80)
                };
                char::from_u32(code)
            })
            .collect();
        check_answer(&text);
    }
}

#[test]
fn every_prefix_of_every_piece_never_panics() {
    for piece in PIECES {
        for (at, _) in piece.char_indices() {
            check_answer(&piece[..at]);
            check_answer(&format!("{} {}", &piece[..at], &piece[at..]));
        }
        check_answer(&piece.repeat(50));
    }
}

/// The empty text is a case of `tests/cases/safe.cases`.
#[test]
fn a_lone_character_never_panics_and_is_answered_whole() {
    for text in [
        "\u{0}", "%", "\\", "&", "&#", "\\u", "\\u{", "%4", "&#6", "\u{200b}",
    ] {
        check_answer(text);
    }
}

// ---- hostile texts ----

/// Spans on boundaries, in order and apart: what [`check_answer`] holds,
/// without the findings, for a text too long to build them for each.
fn check_answer_spans_only(text: &str) {
    let mut at = 0;
    for span in find_spans(text) {
        assert!(span.start >= at && span.start < span.end && span.end <= text.len());
        assert!(text.is_char_boundary(span.start) && text.is_char_boundary(span.end));
        at = span.end;
    }
}

#[test]
fn a_megabyte_of_one_character_and_of_nested_quotes_is_answered_in_order() {
    // The time it takes is in `timing.rs`.
    for name in [
        "one character",
        "nested quotes",
        "base64",
        "partial prefixes",
    ] {
        check_answer_spans_only(&hostile(name, 1 << 20));
    }
}

#[test]
fn every_hostile_text_is_answered_in_order() {
    for name in HOSTILE {
        check_answer_spans_only(&hostile(name, 128 << 10));
    }
}
