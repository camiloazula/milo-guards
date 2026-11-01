//! Whatever the text, reading it ends, never panics, and answers with spans
//! that are on character boundaries, in order and apart; and a hostile text
//! of a megabyte is read in time linear in its length, because the table is
//! built of regular expressions that never backtrack and the hand loops do
//! not rescan.
//!
//! The time is measured here: the crate keeps no clock.

#![allow(
    clippy::disallowed_methods,
    reason = "the guard keeps no clock; only this test times it, to catch a quadratic read"
)]

use std::time::{Duration, Instant};

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

#[test]
fn an_empty_text_and_a_lone_character_are_safe() {
    assert!(find("").is_safe());
    for text in [
        "\u{0}", "%", "\\", "&", "&#", "\\u", "\\u{", "%4", "&#6", "\u{200b}",
    ] {
        check_answer(text);
    }
}

// ---- time ----

/// A hostile text of about `size` bytes, by name.
fn hostile(name: &str, size: usize) -> String {
    let repeat = |unit: &str| unit.repeat(size / unit.len() + 1);
    match name {
        "one character" => repeat("A"),
        "digits" => repeat("1"),
        "spaces" => repeat(" "),
        "quotes" => repeat("\"'"),
        "nested quotes" => format!("{}{}", repeat("{\"a\":\""), repeat("\"}")),
        "escaped quotes" => repeat("\\\""),
        "at signs" => repeat("@"),
        "a at" => repeat("a@"),
        "emails" => repeat("a@b.c"),
        "colons" => repeat(":"),
        "one name" => format!("token={}", repeat(" ")),
        "names" => repeat("token="),
        "names in names" => repeat("a="),
        "open quotes" => repeat("password=\""),
        "key prefixes" => repeat("AKIA"),
        "token prefixes" => repeat("ghp_"),
        "partial prefixes" => repeat("sk-ant-api03-AKIA-ghp_-xoxb-eyJ-SG.-npm_-hf_ "),
        "jwt parts" => repeat("eyJaaaaaaaaaa."),
        "key headers" => repeat("-----BEGIN PRIVATE KEY-----"),
        "one key" => format!("-----BEGIN PRIVATE KEY-----{}", repeat("A")),
        "base64" => repeat("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5+/"),
        "dots" => repeat("1.2.3.4."),
        "addresses" => repeat("8.8.8.8 "),
        "cards" => repeat("4111111111111111 "),
        "card groups" => repeat("4111 "),
        "phones" => repeat("+1234567890 "),
        "escapes" => repeat("%41"),
        "unicode escapes" => repeat("\\u0041"),
        "open escapes" => repeat("\\u{"),
        "entities" => repeat("&#6"),
        "invisible" => repeat("\u{200b}"),
        "scheme parts" => repeat("a://b:c@"),
        "bearers" => repeat("Bearer "),
        "basics" => repeat("Basic AAAAAAAA "),
        "wide characters" => repeat("é日本😀"),
        "spans of escaped names" => repeat("password=\"%22"),
        "spans of escaped keys" => repeat("%41KIAQ7FAKE2TESTK3YZW "),
        "spans of escaped values" => repeat("%41 password=F4kePass9 "),
        "escaped tokens" => repeat("Q7wE9%41rT2yU4%42iO6pA8sD0%43kL1zX3 "),
        "rejected values" => repeat("token=["),
        "rejected references" => repeat("password=${"),
        "documented examples" => repeat("password=EXAMPLE"),
        "stand-ins" => repeat("secret=CHANGE_ME_"),
        "escaped separators" => repeat("password=%26"),
        "unclosed quotes" => repeat("password=\"a "),
        "armour lines" => repeat("-----BEGIN PRIVATE KEY-----A:"),
        "armour headers" => repeat("-----BEGIN PGP PRIVATE KEY BLOCK-----\nA: b\n"),
        "backslashes" => format!("-----BEGIN PRIVATE KEY-----{}", repeat("\\")),
        "line ends" => format!("-----BEGIN PRIVATE KEY-----{}", repeat("\\n")),
        "putty files" => repeat("Private-Lines: 99\n"),
        "netrc words" => repeat("machine password "),
        "signatures" => repeat("?sig="),
        "telegram parts" => repeat("1234567890:AA"),
        "key and secret" => repeat("AKIAFAKE2KEY3ID4TEST,"),
        other => unreachable!("{other}"),
    }
}

const HOSTILE: [&str; 54] = [
    "one character",
    "digits",
    "spaces",
    "quotes",
    "nested quotes",
    "escaped quotes",
    "at signs",
    "a at",
    "emails",
    "colons",
    "one name",
    "names",
    "names in names",
    "open quotes",
    "key prefixes",
    "token prefixes",
    "partial prefixes",
    "jwt parts",
    "key headers",
    "one key",
    "base64",
    "dots",
    "addresses",
    "cards",
    "card groups",
    "phones",
    "escapes",
    "unicode escapes",
    "open escapes",
    "entities",
    "invisible",
    "scheme parts",
    "bearers",
    "basics",
    "wide characters",
    "spans of escaped names",
    "spans of escaped keys",
    "spans of escaped values",
    "escaped tokens",
    "rejected values",
    "rejected references",
    "documented examples",
    "stand-ins",
    "escaped separators",
    "unclosed quotes",
    "armour lines",
    "armour headers",
    "backslashes",
    "line ends",
    "putty files",
    "netrc words",
    "signatures",
    "telegram parts",
    "key and secret",
];

/// The best of `runs` reads of `text`: noise only ever adds.
fn timed(text: &str, runs: usize) -> Duration {
    (0..runs)
        .map(|_| {
            let started = Instant::now();
            let _ = find_spans(text);
            let _ = find_high_entropy(text, 4.5);
            started.elapsed()
        })
        .min()
        .unwrap_or_default()
}

#[test]
fn a_megabyte_of_one_character_and_of_nested_quotes_is_read_in_a_bound() {
    for name in [
        "one character",
        "nested quotes",
        "base64",
        "partial prefixes",
    ] {
        let text = hostile(name, 1 << 20);
        let took = timed(&text, 1);
        assert!(took < LIMIT, "{name} took {took:?}");
        check_answer_spans_only(&text);
    }
}

/// Far above what a read of this size takes (under a second in a build with
/// no optimisation), far below what a quadratic one would take.
const LIMIT: Duration = Duration::from_secs(10);

#[test]
fn every_hostile_text_is_read_in_a_bound() {
    for name in HOSTILE {
        let text = hostile(name, 128 << 10);
        let took = timed(&text, 1);
        assert!(took < LIMIT, "{name} took {took:?}");
        check_answer_spans_only(&text);
    }
}

fn check_answer_spans_only(text: &str) {
    let mut at = 0;
    for span in find_spans(text) {
        assert!(span.start >= at && span.start < span.end && span.end <= text.len());
        assert!(text.is_char_boundary(span.start) && text.is_char_boundary(span.end));
        at = span.end;
    }
}

#[test]
fn reading_takes_time_in_proportion_to_the_text() {
    // Four times the text takes about four times as long to read; a read
    // that rescans takes sixteen. The bound is ten, with a floor under the
    // short time so a fast machine's noise is not a ratio.
    let floor = Duration::from_millis(25);
    for name in HOSTILE {
        let small = timed(&hostile(name, 32 << 10), 2);
        let large = timed(&hostile(name, 128 << 10), 2);
        assert!(
            large < small.max(floor) * 10,
            "{name}: {small:?} for 32 KiB, {large:?} for 128 KiB"
        );
    }
}
