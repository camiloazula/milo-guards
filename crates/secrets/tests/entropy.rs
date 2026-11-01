//! The entropy pass is a function of its own, never a part of `find`.

mod common;

use common::fill;
use milo_guards_secrets::{find, find_high_entropy, Rule};

/// A base64 string of `length` characters that looks random, made by a
/// fixed generator so that it is the same on every run and is no real key.
fn random_looking(seed: u64, length: usize) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut state = seed;
    (0..length)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            char::from(ALPHABET[(state >> 58) as usize])
        })
        .collect()
}

#[test]
fn a_random_looking_run_is_found_and_find_does_not_find_it() {
    let secret = random_looking(1, 40);
    let text = format!("value = \"{secret}\" # ok");
    assert!(find(&text).is_safe(), "{text}");
    let spans = find_high_entropy(&text, 4.5);
    assert_eq!(spans.len(), 1, "{text}");
    assert_eq!(spans[0].rule, Rule::GenericSecret);
    assert_eq!(
        &text[spans[0].start..spans[0].end],
        secret.trim_matches(['+', '/'])
    );
}

#[test]
fn the_threshold_decides() {
    let text = format!("x {}", random_looking(2, 40));
    assert_eq!(find_high_entropy(&text, 4.5).len(), 1);
    assert_eq!(find_high_entropy(&text, 7.0).len(), 0);
    assert_eq!(find_high_entropy(&text, 0.0).len(), 1);
    assert_eq!(find_high_entropy(&text, f64::INFINITY).len(), 0);
    assert_eq!(find_high_entropy(&text, f64::NAN).len(), 0);
}

#[test]
fn what_is_known_to_be_safe_is_not_a_guess() {
    let sha256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    let integrity = format!("sha512-{}==", random_looking(3, 86));
    for text in [
        "3f786850e387550fdab836ed7e6dc881de23001b".to_string(),
        sha256.to_string(),
        "550e8400-e29b-41d4-a716-446655440000".to_string(),
        integrity,
        // Words, identifiers and paths.
        "the quick brown fox jumps over the lazy dog 0123456789".to_string(),
        "parse_http_response_body_with_trailing_newline_and_more".to_string(),
        "ParseHttpResponseBodyWithTrailingNewlineAndMore2".to_string(),
        "/usr/local/lib/python3/site-packages/some_package/module".to_string(),
        "--no-default-features --all-targets --workspace-2".to_string(),
        // Too short, and no digit.
        random_looking(4, 19),
        fill("AbCdEfGhIjKlMnOpQrStUvWxYz", 60),
    ] {
        assert!(find_high_entropy(&text, 4.5).is_empty(), "{text}");
    }
}

#[test]
fn spans_are_in_order_apart_and_on_boundaries() {
    let a = random_looking(5, 30);
    let b = random_looking(6, 45);
    let text = format!("é日 {a}=={b} 😀 key={a}\n{b}");
    let spans = find_high_entropy(&text, 4.0);
    assert!(spans.len() >= 3, "{spans:?}");
    for span in &spans {
        assert!(text.is_char_boundary(span.start) && text.is_char_boundary(span.end));
        assert!(span.start < span.end);
    }
    for pair in spans.windows(2) {
        assert!(pair[0].end <= pair[1].start);
    }
}

#[test]
fn an_escaped_run_is_read_and_its_span_covers_the_spelling() {
    let secret = random_looking(7, 40);
    let spelled = secret.replacen(&secret[..1], "%41", 1);
    let text = format!("k {spelled} z");
    let spans = find_high_entropy(&text, 4.5);
    assert_eq!(spans.len(), 1, "{text}");
    assert!(text.is_char_boundary(spans[0].start) && text.is_char_boundary(spans[0].end));
}
