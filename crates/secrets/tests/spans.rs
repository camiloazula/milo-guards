//! A span is offsets, on character boundaries, and covers exactly what was
//! found: replacing every span leaves the rest of the text byte for byte as
//! it was, with multi-byte text around it.

mod common;

use common::{fill, pem, samples};
use milo_guards_secrets::{find, find_spans, Span};

/// `text` with every span replaced by `with`.
fn replaced(text: &str, spans: &[Span], with: &str) -> String {
    let mut out = String::new();
    let mut at = 0;
    for span in spans {
        out.push_str(&text[at..span.start]);
        out.push_str(with);
        at = span.end;
    }
    out.push_str(&text[at..]);
    out
}

#[test]
fn replacing_a_span_leaves_the_text_around_it_as_it_was() {
    for sample in samples() {
        for (front, back) in [
            ("", ""),
            ("é日本 ", " 😀ü"),
            ("\u{0}\u{7f}\n", "\r\n\u{200f}"),
            ("𝔘𝔫𝔦 ", " 𝔠𝔬𝔡𝔢"),
        ] {
            let text = format!("{front}{}{back}", sample.text());
            let spans = find_spans(&text);
            assert_eq!(spans.len(), 1, "{}: {text:?}", sample.reason);
            let span = spans[0];
            assert!(text.is_char_boundary(span.start), "{text:?}");
            assert!(text.is_char_boundary(span.end), "{text:?}");
            assert_eq!(&text[span.start..span.end], sample.secret, "{text:?}");
            assert_eq!(
                replaced(&text, &spans, "[hidden]"),
                format!("{front}{}[hidden]{}{back}", sample.before, sample.after),
                "{}",
                sample.reason
            );
        }
    }
}

#[test]
fn spans_are_in_order_apart_and_one_for_one_with_the_findings() {
    let text = format!(
        "é {} 日本 token=ghp_{} 😀 4111111111111111 u@acme.io 8.8.8.8 {}",
        pem("RSA PRIVATE KEY"),
        fill("FakeGitHub0", 36),
        pem("PRIVATE KEY"),
    );
    let spans = find_spans(&text);
    let assessment = find(&text);
    assert_eq!(spans.len(), assessment.findings().len());
    assert!(spans.len() >= 6, "{spans:?}");
    for (span, finding) in spans.iter().zip(assessment.findings()) {
        assert_eq!(span.rule, finding.rule);
        assert!(span.start < span.end && span.end <= text.len());
    }
    for pair in spans.windows(2) {
        assert!(pair[0].end <= pair[1].start, "{pair:?}");
    }
}

#[test]
fn a_secret_spelled_with_escapes_is_the_same_secret_and_its_span_is_the_whole_spelling() {
    let token = format!("ghp_{}", fill("FakeGitHub0", 36));
    let aws = ["AKIA", "FAKE2KEY3ID4TEST"].concat();
    for spelling in [
        token.replacen('_', "\\u005f", 1),
        token.replacen("gh", "%67%68", 1),
        token.replacen('p', "\\x70", 1),
        token.replacen('p', "&#112;", 1),
        token.replacen('p', "&#x70;", 1),
        aws.replacen('K', "\\u{4b}", 1),
        format!("{}\u{200b}{}", &token[..10], &token[10..]),
        format!("{}\u{feff}\u{ad}{}", &aws[..6], &aws[6..]),
    ] {
        let text = format!("é日 key={spelling} 😀");
        let spans = find_spans(&text);
        assert_eq!(spans.len(), 1, "{text:?}");
        let found = &text[spans[0].start..spans[0].end];
        assert_eq!(found, spelling.as_str(), "{text:?}");
        assert_eq!(replaced(&text, &spans, "[x]"), "é日 key=[x] 😀", "{text:?}");
    }
}

#[test]
fn an_escape_that_is_not_printable_ascii_is_left_alone() {
    // A line end, a control character and a letter that is not ASCII.
    for text in [
        "password=fake%0APass0word1",
        "token=\\u00e9FakeToken01",
        "api_key=fake&#10;ApiKey01",
    ] {
        let spans = find_spans(text);
        for span in &spans {
            assert!(text.is_char_boundary(span.start) && text.is_char_boundary(span.end));
        }
    }
    assert!(find("see %41KIA and \\u0041KI and &#65K").is_safe());
}

#[test]
fn a_percent_encoded_query_is_read() {
    let text = "https://x.io/?q=password%3Dfake%50ass0word1&x=1";
    let spans = find_spans(text);
    assert_eq!(spans.len(), 1);
    assert_eq!(&text[spans[0].start..spans[0].end], "fake%50ass0word1");
    let text = "https://x.io/?mail=alice%2Esmith%40acme.io";
    let spans = find_spans(text);
    assert_eq!(
        &text[spans[0].start..spans[0].end],
        "alice%2Esmith%40acme.io"
    );
}
