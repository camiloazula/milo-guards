//! One sample per row of the table: each finds exactly its secret, with the
//! rule and the reason of its row, and a finding never repeats the secret.

mod common;

use common::{pem, samples};
use milo_guards_secrets::{find, find_spans, Rule};

#[test]
fn every_row_finds_exactly_its_secret() {
    let mut wrong = Vec::new();
    for sample in samples() {
        let text = sample.text();
        let spans = find_spans(&text);
        let found: Vec<_> = spans
            .iter()
            .map(|span| (span.rule, &text[span.start..span.end]))
            .collect();
        if found != [(sample.rule, sample.secret.as_str())] {
            wrong.push(format!("{}: {text:?}\n    got {found:?}", sample.reason));
            continue;
        }
        let assessment = find(&text);
        let findings = assessment.findings();
        if findings.len() != 1
            || findings[0].rule != sample.rule
            || findings[0].reason != sample.reason
        {
            wrong.push(format!("{}: {text:?}\n    got {findings:?}", sample.reason));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} rows wrong:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

#[test]
fn every_rule_has_a_sample() {
    let rules: Vec<Rule> = samples().iter().map(|sample| sample.rule).collect();
    for rule in Rule::ALL {
        assert!(rules.contains(&rule), "{rule:?} has no sample");
    }
}

/// The longest run of characters a target shares with the secret at its
/// start: what a finding gives away of the front of a secret.
fn shared_front(target: &str, secret: &str) -> usize {
    secret
        .chars()
        .zip(target.chars())
        .take_while(|(a, b)| a == b)
        .count()
}

#[test]
fn no_target_or_reason_holds_the_secret() {
    for sample in samples() {
        let text = sample.text();
        let assessment = find(&text);
        for finding in assessment.findings() {
            let target = finding.target.as_deref().unwrap_or_default();
            let shown = format!("{} | {target}", finding.reason);
            assert!(
                !shown.contains(&sample.secret),
                "{}: {shown}",
                sample.reason
            );
            // No window of eight characters of the secret is in the answer,
            // except the first line of a block of key, which is the same on
            // every key.
            if sample.rule == Rule::PrivateKey && sample.secret.starts_with("-----") {
                assert!(target.starts_with("-----BEGIN "), "{target}");
                assert!(target.ends_with("PRIVATE KEY-----"), "{target}");
                assert!(!target.contains('\n'), "{target:?}");
                continue;
            }
            let chars: Vec<char> = sample.secret.chars().collect();
            for window in chars.windows(8) {
                let window: String = window.iter().collect();
                assert!(!shown.contains(&window), "{}: {shown}", sample.reason);
            }
            assert!(
                shared_front(target, &sample.secret) <= 4,
                "{}: {target}",
                sample.reason
            );
            assert!(
                target.ends_with(" chars)"),
                "{}: {target} shows no length",
                sample.reason
            );
        }
    }
}

#[test]
fn a_target_shows_the_prefix_and_the_length() {
    let key = ["AKIA", "FAKE2KEY3ID4TEST"].concat();
    let assessment = find(&format!("id = {key}"));
    assert_eq!(
        assessment.findings()[0].target.as_deref(),
        Some("AKIA… (20 chars)")
    );
    let token = format!(
        "ghp_{}",
        "FakeGitHub0".chars().cycle().take(36).collect::<String>()
    );
    let assessment = find(&token);
    assert_eq!(
        assessment.findings()[0].target.as_deref(),
        Some("ghp_… (40 chars)")
    );
}

#[test]
fn a_secret_that_begins_with_itself_shows_only_its_length() {
    let assessment = find("password=fakePass0word1");
    let finding = &assessment.findings()[0];
    assert_eq!(finding.target.as_deref(), Some("… (14 chars)"));
    let assessment = find("card 4111111111111111");
    assert_eq!(
        assessment.findings()[0].target.as_deref(),
        Some("… (16 chars)")
    );
}

#[test]
fn a_block_of_key_shows_its_first_line() {
    let assessment = find(&pem("OPENSSH PRIVATE KEY"));
    assert_eq!(
        assessment.findings()[0].target.as_deref(),
        Some("-----BEGIN OPENSSH PRIVATE KEY-----")
    );
}
