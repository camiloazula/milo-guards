//! A URL judged by its host and scheme: what is safe, what is risky and under
//! which rule (a local machine, an address in no public range, a metadata
//! service, credentials, a scheme that is not the web, what cannot be read),
//! and the words and the target each finding carries. The cases are in
//! `tests/cases/urls.cases`; what stays here is made in a loop or checks
//! every answer of that file.

mod common;

use common::posix;
use milo_guards_url::{judge, Rule};

#[test]
fn every_case() {
    common::cases::check("urls");
}

#[test]
fn no_answer_shows_a_password() {
    const PASSWORDS: [&str; 4] = ["hunter2", "Hunter2", "p%40ss", "p@ss"];
    let cases = common::cases::load("urls");
    for case in &cases {
        let assessment = judge(&case.url, &case.paths);
        for password in PASSWORDS {
            assert!(
                !format!("{assessment:?}").contains(password),
                "{}: {:?} echoed {password}",
                case.at,
                case.url
            );
        }
    }
    // The file holds the URLs with a password: not a scan of none.
    let with_one = cases
        .iter()
        .filter(|case| PASSWORDS.iter().any(|password| case.url.contains(password)))
        .count();
    assert_eq!(with_one, 8, "the cases with a password");
}

#[test]
fn a_url_too_long_or_with_a_label_too_long_is_unreadable() {
    for url in [
        format!("https://example.com/{}", "a".repeat(8_200)),
        format!("http://example.com/{}", "a".repeat(70_000)),
        format!("https://{}.com/", "a".repeat(64)),
    ] {
        let found: Vec<Rule> = judge(&url, &posix())
            .findings()
            .iter()
            .map(|finding| finding.rule)
            .collect();
        assert!(found.contains(&Rule::Unreadable), "{found:?}");
    }
}

#[test]
fn a_url_at_the_limit_is_read() {
    let path = "a".repeat(8_192 - "https://example.com/".len());
    let at = format!("https://example.com/{path}");
    assert_eq!(at.len(), 8_192);
    assert!(judge(&at, &posix()).is_safe());
    assert!(!judge(&format!("{at}a"), &posix()).is_safe());
}
