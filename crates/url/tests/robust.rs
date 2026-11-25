//! Whatever the text, judging it ends, never panics, never calls a URL or an
//! address it could not read safe, judges an address as the host of a URL
//! with it, and never repeats a password.

use milo_guards_core::testing::{posix, windows};
use milo_guards_url::{judge, judge_address, Rule};

/// Pieces of URL syntax, joined at random into text no parser expects.
const PIECES: [&str; 48] = [
    "http",
    "https",
    "file",
    "ftp",
    "javascript",
    ":",
    "//",
    "/",
    "\\",
    "@",
    "#",
    "?",
    "%",
    "%25",
    "%2e",
    "%00",
    "[",
    "]",
    "::",
    "::ffff:",
    "fe80::1",
    "127.0.0.1",
    "0x7f.1",
    "2130706433",
    "169.254.169.254",
    "localhost",
    "example.com",
    "xn--",
    "xn--r8jz45g",
    "user:hunter2",
    ".",
    "..",
    "-",
    "_",
    " ",
    "\t",
    "\n",
    "\u{0}",
    "\u{7f}",
    "\u{ff0e}",
    "\u{ff20}",
    "\u{200b}",
    "é",
    "例え",
    "ｌｏｃａｌｈｏｓｔ",
    "0",
    "9",
    "C:",
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
}

#[test]
fn random_text_never_panics_and_is_never_called_safe_unread() {
    let mut random = Lcg(7);
    for _ in 0..6_000 {
        let length = random.next() % 20;
        let text: String = (0..length)
            .map(|_| PIECES[random.next() % PIECES.len()])
            .collect();
        for paths in [posix(), windows()] {
            let assessment = judge(&text, &paths);
            // Never an empty `Risky`, and never repeating the password of
            // a URL that was not read.
            if let milo_guards_url::Assessment::Risky(findings) = &assessment {
                assert!(!findings.is_empty(), "{text:?}");
            }
            if assessment
                .findings()
                .iter()
                .any(|finding| finding.rule == Rule::Unreadable)
            {
                for finding in assessment.findings() {
                    if finding.rule == Rule::Unreadable {
                        assert_eq!(finding.target, None, "{text:?}");
                    }
                }
            }
            for finding in assessment.findings() {
                if finding.rule == Rule::Credentials {
                    let target = finding.target.as_deref().unwrap_or_default();
                    assert!(!target.contains("hunter2"), "{text:?} -> {target:?}");
                }
            }
            // A control character inside is never read as a URL.
            let inner = text.trim_matches([' ', '\t', '\n', '\r', '\x0c']);
            if inner.chars().any(char::is_control) {
                assert!(!assessment.is_safe(), "{text:?}");
                assert_eq!(assessment.findings()[0].rule, Rule::Unreadable, "{text:?}");
            }
            // White space around a URL changes nothing.
            assert_eq!(
                assessment,
                judge(&format!(" \t{text}\n "), &paths),
                "{text:?}"
            );
        }
    }
}

/// Pieces of addresses and what is around one, joined at random.
const ADDRESS_PIECES: [&str; 46] = [
    "%40",
    "%3a",
    "%2f",
    "127",
    "0",
    "1",
    "8",
    "10",
    "169",
    "254",
    "255",
    "256",
    "0x7f",
    "0x",
    "07",
    "ffff",
    "64",
    "ff9b",
    "2002",
    "fe80",
    "a9fe",
    ".",
    ".",
    ":",
    ":",
    "::",
    "[",
    "]",
    "%",
    "%25",
    "eth0",
    ":80",
    ":65536",
    "/",
    "@",
    " ",
    "\t",
    "\n",
    "\u{0}",
    "１",
    "。",
    "\u{ad}",
    "x",
    "8.8.8.8",
    "93.184.216.34",
    "2606:4700::1111",
];

/// The URLs whose host `text` is, if it is one: `http://TEXT/`, and
/// `http://[TEXT]/` for an IPv6 address with no brackets.
fn urls_of(text: &str) -> [String; 2] {
    [format!("http://{text}/"), format!("http://[{text}]/")]
}

#[test]
fn random_text_is_never_an_address_judged_unread_or_unlike_a_url_host() {
    let mut random = Lcg(13);
    let (mut compared, mut safe) = (0, 0);
    for _ in 0..20_000 {
        let length = random.next() % 12;
        let text: String = (0..length)
            .map(|_| ADDRESS_PIECES[random.next() % ADDRESS_PIECES.len()])
            .collect();
        let assessment = judge_address(&text);
        if let milo_guards_url::Assessment::Risky(findings) = &assessment {
            assert!(!findings.is_empty(), "{text:?}");
        }
        for finding in assessment.findings() {
            if finding.rule == Rule::Unreadable {
                assert_eq!(finding.target, None, "{text:?}");
            }
        }
        // A text with a `%` is never safe: a zone is read only on an
        // address that is a finding, and an escape is a spelling.
        if text.contains('%') {
            assert!(!assessment.is_safe(), "{text:?}");
        }
        // White space around an address changes nothing.
        assert_eq!(
            assessment,
            judge_address(&format!(" \t{text}\n ")),
            "{text:?}"
        );
        // An IPv6 zone is no part of a URL to the parser: the address is
        // the text without it.
        let trimmed = text.trim_matches([' ', '\t', '\n', '\r', '\x0c']);
        let (unzoned, zoned) = match trimmed.split_once('%') {
            Some((before, after)) if before.matches(':').count() >= 2 => {
                let close = after.find(']').map_or("", |at| &after[at..]);
                (format!("{before}{close}"), true)
            }
            _ => (trimmed.to_string(), false),
        };
        // A text that holds none of what a URL holds around its host is
        // judged as the host of a URL with it, whenever that URL's host is
        // an address (a zone that is not read, or holds a control
        // character, leaves it unread); and it is safe only then.
        let plain = !unzoned.contains(['/', '?', '#', '\\', '@', '%']);
        let host = urls_of(&unzoned).into_iter().find_map(|url| {
            let parsed = url::Url::parse(&url).ok()?;
            matches!(parsed.host(), Some(url::Host::Ipv4(_) | url::Host::Ipv6(_))).then_some(url)
        });
        let unread = matches!(assessment.findings(), [finding] if finding.rule == Rule::Unreadable);
        match host {
            Some(_) if zoned && unread => {}
            Some(url) if plain => {
                assert_eq!(assessment, judge(&url, &posix()), "{text:?} as {url:?}");
                compared += 1;
            }
            _ => assert!(!assessment.is_safe(), "{text:?}"),
        }
        safe += usize::from(assessment.is_safe());
    }
    // The pieces make addresses, public ones among them: not a scan of none.
    assert!(compared > 1_000, "only {compared} compared");
    assert!(safe > 100, "only {safe} safe");
}

#[test]
fn an_address_too_long_is_not_read() {
    for text in [
        format!("{}127.0.0.1", "0".repeat(70_000)),
        format!("8.8.8.8:{}", "0".repeat(70_000)),
        format!("[{}]", "0:".repeat(40_000)),
        format!("fe80::1%{}", "a".repeat(70_000)),
        "١".repeat(30_000),
    ] {
        let assessment = judge_address(&text);
        assert_eq!(assessment.findings().len(), 1);
        assert_eq!(assessment.findings()[0].rule, Rule::Unreadable);
        assert_eq!(assessment.findings()[0].target, None);
    }
}

#[test]
fn deep_and_odd_addresses_inside_the_limit_end_and_are_never_safe() {
    for text in [
        format!("{}1", "1.".repeat(4_000)),
        format!("[{}]", ":".repeat(4_000)),
        format!("{}::1", "[".repeat(4_000)),
        format!("::1{}", "%".repeat(4_000)),
        "0x".repeat(4_000),
        format!("127.0.0.1:{}", ":".repeat(4_000)),
        "\u{ad}".repeat(2_000),
    ] {
        let assessment = judge_address(&text);
        assert!(!assessment.is_safe(), "{text:?}");
    }
}

#[test]
fn text_with_a_password_never_shows_it() {
    let mut random = Lcg(11);
    for _ in 0..3_000 {
        let length = random.next() % 10;
        let tail: String = (0..length)
            .map(|_| PIECES[random.next() % PIECES.len()])
            .collect();
        for text in [
            format!("http://me:hunter2@{tail}"),
            format!("https://me:hunter2@example.com/{tail}"),
            format!("ftp://hunter2@{tail}"),
        ] {
            let assessment = judge(&text, &posix());
            for finding in assessment.findings() {
                let shown = format!(
                    "{} {}",
                    finding.reason,
                    finding.target.as_deref().unwrap_or("")
                );
                // The password may appear in a path the caller wrote after
                // the host, and in a target that is the URL itself only
                // there; the user-info never does.
                if !tail.contains("hunter2") {
                    assert!(!shown.contains("hunter2"), "{text:?} -> {shown:?}");
                }
            }
        }
    }
}

#[test]
fn a_url_too_long_is_not_read() {
    for text in [
        format!("https://example.com/{}", "a".repeat(70_000)),
        format!("https://{}.com/", "a.".repeat(40_000)),
        format!("http://{}/", "[".repeat(50_000)),
        format!("http://{}/", "@".repeat(50_000)),
        format!("http://{}/", "%".repeat(50_000)),
        "http://".to_string() + &"é".repeat(30_000),
        "a".repeat(1_000_000),
    ] {
        let assessment = judge(&text, &posix());
        assert_eq!(assessment.findings().len(), 1);
        assert_eq!(assessment.findings()[0].rule, Rule::Unreadable);
        assert_eq!(assessment.findings()[0].target, None);
    }
}

#[test]
fn deep_and_odd_text_inside_the_limit_still_ends() {
    for text in [
        format!("http://{}/", "a.".repeat(4_000)),
        format!("http://{}/", "xn--a.".repeat(1_300)),
        format!("http://[{}]/", ":".repeat(4_000)),
        format!("http://{}@example.com/", "u:p@".repeat(2_000)),
        format!("file:///{}", "../".repeat(2_500)),
        format!("file:///{}", "%2e%2e/".repeat(1_000)),
        format!("http://example.com/{}", "?#".repeat(3_000)),
        format!("http://{}", "0x".repeat(3_000)),
        format!("http://{}", "1.".repeat(3_000)),
    ] {
        let assessment = judge(&text, &posix());
        assert!(!assessment.findings().is_empty() || assessment.is_safe());
    }
}
