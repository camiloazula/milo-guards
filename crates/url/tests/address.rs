//! An address the caller resolved a name to or connected to, judged by
//! `judge_address` with `judge`'s tables and reading. The cases of what only
//! an address meets (a port, brackets, a zone, a text that is not an
//! address) are in `tests/cases/address.cases`; what stays here holds the
//! two functions to one answer: every address that is the host of a URL in
//! any case file, as the parser writes it and as the case wrote it, gets
//! from `judge_address` the finding `judge` gives, so a case added to any
//! file later is checked too.

mod common;

use common::cases::{format, Case};
use common::posix;
use milo_guards_url::{judge, judge_address, Assessment, Finding, Rule};
use url::{Host, Url};

/// The white space `judge` trims around a URL.
const AROUND: [char; 5] = [' ', '\t', '\n', '\r', '\x0c'];

#[test]
fn every_case() {
    common::cases::check("address");
}

/// The address the host of `url` is, as the parser reads it and `judge`
/// judges it, or `None` for a name, a URL with no host, and a URL `judge`
/// does not read (empty, too long, with a control character inside).
fn address_of(url: &str) -> Option<Host<String>> {
    let text = url.trim_matches(AROUND);
    if text.is_empty() || text.len() > 8_192 || text.chars().any(char::is_control) {
        return None;
    }
    let parsed = Url::parse(text).ok()?;
    // A host of a scheme the parser does not know is kept as text, and
    // `judge` reads it as a web host is read.
    let host = match parsed.host()? {
        Host::Domain(name) => Host::parse(name).ok()?,
        other => other.to_owned(),
    };
    matches!(host, Host::Ipv4(_) | Host::Ipv6(_)).then_some(host)
}

/// The host of `url` as it is written, with its port: after the last `@` of
/// the authority. `None` when there is no `://` to start an authority at.
fn written_host(url: &str) -> Option<&str> {
    let (_, after) = url.trim_matches(AROUND).split_once("://")?;
    let end = after.find(['/', '?', '#', '\\']).unwrap_or(after.len());
    let authority = &after[..end];
    Some(authority.rsplit('@').next().unwrap_or(authority))
}

/// The cases of every case file but the addresses' own.
fn url_cases() -> Vec<Case> {
    format::names()
        .iter()
        .flat_map(|name| common::cases::load(name))
        .filter(|case| !case.address)
        .collect()
}

/// What `judge` finds of `host` in `assessment`: the local address or
/// metadata finding whose target is the host.
fn host_findings(assessment: &Assessment, host: &str) -> Vec<Finding> {
    assessment
        .findings()
        .iter()
        .filter(|finding| {
            matches!(finding.rule, Rule::LocalAddress | Rule::Metadata)
                && finding.target.as_deref() == Some(host)
        })
        .cloned()
        .collect()
}

#[test]
fn every_address_a_url_case_fetches_gets_the_finding_judge_gives() {
    let mut checked = 0;
    let mut wrong = Vec::new();
    for case in url_cases() {
        let Some(host) = address_of(&case.url) else {
            continue;
        };
        let written = host.to_string();
        let expected = host_findings(&judge(&case.url, &case.paths), &written);
        let mut texts = vec![written.clone()];
        if let Host::Ipv6(_) = host {
            texts.push(written.trim_matches(['[', ']']).to_string());
        }
        for text in texts {
            let got = judge_address(&text);
            if got.findings() != expected {
                wrong.push(format!(
                    "{}: {:?} is the address {text:?}\n    judge found {expected:?}\n    judge_address {got:?}",
                    case.at, case.url
                ));
            }
            checked += 1;
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    // The case files hold many addresses: not a scan of none.
    assert!(checked > 200, "only {checked} addresses checked");
}

#[test]
fn every_address_a_url_case_spells_is_read_as_judge_reads_it() {
    let mut checked = 0;
    let mut wrong = Vec::new();
    for case in url_cases() {
        let (Some(host), Some(written)) = (address_of(&case.url), written_host(&case.url)) else {
            continue;
        };
        // As the case spells it, port included, the address is the host of
        // an `http` URL with the same answer.
        let url = format!("http://{written}/");
        if address_of(&url).as_ref() != Some(&host) {
            wrong.push(format!(
                "{}: {:?} spells {written:?}, which is not the host of {url:?}",
                case.at, case.url
            ));
            continue;
        }
        let (got, expected) = (judge_address(written), judge(&url, &posix()));
        if got != expected {
            wrong.push(format!(
                "{}: {written:?}\n    judge({url:?}) is {expected:?}\n    judge_address is {got:?}",
                case.at
            ));
        }
        checked += 1;
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    assert!(checked > 150, "only {checked} spellings checked");
}

/// The URL whose host `address` is, when it has one that `judge` reads as
/// an address: `http://ADDRESS/`, or `http://[ADDRESS]/` for an IPv6 address
/// with no brackets, with its zone taken off (a zone is no part of a URL to
/// the parser, and is not judged).
fn url_of(address: &str) -> Option<String> {
    let text = address.trim_matches(AROUND);
    let unzoned = match text.split_once('%') {
        Some((before, after)) if before.matches(':').count() >= 2 => {
            let close = after.find(']').map_or("", |at| &after[at..]);
            format!("{before}{close}")
        }
        _ => text.to_string(),
    };
    [format!("http://{unzoned}/"), format!("http://[{unzoned}]/")]
        .into_iter()
        .find(|url| address_of(url).is_some())
}

/// Whether `assessment` says only that its text cannot be read.
fn unread(assessment: &Assessment) -> bool {
    matches!(assessment.findings(), [finding] if finding.rule == Rule::Unreadable)
}

#[test]
fn an_address_case_is_judged_as_the_host_of_a_url_with_it() {
    let (mut checked, mut refused) = (0, 0);
    let mut wrong = Vec::new();
    for case in common::cases::load("address") {
        let got = judge_address(&case.url);
        match url_of(&case.url) {
            Some(url) => {
                let expected = judge(&url, &posix());
                if got == expected {
                    checked += 1;
                } else if unread(&got) && case.url.contains(['/', '?', '#', '\\', '@', '%']) {
                    // A text that holds what a URL holds around its host
                    // (`127.0.0.1/8`, `user@127.0.0.1`), a zone that is not
                    // read, or a zone on a public address is unreadable,
                    // where a URL of it is read: the cautious side only.
                    refused += 1;
                } else {
                    wrong.push(format!(
                        "{}: {:?}\n    judge({url:?}) is {expected:?}\n    judge_address is {got:?}",
                        case.at, case.url
                    ));
                }
            }
            // What no URL holds as an address is never safe.
            None if got.is_safe() => wrong.push(format!(
                "{}: {:?} is safe, and no URL's host",
                case.at, case.url
            )),
            None => {}
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    assert!(checked > 100, "only {checked} addresses checked");
    assert!(refused < 40, "{refused} addresses refused");
}

/// The ports appended to an address with no brackets.
const PORTS: [&str; 6] = ["0", "1", "80", "443", "8080", "65535"];

#[test]
fn a_non_public_address_with_a_port_appended_is_never_safe() {
    // An IPv6 address with no brackets has no port: `::1:80` is read as an
    // address. Whatever is appended, what was not public stays a finding.
    let mut addresses: Vec<String> = Vec::new();
    for case in url_cases() {
        let Some(host) = address_of(&case.url) else {
            continue;
        };
        let written = host.to_string();
        if !host_findings(&judge(&case.url, &case.paths), &written).is_empty() {
            addresses.push(written.trim_matches(['[', ']']).to_string());
            addresses.extend(written_host(&case.url).map(str::to_string));
        }
    }
    for case in common::cases::load("address") {
        let findings = judge_address(&case.url);
        if findings
            .findings()
            .iter()
            .any(|finding| matches!(finding.rule, Rule::LocalAddress | Rule::Metadata))
        {
            addresses.push(case.url.trim_matches(AROUND).to_string());
        }
    }
    let mut wrong = Vec::new();
    let mut checked = 0;
    for address in &addresses {
        if a_group_more_completes_an_address_inside(address) {
            continue;
        }
        for port in PORTS {
            let text = format!("{address}:{port}");
            if judge_address(&text).is_safe() {
                wrong.push(text);
            }
            checked += 1;
        }
    }
    assert!(wrong.is_empty(), "safe:\n{}", wrong.join("\n"));
    assert!(checked > 2_000, "only {checked} checked");
}

/// Whether one more group written after `address` can spell a public IPv4
/// address inside it. `::808` carries `0.0.8.8`, which is not public, and
/// `::ffff:808` carries `255.255.8.8`; a group more moves the last group up,
/// and `::808:808` and `::ffff:808:808` both carry `8.8.8.8`. No connection
/// is made to such an address, and what follows it is read as the parser
/// reads it: a part of the address. They are left out of the test above so
/// a case that names one does not fail it; `address.cases` pins `::808:808`.
fn a_group_more_completes_an_address_inside(address: &str) -> bool {
    let Ok(Host::Ipv6(v6)) = Host::parse(&format!("[{address}]")) else {
        return false;
    };
    let groups = v6.segments();
    (groups[6] == 0 && groups[7] > 0xff) || (groups[..6] == [0; 6] && groups[6] == 0xffff)
}

#[test]
fn an_address_as_long_as_a_url_is_read() {
    // Leading zeros are a spelling the parser reads at any length (`0177`
    // is octal for 127): the address is read up to the length of a URL,
    // and no further.
    let address = format!("{}177.0.0.1", "0".repeat(8_192 - "177.0.0.1".len()));
    assert_eq!(address.len(), 8_192);
    let found: Vec<Rule> = judge_address(&address)
        .findings()
        .iter()
        .map(|finding| finding.rule)
        .collect();
    assert_eq!(found, [Rule::LocalAddress, Rule::Unreadable]);
    let port = format!("8.8.8.8:{}80", "0".repeat(8_192 - "8.8.8.8:80".len()));
    assert!(judge_address(&port).is_safe());

    let longer = format!("0{address}");
    let assessment = judge_address(&longer);
    assert_eq!(assessment.findings().len(), 1);
    assert_eq!(assessment.findings()[0].rule, Rule::Unreadable);
    assert_eq!(assessment.findings()[0].reason, "is too long to read");
    assert_eq!(assessment.findings()[0].target, None);
}
