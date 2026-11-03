//! Reads a URL an agent is about to fetch and says whether it is safe to
//! fetch without asking, or risky and why: [`judge`].
//!
//! A fetch is a read-only call a caller lets run unasked, and the shell guard
//! never sees it. What matters about one is few and well known: the machine
//! itself and its neighbours, the cloud metadata services that hand out
//! credentials, a URL that carries a password, and a scheme that is not the
//! web. The classic way past such a check is a differently spelled address
//! (`http://2130706433/`, `http://0x7f.1/`, `http://[::ffff:127.0.0.1]/`), so
//! the guard judges the host a WHATWG URL parser reads, never the text.
//!
//! - **The parser decides the host.** Decimal, octal, hex and shortened
//!   IPv4, IPv6 with an IPv4 inside, percent-escapes, full-width digits and
//!   the ideographic full stop, international names: all become one host
//!   before it is judged. A spelling where another client could read another
//!   host (a backslash, `http:/host`, a percent sign in the host, an IPv4
//!   address spelled any way but four plain numbers) is
//!   [`Rule::Unreadable`].
//! - **The host is public only by a whitelist.** A public name, or an address
//!   in none of the special ranges. A host this cannot place is a finding,
//!   never safe.
//! - **No lookup.** A name is judged by its spelling alone. A public name
//!   whose own DNS points at a private address cannot be seen without one.
//!
//! What cannot be read is risky: an empty URL, a control character, a URL too
//! long, one the parser rejects. Nothing here touches the network or the
//! file system: a `file:` URL's path is placed against the [`Paths`] the
//! caller passes, by its spelling, like any other path.
//!
//! ```
//! use milo_guards_url::{judge, Rule};
//! use milo_guards_core::Paths;
//!
//! let paths = Paths::new("/work/app", "/home/me", ["/work/app"]);
//!
//! assert!(judge("https://docs.rs/url", &paths).is_safe());
//!
//! let assessment = judge("http://2130706433:9090/admin", &paths);
//! let finding = &assessment.findings()[0];
//! assert_eq!(finding.rule, Rule::LocalAddress);
//! assert_eq!(finding.reason, "fetches your own machine");
//! assert_eq!(finding.target.as_deref(), Some("127.0.0.1"));
//!
//! // The password is never echoed.
//! let assessment = judge("https://me:hunter2@example.com/", &paths);
//! assert_eq!(assessment.findings()[0].rule, Rule::Credentials);
//! assert_eq!(assessment.findings()[0].target.as_deref(), Some("https://…@example.com/"));
//! ```

mod file;
mod host;
mod shape;
mod tables;

use host::Verdict;
pub use milo_guards_core::{Paths, Protected, ProtectedKind};
use tables::MAX_URL;
use url::{Host, Url};

/// What [`judge`] concluded about a URL: safe, or risky with every finding.
pub type Assessment = milo_guards_core::Assessment<Rule>;

/// One reason a URL is risky: the rule that found it, what fetching it would
/// do in a few words a permission prompt can show (`fetches your own
/// machine`), and the part of the URL it is about (the host as the parser
/// reads it, the scheme, the file's path, or the URL with the user-info
/// replaced). Never the password, and never a copy of an unreadable URL.
pub type Finding = milo_guards_core::Finding<Rule>;

/// The rules a URL is judged by. Each finding names one.
///
/// This enum is exhaustive on purpose: a rule added here breaks every
/// caller's `match` at compile time, so each caller decides what to do with
/// the new rule rather than meeting it as an unhandled case at run time.
/// [`Rule::ALL`] lists every rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Rule {
    /// The host is not public: this machine (`127.0.0.0/8`, `::1`, `0.0.0.0`,
    /// `localhost` and what is under it), a machine on the local network
    /// (private, link-local, shared, unique-local addresses; a name with no
    /// dot; a name under `.local`, `.internal`, `.home.arpa`, `.lan` and the
    /// like), a range no public host has (documentation, benchmarking,
    /// multicast, reserved), or a name from a service that answers with the
    /// address it is asked for (`nip.io`). An IPv4 address carried inside an
    /// IPv6 one (mapped, compatible, NAT64, 6to4) is judged by the IPv4
    /// address inside it.
    LocalAddress,
    /// The host is a cloud metadata service, which hands out the machine's
    /// credentials. It wins over [`Rule::LocalAddress`], so the reason says
    /// what it is.
    Metadata,
    /// The URL carries a user name or a password.
    Credentials,
    /// A `file:` URL. A page fetch is not how a file is meant to be read; the
    /// reason says where the path lands.
    LocalFile,
    /// A scheme other than `http`, `https` and `file`.
    Scheme,
    /// The URL cannot be read, or can be read as two hosts: empty, a control
    /// character, too long, not a URL, a host name no resolver reads one
    /// way, or a spelling another client would read differently.
    Unreadable,
}

impl Rule {
    /// Every rule, in the order the design page lists them.
    pub const ALL: [Self; 6] = [
        Self::LocalAddress,
        Self::Metadata,
        Self::Credentials,
        Self::LocalFile,
        Self::Scheme,
        Self::Unreadable,
    ];

    /// The rule's stable name on the wire. It never changes once a caller
    /// uses it, whatever the variant is called in code.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::LocalAddress => "local_address",
            Self::Metadata => "metadata",
            Self::Credentials => "credentials",
            Self::LocalFile => "local_file",
            Self::Scheme => "scheme",
            Self::Unreadable => "unreadable",
        }
    }
}

impl milo_guards_core::RuleName for Rule {
    fn name(self) -> &'static str {
        Rule::name(self)
    }
}

fn finding(rule: Rule, reason: impl Into<String>, target: Option<String>) -> Finding {
    Finding {
        rule,
        reason: reason.into(),
        target,
        instead: None,
    }
}

/// An answer that says the URL cannot be read, and never repeats it: what
/// cannot be read may hold a password.
fn unreadable(why: &str) -> Assessment {
    Assessment::Risky(vec![finding(Rule::Unreadable, why, None)])
}

/// Whether `url` is safe to fetch without asking, or risky and why.
///
/// `paths` is for a `file:` URL, whose path is placed like any other path,
/// and for nothing else.
///
/// Safe is a public host over `http` or `https`, whatever the port, path or
/// query, and however an address is spelled when it comes out public.
/// Anything else has a finding for each thing found, in the order the URL
/// reads: the scheme, the user-info, the host.
pub fn judge(url: &str, paths: &Paths) -> Assessment {
    // White space around a URL changes no host: the parser drops it, and a
    // client that does not fails to read the URL at all.
    let text = url.trim_matches([' ', '\t', '\n', '\r', '\x0c']);
    if text.is_empty() {
        return unreadable("is empty");
    }
    if text.len() > MAX_URL {
        return unreadable("is too long to read");
    }
    // A tab or a newline inside a URL is dropped by the parser and kept by a
    // client that does not; any other control character is no part of one.
    if text.chars().any(char::is_control) {
        return unreadable("holds a control character");
    }
    let Ok(parsed) = Url::parse(text) else {
        return unreadable("cannot be read as a URL");
    };

    let mut findings = Vec::new();
    let scheme = parsed.scheme();
    if !matches!(scheme, "http" | "https" | "file") {
        findings.push(finding(
            Rule::Scheme,
            format!("uses the {scheme} scheme, which is not a web page"),
            Some(scheme.to_string()),
        ));
    }
    if let Some(masked) = credentials(&parsed) {
        findings.push(masked);
    }
    if scheme == "file" {
        let (reason, path) = file::judge(&parsed, paths);
        findings.push(finding(Rule::LocalFile, reason, Some(path)));
    }
    let ipv4 = judge_host(&parsed, &mut findings);
    // A name the parser and an IDNA2003 client read differently is judged as
    // both, and is unreadable itself.
    if let Some(older) = shape::written_host(text).and_then(shape::idna2003) {
        if let Ok(host) = Host::parse(&older) {
            push_verdict(&host, &mut findings);
        }
        findings.push(finding(
            Rule::Unreadable,
            "spells a name that older clients read differently",
            None,
        ));
    }
    if matches!(scheme, "http" | "https") {
        if let Some(why) = shape::odd(text, scheme, ipv4) {
            findings.push(finding(Rule::Unreadable, why.to_string(), None));
        }
    }

    if findings.is_empty() {
        Assessment::Safe
    } else {
        Assessment::Risky(findings)
    }
}

/// A finding when the URL carries a user name or a password. Its target is
/// the URL with the user-info replaced by `…`, built from what the parser
/// read so that no spelling of the password is left in it; with nothing safe
/// to show it has no target.
fn credentials(parsed: &Url) -> Option<Finding> {
    if parsed.username().is_empty() && parsed.password().is_none() {
        return None;
    }
    let mut bare = parsed.clone();
    let cleared = bare.set_username("").is_ok() && bare.set_password(None).is_ok();
    let target = cleared
        .then(|| {
            let text = bare.as_str();
            let at = text.find("://")? + 3;
            Some(format!("{}…@{}", &text[..at], &text[at..]))
        })
        .flatten();
    Some(finding(
        Rule::Credentials,
        "sends a user name or a password in the URL",
        target,
    ))
}

/// Judge the host of `parsed`, pushing what it finds. Returns whether the
/// host is an IPv4 address.
fn judge_host(parsed: &Url, findings: &mut Vec<Finding>) -> bool {
    let Some(host) = parsed.host() else {
        return false;
    };
    // A host of a scheme the parser does not know is kept as text; read it
    // the way a web host is read.
    let host: Host<String> = match host {
        Host::Domain(name) => {
            let Ok(host) = Host::parse(name) else {
                findings.push(finding(
                    Rule::Unreadable,
                    "has a host name that cannot be read",
                    None,
                ));
                return false;
            };
            host
        }
        other => other.to_owned(),
    };
    push_verdict(&host, findings)
}

/// Judge `host`, pushing what it finds. Returns whether it is an IPv4 address.
fn push_verdict(host: &Host<String>, findings: &mut Vec<Finding>) -> bool {
    let (verdict, ipv4) = match host {
        Host::Domain(name) => (host::name(name), false),
        Host::Ipv4(address) => (host::v4(address.octets()), true),
        Host::Ipv6(address) => (host::v6(address.segments()), false),
    };
    let target = Some(host.to_string());
    match verdict {
        Verdict::Public => {}
        Verdict::Local(reach) => findings.push(finding(Rule::LocalAddress, reach.reason(), target)),
        Verdict::Metadata(provider) => findings.push(finding(
            Rule::Metadata,
            format!("fetches the cloud metadata service ({provider}), which hands out credentials"),
            target,
        )),
        Verdict::Unreadable(why) => findings.push(finding(Rule::Unreadable, why, None)),
    }
    ipv4
}
