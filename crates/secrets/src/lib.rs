//! Reads a text and says whether it holds a credential, and where:
//! [`find`].
//!
//!
//! A caller that puts text in front of a model scrubs it first, and a caller
//! that lets an agent write a source file asks whether the content carries a
//! key into it. Both are the same question of a text: what in it is a secret.
//! The text has no place, so unlike the guards that judge a path there is no
//! `Paths` here: a text in, findings out.
//!
//! - **A finding never carries the secret.** [`Finding::target`] is masked:
//!   the public prefix of a key and its length (`AKIA… (20 chars)`), only the
//!   length when what was found begins with the secret itself (`… (8 chars)`),
//!   or the first line of a block of private key. Neither the target nor the
//!   reason ever holds more of the matched text than that.
//! - **The spans are offsets, not text.** [`find_spans`] gives the byte range
//!   of each thing found, on character boundaries, so a caller can replace it
//!   and leave the text around it as it was. Where two things overlap they
//!   are one span that covers both, with the rule of the more specific, so
//!   that scrubbing it leaves no part of either behind.
//! - **The table is judged by shape and by value.** A key is found by the
//!   prefix and the length its provider publishes; what is not shaped (a
//!   password) only where a name says so; and a number only when it passes
//!   its own check (the Luhn check of a card). What is safe on purpose is
//!   listed on the design page.
//! - **A text that is no key is safe.** SHAs, UUIDs, base64 fixtures, hashes,
//!   minified code and a lockfile's integrity hashes are [`Safe`](Assessment::Safe).
//! - **Shapeless secrets are a second function**, [`find_high_entropy`],
//!   never a part of [`find`]: a guard has no modes, and a caller that wants
//!   a guess calls it.
//!
//! The text is read in time linear in its length, whatever it holds. Nothing
//! here reads a file or the environment, and no clock is kept.
//!
//! ```
//! use milo_guards_secrets::{find, find_spans, Rule};
//!
//! assert!(find("let sha = \"3f786850e387550fdab836ed7e6dc881de23001b\";").is_safe());
//!
//! // `AKIA` and sixteen characters: an AWS access key.
//! let text = format!("key = {}", ["AKIA", "FAKE2KEY3ID4TEST"].concat());
//! let assessment = find(&text);
//! let finding = &assessment.findings()[0];
//! assert_eq!(finding.rule, Rule::CloudKey);
//! assert_eq!(finding.reason, "holds an AWS access key");
//! assert_eq!(finding.target.as_deref(), Some("AKIA… (20 chars)"));
//!
//! // A caller that scrubs replaces the span, and nothing else.
//! let span = find_spans(&text)[0];
//! assert_eq!((span.rule, span.start, span.end), (Rule::CloudKey, 6, 26));
//! assert_eq!(format!("{}[hidden]{}", &text[..span.start], &text[span.end..]), "key = [hidden]");
//! ```

#![allow(
    clippy::doc_markdown,
    reason = "the docs name providers: OpenAI, GitHub, PyPI"
)]

mod base64;
mod card;
mod entropy;
mod generic;
mod ip;
mod mask;
mod pem;
mod personal;
mod reading;
mod rows;
mod scan;
mod text;

/// What [`find`] concluded about a text: safe, or risky with every finding.
pub type Assessment = milo_guards_core::Assessment<Rule>;

/// One thing found in a text: the rule that found it, what it is in a few
/// words a permission prompt can show (`holds an AWS access key`), and the
/// masked target: never the secret itself.
pub type Finding = milo_guards_core::Finding<Rule>;

/// The kinds of secret and personal data a text is read for. Each finding
/// names one.
///
/// A rule is a kind, and a kind is as wide as what a caller would treat
/// alike: all the keys of providers are [`Rule::ApiKey`] and the reason says
/// which. A finer split later is a new rule, never a rename.
///
/// This enum is exhaustive on purpose: a rule added here breaks every
/// caller's `match` at compile time, so each caller decides what to do with
/// the new rule rather than meeting it as an unhandled case at run time.
/// [`Rule::ALL`] lists every rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Rule {
    /// A private key: a block `-----BEGIN … PRIVATE KEY-----`, its body and
    /// its end line (a body cut short counts, a header with no body does not),
    /// a PuTTY key's private lines, or an age secret key.
    PrivateKey,
    /// A key of a cloud: AWS (access key ids, and the secret key where it is
    /// named), Google (API keys, OAuth secrets and access tokens), Azure
    /// (storage account keys, client secrets, shared access signatures) and
    /// DigitalOcean.
    CloudKey,
    /// A key or token of a service: Anthropic, OpenAI, GitHub, GitLab,
    /// Slack, Discord, Telegram, Stripe, SendGrid, Twilio, npm, PyPI, crates.io, Hugging Face
    /// and Shopify.
    ApiKey,
    /// A JSON web token: `eyJ…` header, payload and signature.
    Jwt,
    /// The base64 of `user:password` after the word `Basic`, or as the
    /// `auth` of a Docker config.
    BasicAuth,
    /// A token after the word `Bearer`, that no other rule already found.
    BearerToken,
    /// A password in the connection string of a database or a broker:
    /// `postgres://user:password@host/db`.
    ConnectionString,
    /// A password in any other URL: `https://user:password@host/`.
    UrlCredentials,
    /// A password, secret or token written as the value of a name
    /// (`password=…`, `"api_key": "…"`) or after `password` in a `.netrc`,
    /// or, from [`find_high_entropy`], a run of characters that looks random.
    GenericSecret,
    /// A payment card number: thirteen to nineteen digits of a card
    /// network that pass the Luhn check.
    CreditCard,
    /// A government's id number: a US social security number, a UK national
    /// insurance number, a Brazilian CPF.
    GovernmentId,
    /// An email address, but not one on a name reserved for examples.
    Email,
    /// A phone number in the international form (`+` and a country code).
    Phone,
    /// A public IP address, v4 or v6: not private, shared, loopback,
    /// link-local, documentation, benchmarking, multicast or reserved.
    PublicIp,
}

impl Rule {
    /// Every rule, in the order the design page lists them.
    pub const ALL: [Self; 14] = [
        Self::PrivateKey,
        Self::CloudKey,
        Self::ApiKey,
        Self::Jwt,
        Self::BasicAuth,
        Self::BearerToken,
        Self::ConnectionString,
        Self::UrlCredentials,
        Self::GenericSecret,
        Self::CreditCard,
        Self::GovernmentId,
        Self::Email,
        Self::Phone,
        Self::PublicIp,
    ];

    /// The rule's stable name on the wire. It never changes once a caller
    /// uses it, whatever the variant is called in code.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::PrivateKey => "private_key",
            Self::CloudKey => "cloud_key",
            Self::ApiKey => "api_key",
            Self::Jwt => "jwt",
            Self::BasicAuth => "basic_auth",
            Self::BearerToken => "bearer_token",
            Self::ConnectionString => "connection_string",
            Self::UrlCredentials => "url_credentials",
            Self::GenericSecret => "generic_secret",
            Self::CreditCard => "credit_card",
            Self::GovernmentId => "government_id",
            Self::Email => "email",
            Self::Phone => "phone",
            Self::PublicIp => "public_ip",
        }
    }
}

impl milo_guards_core::RuleName for Rule {
    fn name(self) -> &'static str {
        Rule::name(self)
    }
}

/// Where something was found: its rule and its byte range in the text.
///
/// The range is offsets and never text, so a span is as safe to log as a
/// finding is. `start` and `end` are on character boundaries, so
/// `&text[start..end]` never panics, and replacing the range leaves the rest
/// of the text byte for byte as it was. What the range covers is the secret
/// alone: the password of a connection string and not its host, the value
/// of `password=` and not its name or quotes, the whole of a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Span {
    /// What was found.
    pub rule: Rule,
    /// The byte where it starts.
    pub start: usize,
    /// The byte after where it ends.
    pub end: usize,
}

/// Whether `text` holds a credential or personal data, and what.
///
/// Safe is a text with none of what [`Rule`] lists. Anything else has a
/// finding for each thing found, in the order the text reads, none overlapping
/// another. Each finding's target is masked (see the crate page); nothing in
/// the answer repeats a secret.
///
/// Reads the text in time linear in its length. There is no text this cannot
/// read, so there is no unreadable answer.
pub fn find(text: &str) -> Assessment {
    let scan = scan::scan(text);
    if scan.hits.is_empty() {
        return Assessment::Safe;
    }
    let read = scan.reading.text();
    Assessment::Risky(
        scan.hits
            .iter()
            .map(|hit| Finding {
                rule: hit.rule,
                reason: hit.reason.to_string(),
                target: Some(mask::target(read, hit)),
                instead: None,
            })
            .collect(),
    )
}

/// The byte ranges of everything [`find`] finds, in the order the text
/// reads, so a caller can scrub them.
///
/// The same text gives the same ranges as the findings of [`find`], one for
/// one.
pub fn find_spans(text: &str) -> Vec<Span> {
    let scan = scan::scan(text);
    scan.hits
        .iter()
        .map(|hit| {
            let (start, end) = scan.reading.original(hit.start, hit.end);
            Span {
                rule: hit.rule,
                start,
                end,
            }
        })
        .collect()
}

/// The runs of `text` that look random, for a secret with no shape of its
/// own. Never part of [`find`]: a caller that wants the guess calls it.
///
/// A run is a stretch of letters, digits, `+`, `/`, `_` and `-` at least 20
/// long, with a letter and a digit in it, that is not a hash (32, 40, 56, 64,
/// 96 or 128 hex digits), a UUID or an integrity hash (`sha512-…`), and whose
/// Shannon entropy is at least `bits` per character. A random base64 string
/// has about 5.5 bits, a random hex one at most 4, English words around 3 to
/// 4: `4.5` finds the first and not the others. Every span is a
/// [`Rule::GenericSecret`], in order, none overlapping another. A `bits` that
/// is not a number finds nothing.
///
/// This guesses, so it has false alarms the shaped rules do not: a long
/// base64 fixture, an encoded image, a compressed blob. A caller that scrubs
/// is safe from them; a caller that blocks is not, and chooses.
pub fn find_high_entropy(text: &str, bits: f64) -> Vec<Span> {
    let reading = reading::Reading::new(text);
    entropy::find(reading.text(), bits)
        .into_iter()
        .map(|span| {
            let (start, end) = reading.original(span.start, span.end);
            Span { start, end, ..span }
        })
        .collect()
}
