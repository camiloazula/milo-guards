//! The table of shapes: one row per kind of secret or personal data that a
//! regular expression can find, each with the rule it breaks, the reason a
//! prompt shows, and the check that turns a candidate into a finding.
//!
//! The rows are written from each provider's published description of its
//! own format: the prefix, the length, the alphabet. A row never decides on
//! the shape alone when the shape is common: a card number must pass the
//! Luhn check, a Basic header must decode to `user:password`, an address
//! must be public. Rows are in two groups, secrets and personal data, and
//! within each the order is the order of precedence when two overlap.

use std::sync::OnceLock;

use regex::Regex;

use crate::mask::Mask;
use crate::scan::Hit;
use crate::{base64, card, ip, personal, text, Rule};

/// A candidate a row's pattern matched, for the row's check.
pub(crate) struct Candidate<'a> {
    /// The whole text.
    pub(crate) text: &'a str,
    /// Where the secret starts and ends in it.
    pub(crate) start: usize,
    pub(crate) end: usize,
    /// The secret: `text[start..end]`.
    pub(crate) secret: &'a str,
    /// What the row's `context` group matched (a URL's scheme), or empty.
    pub(crate) context: &'a str,
}

/// What a row does once its pattern has matched.
type Check = fn(&Candidate<'_>) -> bool;

fn always(_: &Candidate<'_>) -> bool {
    true
}

/// One row, as written.
struct Spec {
    rule: Rule,
    reason: &'static str,
    /// Lowercase texts of which at least one must be in the text for the row
    /// to run at all: a cheap way to skip a row the text cannot hold. Empty
    /// means the row always runs.
    needles: &'static [&'static str],
    pattern: &'static str,
    /// The pattern's group that holds the secret; 0 is the whole match.
    group: usize,
    /// The pattern's group that holds what the check also needs; 0 is none.
    context: usize,
    check: Check,
    mask: Mask,
    /// Whether the secret must stand alone: no ASCII letter or digit
    /// touching it on either side.
    alone: bool,
}

impl Spec {
    const fn new(
        rule: Rule,
        reason: &'static str,
        needles: &'static [&'static str],
        pattern: &'static str,
    ) -> Self {
        Self {
            rule,
            reason,
            needles,
            pattern,
            group: 0,
            context: 0,
            check: always,
            mask: Mask::Prefix(4),
            alone: true,
        }
    }

    const fn group(mut self, group: usize) -> Self {
        self.group = group;
        self
    }

    const fn context(mut self, context: usize) -> Self {
        self.context = context;
        self
    }

    const fn check(mut self, check: Check) -> Self {
        self.check = check;
        self
    }

    const fn mask(mut self, mask: Mask) -> Self {
        self.mask = mask;
        self
    }

    const fn unbounded(mut self) -> Self {
        self.alone = false;
        self
    }
}

/// A row, with its pattern compiled.
pub(crate) struct Row {
    spec: Spec,
    /// `None` only if the pattern fails to compile, which a test rules out;
    /// the row then finds nothing.
    regex: Option<Regex>,
}

impl Row {
    #[cfg(test)]
    pub(crate) fn reason(&self) -> &'static str {
        self.spec.reason
    }

    #[cfg(test)]
    pub(crate) fn compiled(&self) -> bool {
        self.regex.is_some()
    }
}

/// Every row, compiled once.
pub(crate) struct Table {
    /// Keys, tokens, passwords in addresses: what grants access.
    pub(crate) secrets: Vec<Row>,
    /// Card numbers, ids, addresses: who someone is.
    pub(crate) personal: Vec<Row>,
}

pub(crate) fn table() -> &'static Table {
    static TABLE: OnceLock<Table> = OnceLock::new();
    TABLE.get_or_init(|| Table {
        secrets: compile(secrets()),
        personal: compile(personal()),
    })
}

fn compile(specs: Vec<Spec>) -> Vec<Row> {
    specs
        .into_iter()
        .map(|spec| {
            let regex = Regex::new(spec.pattern).ok();
            Row { spec, regex }
        })
        .collect()
}

/// Adds a hit for each match of each row of `rows` in `text`.
pub(crate) fn scan(rows: &[Row], text: &str, lower: &str, out: &mut Vec<Hit>) {
    for row in rows {
        let spec = &row.spec;
        if !spec.needles.is_empty() && !spec.needles.iter().any(|needle| lower.contains(needle)) {
            continue;
        }
        let Some(regex) = &row.regex else {
            continue;
        };
        for captures in regex.captures_iter(text) {
            let Some(secret) = captures.get(spec.group) else {
                continue;
            };
            let (start, end) = (secret.start(), secret.end());
            if spec.alone && !text::alone(text, start, end) {
                continue;
            }
            let candidate = Candidate {
                text,
                start,
                end,
                secret: secret.as_str(),
                context: captures.get(spec.context).map_or("", |c| c.as_str()),
            };
            if !(spec.check)(&candidate) {
                continue;
            }
            out.push(Hit {
                rule: spec.rule,
                reason: spec.reason,
                start,
                end,
                mask: spec.mask,
            });
        }
    }
}

fn varied(candidate: &Candidate<'_>) -> bool {
    text::varied(candidate.secret)
}

// ---- secrets ----

#[allow(clippy::too_many_lines, reason = "one table, read top to bottom")]
fn secrets() -> Vec<Spec> {
    use Rule::{
        ApiKey, BasicAuth, BearerToken, CloudKey, ConnectionString, Jwt, PrivateKey, UrlCredentials,
    };
    vec![
        // -- a key in one line: the secret key of age, in bech32 --
        Spec::new(
            PrivateKey,
            "holds an age secret key",
            &["age-secret-key-1"],
            r"AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}",
        )
        .check(varied),
        // -- cloud keys --
        // AWS access key ids: a four-letter kind and sixteen base32 characters.
        // The ids AWS's documentation shows end in EXAMPLE.
        Spec::new(
            CloudKey,
            "holds an AWS access key",
            &["akia", "asia", "abia", "acca"],
            r"(?:AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}",
        )
        .check(|c| varied(c) && !c.secret.ends_with("EXAMPLE")),
        // The secret half has no shape of its own (forty characters of
        // base64), so it is found only where it is named.
        Spec::new(
            CloudKey,
            "holds an AWS secret access key",
            &["secret"],
            r#"(?i)(?:aws[_\-.]?secret[_\-.]?(?:access[_\-.]?)?key|secret[_\-.]?access[_\-.]?key)["']?[ \t]*(?:=>|[:=])[ \t]*["']?([A-Za-z0-9/+]{40})"#,
        )
        .group(1)
        .mask(Mask::Length)
        .check(|c| varied(c) && !c.secret.ends_with("EXAMPLEKEY")),
        Spec::new(
            CloudKey,
            "holds a Google API key",
            &["aiza"],
            r"AIza[0-9A-Za-z_\-]{35}",
        )
        .check(varied),
        Spec::new(
            CloudKey,
            "holds a Google OAuth client secret",
            &["gocspx-"],
            r"GOCSPX-[0-9A-Za-z_\-]{28}",
        )
        .check(varied),
        Spec::new(
            CloudKey,
            "holds a Google OAuth access token",
            &["ya29."],
            r"ya29\.[0-9A-Za-z_\-]{20,}",
        )
        .check(varied),
        Spec::new(
            CloudKey,
            "holds an Azure storage account key",
            &["accountkey="],
            r"(?i)AccountKey=([A-Za-z0-9+/]{86}==)",
        )
        .group(1)
        .mask(Mask::Length)
        .unbounded(),
        // Azure AD client secrets: three random characters, a digit, `Q~`,
        // and thirty-one to thirty-four more.
        Spec::new(
            CloudKey,
            "holds an Azure client secret",
            &["q~"],
            r"[0-9A-Za-z_~.\-]{3}[0-9]Q~[0-9A-Za-z_~.\-]{31,34}",
        )
        .mask(Mask::Length)
        .check(varied),
        Spec::new(
            CloudKey,
            "holds a DigitalOcean token",
            &["_v1_"],
            r"do[por]_v1_[a-f0-9]{64}",
        )
        .check(varied),
        // -- api keys --
        Spec::new(
            ApiKey,
            "holds an Anthropic API key",
            &["sk-ant-"],
            r"sk-ant-[a-z0-9]{2,12}-[A-Za-z0-9_\-]{32,}",
        )
        .check(varied),
        // Project and service-account keys have a kind; the older ones are
        // `sk-` and forty-eight characters, or carry `T3BlbkFJ` ("OpenAI"
        // in base64) in the middle.
        Spec::new(
            ApiKey,
            "holds an OpenAI API key",
            &["sk-"],
            r"sk-(?:(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{40,}|[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}|[A-Za-z0-9]{48})",
        )
        .mask(Mask::Prefix(3))
        .check(varied),
        // `ghp_` personal, `gho_` OAuth, `ghu_` user, `ghs_` server, `ghr_`
        // refresh, and the fine-grained `github_pat_`.
        Spec::new(
            ApiKey,
            "holds a GitHub token",
            &["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"],
            r"gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}",
        )
        .check(varied),
        Spec::new(
            ApiKey,
            "holds a GitLab token",
            &[
                "glpat-", "glptt-", "glrt-", "gldt-", "glcbt-", "glft-", "glimt-", "glagent-",
                "gloas-", "glsoat-",
            ],
            r"gl(?:pat|ptt|rt|dt|cbt|ft|imt|agent|oas|soat)-[A-Za-z0-9_\-]{20,}(?:\.[A-Za-z0-9]{2,12}){0,2}",
        )
        .check(varied),
        Spec::new(
            ApiKey,
            "holds a Slack token",
            &["xox", "xapp-"],
            r"xox[abeoprs]-[A-Za-z0-9\-]{20,}|xoxe\.xox[bp]-[A-Za-z0-9\-]{20,}|xapp-[0-9]-[A-Za-z0-9\-]{20,}",
        )
        .check(varied),
        Spec::new(
            ApiKey,
            "holds a Slack webhook URL",
            &["hooks.slack.com"],
            r"https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9/_\-]{20,}",
        )
        .unbounded(),
        Spec::new(
            ApiKey,
            "holds a Stripe key",
            &["sk_", "rk_", "whsec_"],
            r"[sr]k_(?:live|test)_[0-9A-Za-z]{24,99}|whsec_[0-9A-Za-z]{32,}",
        )
        .check(varied),
        Spec::new(
            ApiKey,
            "holds a SendGrid API key",
            &["sg."],
            r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}",
        )
        .mask(Mask::Prefix(3))
        .check(varied),
        // A Twilio auth token is thirty-two hex characters with no mark of
        // its own, so it is found only where it is named.
        Spec::new(
            ApiKey,
            "holds a Twilio auth token",
            &["twilio"],
            r#"(?i)twilio[A-Za-z0-9_.\-]{0,24}(?:token|secret)["']?[ \t]*(?:=>|[:=])[ \t]*["']?([0-9a-f]{32})"#,
        )
        .group(1)
        .mask(Mask::Length)
        .check(varied),
        Spec::new(
            ApiKey,
            "holds an npm token",
            &["npm_"],
            r"npm_[A-Za-z0-9]{36}",
        )
        .check(varied),
        Spec::new(
            ApiKey,
            "holds a PyPI token",
            &["pypi-"],
            r"pypi-Ag[EF][A-Za-z0-9_\-]{50,}",
        )
        .check(varied),
        Spec::new(
            ApiKey,
            "holds a crates.io token",
            &["cio"],
            r"cio[A-Za-z0-9]{32}",
        )
        .mask(Mask::Prefix(3))
        .check(varied),
        Spec::new(
            ApiKey,
            "holds a Hugging Face token",
            &["hf_", "api_org_"],
            r"hf_[A-Za-z0-9]{34,}|api_org_[A-Za-z0-9]{34}",
        )
        .mask(Mask::Prefix(3))
        .check(varied),
        Spec::new(
            ApiKey,
            "holds a Shopify token",
            &["shp"],
            r"shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}",
        )
        .check(varied),
        // -- a signed token: header.payload.signature, the first two parts
        // base64url of a JSON object (`{"` is `eyJ`) --
        Spec::new(
            Jwt,
            "holds a JSON web token",
            &["eyj"],
            r"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*",
        )
        .mask(Mask::Prefix(3)),
        // -- passwords in addresses --
        Spec::new(
            ConnectionString,
            "holds a password in a connection string",
            &["://"],
            r#"(?i)(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver|cockroachdb|clickhouse|cassandra|neo4j(?:\+ssc?)?|couchbases?|memcached?|nats)://[^ \t\r\n:/@'"<>\\]*:([^ \t\r\n'"<>/\\]+)@"#,
        )
        .group(1)
        .mask(Mask::Length)
        .unbounded()
        .check(|c| !text::is_reference(c.secret)),
        Spec::new(
            UrlCredentials,
            "holds a password in a URL",
            &["://"],
            r#"([A-Za-z][A-Za-z0-9+.\-]{1,24})://[^ \t\r\n:/@'"<>\\]*:([^ \t\r\n'"<>/\\]+)@"#,
        )
        .group(2)
        .context(1)
        .mask(Mask::Length)
        .unbounded()
        .check(|c| !text::is_reference(c.secret) && !is_database(c.context)),
        // -- headers --
        // `Authorization: Basic ` and the base64 of `user:password`. Any
        // word after "basic" is base64, so the text must decode to a pair.
        Spec::new(
            BasicAuth,
            "holds a Basic authorization credential",
            &["basic"],
            r"(?i)basic[ \t]+([A-Za-z0-9+/]{8,}={0,2})",
        )
        .group(1)
        .mask(Mask::Length)
        .check(|c| base64::is_user_and_password(c.secret)),
        Spec::new(
            BearerToken,
            "holds a bearer token",
            &["bearer"],
            r"(?i)bearer[ \t]+([A-Za-z0-9._~+/\-]{20,}={0,2})",
        )
        .group(1)
        .mask(Mask::Length)
        .check(|c| {
            varied(c)
                && c.secret.bytes().any(|b| b.is_ascii_digit())
                && c.secret.bytes().any(|b| b.is_ascii_alphabetic())
        }),
    ]
}

/// The schemes whose password is a database's, which the connection-string
/// row owns.
fn is_database(scheme: &str) -> bool {
    const SCHEMES: [&str; 18] = [
        "postgres",
        "postgresql",
        "mysql",
        "mariadb",
        "mongodb",
        "mongodb+srv",
        "redis",
        "rediss",
        "amqp",
        "amqps",
        "mssql",
        "sqlserver",
        "cockroachdb",
        "clickhouse",
        "cassandra",
        "couchbase",
        "couchbases",
        "memcached",
    ];
    let scheme = scheme.to_ascii_lowercase();
    SCHEMES.contains(&scheme.as_str())
        || scheme == "memcache"
        || scheme == "nats"
        || scheme.starts_with("neo4j")
}

// ---- personal data ----

fn personal() -> Vec<Spec> {
    use Rule::{CreditCard, Email, GovernmentId, Phone, PublicIp};
    vec![
        // Thirteen to nineteen digits, plain or in groups, that pass the
        // Luhn check and begin as a card network's numbers begin.
        Spec::new(
            CreditCard,
            "holds a payment card number",
            &[],
            r"[0-9]{4}(?:[ \-][0-9]{4}){2,3}(?:[ \-][0-9]{1,4})?|[0-9]{4}[ \-][0-9]{6}[ \-][0-9]{4,5}|[0-9]{13,19}",
        )
        .mask(Mask::Length)
        .check(card::is_card),
        Spec::new(
            GovernmentId,
            "holds a US social security number",
            &["-"],
            r"[0-9]{3}-[0-9]{2}-[0-9]{4}",
        )
        .mask(Mask::Length)
        .check(personal::is_ssn),
        Spec::new(
            GovernmentId,
            "holds a UK national insurance number",
            &[],
            r"[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z] ?[0-9]{2} ?[0-9]{2} ?[0-9]{2} ?[A-D]",
        )
        .mask(Mask::Length)
        .check(personal::is_nino),
        Spec::new(
            GovernmentId,
            "holds a Brazilian CPF number",
            &["-"],
            r"[0-9]{3}\.[0-9]{3}\.[0-9]{3}-[0-9]{2}",
        )
        .mask(Mask::Length)
        .check(personal::is_cpf),
        Spec::new(
            Email,
            "holds an email address",
            &["@"],
            r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}",
        )
        .mask(Mask::Length)
        .check(personal::is_email),
        Spec::new(
            Phone,
            "holds a phone number",
            &["+"],
            r"\+[1-9][0-9]{0,2}(?:[ .\-]?\(?[0-9]{2,4}\)?){2,5}",
        )
        .mask(Mask::Length)
        .unbounded()
        .check(personal::is_phone),
        Spec::new(
            PublicIp,
            "holds a public IP address",
            &["."],
            r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}",
        )
        .mask(Mask::Length)
        .unbounded()
        .check(ip::is_public_v4),
        Spec::new(
            PublicIp,
            "holds a public IP address",
            &[":"],
            r"[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{0,4}){2,7}",
        )
        .mask(Mask::Length)
        .unbounded()
        .check(ip::is_public_v6),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_pattern_compiles() {
        let table = table();
        for row in table.secrets.iter().chain(&table.personal) {
            assert!(row.compiled(), "{}", row.reason());
        }
    }
}
