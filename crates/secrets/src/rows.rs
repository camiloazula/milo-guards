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
use crate::reading::Reading;
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

/// A password in an address is judged without a name, and is no constant.
const ADDRESS: text::Standin<'static> = text::Standin {
    word: None,
    quoted: false,
    address: true,
    env_file: false,
};

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
    /// Whether the pattern also runs over the text as it was written, where
    /// an escape is not what it stands for: a `%2F` in a password is not
    /// the `/` that ends it. The read text is still run, to find what is
    /// written in escapes.
    raw: bool,
    /// Whether a match that is no hit lets the search go on one character
    /// after its start and not after its end: for a row whose matches are
    /// short and whose check can reject a decoy that hides a real token.
    rescan: bool,
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
            raw: false,
            rescan: false,
        }
    }

    const fn rescan(mut self) -> Self {
        self.rescan = true;
        self
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

    const fn raw(mut self) -> Self {
        self.raw = true;
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

/// Adds a hit for each match of each row of `rows` in the text of `reading`.
pub(crate) fn scan(rows: &[Row], reading: &Reading<'_>, lower: &str, out: &mut Vec<Hit>) {
    let written_lower = reading
        .changed()
        .then(|| reading.written().to_ascii_lowercase());
    for row in rows {
        let Some(regex) = &row.regex else {
            continue;
        };
        if row.spec.raw {
            if let Some(written_lower) = &written_lower {
                run(
                    &row.spec,
                    regex,
                    reading.written(),
                    written_lower,
                    Some(reading),
                    out,
                );
            }
        }
        run(&row.spec, regex, reading.text(), lower, None, out);
    }
}

/// Runs one row over `text`. When `reading` is given, `text` is the written
/// text and the hits are carried to the read one.
fn run(
    spec: &Spec,
    regex: &Regex,
    text: &str,
    lower: &str,
    reading: Option<&Reading<'_>>,
    out: &mut Vec<Hit>,
) {
    if !spec.needles.is_empty() && !spec.needles.iter().any(|needle| lower.contains(needle)) {
        return;
    }
    let mut at = 0;
    while at <= text.len() {
        let Some(captures) = regex.captures_at(text, at) else {
            break;
        };
        let whole = captures.get(0).map_or(at..at, |m| m.start()..m.end());
        // Where the search goes on: after the match, or, when the match is
        // no hit and the row is told to rescan, one character after its
        // start, so a decoy cannot swallow a real token that overlaps it or
        // follows it. A match is short, so the cost stays linear.
        let past = if whole.end > whole.start {
            whole.end
        } else {
            text::next_boundary(text, whole.end)
        };
        let rejected = if spec.rescan {
            text::next_boundary(text, whole.start)
        } else {
            past
        };
        let Some(secret) = captures.get(spec.group) else {
            at = rejected;
            continue;
        };
        let (start, end) = (secret.start(), secret.end());
        if spec.alone && !text::alone(text, start, end) {
            at = rejected;
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
            at = rejected;
            continue;
        }
        at = past;
        let (start, end) = reading.map_or((start, end), |reading| {
            (reading.read_point(start), reading.read_point(end))
        });
        out.push(Hit {
            rule: spec.rule,
            reason: spec.reason,
            start,
            end,
            mask: spec.mask,
        });
    }
}

/// Whether one of `words` is within 300 bytes of the candidate, either side.
fn near(candidate: &Candidate<'_>, words: &[&str]) -> bool {
    let bytes = candidate.text.as_bytes();
    let from = candidate.start.saturating_sub(300);
    let to = (candidate.end + 300).min(bytes.len());
    let window = bytes.get(from..to).unwrap_or_default();
    words.iter().any(|word| {
        window
            .windows(word.len())
            .any(|piece| piece.eq_ignore_ascii_case(word.as_bytes()))
    })
}

/// A Telegram token: random enough, not a piece of a longer word, except
/// after `bot`, where the API puts it.
fn telegram(candidate: &Candidate<'_>) -> bool {
    let head = candidate.text.get(..candidate.start).unwrap_or_default();
    let left = match text::before(candidate.text, candidate.start) {
        None => true,
        Some(c) if !c.is_ascii_alphanumeric() => true,
        Some(_) => head
            .strip_suffix("bot")
            .is_some_and(|rest| !rest.ends_with(|c: char| c.is_ascii_alphanumeric())),
    };
    let right =
        !text::after(candidate.text, candidate.end).is_some_and(|c| c.is_ascii_alphanumeric());
    left && right && varied(candidate)
}

/// A Discord bot token: its first part is the base64url of a user's id, it
/// varies as a signature does, and it is not the tail of a longer word.
///
/// Up to three letters or digits may touch its front: a decoy match
/// (`NMTIz…`) starts one letter too early, and that letter must not hide the
/// token that begins after it. Four or more are a longer id of which this
/// is only a tail (an id's digits come in groups of four characters), and a
/// letter or digit after it is a longer third part. Only the run of letters
/// and digits counts: the base64url of an id made of digits never holds `_`
/// or `-`, so one that touches the token proves it is not the tail of a
/// longer id (`token_…`, `my-bot-…`), and the run stops there.
fn discord_bot(candidate: &Candidate<'_>) -> bool {
    let glued = candidate
        .text
        .get(..candidate.start)
        .unwrap_or_default()
        .chars()
        .rev()
        .take(4)
        .take_while(char::is_ascii_alphanumeric)
        .count();
    glued < 4
        && !text::after(candidate.text, candidate.end).is_some_and(|c| c.is_ascii_alphanumeric())
        && candidate
            .secret
            .split_once('.')
            .is_some_and(|(id, _)| base64::is_numeric_id(id))
        && varied(candidate)
}

/// `text` without `word` at its end, whatever the case of the word.
fn strip_word<'a>(text: &'a str, word: &str) -> Option<&'a str> {
    let at = text.len().checked_sub(word.len())?;
    text.get(at..)
        .filter(|tail| tail.eq_ignore_ascii_case(word))
        .and_then(|_| text.get(..at))
}

/// A `.netrc` password: after the word `password` that begins a word, in
/// an entry that names a machine or a login, and not a stand-in.
fn netrc(candidate: &Candidate<'_>) -> bool {
    let Some(head) = candidate.text.get(..candidate.start) else {
        return false;
    };
    let Some(head) = strip_word(head.trim_end_matches([' ', '\t']), "password") else {
        return false;
    };
    let from = head.len().saturating_sub(300);
    let window = head
        .as_bytes()
        .get(from..)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let names = |word: &[u8]| window.windows(word.len()).any(|piece| piece == word);
    (head.is_empty() || head.ends_with(char::is_whitespace))
        && (names(b"machine ") || names(b"login ") || names(b"default"))
        && !text::is_reference(candidate.secret)
        && !text::is_placeholder(
            candidate.secret,
            &text::Standin {
                word: Some("password"),
                quoted: false,
                address: false,
                env_file: false,
            },
        )
}

fn varied(candidate: &Candidate<'_>) -> bool {
    text::varied(candidate.secret)
}

// ---- secrets ----

#[allow(clippy::too_many_lines, reason = "one table, read top to bottom")]
fn secrets() -> Vec<Spec> {
    use Rule::{
        ApiKey, BasicAuth, BearerToken, CloudKey, ConnectionString, GenericSecret, Jwt, PrivateKey,
        UrlCredentials,
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
        // An access key id and its secret together, as the console's
        // credentials file writes them: the id, a separator, forty
        // characters, with no name before either.
        Spec::new(
            CloudKey,
            "holds an AWS secret access key",
            &["akia", "asia"],
            r#"((?:AKIA|ASIA)[A-Z2-7]{16})["',;:= \t]{1,4}([A-Za-z0-9/+]{40})"#,
        )
        .group(2)
        .context(1)
        .mask(Mask::Length)
        .check(|c| {
            varied(c) && !c.secret.ends_with("EXAMPLEKEY") && !c.context.ends_with("EXAMPLE")
        }),
        // A shared access signature: `sig=` and the base64 of an HMAC, in a
        // query that also has the version and a time or a permission.
        Spec::new(
            CloudKey,
            "holds an Azure shared access signature",
            &["sig="],
            r"(?i)[?&;]sig=([A-Za-z0-9+/_\-]{40,}={0,2})",
        )
        .group(1)
        .mask(Mask::Length)
        .check(|c| varied(c) && near(c, &["sv=", "se=", "sp=", "sr=", "srt="])),
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
        // A Discord bot's token is its id, the age of the token and a
        // signature, three base64url parts; a webhook is a URL with its
        // token in it. The lengths alone are those of a chain of ordinary
        // identifiers (`Controller.handler.processRequest`): the first part
        // must decode to the digits of an id. A match that fails that check
        // is searched again from one character after its start, and a
        // letter glued before the id does not hide it.
        Spec::new(
            ApiKey,
            "holds a Discord bot token",
            &["."],
            r"[MNO][A-Za-z0-9_\-]{22,27}\.[A-Za-z0-9_\-]{6,7}\.[A-Za-z0-9_\-]{27,40}",
        )
        .mask(Mask::Length)
        .check(discord_bot)
        .unbounded()
        .rescan(),
        Spec::new(
            ApiKey,
            "holds a Discord webhook URL",
            &["webhooks/"],
            r"https://(?:[a-z]+\.)?discord(?:app)?\.com/api/(?:v[0-9]+/)?webhooks/[0-9]{17,20}/[A-Za-z0-9_\-]{60,80}",
        )
        .unbounded(),
        // A Telegram bot's token is its id, a colon, `AA` and thirty-three
        // characters; the API takes it after `bot` in a URL.
        Spec::new(
            ApiKey,
            "holds a Telegram bot token",
            &[":aa"],
            r"[0-9]{8,10}:AA[A-Za-z0-9_\-]{33}",
        )
        .mask(Mask::Length)
        .unbounded()
        .check(telegram),
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
        .mask(Mask::Prefix(3))
        // A signature is a hash: empty (`none`) or long. The word
        // `signature` after two parts is a document's.
        .check(|c| {
            let signature = c.secret.rsplit('.').next().unwrap_or_default();
            signature.is_empty() || signature.len() >= 16
        }),
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
        .raw()
        .check(|c| !text::is_reference(c.secret) && !text::is_placeholder(c.secret, &ADDRESS)),
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
        .raw()
        .check(|c| {
            !text::is_reference(c.secret)
                && !text::is_placeholder(c.secret, &ADDRESS)
                && !is_database(c.context)
        }),
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
        // The `auth` of a Docker `config.json` (and the like) is the base64
        // of `user:password`, as a Basic header's is.
        Spec::new(
            BasicAuth,
            "holds a registry login (the base64 of a user and password)",
            &["auth"],
            r#"(?i)auth["']?[ \t]*:[ \t]*["']?([A-Za-z0-9+/]{8,}={0,2})"#,
        )
        .group(1)
        .mask(Mask::Length)
        .check(|c| base64::is_user_and_password(c.secret)),
        // A `.netrc` entry: `machine`, `login` and `password` and a word.
        Spec::new(
            GenericSecret,
            "holds a password beside a machine and a login",
            &["password"],
            r"(?i)password[ \t]+([^ \t\r\n]{4,})",
        )
        .group(1)
        .mask(Mask::Length)
        .check(netrc),
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
