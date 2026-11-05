//! What the tests share: values that match each provider's published format
//! and are obviously fake, built here so no credential-shaped literal sits in
//! the repository, one sample per row of the guard's table, and (in
//! [`cases`]) the runner of the case files in `tests/cases`, which hold the
//! texts that need no such value, and (in [`hostile`]) the hostile texts.

#![allow(dead_code, unreachable_pub)]

pub mod cases;
pub mod hostile;

use milo_guards_secrets::{find_spans, Rule};

/// `length` characters made by repeating `seed`.
pub fn fill(seed: &str, length: usize) -> String {
    seed.chars().cycle().take(length).collect()
}

/// Whether every byte of the first `secret` in `text` is in a span, and what
/// the findings say if a part is not.
pub fn covered(text: &str, secret: &str) -> Result<(), String> {
    let Some(at) = text.find(secret) else {
        return Err("the secret is not in the text".to_string());
    };
    let spans = find_spans(text);
    let missed = (at..at + secret.len())
        .filter(|byte| {
            !spans
                .iter()
                .any(|span| span.start <= *byte && *byte < span.end)
        })
        .count();
    if missed == 0 {
        return Ok(());
    }
    Err(format!(
        "{missed} of {} bytes not found, spans {spans:?}",
        secret.len()
    ))
}

/// A row: the text, and the secret in it that must be found whole.
pub fn p(bad: &mut Vec<String>, label: &str, text: &str, secret: &str) {
    if let Err(why) = covered(text, secret) {
        bad.push(format!("{label}: {why}"));
    }
}

/// The rows `p` found wrong, all of them in one message.
pub fn nothing_wrong(bad: &[String]) {
    assert!(
        bad.is_empty(),
        "{} rows wrong:\n{}",
        bad.len(),
        bad.join("\n")
    );
}

/// `text` as unpadded base64url, the way a Discord bot token writes its id.
pub fn base64url(text: &str) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in text.as_bytes().chunks(3) {
        let a = u32::from(chunk[0]);
        let b = chunk.get(1).map_or(0, |b| u32::from(*b));
        let c = chunk.get(2).map_or(0, |b| u32::from(*b));
        let bits = (a << 16) | (b << 8) | c;
        let digits = chunk.len() + 1;
        for n in 0..digits {
            let at = ((bits >> (18 - 6 * n)) & 63) as usize;
            out.push(char::from(ALPHABET[at]));
        }
    }
    out
}

/// A Discord bot token made from a user id, with a fake age and signature.
pub fn token(id: &str) -> String {
    format!("{}.GaBcDe.{}", base64url(id), fill("FakeDiscordTok_-9", 38))
}

/// One sample: the text around a secret, the secret itself and the rule and
/// reason a finding about it must have.
pub struct Sample {
    pub rule: Rule,
    pub reason: &'static str,
    pub before: String,
    pub secret: String,
    pub after: String,
}

impl Sample {
    pub fn text(&self) -> String {
        format!("{}{}{}", self.before, self.secret, self.after)
    }
}

fn sample(rule: Rule, reason: &'static str, before: &str, secret: String, after: &str) -> Sample {
    Sample {
        rule,
        reason,
        before: before.to_string(),
        secret,
        after: after.to_string(),
    }
}

/// A block of private key of the given kind, with a body of base64 lines.
pub fn pem(kind: &str) -> String {
    let body = (0..4)
        .map(|n| fill(&format!("FakeKeyBody{n}+/"), 64))
        .collect::<Vec<_>>()
        .join("\n");
    format!("-----BEGIN {kind}-----\n{body}\n-----END {kind}-----")
}

/// Every row of the table with a text that must hold exactly its secret.
#[allow(clippy::too_many_lines, reason = "one table, read top to bottom")]
pub fn samples() -> Vec<Sample> {
    use Rule::{
        ApiKey, BasicAuth, BearerToken, CloudKey, ConnectionString, CreditCard, Email,
        GenericSecret, GovernmentId, Jwt, Phone, PrivateKey, PublicIp, UrlCredentials,
    };
    let key = |prefix: &str, seed: &str, length: usize| format!("{prefix}{}", fill(seed, length));
    vec![
        sample(
            PrivateKey,
            "holds a private key",
            "key:\n",
            pem("RSA PRIVATE KEY"),
            "\nmore\n",
        ),
        sample(
            PrivateKey,
            "holds a private key",
            "",
            pem("OPENSSH PRIVATE KEY"),
            "",
        ),
        sample(
            PrivateKey,
            "holds a private key",
            "",
            pem("PRIVATE KEY"),
            "\n",
        ),
        sample(
            CloudKey,
            "holds an AWS access key",
            "aws_access_key_id = ",
            ["AKIA", "FAKE2KEY3ID4TEST"].concat(),
            "\n",
        ),
        sample(
            CloudKey,
            "holds an AWS access key",
            "temporary: ",
            ["ASIA", "FAKE2KEY3ID4TEST"].concat(),
            ",",
        ),
        sample(
            CloudKey,
            "holds an AWS secret access key",
            "aws_secret_access_key = \"",
            fill("fakeSecret/Key+0", 40),
            "\"",
        ),
        sample(
            CloudKey,
            "holds a Google API key",
            "GOOGLE_API_KEY=",
            key("AIza", "FakeGoogleKey_0-9", 35),
            "\n",
        ),
        sample(
            CloudKey,
            "holds a Google OAuth client secret",
            "client_secret: ",
            key("GOCSPX-", "FakeClient_0-9", 28),
            "",
        ),
        sample(
            CloudKey,
            "holds a Google OAuth access token",
            "token ",
            key("ya29.", "FakeAccess_0-9", 40),
            ".",
        ),
        sample(
            CloudKey,
            "holds an Azure storage account key",
            "DefaultEndpointsProtocol=https;AccountName=fake;AccountKey=",
            format!("{}==", fill("FakeAzure+/0", 86)),
            ";EndpointSuffix=core.windows.net",
        ),
        sample(
            CloudKey,
            "holds an Azure client secret",
            "secret: ",
            ["fak8Q~", &fill("fake-secret_value.0", 34)].concat(),
            "",
        ),
        sample(
            CloudKey,
            "holds a DigitalOcean token",
            "do_token=",
            key("dop_v1_", "0fadebc1", 64),
            "",
        ),
        sample(
            ApiKey,
            "holds an Anthropic API key",
            "ANTHROPIC=",
            [&key("sk-ant-api03-", "FakeAnt_0-9", 93), "AA"].concat(),
            "\n",
        ),
        sample(
            ApiKey,
            "holds an OpenAI API key",
            "key ",
            key("sk-proj-", "FakeOpenAI_0-9", 60),
            "",
        ),
        sample(
            ApiKey,
            "holds an OpenAI API key",
            "key ",
            key("sk-", "FakeOpenAI0", 48),
            "",
        ),
        sample(
            ApiKey,
            "holds an OpenAI API key",
            "key ",
            [
                "sk-",
                &fill("FakeLegacy0", 20),
                "T3BlbkFJ",
                &fill("FakeLegacy1", 20),
            ]
            .concat(),
            "",
        ),
        sample(
            ApiKey,
            "holds a Discord bot token",
            "DISCORD=",
            [
                "MTIzNDU2Nzg5MDEyMzQ1Njc4.GaBcDe.",
                &fill("FakeDiscordTok_-9", 38),
            ]
            .concat(),
            "\n",
        ),
        sample(
            ApiKey,
            "holds a Discord webhook URL",
            "curl ",
            [
                "https://discord.com/api/webhooks/123456789012345678/",
                &fill("FakeDiscordHook_-09", 68),
            ]
            .concat(),
            " -d x",
        ),
        sample(
            ApiKey,
            "holds a Telegram bot token",
            "https://api.telegram.org/bot",
            ["123456789:AA", &fill("FakeTgBotTok_-09", 33)].concat(),
            "/getMe",
        ),
        sample(
            CloudKey,
            "holds an Azure shared access signature",
            "https://fake.blob.core.windows.net/c?sv=2022-11-02&se=2030-01-01T00:00:00Z&sig=",
            fill("FakeSasSig0123AbCd", 43),
            "&x=1",
        ),
        sample(
            BasicAuth,
            "holds a registry login (the base64 of a user and password)",
            "{\"auth\": \"",
            "ZmFrZXVzZXI6ZmFrZXBhc3M5".to_string(),
            "\"}",
        ),
        sample(
            GenericSecret,
            "holds a password beside a machine and a login",
            "machine api.fake.test login fakeuser password ",
            "F4kePassw0rdZ".to_string(),
            "\n",
        ),
        sample(
            PrivateKey,
            "holds a PuTTY private key",
            "Private-Lines: 1\n",
            fill("FakeKeyBody0+/", 64),
            "\nPrivate-MAC: 00ff",
        ),
        sample(
            ApiKey,
            "holds a GitHub token",
            "GITHUB_TOKEN=",
            key("ghp_", "FakeGitHub0", 36),
            "\n",
        ),
        sample(
            ApiKey,
            "holds a GitHub token",
            "https://x:",
            key("gho_", "FakeGitHub1", 36),
            "@github.com",
        ),
        sample(
            ApiKey,
            "holds a GitHub token",
            "",
            [
                "github_pat_",
                &fill("FakePat0", 22),
                "_",
                &fill("FakePat1", 59),
            ]
            .concat(),
            "",
        ),
        sample(
            ApiKey,
            "holds a GitLab token",
            "gitlab ",
            key("glpat-", "FakeGitLab0", 20),
            "",
        ),
        sample(
            ApiKey,
            "holds a Slack token",
            "SLACK=",
            key("xoxb-", "1234567890-FakeSlack", 40),
            "",
        ),
        sample(
            ApiKey,
            "holds a Slack token",
            "SLACK=",
            key("xapp-1-", "A0FAKE00-1234-fakeslack", 40),
            "",
        ),
        sample(
            ApiKey,
            "holds a Slack webhook URL",
            "curl ",
            [
                "https://hooks.slack.com/services/T0FAKE000/B0FAKE000/",
                &fill("FakeHook0", 24),
            ]
            .concat(),
            " -d x",
        ),
        sample(
            ApiKey,
            "holds a Stripe key",
            "STRIPE=",
            key("sk_test_", "FakeStripe0", 28),
            "",
        ),
        sample(
            ApiKey,
            "holds a Stripe key",
            "STRIPE=",
            key("whsec_", "FakeStripe1", 36),
            "",
        ),
        sample(
            ApiKey,
            "holds a SendGrid API key",
            "SENDGRID=",
            ["SG.", &fill("FakeGrid0", 22), ".", &fill("FakeGrid1", 43)].concat(),
            "",
        ),
        sample(
            ApiKey,
            "holds a Twilio auth token",
            "TWILIO_AUTH_TOKEN=",
            fill("0fadebc1", 32),
            "\n",
        ),
        sample(
            ApiKey,
            "holds an npm token",
            "//registry.npmjs.org/:_authToken=",
            key("npm_", "FakeNpm0", 36),
            "",
        ),
        sample(
            ApiKey,
            "holds a PyPI token",
            "password: ",
            key("pypi-AgEIcHlwaS5vcmc", "FakePyPI0-", 60),
            "",
        ),
        sample(
            ApiKey,
            "holds a crates.io token",
            "cargo login ",
            key("cio", "FakeCrates0", 32),
            "",
        ),
        sample(
            ApiKey,
            "holds a Hugging Face token",
            "HF=",
            key("hf_", "FakeHugging", 34),
            "",
        ),
        sample(
            ApiKey,
            "holds a Shopify token",
            "SHOPIFY=",
            key("shpat_", "0fadebc1", 32),
            "",
        ),
        sample(
            Jwt,
            "holds a JSON web token",
            "token ",
            [
                "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlLXVzZXIifQ.",
                &fill("FakeSign0-", 43),
            ]
            .concat(),
            " ok",
        ),
        sample(
            ConnectionString,
            "holds a password in a connection string",
            "postgres://app:",
            "fakePass0word1".to_string(),
            "@db.internal:5432/app",
        ),
        sample(
            ConnectionString,
            "holds a password in a connection string",
            "REDIS_URL=redis://:",
            "fakePass0word1".to_string(),
            "@cache.internal:6379",
        ),
        sample(
            UrlCredentials,
            "holds a password in a URL",
            "git clone https://deploy:",
            "fakePass0word1".to_string(),
            "@git.corp.io/repo.git",
        ),
        sample(
            BasicAuth,
            "holds a Basic authorization credential",
            "Authorization: Basic ",
            "ZmFrZXVzZXI6ZmFrZXBhc3M=".to_string(),
            "\n",
        ),
        sample(
            BearerToken,
            "holds a bearer token",
            "Authorization: Bearer ",
            fill("FakeBearer0123456789", 40),
            "\n",
        ),
        sample(
            GenericSecret,
            "holds a password or secret",
            "DB_PASSWORD=",
            "fakePass0word1".to_string(),
            "\n",
        ),
        sample(
            GenericSecret,
            "holds a password or secret",
            "{\"api_key\": \"",
            "fakeValueAbc12".to_string(),
            "\"}",
        ),
        sample(
            CreditCard,
            "holds a payment card number",
            "card ",
            "4111 1111 1111 1111".to_string(),
            ".",
        ),
        sample(
            GovernmentId,
            "holds a US social security number",
            "ssn ",
            "123-45-6789".to_string(),
            "",
        ),
        sample(
            GovernmentId,
            "holds a UK national insurance number",
            "NI ",
            "AB 12 34 56 C".to_string(),
            "",
        ),
        sample(
            GovernmentId,
            "holds a Brazilian CPF number",
            "cpf ",
            "529.982.247-25".to_string(),
            "",
        ),
        sample(
            Email,
            "holds an email address",
            "mail ",
            "alice.smith@acme.io".to_string(),
            ".",
        ),
        sample(
            Phone,
            "holds a phone number",
            "call ",
            "+1 415 555 0132".to_string(),
            "",
        ),
        sample(
            PublicIp,
            "holds a public IP address",
            "ip ",
            "8.8.8.8".to_string(),
            "",
        ),
        sample(
            PublicIp,
            "holds a public IP address",
            "ip ",
            "2606:4700:4700::1111".to_string(),
            "",
        ),
    ]
}
