//! What must be Safe: the ordinary text of a code base, which is full of
//! things that look like secrets and are not, and the stand-ins for secrets
//! that a document writes on purpose. Each row is a false alarm this guard
//! does not raise; the ones it does raise are listed on its design page. The
//! plain texts are in `tests/cases/safe.cases`; what stays here is built in
//! Rust, so that no value shaped like a real key sits in the repository, or
//! is a whole page.

mod common;

use common::{base64url, fill};
use milo_guards_secrets::find;

/// Every row is Safe.
fn assert_safe(rows: &[String]) {
    for row in rows {
        assert!(
            find(row).is_safe(),
            "{row:?}\n  got {:?}",
            find(row).findings()
        );
    }
}

#[test]
fn every_case() {
    common::cases::check("safe");
}

#[test]
fn encoded_data_is_safe() {
    let integrity = format!("sha512-{}==", fill("Zm9vYmFyMDEyMzQ1Njc4OWFiY2RlZg+/", 86));
    let blob = fill("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5+/", 400);
    assert_safe(&[
        format!("\"resolved\": \"https://registry.npmjs.org/x/-/x-1.0.0.tgz\",\n\"integrity\": \"{integrity}\""),
        blob.clone(),
        format!("data:image/png;base64,{blob}"),
    ]);
}

#[test]
fn a_page_of_rust_source_is_safe() {
    let page = r#"
//! The parser reads a line at a time.
use std::collections::HashMap;

const SHA: &str = "3f786850e387550fdab836ed7e6dc881de23001b";
const ID: &str = "550e8400-e29b-41d4-a716-446655440000";
const FIXTURE: &str = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=";
const DIGEST: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

pub struct Config {
    pub password: String,
    pub token: Option<String>,
    pub secret_key: &'static str,
    pub max_tokens: usize,
    pub api_key: SecretString,
}

impl Config {
    pub fn from_env() -> Self {
        let password = std::env::var("APP_PASSWORD").unwrap_or_default();
        let token = get_token();
        let secret = self.secret;
        Self { password, token, secret_key: "", max_tokens: 100000, api_key: api_key() }
    }

    fn login(&self, user: &str, password: &str) -> Result<(), Error> {
        let password = password.trim();
        self.client.login(user, password = password)?;
        let token = self.token;
        let tokens = lex(&self.text);
        if token == tokens[0] { return Ok(()); }
        for (i, b) in bytes.iter().enumerate() { total += b * 2654435761 % 4294967296; }
        Err(Error::new("invalid password"))
    }
}

#[test]
fn it_hashes() {
    assert_eq!(sha1("abc"), "a9993e364706816aba3e25717850c26c9cd0d89d");
    let mut map: HashMap<&str, u64> = HashMap::new();
    map.insert("version", 1);
    let url = "https://example.com/a/b?c=d#e";
    let mail = "someone@example.com";
    let remote = "git@github.com:org/repo.git";
    let ip = "127.0.0.1"; let net = "192.168.1.10"; let meta = "169.254.169.254";
    let v6 = "::1"; let doc = "2001:db8::1"; let ll = "fe80::1";
    let t = "12:30:45"; let path = "std::string::String";
}
"#;
    assert!(find(page).is_safe(), "{:?}", find(page).findings());
}

#[test]
fn stand_ins_for_secrets_are_safe() {
    assert_safe(&[
        // The secret AWS's documentation shows ends in EXAMPLEKEY.
        format!(
            "aws_secret_access_key = {}",
            ["wJalrXUtnFEMI/K7MDENG/", "bPxRfiCYEXAMPLEKEY"].concat()
        ),
        format!("ghp_{}", "x".repeat(36)),
        format!("ghp_{}", "0".repeat(36)),
        format!("sk-ant-api03-{}", "x".repeat(95)),
        format!("sk-{}", "A".repeat(48)),
        format!("AKIA{}", "X".repeat(16)),
        format!("npm_{}", "x".repeat(36)),
    ]);
}

#[test]
fn a_token_inside_a_longer_word_is_not_a_token() {
    let github = format!("ghp_{}", fill("FakeGitHub0", 36));
    let aws = ["AKIA", "FAKE2KEY3ID4TEST"].concat();
    assert_safe(&[
        format!("x{github}"),
        format!("abc{aws}"),
        format!("{aws}ABC"),
        format!("{aws}7"),
    ]);
}

#[test]
fn lower_case_is_not_a_provider_key() {
    let aws = ["akia", "fake2key3id4test"].concat();
    assert!(find(&aws).is_safe());
    let github = format!("GHP_{}", fill("FakeGitHub0", 36));
    assert!(find(&github).is_safe());
}

#[test]
fn a_placeholder_key_is_safe_by_what_follows_the_providers_prefix() {
    // The letters of a prefix (`sk_live_`, `glpat-`) are not variety.
    for (prefix, length) in [
        ("sk_live_", 24),
        ("sk_test_", 24),
        ("rk_live_", 24),
        ("glpat-", 20),
        ("npm_", 36),
        ("ghp_", 36),
        ("hf_", 34),
        ("shpat_", 32),
        ("sk-ant-api03-", 93),
        ("xoxb-", 24),
        ("whsec_", 32),
    ] {
        for filler in ["x", "0", "ab"] {
            let key = format!(
                "{prefix}{}",
                filler
                    .repeat(length)
                    .chars()
                    .take(length)
                    .collect::<String>()
            );
            assert!(find(&key).is_safe(), "{key} {:?}", find(&key).findings());
            let line = format!("KEY={key}");
            assert!(find(&line).is_safe(), "{line}");
        }
    }
    // And a key that is random behind its prefix is one.
    for key in [
        format!("sk_live_{}", fill("Q7wE9rT2yU4iO6pA8sD0", 24)),
        format!("glpat-{}", fill("Q7wE9rT2yU4iO6pA8sD0", 20)),
        format!(
            "sk_test_{}{}",
            fill("Q7wE9rT2yU4iO6pA8sD0", 12),
            "x".repeat(12)
        ),
    ] {
        assert!(!find(&key).is_safe(), "{key}");
    }
}

#[test]
fn a_dotted_chain_that_decodes_to_no_user_id_is_not_a_discord_token() {
    assert_safe(&[
        // The first part decodes to letters, not to an id.
        format!(
            "see {}.GaBcDe.{}",
            base64url("abcdefghijklmnopqr"),
            fill("FakeDiscordTok_-9", 38)
        ),
        // Digits and letters: not an id either.
        format!(
            "x = {}.GaBcDe.{}",
            base64url("12345678901234567x"),
            fill("FakeDiscordTok_-9", 38)
        ),
        // An id that is too short, and one that is too long, are not a user's.
        format!(
            "{}.GaBcDe.{}",
            base64url("1234567890123456"),
            fill("FakeDiscordTok_-9", 38)
        ),
        format!(
            "{}.GaBcDe.{}",
            base64url("1234567890123456789012"),
            fill("FakeDiscordTok_-9", 38)
        ),
    ]);
}
