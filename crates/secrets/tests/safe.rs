//! What must be Safe: the ordinary text of a code base, which is full of
//! things that look like secrets and are not, and the stand-ins for secrets
//! that a document writes on purpose. Each row is a false alarm this guard
//! does not raise; the ones it does raise are listed on its design page.

mod common;

use common::fill;
use milo_guards_core::testing::check;
use milo_guards_secrets::{find, Rule};

#[test]
fn hashes_ids_and_encoded_data_are_safe() {
    let sha1 = "3f786850e387550fdab836ed7e6dc881de23001b";
    let sha256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    let integrity = format!("sha512-{}==", fill("Zm9vYmFyMDEyMzQ1Njc4OWFiY2RlZg+/", 86));
    let blob = fill("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5+/", 400);
    let rows = [
        sha1.to_string(),
        sha256.to_string(),
        format!("commit {sha1}"),
        format!("[[package]]\nname = \"x\"\nchecksum = \"{sha256}\""),
        format!("\"resolved\": \"https://registry.npmjs.org/x/-/x-1.0.0.tgz\",\n\"integrity\": \"{integrity}\""),
        "550e8400-e29b-41d4-a716-446655440000".to_string(),
        "id: 123e4567-e89b-12d3-a456-426614174000".to_string(),
        blob.clone(),
        format!("data:image/png;base64,{blob}"),
        "const t=function(e){return e.map(function(n){return n*2})};var a=[1,2,3],b={x:1};".to_string(),
        "!function(e,t){\"object\"==typeof exports?module.exports=t():e.lib=t()}(this,function(){return{a:1}});".to_string(),
        "1700000000000".to_string(),
        "ts=1700000000123456".to_string(),
        "0x4111111111111111".to_string(),
    ];
    for row in &rows {
        assert!(
            find(row).is_safe(),
            "{row:?}\n  got {:?}",
            find(row).findings()
        );
    }
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
fn names_that_look_like_secrets_but_hold_none_are_safe() {
    let safe = [
        "password: String,",
        "pub token: Option<String>,",
        "token?: string;",
        "const password = get_password();",
        "let password = prompt();",
        "token = self.token",
        "token=self.token",
        "password=args.password",
        "password = os.environ[\"PASSWORD\"]",
        "password=getpass.getpass()",
        "max_tokens=100000",
        "\"max_tokens\": 100000",
        "num_tokens: 4096",
        "tokenizer = \"bert-base-uncased\"",
        "password_hash = \"abc123\"",
        "password_field: \"user_password\"",
        "\"password\": \"Password\"",
        "\"password\": \"Mot de passe\"",
        "\"password\": \"string\"",
        "\"password\": \"\"",
        "password=",
        "password: ",
        "password = ''",
        "password=${DB_PASSWORD}",
        "password: ${DB_PASSWORD:-changeme-not-a-value}",
        "PASSWORD=$DB_PASSWORD",
        "password: <your password>",
        "--password=<password>",
        "token={{ token }}",
        "token: \"{{ vault_token }}\"",
        "password=%s",
        "password: [REDACTED]",
        "password: \"********\"",
        "password=xxxxxxxxxx",
        "token=YOUR_TOKEN_HERE",
        "secret: !secret db_secret",
        "token: null",
        "password: true",
        "bypass=1234567890",
        "compass=northeast",
        "api_key=abc",
        "type=\"password\"",
        "<input type=\"password\" name=\"password\" placeholder=\"Password\">",
        "secret_name: my-secret-name-with-dashes",
        "password == other.password",
    ];
    for row in safe {
        assert!(
            find(row).is_safe(),
            "{row:?}\n  got {:?}",
            find(row).findings()
        );
    }
}

#[test]
fn stand_ins_for_secrets_are_safe() {
    let rows = [
        // The ids AWS's documentation shows end in EXAMPLE.
        "AKIAIOSFODNN7EXAMPLE".to_string(),
        format!("aws_secret_access_key = {}", ["wJalrXUtnFEMI/K7MDENG/", "bPxRfiCYEXAMPLEKEY"].concat()),
        format!("ghp_{}", "x".repeat(36)),
        format!("ghp_{}", "0".repeat(36)),
        format!("sk-ant-api03-{}", "x".repeat(95)),
        format!("sk-{}", "A".repeat(48)),
        format!("AKIA{}", "X".repeat(16)),
        format!("npm_{}", "x".repeat(36)),
        "postgres://user:${DB_PASSWORD}@db/app".to_string(),
        "postgres://user:<password>@db/app".to_string(),
        "https://user:$PASS@host.io/".to_string(),
        "postgres://user@db/app".to_string(),
        "postgres://db:5432/app".to_string(),
        "https://host.io:8080/path?x=a@b".to_string(),
        "ssh://git@github.com:22/org/repo.git".to_string(),
        "Authorization: Bearer ${TOKEN}".to_string(),
        "Authorization: Bearer <token>".to_string(),
        "Authorization: Bearer YOUR_TOKEN_HERE".to_string(),
        "Authorization: Bearer".to_string(),
        "Basic authentication sends the credentials in a header".to_string(),
        "Basic configuration for the build".to_string(),
        "Authorization: Basic ZmFrZQ==".to_string(),
        // The pair RFC 7617 writes its example with.
        "Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==".to_string(),
        "bearer instruments are issued unregistered".to_string(),
        // A header alone is not a key.
        "-----BEGIN PRIVATE KEY-----".to_string(),
        "Paste the block that starts with `-----BEGIN RSA PRIVATE KEY-----` here.".to_string(),
        "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----".to_string(),
        "-----BEGIN PRIVATE KEY-----\nThe key goes here, and this is how it is read by the tool.\n-----END PRIVATE KEY-----".to_string(),
        "-----BEGIN CERTIFICATE-----\nMIIBsjCCAVigAwIBAgIUFakeFakeFakeFakeFakeFakeFakeFakeFake\n-----END CERTIFICATE-----".to_string(),
        "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFakeFakeFakeFakeFakeFakeFake\n-----END PUBLIC KEY-----".to_string(),
    ];
    for row in &rows {
        assert!(
            find(row).is_safe(),
            "{row:?}\n  got {:?}",
            find(row).findings()
        );
    }
}

#[test]
fn addresses_and_numbers_that_belong_to_no_one_are_safe() {
    let rows = [
        // Reserved for examples.
        "user@example.com",
        "user@mail.example.org",
        "me@example.net",
        "me@host.invalid",
        "me@box.test",
        "me@laptop.localhost",
        // Not an address.
        "git@github.com:org/repo.git",
        "scp file git@host.io:/srv/x",
        "logo@2x.png",
        "icon@3x.png",
        "lodash@4.17.21",
        "react@latest",
        "@types/node",
        "a@b",
        // Not public.
        "127.0.0.1",
        "0.0.0.0",
        "10.1.2.3",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "192.0.2.1",
        "198.51.100.7",
        "203.0.113.9",
        "224.0.0.1",
        "255.255.255.255",
        "::1",
        "::",
        "fe80::1",
        "fd00::1234",
        "ff02::1",
        "2001:db8::1",
        "2002:c000:204::1",
        "std::string::String",
        "Add::add",
        "12:30:45",
        "10:20:30:40",
        // Not an address at all.
        "1.2.3",
        "256.1.1.1",
        "01.2.3.4",
        "1.2.3.4.5",
        "v1.2.3.4",
        "1.2.3.4-beta",
        "1.2.3.4.5.6",
        "1.3.6.1.4.1.311",
        // Not an id or a card.
        "000-12-3456",
        "666-12-3456",
        "900-12-3456",
        "123-00-6789",
        "123-45-0000",
        "1234-45-6789",
        "123-45-67890",
        "2024-01-0001",
        "BG 12 34 56 C",
        "AB 12 34 56 E",
        "4111111111111112",
        "4111 1111 1111 1112",
        "1111111111111111",
        "0000000000000000",
        "1234567890123456",
        "41111111111111111111",
        "529.982.247-26",
        "111.111.111-11",
        // Not a phone.
        "+1",
        "+12345",
        "a+b",
        "x = 1 +2",
        "+0123456789",
        "abc+14155550132",
        "c3VwZXIrMTQxNTU1NTAxMzI=",
        "1+14155550132",
        "+14155550132abc",
    ];
    for row in rows {
        assert!(
            find(row).is_safe(),
            "{row:?}\n  got {:?}",
            find(row).findings()
        );
    }
}

#[test]
fn a_token_inside_a_longer_word_is_not_a_token() {
    let github = format!("ghp_{}", fill("FakeGitHub0", 36));
    let aws = ["AKIA", "FAKE2KEY3ID4TEST"].concat();
    for row in [
        format!("x{github}"),
        format!("abc{aws}"),
        format!("{aws}ABC"),
        format!("{aws}7"),
    ] {
        assert!(
            find(&row).is_safe(),
            "{row:?}\n  got {:?}",
            find(&row).findings()
        );
    }
}

#[test]
fn lower_case_is_not_a_provider_key() {
    let aws = ["akia", "fake2key3id4test"].concat();
    assert!(find(&aws).is_safe());
    let github = format!("GHP_{}", fill("FakeGitHub0", 36));
    assert!(find(&github).is_safe());
}

#[test]
fn what_is_found_is_not_found_twice() {
    // The password of a URL is not also read as an email's local part, and
    // a card number is not also a phone.
    let text = "https://me:fakePass0word1@git.corp.io/r.git";
    check(&[], &[(text, Rule::UrlCredentials)], find);
    assert_eq!(find(text).findings().len(), 1);
}

#[test]
fn a_stand_in_is_safe_by_its_shape() {
    // Upper snake case, the name of a constant.
    // Repeated characters, or too few different ones.
    // A value that contains its own name. An elision. A stem from the closed
    // list, and a literal.
    let rows = [
        // upper snake case
        "password: DEFAULT_PASSWORD",
        "token=DEFAULT_TOKEN",
        "def auth(self, password=None, token=DEFAULT_TOKEN):",
        "CLIENT_SECRET=REPLACE_ME",
        "API_KEY=YOUR_API_KEY_HERE",
        "secret: SECRET_FROM_VAULT",
        "secret = \"MY_SECRET_2\"",
        // repeated characters
        "password=aaaaaaaaaa",
        "token: \"0000000000000000\"",
        "secret=abababababababababab",
        "GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "api_key=1111111111111111",
        // its own name
        "api_key=api_key",
        "API_KEY=api-key",
        "apiKey: apiKey",
        "api_key = \"API_KEY\"",
        "password=password",
        "db_password=dummy_password",
        "secret: test-secret-value",
        "secret_key: my-secret-2",
        "existingSecret: my-secret-2",
        "token: my-token-1",
        "pass=pass",
        // an elision
        "OPENAI_API_KEY=sk-...",
        "OPENAI_API_KEY=\"sk-…\"",
        "token=ghp_...",
        // the closed list of stems, and literals
        "password=changeme",
        "PASSWORD: changeme123",
        "password: \"change-me-please\"",
        "password=change_me_1",
        "token=replace-with-your-token-1",
        "secret=dummy-value-1",
        "password: placeholder1",
        "token: example-token-1",
        "secret=sample-secret-1",
        "password=todo-fix-this-1",
        "password: string;",
        "\"password\": \"string\"",
        "token: undefined,",
        // in an address, by the shapes that need no name
        "postgres://user:CHANGE_ME@db.fake.test/app",
        "postgres://user:changeme@db.fake.test/app",
        "https://user:xxxxxxxx@host.fake.test/",
    ];
    for row in rows {
        assert!(
            find(row).is_safe(),
            "{row:?}\n  got {:?}",
            find(row).findings()
        );
    }
}

#[test]
fn a_stand_in_shape_does_not_hide_a_value_that_is_one() {
    // The shapes are of a stand-in; a value that is none of them is a secret,
    // whatever it looks like next to its name.
    for row in [
        "password=F4kePass9word1",
        "api_key=F4keApiKey0123456789abcdef",
        "OPENAI_API_KEY=F4keApiKey0123456789abcdef",
        "token=F4keTokenValue0123456789",
        "secret: \"F4keSecretValue0123456789\"",
        "password=Xy9!Qz2#Lm4$",
        "password=hunter22hunter",
        "db_pass=F4kePass9word1",
        "API_KEY=a1B2c3D4e5F6",
        "token=ABCDEF0123456789",
        "token=Replacement9Xy2",
        "postgres://app:F4kePass9word1@db.fake.test/app",
    ] {
        assert!(!find(row).is_safe(), "{row:?}");
    }
}
