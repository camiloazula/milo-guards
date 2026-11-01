//! What a second review's probe found, kept as rows: every kind of key in the
//! dress it comes in is found whole (each byte of the secret is in a span), and
//! the text of a code base that looks like a secret and is not is Safe. A row
//! of these is a hole that was found once; a change that reopens it fails here.

mod common;

use milo_guards_secrets::{find, find_spans};

fn fill(seed: &str, length: usize) -> String {
    common::fill(seed, length)
}

/// Whether every byte of the first `secret` in `text` is in a span, and what
/// the findings say if a part is not.
fn covered(text: &str, secret: &str) -> Result<(), String> {
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
fn p(bad: &mut Vec<String>, label: &str, text: &str, secret: &str) {
    if let Err(why) = covered(text, secret) {
        bad.push(format!("{label}: {why}"));
    }
}

/// A row: the text must be Safe.
fn s(bad: &mut Vec<String>, label: &str, text: &str) {
    let assessment = find(text);
    if !assessment.is_safe() {
        bad.push(format!("{label}: {:?}", assessment.findings()));
    }
}

fn nothing_wrong(bad: &[String]) {
    assert!(
        bad.is_empty(),
        "{} rows wrong:\n{}",
        bad.len(),
        bad.join("\n")
    );
}

#[test]
fn the_second_probe_rows_of_where_a_value_ends() {
    let mut bad = Vec::new();
    p(
        &mut bad,
        "%26 in query value",
        "https://api.fake.test/login?user=me&password=F4kePa%26ss9word&next=/",
        "F4kePa%26ss9word",
    );
    p(
        &mut bad,
        "%20 in value",
        "password=F4kePass9%20more9",
        "F4kePass9%20more9",
    );
    p(
        &mut bad,
        "json escaped quote",
        "{\"password\": \"F4kePass9\\\"tail0123\"}",
        "F4kePass9\\\"tail0123",
    );
    p(
        &mut bad,
        "json \\u0022",
        "{\"password\": \"F4kePass9\\u0022tail0123\"}",
        "F4kePass9\\u0022tail0123",
    );
    p(
        &mut bad,
        "alt \\\" and %22",
        "{\"password\": \"F4ke\\\"Pa%22ss\\\"9w%22ord\"}",
        "F4ke\\\"Pa%22ss\\\"9w%22ord",
    );
    p(
        &mut bad,
        "alt %22 unquoted",
        "password=F4ke%22Pa%22ss9word",
        "F4ke%22Pa%22ss9word",
    );
    p(
        &mut bad,
        "pipe",
        "SECRET=F4kePass9|tail0123",
        "F4kePass9|tail0123",
    );
    p(&mut bad, "comma", "SECRET=F4ke,Pass9word", "F4ke,Pass9word");
    p(
        &mut bad,
        "semicolon no pair",
        "password=F4ke;Pass9word",
        "F4ke;Pass9word",
    );
    p(
        &mut bad,
        "amp no pair",
        "SECRET=F4ke&Pass9word",
        "F4ke&Pass9word",
    );
    p(
        &mut bad,
        "query & inside quoted value",
        "?user=me&password=\"F4ke&Pass9=x\"&next=1",
        "F4ke&Pass9=x",
    );
    p(
        &mut bad,
        "adonet ; inside quoted pw",
        "Server=db;User Id=me;Password=\"F4ke;Pass9=x\";Encrypt=true",
        "F4ke;Pass9=x",
    );
    p(
        &mut bad,
        "adonet ; inside single-quoted pw",
        "Server=db;User Id=me;Password='F4ke;Pass9=x';Encrypt=true",
        "F4ke;Pass9=x",
    );
    p(
        &mut bad,
        "odbc braces ; inside",
        "Driver={SQL};Uid=me;Pwd={F4ke;Pass9=x};",
        "F4ke;Pass9=x",
    );
    p(
        &mut bad,
        "unbalanced ( open",
        "(password=F4kePass9word",
        "F4kePass9word",
    );
    p(
        &mut bad,
        "name in json string, escaped quote in value",
        "[\"password=F4kePa\\\"ss9word\"]",
        "F4kePa\\\"ss9word",
    );
    p(
        &mut bad,
        "name in single-quoted, '' in value",
        "'password=F4kePa''ss9word'",
        "F4kePa''ss9word",
    );
    p(
        &mut bad,
        "quoted never closes",
        "password=\"F4kePass9word and more",
        "F4kePass9word",
    );
    p(
        &mut bad,
        "pg %2F",
        "postgres://fakeuser:F4ke%2FPass9@db.fake.test/app",
        "F4ke%2FPass9",
    );
    p(
        &mut bad,
        "pg user %40",
        "postgres://fakeuser%40fakeserver:F4kePass9@fake.postgres.database.azure.com/app",
        "F4kePass9",
    );
    p(
        &mut bad,
        "https %2F",
        "https://fakeuser:F4ke%2FPass9@git.fake.test/r.git",
        "F4ke%2FPass9",
    );
    p(
        &mut bad,
        "pg %2F%40 mix",
        "postgres://u%40s:F4%2Fke%40Pa%3Ass9@db.fake.test/app",
        "F4%2Fke%40Pa%3Ass9",
    );
    p(
        &mut bad,
        "pg password with literal space? no; tab",
        "postgres://u:F4kePass9@db",
        "F4kePass9",
    );
    p(
        &mut bad,
        "yaml single quoted '' ",
        "db_password: 'F4ke''Pass9'",
        "F4ke''Pass9",
    );
    p(&mut bad, "pgp comment email", &format!("-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: GnuPG v2\nComment: Fake <fake@example.org>\n\n{}\n=Ab3d\n-----END PGP PRIVATE KEY BLOCK-----", fill("FakeKeyBody0+/", 256)), &fill("FakeKeyBody0+/", 256)[..64]);
    let b = fill("FakeKeyBody0+/", 64);
    p(
        &mut bad,
        "pem body line > 4096",
        &format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
            fill("FakeKeyBody0+/", 6000)
        ),
        &fill("FakeKeyBody0+/", 6000),
    );
    p(&mut bad, "pem double escaped", &format!("{{\"k\": \"{{\\\"private_key\\\": \\\"-----BEGIN PRIVATE KEY-----\\\\n{b}\\\\n{b}\\\\n-----END PRIVATE KEY-----\\\"}}\"}}"), &b);
    nothing_wrong(&bad);
}

#[test]
fn the_second_probe_rows_of_standins_and_values() {
    let mut bad = Vec::new();
    for (l, t, s) in [
        ("Password1", "password=Password1", "Password1"),
        ("MyPassword!", "password=MyPassword!", "MyPassword!"),
        ("supersecret42", "secret=supersecret42", "supersecret42"),
        ("token-8f3a hex", "token=token-8f3a9c2e", "token-8f3a9c2e"),
        (
            "token-8f3a long",
            "token=token-8f3a9c2e7b1d4f60",
            "token-8f3a9c2e7b1d4f60",
        ),
        (
            "prod_api_key_9X",
            "api_key=prod_api_key_9Xq",
            "prod_api_key_9Xq",
        ),
        (
            "prod_api_key long",
            "api_key=prod_api_key_9XqZwTnV",
            "prod_api_key_9XqZwTnV",
        ),
        (
            "Secret!Strong",
            "client_secret: \"MySecret!Strong#Pass\"",
            "MySecret!Strong#Pass",
        ),
        ("P@ssword2024", "DB_PASSWORD=P@ssword2024", "P@ssword2024"),
        ("Passw0rd!", "password=Passw0rd!", "Passw0rd!"),
        (
            "pg Password1",
            "postgres://admin:Password1@db.fake.test/app",
            "Password1",
        ),
        (
            "upper snake env",
            "DB_PASSWORD=K7X_93QZ_M2PL_W8RT",
            "K7X_93QZ_M2PL_W8RT",
        ),
        (
            "upper snake quoted",
            "secret: \"QZ7W_P3XK_M2LV_9TRB\"",
            "QZ7W_P3XK_M2LV_9TRB",
        ),
        (
            "upper snake in pg",
            "postgres://u:PROD_PW_7X3K@db.fake.test/x",
            "PROD_PW_7X3K",
        ),
        (
            "upper snake jwt secret",
            "JWT_SECRET=MY_APP_JWT_KEY_2024",
            "MY_APP_JWT_KEY_2024",
        ),
        ("stem Example", "password=Example#2024", "Example#2024"),
        ("stem Sample", "password=Sample1234", "Sample1234"),
        ("stem Todo", "secret=Todo4Ever99", "Todo4Ever99"),
        ("stem Replace", "token=Replace!Me9x", "Replace!Me9x"),
        (
            "stem in pg",
            "postgres://u:Dummy2024x@db.fake.test/x",
            "Dummy2024x",
        ),
        ("elided real", "password=ab...cd9X", "ab...cd9X"),
        (
            "repeated tail pw",
            "password=Zq9!aaaaaaaaaaaaaaaaaa",
            "Zq9!aaaaaaaaaaaaaaaaaa",
        ),
        ("mask-ish pw", "password=-_-_-_-_", "-_-_-_-_"),
        (
            "long low variety key",
            "api_key=a1b2c3a1b2c3a1b2c3a1b2c3",
            "a1b2c3a1b2c3a1b2c3a1b2c3",
        ),
    ] {
        p(&mut bad, l, t, s);
    }
    // provider rows with low variety tails
    p(
        &mut bad,
        "ghp low variety tail",
        &format!(
            "x ghp_{}{} y",
            fill("Q7wE9rT2yU4iO6pA8sD0", 20),
            fill("ab12", 16)
        ),
        &format!(
            "ghp_{}{}",
            fill("Q7wE9rT2yU4iO6pA8sD0", 20),
            fill("ab12", 16)
        ),
    );
    p(
        &mut bad,
        "ghp 5 distinct tail",
        &format!(
            "x ghp_{}{} y",
            fill("Q7wE9rT2yU4iO6pA8sD0", 20),
            fill("abc12", 16)
        ),
        &format!(
            "ghp_{}{}",
            fill("Q7wE9rT2yU4iO6pA8sD0", 20),
            fill("abc12", 16)
        ),
    );
    p(
        &mut bad,
        "ghp 6 distinct tail",
        &format!(
            "x ghp_{}{} y",
            fill("Q7wE9rT2yU4iO6pA8sD0", 20),
            fill("abc123", 16)
        ),
        &format!(
            "ghp_{}{}",
            fill("Q7wE9rT2yU4iO6pA8sD0", 20),
            fill("abc123", 16)
        ),
    );
    // precision: standins still Safe?
    for t in [
        "api_key=api_key",
        "password=PASSWORD",
        "token = DEFAULT_TOKEN",
        "OPENAI_API_KEY=sk-...",
        "password=changeme",
        "GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    ] {
        s(&mut bad, t, t);
    }
    nothing_wrong(&bad);
}

#[test]
fn the_second_probe_rows_of_merging() {
    let mut bad = Vec::new();
    let aws = format!("AKIA{}", "Q7FAKE2TESTK3YZW");
    let gh = format!("ghp_{}", fill("FakeGitHubToken0123x", 36));
    let jwt = format!(
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlIn0.{}",
        fill("FakeSig_09-", 43)
    );
    p(
        &mut bad,
        "aws inside longer password",
        &format!("password=Xy9!{aws}/tail9"),
        &format!("Xy9!{aws}/tail9"),
    );
    p(
        &mut bad,
        "gh then suffix",
        &format!("secret=\"{gh}-extra-9\""),
        &format!("{gh}-extra-9"),
    );
    p(
        &mut bad,
        "chain gh + email + ip in pw",
        &format!("password=\"{gh}:me@fake.io:8.8.4.4\""),
        &format!("{gh}:me@fake.io:8.8.4.4"),
    );
    p(
        &mut bad,
        "jwt in url pw",
        &format!("https://u:{jwt}@h.fake.test/"),
        &jwt,
    );
    p(
        &mut bad,
        "two keys joined",
        &format!("token={aws}{}", &gh[..]),
        &format!("{aws}{gh}"),
    );
    p(
        &mut bad,
        "escaped key + generic",
        &format!("token=%41KIA{}/zz9", "Q7FAKE2TESTK3YZW"),
        &format!("%41KIA{}/zz9", "Q7FAKE2TESTK3YZW"),
    );
    nothing_wrong(&bad);
}

#[test]
fn the_second_probe_extra_rows() {
    let mut bad = Vec::new();
    p(
        &mut bad,
        "odbc braces plain",
        "Driver={SQL};Uid=me;Pwd={F4kePass9};",
        "F4kePass9",
    );
    p(
        &mut bad,
        "mysecretpassword",
        "POSTGRES_PASSWORD=mysecretpassword",
        "mysecretpassword",
    );
    p(
        &mut bad,
        "secret_key django",
        "SECRET_KEY = 'django-insecure-secret-key-9x'",
        "django-insecure-secret-key-9x",
    );
    p(
        &mut bad,
        "token own + 3 digits",
        "token=mytoken_A1b2C3zz",
        "mytoken_A1b2C3zz",
    );
    nothing_wrong(&bad);
}
