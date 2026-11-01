//! One table of texts per rule: each text must break its rule, and the
//! spelling variants a reviewer would try are rows of their own.

mod common;

use common::{fill, pem};
use milo_guards_core::testing::check;
use milo_guards_secrets::{find, find_spans, Rule};

/// The rules a text breaks, in order.
fn rules(text: &str) -> Vec<Rule> {
    find_spans(text).iter().map(|span| span.rule).collect()
}

/// A text with `value` as its only secret has exactly one finding of `rule`.
fn only(text: &str, rule: Rule) {
    assert_eq!(rules(text), [rule], "{text:?}");
}

#[test]
fn a_private_key_in_any_dress() {
    let body = fill("FakeKeyBody0+/", 64);
    let key = pem("RSA PRIVATE KEY");
    let escaped = key.replace('\n', "\\n");
    let crlf = key.replace('\n', "\r\n");
    let indented = key
        .lines()
        .map(|line| format!("    {line}"))
        .collect::<Vec<_>>()
        .join("\n");
    let commented = key
        .lines()
        .map(|line| format!("# {line}"))
        .collect::<Vec<_>>()
        .join("\n");
    let quoted = key
        .lines()
        .map(|line| format!("> {line}"))
        .collect::<Vec<_>>()
        .join("\n");
    let rows = [
        key,
        format!("{{\"private_key\": \"{escaped}\\n\"}}"),
        escaped,
        crlf,
        indented,
        commented,
        quoted,
        format!("-----BEGIN PRIVATE KEY-----\n{body}"),
        format!("-----BEGIN PRIVATE KEY-----\\n{body}\\n"),
        format!("key = '-----BEGIN EC PRIVATE KEY-----\n{body}\n'"),
        format!("-----BEGIN ENCRYPTED PRIVATE KEY-----\n{body}\n-----END ENCRYPTED PRIVATE KEY-----"),
        format!(
            "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0FADEBC10FADEBC1\n\n{body}\n-----END RSA PRIVATE KEY-----"
        ),
        format!(
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: Fake 1.0\n\n{body}\n=ab12\n-----END PGP PRIVATE KEY BLOCK-----"
        ),
        format!("-----BEGIN DSA PRIVATE KEY-----\n{body}\n-----END DSA PRIVATE KEY-----"),
        format!("-----BEGIN SSH2 ENCRYPTED PRIVATE KEY-----\n{body}\n-----END SSH2 ENCRYPTED PRIVATE KEY-----"),
    ];
    for row in &rows {
        only(row, Rule::PrivateKey);
    }
}

#[test]
fn a_private_key_is_found_whole_and_twice_when_there_are_two() {
    let key = pem("PRIVATE KEY");
    let text = format!("a\n{key}\nb\n{key}\nc");
    let spans = find_spans(&text);
    assert_eq!(spans.len(), 2);
    for span in &spans {
        assert_eq!(&text[span.start..span.end], key);
    }
}

#[test]
fn a_key_cut_short_is_a_key_as_far_as_it_goes() {
    let body = fill("FakeKeyBody0+/", 64);
    let text = format!("-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n\n\n");
    let spans = find_spans(&text);
    assert_eq!(spans.len(), 1);
    assert_eq!(
        &text[spans[0].start..spans[0].end],
        format!("-----BEGIN OPENSSH PRIVATE KEY-----\n{body}")
    );
}

#[test]
fn a_cloud_key() {
    let aws = ["AKIA", "FAKE2KEY3ID4TEST"].concat();
    let sts = ["ASIA", "FAKE2KEY3ID4TEST"].concat();
    let secret = fill("fakeSecret/Key+0", 40);
    let google = format!("AIza{}", fill("FakeGoogleKey_0-9", 35));
    let risky = [
        (format!("AWS_ACCESS_KEY_ID={aws}"), Rule::CloudKey),
        (format!("\"AccessKeyId\": \"{aws}\""), Rule::CloudKey),
        (aws.clone(), Rule::CloudKey),
        (format!("(\"{sts}\")"), Rule::CloudKey),
        (format!("密钥{aws}结束"), Rule::CloudKey),
        (format!("x={aws},y={aws}"), Rule::CloudKey),
        (format!("AWS_SECRET_ACCESS_KEY={secret}"), Rule::CloudKey),
        (format!("aws_secret_access_key: '{secret}'"), Rule::CloudKey),
        (format!("\"SecretAccessKey\": \"{secret}\""), Rule::CloudKey),
        (format!("secretAccessKey: \"{secret}\""), Rule::CloudKey),
        (format!("?key={google}&x=1"), Rule::CloudKey),
        (google, Rule::CloudKey),
    ];
    let rows: Vec<(&str, Rule)> = risky.iter().map(|(t, r)| (t.as_str(), *r)).collect();
    check(&[], &rows, find);
    assert_eq!(find_spans(&format!("x={aws},y={aws}")).len(), 2);
}

#[test]
fn a_key_of_a_service() {
    let github = format!("ghp_{}", fill("FakeGitHub0", 36));
    let refresh = format!("ghr_{}", fill("FakeGitHub0", 36));
    let anthropic = format!("sk-ant-api03-{}AA", fill("FakeAnt_0-9", 93));
    let oauth = format!("sk-ant-oat01-{}", fill("FakeAnt_0-9", 60));
    let openai = format!("sk-proj-{}", fill("FakeOpenAI_0-9", 60));
    let svc = format!("sk-svcacct-{}", fill("FakeOpenAI_0-9", 60));
    let stripe = format!("rk_live_{}", fill("FakeStripe0", 30));
    let slack = format!("xoxp-{}", fill("1234567890-FakeSlack", 40));
    let rows = [
        format!("GITHUB_TOKEN={github}"),
        format!("Authorization: token {github}"),
        format!("https://x-access-token:{github}@github.com/org/repo.git"),
        format!("{{\"token\":\"{github}\"}}"),
        format!("\"{refresh}\""),
        format!("ANTHROPIC_API_KEY={anthropic}"),
        format!("x-api-key: {anthropic}"),
        oauth,
        format!("OPENAI_API_KEY={openai}"),
        format!("Bearer {svc}"),
        stripe,
        format!("SLACK_TOKEN={slack}"),
    ];
    let wanted = [
        Rule::ApiKey,
        Rule::ApiKey,
        Rule::ApiKey,
        Rule::ApiKey,
        Rule::ApiKey,
        Rule::ApiKey,
        Rule::ApiKey,
        Rule::ApiKey,
        Rule::ApiKey,
        Rule::ApiKey,
        Rule::ApiKey,
        Rule::ApiKey,
    ];
    for (row, rule) in rows.iter().zip(wanted) {
        only(row, rule);
    }
}

#[test]
fn a_key_that_another_rule_also_reads_is_found_once_by_the_most_specific() {
    let github = format!("ghp_{}", fill("FakeGitHub0", 36));
    // A password-shaped name and a bearer word both read the same token.
    only(&format!("token={github}"), Rule::ApiKey);
    only(&format!("password: \"{github}\""), Rule::ApiKey);
    only(&format!("Authorization: Bearer {github}"), Rule::ApiKey);
    let jwt = format!(
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlLXVzZXIifQ.{}",
        fill("FakeSign0-", 43)
    );
    only(&format!("Authorization: Bearer {jwt}"), Rule::Jwt);
    only(&format!("token={jwt}"), Rule::Jwt);
    only(&format!("https://u:{github}@host.io/"), Rule::ApiKey);
}

#[test]
fn a_jwt() {
    let signature = fill("FakeSign0-", 43);
    let rows = [
        format!("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlLXVzZXIifQ.{signature}"),
        format!("token: \"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlLXVzZXIifQ.{signature}\""),
        // Signed with `none`: no signature.
        "eyJhbGciOiJub25lIn0.eyJzdWIiOiJmYWtlLXVzZXIifQ.".to_string(),
    ];
    for row in &rows {
        only(row, Rule::Jwt);
    }
}

#[test]
fn basic_and_bearer_headers() {
    let bearer = fill("FakeBearer0123456789", 40);
    let risky = [
        (
            "Authorization: Basic ZmFrZXVzZXI6ZmFrZXBhc3M=",
            Rule::BasicAuth,
        ),
        (
            "authorization: basic ZmFrZXVzZXI6ZmFrZXBhc3M=",
            Rule::BasicAuth,
        ),
        (
            "curl -H 'Authorization: Basic ZmFrZXVzZXI6ZmFrZXBhc3M=' x",
            Rule::BasicAuth,
        ),
        (
            "Proxy-Authorization: Basic ZmFrZXVzZXI6ZmFrZXBhc3M=",
            Rule::BasicAuth,
        ),
        // No padding.
        (
            "Authorization: Basic ZmFrZXVzZXI6ZmFrZXBhc3N4",
            Rule::BasicAuth,
        ),
    ];
    check(&[], &risky, find);
    for header in [
        format!("Authorization: Bearer {bearer}"),
        format!("authorization: bearer {bearer}"),
        format!("curl -H \"Authorization: Bearer {bearer}\" https://x.io"),
        format!("{{\"Authorization\": \"Bearer {bearer}\"}}"),
    ] {
        only(&header, Rule::BearerToken);
    }
}

#[test]
fn a_password_in_an_address() {
    let risky = [
        ("postgres://u:p@h/db", Rule::ConnectionString),
        (
            "postgresql://app:fakePass0word1@db.internal:5432/app",
            Rule::ConnectionString,
        ),
        (
            "mysql://root:fakePass0word1@localhost/db",
            Rule::ConnectionString,
        ),
        (
            "mongodb://app:fakePass0word1@h1:27017,h2:27017/db",
            Rule::ConnectionString,
        ),
        (
            "mongodb+srv://app:fakePass0word1@cluster.example.io/db",
            Rule::ConnectionString,
        ),
        (
            "redis://:fakePass0word1@cache:6379/0",
            Rule::ConnectionString,
        ),
        (
            "rediss://default:fakePass0word1@cache:6380",
            Rule::ConnectionString,
        ),
        (
            "amqps://app:fakePass0word1@mq.example.io/vhost",
            Rule::ConnectionString,
        ),
        (
            "POSTGRES://app:fakePass0word1@db/app",
            Rule::ConnectionString,
        ),
        (
            "DATABASE_URL=\"postgres://app:fakePass0word1@db/app?sslmode=require\"",
            Rule::ConnectionString,
        ),
        (
            "https://me:fakePass0word1@example.net/",
            Rule::UrlCredentials,
        ),
        ("http://:fakePass0word1@example.net/", Rule::UrlCredentials),
        (
            "ftp://me:fakePass0word1@files.example.net/x",
            Rule::UrlCredentials,
        ),
        (
            "git+https://me:fakePass0word1@host.io/r.git",
            Rule::UrlCredentials,
        ),
        ("ssh://me:fakePass0word1@host.io/", Rule::UrlCredentials),
    ];
    check(&[], &risky, find);
}

#[test]
fn the_password_of_an_address_is_the_span_and_the_rest_stays() {
    let text = "dsn = postgres://app:p@ss0rd@db.internal:5432/app";
    let spans = find_spans(text);
    assert_eq!(spans.len(), 1);
    assert_eq!(&text[spans[0].start..spans[0].end], "p@ss0rd");
    let text = "git clone https://me:fakePass0word1@host.io/r.git";
    let spans = find_spans(text);
    assert_eq!(&text[spans[0].start..spans[0].end], "fakePass0word1");
}

#[test]
fn a_secret_written_as_the_value_of_a_name() {
    let risky = [
        ("password=fakePass0word1", Rule::GenericSecret),
        ("PASSWORD=fakeHorse1Staple", Rule::GenericSecret),
        ("export TOKEN=fakeValueXyz", Rule::GenericSecret),
        ("secret = 'fakeValue0Xyz'", Rule::GenericSecret),
        ("secret: fakeValue0Xyz", Rule::GenericSecret),
        ("\"password\": \"fakeHorse1Staple\"", Rule::GenericSecret),
        (
            "{\"client_secret\":\"fakeClientValue\"}",
            Rule::GenericSecret,
        ),
        ("api_key = \"fakeValueAbc12\"", Rule::GenericSecret),
        ("X-Api-Key: fakeValue0123", Rule::GenericSecret),
        ("--password=fakeHorse1Staple", Rule::GenericSecret),
        (
            "https://x.io/a?token=fakeValue0123b&b=1",
            Rule::GenericSecret,
        ),
        (
            "Server=db;User Id=sa;Password=fakePass0word1;Encrypt=true",
            Rule::GenericSecret,
        ),
        ("let password = \"fakeHorse1Staple\";", Rule::GenericSecret),
        ("db.password: fakePass0word1", Rule::GenericSecret),
        ("pass=fakeHorse1Staple", Rule::GenericSecret),
        ("db_pass: fakePass0word1", Rule::GenericSecret),
        ("AUTH_TOKEN = fakeValue01", Rule::GenericSecret),
        ("secret_key: \"fakeValue123\"", Rule::GenericSecret),
        ("passphrase: \"fakeHorseStaple\"", Rule::GenericSecret),
        ("data: password=fakePass0word1", Rule::GenericSecret),
        ("token := \"fakeValueXyz\"", Rule::GenericSecret),
        ("password => \"fakeHorse1Staple\"", Rule::GenericSecret),
    ];
    check(&[], &risky, find);
}

#[test]
fn a_generic_secrets_span_is_its_value_without_its_name_or_quotes() {
    for (text, value) in [
        ("password=fakePass0word1 next", "fakePass0word1"),
        ("api_key = \"fakeValueAbc12\" # ok", "fakeValueAbc12"),
        (
            "{\"password\": \"fakePass0word1\", \"user\": \"x\"}",
            "fakePass0word1",
        ),
        ("Password=fakePass0word1;Encrypt=true", "fakePass0word1"),
        ("?token=fakeValue0123b&b=1", "fakeValue0123b"),
    ] {
        let spans = find_spans(text);
        assert_eq!(spans.len(), 1, "{text:?}");
        assert_eq!(&text[spans[0].start..spans[0].end], value, "{text:?}");
    }
}

#[test]
fn a_card_number() {
    let risky = [
        ("4111111111111111", Rule::CreditCard),
        ("card: 4111 1111 1111 1111.", Rule::CreditCard),
        ("4111-1111-1111-1111", Rule::CreditCard),
        ("{\"card\":\"4012888888881881\"}", Rule::CreditCard),
        ("5555555555554444", Rule::CreditCard),
        ("2223003122003222", Rule::CreditCard),
        ("3782 822463 10005", Rule::CreditCard),
        ("378282246310005", Rule::CreditCard),
        ("6011111111111117", Rule::CreditCard),
        ("30569309025904", Rule::CreditCard),
        ("3530111333300000", Rule::CreditCard),
        ("4222222222222", Rule::CreditCard),
        ("6200000000000005", Rule::CreditCard),
    ];
    check(&[], &risky, find);
}

#[test]
fn an_id_number() {
    let risky = [
        ("ssn: 123-45-6789", Rule::GovernmentId),
        ("(123-45-6789)", Rule::GovernmentId),
        ("NI AB 12 34 56 C", Rule::GovernmentId),
        ("NI AB123456C", Rule::GovernmentId),
        ("cpf 529.982.247-25", Rule::GovernmentId),
    ];
    check(&[], &risky, find);
}

#[test]
fn an_email_a_phone_and_an_address() {
    let risky = [
        ("alice.smith@acme.io", Rule::Email),
        ("Alice <alice+tag@mail.acme.co.uk>", Rule::Email),
        ("mailto:a_b-c@acme.io?subject=x", Rule::Email),
        ("+14155550132", Rule::Phone),
        ("+1 (415) 555-0132", Rule::Phone),
        ("tel:+49 151 12345678", Rule::Phone),
        ("+44.20.7946.0958", Rule::Phone),
        ("8.8.8.8", Rule::PublicIp),
        ("connect to 93.184.216.34:443", Rule::PublicIp),
        ("2606:4700:4700::1111", Rule::PublicIp),
        ("[2001:4860:4860:0:0:0:0:8888]:53", Rule::PublicIp),
    ];
    check(&[], &risky, find);
}

#[test]
fn many_kinds_in_one_text_are_found_in_the_order_they_read() {
    let text = format!(
        "{}\nkey=AKIA{}\ntoken=ghp_{}\nanth=sk-ant-api03-{}AA\ndb=postgres://u:p@h/db\ncard 4111111111111111\njwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlLXVzZXIifQ.{}",
        pem("PRIVATE KEY"),
        "FAKE2KEY3ID4TEST",
        fill("FakeGitHub0", 36),
        fill("FakeAnt_0-9", 93),
        fill("FakeSign0-", 43),
    );
    assert_eq!(
        rules(&text),
        [
            Rule::PrivateKey,
            Rule::CloudKey,
            Rule::ApiKey,
            Rule::ApiKey,
            Rule::ConnectionString,
            Rule::CreditCard,
            Rule::Jwt,
        ]
    );
    let assessment = find(&text);
    assert_eq!(assessment.findings().len(), 7);
    let spans = find_spans(&text);
    assert!(spans.windows(2).all(|pair| pair[0].end <= pair[1].start));
}

#[test]
fn an_email_in_a_query_is_found_and_one_in_a_login_is_the_urls() {
    only(
        "https://x.io/unsubscribe?email=alice.smith@acme.io",
        Rule::Email,
    );
    only("https://x.io/contact/alice.smith@acme.io", Rule::Email);
    assert!(find("https://alice.smith@acme.io/repo.git").is_safe());
}

/// The span of the only finding in `text`.
fn only_span(text: &str) -> (Rule, String) {
    let spans = find_spans(text);
    assert_eq!(spans.len(), 1, "{text:?} {spans:?}");
    (
        spans[0].rule,
        text[spans[0].start..spans[0].end].to_string(),
    )
}

#[test]
fn where_a_value_ends_is_decided_on_the_text_as_written() {
    // An escape is never a separator: the whole value is the span.
    for (text, value) in [
        (
            "https://api.fake.test/login?user=me&password=F4kePa%26ss9word&next=/",
            "F4kePa%26ss9word",
        ),
        ("password=F4kePass9%20more9", "F4kePass9%20more9"),
        ("password=F4ke%22Pass9word", "F4ke%22Pass9word"),
        ("password=F4ke\"Pass9word", "F4ke\"Pass9word"),
        ("password=F4ke'Pass9word", "F4ke'Pass9word"),
        (
            "{\"password\": \"F4kePass9\\\"tail0123\"}",
            "F4kePass9\\\"tail0123",
        ),
        (
            "{\"password\": \"F4kePass9\\u0022tail0123\"}",
            "F4kePass9\\u0022tail0123",
        ),
        ("password = \"F4ke\\\\Pass9word\"", "F4ke\\\\Pass9word"),
        ("password = 'F4ke\\'Pass9word'", "F4ke\\'Pass9word"),
        ("password: 'F4ke''Pass9word'", "F4ke''Pass9word"),
        (
            "{\\\"password\\\": \\\"F4kePass9\\\\tail0123\\\"}",
            "F4kePass9\\\\tail0123",
        ),
        // Not a separator of an unquoted value: only white space ends it.
        ("SECRET=F4kePass9|tail0123", "F4kePass9|tail0123"),
        ("SECRET=F4ke;Pass9word", "F4ke;Pass9word"),
        ("SECRET=F4ke&Pass9word", "F4ke&Pass9word"),
        ("SECRET=F4ke(Pass9)word", "F4ke(Pass9)word"),
        ("SECRET=F4ke`Pass9word", "F4ke`Pass9word"),
        ("SECRET=F4ke,Pass9word", "F4ke,Pass9word"),
        // The format's own separator, where there is one.
        ("?user=me&password=F4kePass9&next=/", "F4kePass9"),
        ("password=F4kePass9&x=1", "F4kePass9"),
        (
            "Server=db;User Id=sa;Password=F4kePass9;Encrypt=true",
            "F4kePass9",
        ),
        ("Password=F4kePass9;User Id=sa;Server=db", "F4kePass9"),
        ("Password=F4ke%3BPass9;User Id=sa", "F4ke%3BPass9"),
        // The quote or bracket the name sits in.
        ("echo \"password=F4kePass9word\" >> .env", "F4kePass9word"),
        ("login(password=F4kePass9word)", "F4kePass9word"),
        ("{password: F4kePass9word}", "F4kePass9word"),
        ("[password=F4kePass9word]", "F4kePass9word"),
        ("\"password=F4kePass9word\"", "F4kePass9word"),
    ] {
        assert_eq!(
            only_span(text),
            (Rule::GenericSecret, value.to_string()),
            "{text:?}"
        );
    }
}

#[test]
fn a_value_that_never_closes_is_read_as_the_word_after_the_quote() {
    for (text, value) in [
        ("password=\"F4kePass9word and more", "F4kePass9word"),
        ("password='F4kePass9word", "F4kePass9word"),
    ] {
        assert_eq!(
            only_span(text),
            (Rule::GenericSecret, value.to_string()),
            "{text:?}"
        );
    }
}

#[test]
fn spans_that_overlap_become_one_that_covers_both() {
    let aws = ["AKIA", "FAKE2KEY3ID4TEST"].concat();
    let github = format!("ghp_{}", fill("FakeGitHub0", 36));
    for (text, whole, rule) in [
        (
            format!("password=Xy9!{aws}/tail9"),
            format!("Xy9!{aws}/tail9"),
            Rule::CloudKey,
        ),
        (
            format!("secret=\"{github}-extra-9\""),
            format!("{github}-extra-9"),
            Rule::ApiKey,
        ),
        (
            format!("token={github}-9"),
            format!("{github}-9"),
            Rule::ApiKey,
        ),
        (
            "postgres://u:F4ke.me@fake.io@db.fake.test/x".to_string(),
            "F4ke.me@fake.io".to_string(),
            Rule::ConnectionString,
        ),
    ] {
        assert_eq!(only_span(&text), (rule, whole), "{text:?}");
    }
}

#[test]
fn a_merged_finding_shows_no_front_that_is_not_the_keys() {
    let aws = ["AKIA", "FAKE2KEY3ID4TEST"].concat();
    let text = format!("password=Xy9!{aws}/tail9");
    let assessment = find(&text);
    assert_eq!(assessment.findings().len(), 1);
    // The span begins with the password, not with the key: no prefix.
    assert_eq!(
        assessment.findings()[0].target.as_deref(),
        Some("… (30 chars)")
    );
}

#[test]
fn a_password_in_an_address_with_escapes_in_it() {
    for (text, secret) in [
        (
            "postgres://fakeuser:F4ke%2FPass9@db.fake.test/app",
            "F4ke%2FPass9",
        ),
        (
            "postgres://fakeuser:F4ke%40Pass9@db.fake.test/app",
            "F4ke%40Pass9",
        ),
        (
            "postgres://fakeuser:F4ke%23Pass9@db.fake.test/app",
            "F4ke%23Pass9",
        ),
        (
            "postgres://fakeuser:F4ke%3FPass9@db.fake.test/app",
            "F4ke%3FPass9",
        ),
        (
            "postgres://fakeuser%40fakeserver:F4kePass9@fakeserver.postgres.database.azure.com/app",
            "F4kePass9",
        ),
        (
            "https://fakeuser:F4ke%2FPass9@git.fake.test/repo.git",
            "F4ke%2FPass9",
        ),
        (
            "https://fake%40user:F4kePass9@git.fake.test/repo.git",
            "F4kePass9",
        ),
        // Written in escapes as a whole, in a query.
        (
            "?next=postgres%3A%2F%2Ffakeuser%3AF4kePass9%40db.fake.test%2Fapp",
            "F4kePass9",
        ),
    ] {
        let spans = find_spans(text);
        assert!(
            spans
                .iter()
                .any(|span| text[span.start..span.end].contains(secret)
                    && matches!(span.rule, Rule::ConnectionString | Rule::UrlCredentials)),
            "{text:?} {spans:?}"
        );
    }
}

#[test]
fn a_pgp_block_with_armour_headers_and_other_dresses_of_a_key() {
    let body = (0..4)
        .map(|n| fill(&format!("FakeKeyBody{n}+/"), 64))
        .collect::<Vec<_>>();
    let joined = body.join("\n");
    let pgp = format!(
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: GnuPG v2\nComment: Fake User <fake@example.org>\nComment: a second line, with (marks) and \"quotes\"\n\n{joined}\n=Ab3d\n-----END PGP PRIVATE KEY BLOCK-----"
    );
    let ssh2 = format!(
        "---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----\nComment: \"2048-bit rsa, fake@host\"\nSubject: fake\n\n{joined}\n---- END SSH2 ENCRYPTED PRIVATE KEY ----"
    );
    let escaped = format!(
        "{{\"private_key\": \"-----BEGIN PRIVATE KEY-----\\n{}\\n-----END PRIVATE KEY-----\\n\"}}",
        body.join("\\n")
    );
    let twice = format!(
        "{{\"k\": \"{{\\\"private_key\\\": \\\"-----BEGIN PRIVATE KEY-----\\\\n{}\\\\n-----END PRIVATE KEY-----\\\"}}\"}}",
        body.join("\\\\n")
    );
    let strings = format!(
        "KEY = (\"-----BEGIN RSA PRIVATE KEY-----\\n\"\n       \"{}\\n\"\n       \"{}\\n\"\n       \"-----END RSA PRIVATE KEY-----\\n\")",
        body[0], body[1]
    );
    let continued = format!(
        "-----BEGIN RSA PRIVATE KEY-----\nComment: a long \\\n   line of armour\n\n{joined}\n-----END RSA PRIVATE KEY-----"
    );
    for (label, text) in [
        ("pgp", &pgp),
        ("ssh2", &ssh2),
        ("escaped", &escaped),
        ("escaped twice", &twice),
        ("strings", &strings),
        ("armour line that continues", &continued),
    ] {
        let spans = find_spans(text);
        assert_eq!(spans.len(), 1, "{label}: {spans:?}");
        assert_eq!(spans[0].rule, Rule::PrivateKey, "{label}");
        let found = &text[spans[0].start..spans[0].end];
        for line in &body[..2] {
            assert!(
                found.contains(line.as_str()),
                "{label}: the body is not all in the span"
            );
        }
    }
    // The whole block is the span, the footer included.
    let spans = find_spans(&pgp);
    assert_eq!(&pgp[spans[0].start..spans[0].end], pgp);
    let spans = find_spans(&ssh2);
    assert_eq!(&ssh2[spans[0].start..spans[0].end], ssh2);
}

#[test]
fn a_putty_key_file_private_lines() {
    let line = fill("FakeKeyBody0+/", 64);
    let two = fill("FakeKeyBody1+/", 64);
    let text = format!(
        "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nComment: fake\nPublic-Lines: 1\n{two}\nPrivate-Lines: 2\n{line}\n{two}\nPrivate-MAC: 0123456789abcdef"
    );
    let spans = find_spans(&text);
    assert_eq!(spans.len(), 1, "{spans:?}");
    assert_eq!(spans[0].rule, Rule::PrivateKey);
    assert_eq!(
        &text[spans[0].start..spans[0].end],
        format!("{line}\n{two}")
    );
    // The public part is public, and a count with nothing after it is not a key.
    assert!(find(&format!("Public-Lines: 1\n{two}\n")).is_safe());
    assert!(find("Private-Lines: 1\nMAC\n").is_safe());
}

#[test]
fn an_access_key_id_and_its_secret_with_no_name() {
    let aws = ["AKIA", "FAKE2KEY3ID4TEST"].concat();
    let secret = fill("fakeSecret/Key+0", 40);
    for text in [
        format!("{aws},{secret}"),
        format!("\"{aws}\",\"{secret}\""),
        format!("{aws} {secret}"),
        format!("{aws}:{secret}"),
        format!("user,{aws},{secret},2024"),
    ] {
        let spans = find_spans(&text);
        assert_eq!(spans.len(), 2, "{text:?} {spans:?}");
        assert_eq!(&text[spans[1].start..spans[1].end], secret, "{text:?}");
        assert_eq!(spans[1].rule, Rule::CloudKey);
    }
}

#[test]
fn chat_and_cloud_credentials_of_a_few_more_providers() {
    let discord = format!(
        "MTIzNDU2Nzg5MDEyMzQ1Njc4.GaBcDe.{}",
        fill("FakeDiscordTok_-9", 38)
    );
    let hook = format!(
        "https://discord.com/api/webhooks/123456789012345678/{}",
        fill("FakeDiscordHook_-09", 68)
    );
    let telegram = format!("123456789:AA{}", fill("FakeTgBotTok_-09", 33));
    let sas = fill("FakeSasSig0123AbCd", 43);
    let query =
        format!("sv=2022-11-02&ss=b&srt=sco&sp=rwdlac&se=2030-01-01T00:00:00Z&sig={sas}%3D");
    let docker = "ZmFrZXVzZXI6ZmFrZXBhc3M5";
    for (text, secret, rule) in [
        (format!("DISCORD: {discord}"), discord, Rule::ApiKey),
        (format!("url: {hook}"), hook, Rule::ApiKey),
        (
            format!(
                "https://canary.discordapp.com/api/v9/webhooks/123456789012345678/{}",
                fill("FakeDiscordHook_-09", 68)
            ),
            String::new(),
            Rule::ApiKey,
        ),
        (
            format!("bot{telegram}/getMe"),
            telegram.clone(),
            Rule::ApiKey,
        ),
        (format!("TELEGRAM {telegram}"), telegram, Rule::ApiKey),
        (
            format!("https://fake.blob.core.windows.net/c?{query}"),
            sas,
            Rule::CloudKey,
        ),
        (
            format!(
                "{{\"auths\": {{\"https://index.docker.io/v1/\": {{\"auth\": \"{docker}\"}}}}}}"
            ),
            docker.to_string(),
            Rule::BasicAuth,
        ),
        (
            "machine api.fake.test login fakeuser password F4kePassw0rdZ".to_string(),
            "F4kePassw0rdZ".to_string(),
            Rule::GenericSecret,
        ),
        (
            "machine api.fake.test\n  login fakeuser\n  password F4kePassw0rdZ\n".to_string(),
            "F4kePassw0rdZ".to_string(),
            Rule::GenericSecret,
        ),
        (
            "default login fakeuser password F4kePassw0rdZ".to_string(),
            "F4kePassw0rdZ".to_string(),
            Rule::GenericSecret,
        ),
    ] {
        let spans = find_spans(&text);
        assert!(!spans.is_empty(), "{text:?}");
        assert_eq!(spans[0].rule, rule, "{text:?}");
        if !secret.is_empty() {
            let found = &text[spans[0].start..spans[0].end];
            assert!(found.contains(&secret), "{text:?} found {found:?}");
        }
    }
}

#[test]
fn a_provider_shape_with_nothing_to_say_it_is_one_is_safe() {
    let telegram = format!("123456789:AA{}", fill("FakeTgBotTok_-09", 33));
    for text in [
        // A third word that is too long is not a bot's token.
        format!(
            "see MTIzNDU2Nzg5MDEyMzQ1Njc4.GaBcDe.{}",
            fill("FakeDiscordTok_-9", 48)
        ),
        format!("x{telegram}"),
        format!("{telegram}9"),
        "https://fake.test/?sig=FakeSasSig0123AbCdFakeSasSig0123AbCdFakeSasSig0123AbCd".to_string(),
        "password for the machine is in the vault".to_string(),
        "Enter your password to log in to the machine".to_string(),
        "{\"auth\": \"ZmFrZQ==\"}".to_string(),
        "auth: bW9zdGx5IGhhcm1sZXNzIHRleHQ=".to_string(),
    ] {
        assert!(
            find(&text).is_safe(),
            "{text:?} {:?}",
            find(&text).findings()
        );
    }
}

#[test]
fn braces_quote_a_value_of_a_connection_string() {
    for (text, value) in [
        ("Driver={SQL};Uid=me;Pwd={F4kePass9};", "F4kePass9"),
        ("Driver={SQL};Uid=me;Pwd={F4ke;Pass9=x};", "F4ke;Pass9=x"),
        ("Driver={SQL};Uid=me;Pwd={F4ke}}Pass9};", "F4ke}}Pass9"),
    ] {
        let found = only_span(text);
        assert_eq!(found.0, Rule::GenericSecret, "{text:?}");
        assert_eq!(found.1, value, "{text:?}");
    }
    // A template or a value that is its own name is no password.
    for text in [
        "token={{ token }}",
        "token={token}",
        "Pwd={}",
        "password={PASSWORD}",
    ] {
        assert!(find(text).is_safe(), "{text:?}");
    }
}

#[test]
fn a_quote_that_closes_the_string_a_name_is_in_is_one_only_if_it_is_not_escaped() {
    for (text, value) in [
        ("[\"password=F4kePa\\\"ss9word\"]", "F4kePa\\\"ss9word"),
        ("'password=F4kePa''ss9word'", "F4kePa''ss9word"),
        (
            "\"password=F4ke\\\\\\\"Pass9word\"",
            "F4ke\\\\\\\"Pass9word",
        ),
        ("echo \"password=F4kePass9word\" >> .env", "F4kePass9word"),
        ("'password=F4kePass9word' x", "F4kePass9word"),
    ] {
        assert_eq!(
            only_span(text),
            (Rule::GenericSecret, value.to_string()),
            "{text:?}"
        );
    }
}

#[test]
fn a_bracket_in_a_value_ends_it_when_the_name_is_in_one() {
    // Known limit: a closing bracket is not escaped by anything, so the value
    // of a name inside brackets ends at the first one. The part after it is
    // not covered; the rest of the text is read on.
    for (text, covered) in [
        ("[password=F4kePass9]word]", "F4kePass9"),
        ("f(password=F4kePass9)word)", "F4kePass9"),
        ("{password=F4kePass9}word}", "F4kePass9"),
    ] {
        assert_eq!(
            only_span(text),
            (Rule::GenericSecret, covered.to_string()),
            "{text:?}"
        );
    }
}

#[test]
fn the_limits_of_reading_a_value_are_kept_as_rows() {
    // `&` before something that reads as another pair ends a value, even
    // when it was part of the password.
    assert_eq!(
        only_span("SECRET=F4kePa&ss9=word"),
        (Rule::GenericSecret, "F4kePa".to_string())
    );
    // A quoted value with a space in it is prose to this guard.
    assert!(find("export PASSWORD=\"F4ke Pass9 x\"").is_safe());
    // A block of key written on one line with spaces for its line ends is not
    // read: a text of plain words between the lines is no key.
    let body = fill("FakeKeyBody0+/", 64);
    assert!(find(&format!(
        "KEY=\"-----BEGIN RSA PRIVATE KEY----- {body} {body} -----END RSA PRIVATE KEY-----\""
    ))
    .is_safe());
    // A password of fewer than six characters, and a password that is the
    // value of a name that does not end in a word of a secret's, are not
    // found.
    assert!(find("password=Ab3d9").is_safe());
    assert!(find("passcode=F4kePass9word").is_safe());
}
