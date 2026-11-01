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
        ("PASSWORD=fakePassword", Rule::GenericSecret),
        ("export TOKEN=fakeTokenValue", Rule::GenericSecret),
        ("secret = 'fakeSecret0'", Rule::GenericSecret),
        ("secret: fakeSecret0", Rule::GenericSecret),
        ("\"password\": \"fakePassword\"", Rule::GenericSecret),
        (
            "{\"client_secret\":\"fakeClientSecret\"}",
            Rule::GenericSecret,
        ),
        ("api_key = \"fakeApiKeyValue\"", Rule::GenericSecret),
        ("X-Api-Key: fakeApiKey0123", Rule::GenericSecret),
        ("--password=fakePassword", Rule::GenericSecret),
        (
            "https://x.io/a?token=fakeToken0123&b=1",
            Rule::GenericSecret,
        ),
        (
            "Server=db;User Id=sa;Password=fakePass0word1;Encrypt=true",
            Rule::GenericSecret,
        ),
        ("let password = \"fakePassword\";", Rule::GenericSecret),
        ("db.password: fakePass0word1", Rule::GenericSecret),
        ("pass=fakePassword", Rule::GenericSecret),
        ("db_pass: fakePass0word1", Rule::GenericSecret),
        ("AUTH_TOKEN = fakeToken01", Rule::GenericSecret),
        ("secret_key: \"fakeSecretKey123\"", Rule::GenericSecret),
        ("passphrase: \"fakePassphrase\"", Rule::GenericSecret),
        ("data: password=fakePass0word1", Rule::GenericSecret),
        ("token := \"fakeTokenValue\"", Rule::GenericSecret),
        ("password => \"fakePassword\"", Rule::GenericSecret),
    ];
    check(&[], &risky, find);
}

#[test]
fn a_generic_secrets_span_is_its_value_without_its_name_or_quotes() {
    for (text, value) in [
        ("password=fakePass0word1 next", "fakePass0word1"),
        ("api_key = \"fakeApiKeyValue\" # ok", "fakeApiKeyValue"),
        (
            "{\"password\": \"fakePass0word1\", \"user\": \"x\"}",
            "fakePass0word1",
        ),
        ("Password=fakePass0word1;Encrypt=true", "fakePass0word1"),
        ("?token=fakeToken0123&b=1", "fakeToken0123"),
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
