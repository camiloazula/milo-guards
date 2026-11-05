//! Texts by rule: each text must break its rule, and the spelling variants a
//! reviewer would try are rows of their own. A Discord bot token is found by
//! its own shape (its first part is a user id in base64url, digits when
//! decoded), and the real passwords and tokens beside the rows of `safe.rs`
//! are still found. The texts that hold no value shaped like a real key are
//! in `tests/cases/rules.cases`; what stays here builds such a value in Rust,
//! so that none sits in the repository.

mod common;

use common::{base64url, discord, fill, pem, token};
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

/// Every row has exactly one finding, of `rule`, and its span is the row's
/// secret.
fn assert_found(rows: &[(String, String)], rule: Rule) {
    for (text, secret) in rows {
        let spans = find_spans(text);
        assert_eq!(spans.len(), 1, "{text:?}\n  got {spans:?}");
        assert_eq!(spans[0].rule, rule, "{text:?}");
        assert_eq!(&text[spans[0].start..spans[0].end], secret, "{text:?}");
    }
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
fn every_case() {
    common::cases::check("rules");
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
    for row in &rows {
        only(row, Rule::ApiKey);
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
    ];
    for row in &rows {
        only(row, Rule::Jwt);
    }
}

#[test]
fn a_bearer_header() {
    let bearer = fill("FakeBearer0123456789", 40);
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
    // The public part is public.
    assert!(find(&format!("Public-Lines: 1\n{two}\n")).is_safe());
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
    ] {
        assert!(
            find(&text).is_safe(),
            "{text:?} {:?}",
            find(&text).findings()
        );
    }
}

#[test]
fn a_block_of_key_on_one_line_with_spaces_for_its_line_ends_is_not_read() {
    // A text of plain words between the lines is no key.
    let body = fill("FakeKeyBody0+/", 64);
    assert!(find(&format!(
        "KEY=\"-----BEGIN RSA PRIVATE KEY----- {body} {body} -----END RSA PRIVATE KEY-----\""
    ))
    .is_safe());
}

#[test]
fn the_encoder_writes_what_the_discord_row_expects() {
    assert_eq!(base64url("123456789012345678"), "MTIzNDU2Nzg5MDEyMzQ1Njc4");
}

#[test]
fn a_real_discord_bot_token_is_still_found() {
    let ids = [
        "123456789012345678",
        "1234567890123456789",
        "12345678901234567890",
        "987654321098765432",
        "876543210987654321",
        "556677889900112233",
        // An id of seventeen digits, from the first years of the service.
        "12345678901234567",
    ];
    let mut rows = Vec::new();
    for id in ids {
        let secret = token(id);
        rows.push((format!("DISCORD: {secret}"), secret.clone()));
        rows.push((format!("DISCORD_TOKEN={secret}\n"), secret.clone()));
        rows.push((format!("client.login(\"{secret}\")"), secret.clone()));
        rows.push((format!("see {secret} and more"), secret));
    }
    assert_found(&rows, Rule::ApiKey);
}

#[test]
fn a_discord_token_with_a_seven_character_age_is_found() {
    let secret = format!(
        "{}.GaBcDeF.{}",
        base64url("123456789012345678"),
        fill("FakeDiscordTok_-9", 27)
    );
    assert_found(&[(format!("bot: {secret}"), secret)], Rule::ApiKey);
}

#[test]
fn a_page_access_token_is_still_a_secret() {
    let facebook = "EAAGm0PX4ZCpsBAKZB7Xk9fQ2mZ7pLw3RtY8vBn4CsHj6KdEa1UgZDZD";
    let word = "Xk9fQ2mZ7pLw3RtY8vBn4CsHj6KdEa1Ug";
    let rows = [
        format!("PAGE_TOKEN={facebook}"),
        format!("FB_PAGE_TOKEN={facebook}"),
        format!("export FACEBOOK_PAGE_TOKEN=\"{facebook}\""),
        format!("page_token={facebook}"),
        format!("{{\"page_token\": \"{facebook}\"}}"),
        format!("WEBPAGE_TOKEN={word}"),
        format!("homepage_token = \"{word}\""),
    ];
    for row in &rows {
        assert!(!find(row).is_safe(), "{row:?} is a secret");
    }
}

#[test]
fn a_decoy_discord_match_does_not_hide_the_real_token() {
    // The decoy begins at a glued letter and the real token is inside it, or
    // the third part of the decoy swallows the id of the real token.
    for (head, id) in [
        ("N", "123456789012345678"),
        ("O_", "123456789012345678"),
        (
            "see NavigationControllerDelegate.handler.",
            "12345678901234567890",
        ),
    ] {
        let real = discord(id);
        let text = format!("{head}{real}");
        assert_eq!(rules(&text), [Rule::ApiKey], "{text:?}");
        assert_eq!(only_span(&text), (Rule::ApiKey, real), "{text:?}");
    }
}

#[test]
fn a_separator_before_a_discord_token_is_not_part_of_a_longer_id() {
    // The base64url of an id made of digits holds no `_` or `-`, so one that
    // touches the token ends the run of letters before it, whatever it was.
    let secret = discord("123456789012345678");
    let rows: Vec<(String, String)> = [
        "token_",
        "key-",
        "prod_",
        "abc_",
        "my-bot-",
        "secrets/discord-bot-",
        "____",
        "----",
        "--token--",
    ]
    .into_iter()
    .map(|head| (format!("{head}{secret}"), secret.clone()))
    .collect();
    assert_found(&rows, Rule::ApiKey);
    assert!(
        !find(&format!("secrets/discord-bot-{secret}.txt")).is_safe(),
        "a token in a file name is a secret"
    );
    // Four letters or digits right before the token are still a longer id.
    for head in ["abcd", "x_abcd", "Zm9v1234"] {
        let row = format!("{head}{secret}");
        assert!(
            find_spans(&row).iter().all(|s| s.rule != Rule::ApiKey),
            "{row:?} is the tail of a longer id"
        );
    }
}

#[test]
fn a_long_real_token_beside_the_safe_rows_is_still_found() {
    let long = fill("Fk9Zq2Xw", 32);
    let rows: Vec<(String, String)> = [
        format!("{{\"token\": \"{long}\"}}"),
        format!("let token = \"{long}\";"),
        format!("\"next_token_secret\": \"{long}\""),
        format!("{{\"page_secret\": \"{long}\"}}"),
        format!("{{\"api_key\": \"{long}\"}}"),
    ]
    .into_iter()
    .map(|text| (text, long.clone()))
    .collect();
    assert_found(&rows, Rule::GenericSecret);
}
