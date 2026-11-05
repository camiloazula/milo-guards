//! Every kind of key, in the dress it comes in, is found whole: each byte of
//! the secret is in a span. The tables hold the keys of each provider and
//! format, where the value of a name ends, spans that overlap and are merged
//! into one, and values that look like a stand-in but are real. The texts
//! that hold no value shaped like a real key are in
//! `tests/cases/found_whole.cases`; what stays here builds such a value in
//! Rust, so that none sits in the repository.

mod common;

use common::{fill, nothing_wrong, p};

#[test]
fn every_case() {
    common::cases::check("found_whole");
}

#[test]
fn a_mongodb_atlas_uri_is_found_whole() {
    // Its host is joined here, so that no Atlas connection string with a
    // password sits in the repository for a secret scanner to report.
    let host = ["cluster0", "fake", "mongodb", "net"].join(".");
    let text = format!("DATABASE_URL=mongodb+srv://fakeuser:F4kePass9@{host}/?retryWrites=true");
    let mut bad = Vec::new();
    p(&mut bad, "mongodb+srv", &text, "F4kePass9");
    nothing_wrong(&bad);
}

#[test]
fn every_kind_of_key_in_every_dress_is_found_whole() {
    let mut bad = Vec::new();
    let aws = format!("AKIA{}", "Q7FAKE2TESTK3YZW");
    let awssec = fill("FakeSecretAccessKey9Test/+", 40);
    let gh = format!("ghp_{}", fill("FakeGitHubToken0123x", 36));
    let ant = format!("sk-ant-api03-{}", fill("FakeAnthropicKey_09-", 95));
    let jwt = format!(
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlIn0.{}",
        fill("FakeSig_09-", 43)
    );
    // PEM
    let body: Vec<String> = (0..4)
        .map(|n| fill(&format!("FakeKeyBody{n}+/"), 64))
        .collect();
    for kind in [
        "RSA PRIVATE KEY",
        "EC PRIVATE KEY",
        "OPENSSH PRIVATE KEY",
        "ENCRYPTED PRIVATE KEY",
        "PRIVATE KEY",
        "DSA PRIVATE KEY",
    ] {
        let lf = format!(
            "-----BEGIN {kind}-----\n{}\n-----END {kind}-----",
            body.join("\n")
        );
        p(
            &mut bad,
            &format!("pem lf {kind}"),
            &format!("x\n{lf}\ny"),
            &lf,
        );
        let crlf = lf.replace('\n', "\r\n");
        p(
            &mut bad,
            &format!("pem crlf {kind}"),
            &format!("x\r\n{crlf}\r\ny"),
            &crlf,
        );
    }
    let pgp = format!("-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: GnuPG v2\nComment: Fake User <fake@example.org>\n\n{}\n=Ab3d\n-----END PGP PRIVATE KEY BLOCK-----", body.join("\n"));
    p(&mut bad, "pgp with Comment <email>", &pgp, &pgp);
    let pgp2 = format!("-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: GnuPG v2\n\n{}\n=Ab3d\n-----END PGP PRIVATE KEY BLOCK-----", body.join("\n"));
    p(&mut bad, "pgp plain", &pgp2, &pgp2);
    let enc = format!("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0123456789ABCDEF0123456789ABCDEF\n\n{}\n-----END RSA PRIVATE KEY-----", body.join("\n"));
    p(&mut bad, "pem legacy encrypted", &enc, &enc);
    let sa = format!("{{\"type\": \"service_account\", \"private_key\": \"-----BEGIN PRIVATE KEY-----\\n{}\\n-----END PRIVATE KEY-----\\n\", \"x\": 1}}", body.join("\\n"));
    let inner =
        &sa[sa.find("-----BEGIN").unwrap()..sa.find("-----END PRIVATE KEY-----").unwrap() + 25];
    p(&mut bad, "google SA json", &sa, inner);
    let py = format!("KEY = (\"-----BEGIN RSA PRIVATE KEY-----\\n\"\n       \"{}\\n\"\n       \"{}\\n\"\n       \"-----END RSA PRIVATE KEY-----\\n\")", body[0], body[1]);
    p(
        &mut bad,
        "pem as concatenated py strings (body line 0)",
        &py,
        &body[0],
    );
    let dbl = format!("{{\"k\": \"{{\\\"private_key\\\": \\\"-----BEGIN PRIVATE KEY-----\\\\n{}\\\\n-----END PRIVATE KEY-----\\\"}}\"}}", body.join("\\\\n"));
    p(&mut bad, "pem double-escaped json (body0)", &dbl, &body[0]);
    let putty = format!(
        "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nPrivate-Lines: 1\n{}\n",
        body[0]
    );
    p(&mut bad, "putty ppk private lines", &putty, &body[0]);
    let ssh2 = format!(
        "---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----\n{}\n---- END SSH2 ENCRYPTED PRIVATE KEY ----",
        body.join("\n")
    );
    p(&mut bad, "ssh.com ssh2", &ssh2, &body[0]);

    // AWS
    for (l, t) in [
        ("start", format!("{aws} x")),
        ("end", format!("x {aws}")),
        ("json", format!("{{\"k\":\"{aws}\"}}")),
        ("eq", format!("K={aws}")),
        ("eq sp", format!("K = {aws}")),
        ("yaml", format!("k: {aws}")),
        ("export", format!("export AWS_ACCESS_KEY_ID={aws}")),
    ] {
        p(&mut bad, &format!("aws id {l}"), &t, &aws);
    }
    for (l, t) in [
        (
            "aws secret named",
            format!("aws_secret_access_key = {awssec}"),
        ),
        (
            "aws secret env",
            format!("export AWS_SECRET_ACCESS_KEY={awssec}"),
        ),
        (
            "aws secret yaml",
            format!("AWS_SECRET_ACCESS_KEY: \"{awssec}\""),
        ),
        (
            "aws secret json camel",
            format!("{{\"SecretAccessKey\": \"{awssec}\"}}"),
        ),
        ("aws secret beside id csv", format!("{aws},{awssec}")),
        (
            "aws secret beside id ini",
            format!("[default]\naws_access_key_id={aws}\naws_secret_access_key={awssec}\n"),
        ),
    ] {
        p(&mut bad, l, &t, &awssec);
    }
    // url-encoded / escapes
    let enc_aws = aws
        .chars()
        .map(|c| format!("%{:02X}", u32::from(c)))
        .collect::<Vec<_>>()
        .concat();
    p(
        &mut bad,
        "aws fully %-encoded",
        &format!("k={enc_aws}"),
        &enc_aws,
    );
    let mixed = format!("{}%{:02x}{}", &aws[..10], aws.as_bytes()[10], &aws[11..]);
    p(
        &mut bad,
        "aws one %-escape",
        &format!("k {mixed} x"),
        &mixed,
    );
    let uenc = aws
        .chars()
        .map(|c| format!("\\u{:04x}", u32::from(c)))
        .collect::<Vec<_>>()
        .concat();
    p(&mut bad, "aws \\u-encoded", &format!("\"{uenc}\""), &uenc);
    let zw = format!("{}\u{200b}{}", &gh[..10], &gh[10..]);
    p(&mut bad, "gh zero-width", &format!("t {zw} t"), &zw);
    // github
    p(&mut bad, "gh", &format!("token: {gh}"), &gh);
    p(
        &mut bad,
        "gh fine-grained",
        &format!(
            "x github_pat_{}_{} y",
            fill("Fake22CharsAbcdefgh0123", 22),
            fill("Fake59Chars0123456789abcdefghij", 59)
        ),
        &format!(
            "github_pat_{}_{}",
            fill("Fake22CharsAbcdefgh0123", 22),
            fill("Fake59Chars0123456789abcdefghij", 59)
        ),
    );
    p(
        &mut bad,
        "anthropic",
        &format!("ANTHROPIC_API_KEY={ant}"),
        &ant,
    );
    p(
        &mut bad,
        "jwt",
        &format!("Authorization: Bearer {jwt}"),
        &jwt,
    );
    p(
        &mut bad,
        "jwt in cookie",
        &format!("Cookie: session={jwt}; path=/"),
        &jwt,
    );
    // slack, discord, telegram
    let slackhook = format!(
        "https://hooks.slack.com/services/T0FAKE123/B0FAKE456/{}",
        fill("FakeHookSecret0123", 24)
    );
    p(
        &mut bad,
        "slack webhook",
        &format!("url: {slackhook}"),
        &slackhook,
    );
    let discord_hook = format!(
        "https://discord.com/api/webhooks/123456789012345678/{}",
        fill("FakeDiscordHook_-09", 68)
    );
    p(
        &mut bad,
        "discord webhook",
        &format!("url: {discord_hook}"),
        &fill("FakeDiscordHook_-09", 68),
    );
    let discord_tok = format!(
        "MTIzNDU2Nzg5MDEyMzQ1Njc4.GaBcDe.{}",
        fill("FakeDiscordTok_-9", 38)
    );
    p(
        &mut bad,
        "discord bot token",
        &format!("DISCORD: {discord_tok}"),
        &discord_tok,
    );
    let tg = format!("123456789:AA{}", fill("FakeTgBotTok_-09", 33));
    p(
        &mut bad,
        "telegram bot token",
        &format!("bot{tg}/getMe"),
        &tg,
    );
    p(
        &mut bad,
        "telegram bot token bare",
        &format!("TELEGRAM {tg}"),
        &tg,
    );
    // azure
    let azk = format!("{}==", fill("FakeAzureStorageKey0123+/", 86));
    p(&mut bad, "azure conn string", &format!("DefaultEndpointsProtocol=https;AccountName=fakeacct;AccountKey={azk};EndpointSuffix=core.windows.net"), &azk);
    let sas = format!(
        "sv=2022-11-02&ss=b&srt=sco&sp=rwdlac&se=2030-01-01T00:00:00Z&sig={}%3D",
        fill("FakeSasSig0123AbCd", 43)
    );
    p(
        &mut bad,
        "azure SAS sig",
        &format!("https://fake.blob.core.windows.net/?{sas}"),
        &fill("FakeSasSig0123AbCd", 43),
    );
    // headers
    let basic = "ZmFrZXVzZXI6ZmFrZXBhc3M5"; // fakeuser:fakepass9
    p(
        &mut bad,
        "basic header",
        &format!("Authorization: Basic {basic}"),
        basic,
    );
    let bearer = fill("FakeOpaqueBearer9tok", 32);
    p(
        &mut bad,
        "bearer opaque",
        &format!("Authorization: Bearer {bearer}"),
        &bearer,
    );
    p(
        &mut bad,
        "docker auths",
        &format!("{{\"auths\": {{\"https://index.docker.io/v1/\": {{\"auth\": \"{basic}\"}}}}}}"),
        basic,
    );
    p(
        &mut bad,
        "npmrc authToken",
        &format!(
            "//registry.npmjs.org/:_authToken={}",
            fill("F4keNpmTok3n-0123-abcd", 36)
        ),
        &fill("F4keNpmTok3n-0123-abcd", 36),
    );
    // provider prefixes
    for (l, key) in [
        (
            "stripe sk_live",
            format!("sk_live_{}", fill("F4keStripe0123", 24)),
        ),
        (
            "gitlab",
            format!("glpat-{}", fill("F4keGitlab_0123-xy", 20)),
        ),
        (
            "openai proj",
            format!("sk-proj-{}", fill("F4keOpenAi_0123-xy", 120)),
        ),
        (
            "openai old T3Blbk",
            format!(
                "sk-{}T3BlbkFJ{}",
                fill("F4keOpenAi0123", 20),
                fill("F4keOpenAi0123", 20)
            ),
        ),
        (
            "google key",
            format!("AIza{}", fill("F4keGoogle_0123-xy", 35)),
        ),
        (
            "age",
            format!(
                "AGE-SECRET-KEY-1{}",
                fill("QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L", 58)
            ),
        ),
    ] {
        p(&mut bad, l, &key, &key);
    }
    // multibyte neighbours
    p(
        &mut bad,
        "gh next to emoji",
        &format!("😀{gh}é\u{301}"),
        &gh,
    );
    p(&mut bad, "gh next to cjk", &format!("密钥{gh}已"), &gh);
    nothing_wrong(&bad);
}

#[test]
fn the_body_of_a_key_is_found_whole() {
    let mut bad = Vec::new();
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
fn spans_that_overlap_are_merged_into_one_that_holds_each_secret_whole() {
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
        "gh then suffix in secret",
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
fn a_provider_key_with_a_tail_of_low_variety_is_found_whole() {
    let mut bad = Vec::new();
    for (l, tail) in [
        ("ghp low variety tail", "ab12"),
        ("ghp 5 distinct tail", "abc12"),
        ("ghp 6 distinct tail", "abc123"),
    ] {
        let key = format!("ghp_{}{}", fill("Q7wE9rT2yU4iO6pA8sD0", 20), fill(tail, 16));
        p(&mut bad, l, &format!("x {key} y"), &key);
    }
    nothing_wrong(&bad);
}
