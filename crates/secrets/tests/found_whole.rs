//! Every kind of key, in the dress it comes in, is found whole: each byte of
//! the secret is in a span. The tables hold the keys of each provider and
//! format, where the value of a name ends, spans that overlap and are merged
//! into one, and values that look like a stand-in but are real.

mod common;

use common::{fill, nothing_wrong, p};

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
    // files of login details, headers and names of a key
    for (l, t, s) in [
        (
            "netrc",
            "machine api.fake.test login fakeuser password F4kePassw0rdZ",
            "F4kePassw0rdZ",
        ),
        (
            "netrc multiline",
            "machine api.fake.test\n  login fakeuser\n  password F4kePassw0rdZ\n",
            "F4kePassw0rdZ",
        ),
        ("pypirc", "[pypi]\nusername = __token__\npassword = pypi-AgEIcHlwaS5vcmcFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFake0123456789\n", "pypi-AgEIcHlwaS5vcmcFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFake0123456789"),
        (
            "pypirc plain password",
            "[pypi]\nusername = fakeuser\npassword = F4kePassw0rdZ\n",
            "F4kePassw0rdZ",
        ),
        (
            "client_secret azure",
            "client_secret=F4ke8Q~abcdefghijklmnopqrstuvwxyz0123456",
            "F4ke8Q~abcdefghijklmnopqrstuvwxyz0123456",
        ),
        (
            "api-key header",
            "x-api-key: F4keApiKey0123456789abcdef",
            "F4keApiKey0123456789abcdef",
        ),
        (
            "api_key yaml",
            "api_key: F4keApiKey0123456789abcdef",
            "F4keApiKey0123456789abcdef",
        ),
        (
            "apiKey js",
            "const apiKey = 'F4keApiKey0123456789abcdef';",
            "F4keApiKey0123456789abcdef",
        ),
        (
            "OPENAI_API_KEY env",
            "OPENAI_API_KEY=F4keApiKey0123456789abcdef",
            "F4keApiKey0123456789abcdef",
        ),
        // base64-wrapped once
        (
            "k8s secret b64 of password",
            "data:\n  password: RjRrZVBhc3M5d29yZA==\n",
            "RjRrZVBhc3M5d29yZA==",
        ),
        (
            "card visa",
            "card 4242 4242 4242 4242 exp",
            "4242 4242 4242 4242",
        ),
    ] {
        p(&mut bad, l, t, s);
    }
    // connection strings
    for (l, u, s) in [
        ("pg", "postgres://fakeuser:F4kePass9@db.fake.test:5432/app", "F4kePass9"),
        ("mysql", "mysql://fakeuser:F4kePass9@db.fake.test/app", "F4kePass9"),
        ("mongo srv", "mongodb+srv://fakeuser:F4kePass9@cluster0.fake.mongodb.net/?retryWrites=true", "F4kePass9"),
        ("redis no user", "redis://:F4kePass9@cache.fake.test:6379/0", "F4kePass9"),
        ("amqp", "amqp://fakeuser:F4kePass9@mq.fake.test:5672/vhost", "F4kePass9"),
        ("pg pass with %2F", "postgres://fakeuser:F4ke%2FPass9@db.fake.test/app", "F4ke%2FPass9"),
        ("pg pass with %40", "postgres://fakeuser:F4ke%40Pass9@db.fake.test/app", "F4ke%40Pass9"),
        ("pg user with %40 (azure)", "postgres://fakeuser%40fakeserver:F4kePass9@fakeserver.postgres.database.azure.com/app", "F4kePass9"),
        ("pg pass with %23", "postgres://fakeuser:F4ke%23Pass9@db.fake.test/app", "F4ke%23Pass9"),
        ("pg pass with %3F", "postgres://fakeuser:F4ke%3FPass9@db.fake.test/app", "F4ke%3FPass9"),
        ("https creds %2F", "https://fakeuser:F4ke%2FPass9@git.fake.test/repo.git", "F4ke%2FPass9"),
        ("jdbc", "jdbc:postgresql://db.fake.test:5432/app?user=fakeuser&password=F4kePass9", "F4kePass9"),
        ("ado.net", "Server=tcp:fake.database.windows.net;Database=app;User ID=fakeuser;Password=F4kePass9;Encrypt=true", "F4kePass9"),
        ("pg kv dsn", "host=db.fake.test user=fakeuser password=F4kePass9 dbname=app", "F4kePass9"),
        ("pg pass with literal #", "postgres://fakeuser:F4ke#Pass9@db.fake.test/app", "F4ke#Pass9"),
        ("pg pass with literal ?", "postgres://fakeuser:F4ke?Pass9@db.fake.test/app", "F4ke?Pass9"),
    ] { p(&mut bad, &format!("conn {l}"), &format!("DATABASE_URL={u}"), s); }
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
fn a_value_is_found_whole_up_to_where_it_ends() {
    let mut bad = Vec::new();
    for (l, t, s) in [
        // escapes that decode to a separator
        (
            "%26 in query value",
            "https://api.fake.test/login?user=me&password=F4kePa%26ss9word&next=/",
            "F4kePa%26ss9word",
        ),
        (
            "%20 in value",
            "password=F4kePass9%20more9",
            "F4kePass9%20more9",
        ),
        (
            "json escaped quote",
            "{\"password\": \"F4kePass9\\\"tail0123\"}",
            "F4kePass9\\\"tail0123",
        ),
        (
            "json \\u0022",
            "{\"password\": \"F4kePass9\\u0022tail0123\"}",
            "F4kePass9\\u0022tail0123",
        ),
        (
            "alt \\\" and %22",
            "{\"password\": \"F4ke\\\"Pa%22ss\\\"9w%22ord\"}",
            "F4ke\\\"Pa%22ss\\\"9w%22ord",
        ),
        (
            "alt %22 unquoted",
            "password=F4ke%22Pa%22ss9word",
            "F4ke%22Pa%22ss9word",
        ),
        (
            "generic quoted with newline-escape",
            "password = \"F4ke\\nPass9word\"",
            "F4ke\\nPass9word",
        ),
        // the dress of a name and its value
        (
            "generic yaml single",
            "db_password: 'F4kePass9'",
            "F4kePass9",
        ),
        (
            "yaml single quoted '' ",
            "db_password: 'F4ke''Pass9'",
            "F4ke''Pass9",
        ),
        (
            "generic env export",
            "export DB_PASSWORD=F4kePass9",
            "F4kePass9",
        ),
        (
            "generic --password=",
            "run --password=F4kePass9 now",
            "F4kePass9",
        ),
        // a character that is no separator of an unquoted value
        ("pipe", "SECRET=F4kePass9|tail0123", "F4kePass9|tail0123"),
        ("comma", "SECRET=F4ke,Pass9word", "F4ke,Pass9word"),
        (
            "semicolon no pair",
            "password=F4ke;Pass9word",
            "F4ke;Pass9word",
        ),
        ("amp no pair", "SECRET=F4ke&Pass9word", "F4ke&Pass9word"),
        (
            "generic value with ( )",
            "SECRET=F4ke(Pass9)word",
            "F4ke(Pass9)word",
        ),
        (
            "generic value with backtick",
            "SECRET=F4ke`Pass9word",
            "F4ke`Pass9word",
        ),
        // a separator inside quotes or braces
        (
            "query & inside quoted value",
            "?user=me&password=\"F4ke&Pass9=x\"&next=1",
            "F4ke&Pass9=x",
        ),
        (
            "adonet ; inside quoted pw",
            "Server=db;User Id=me;Password=\"F4ke;Pass9=x\";Encrypt=true",
            "F4ke;Pass9=x",
        ),
        (
            "adonet ; inside single-quoted pw",
            "Server=db;User Id=me;Password='F4ke;Pass9=x';Encrypt=true",
            "F4ke;Pass9=x",
        ),
        (
            "odbc braces plain",
            "Driver={SQL};Uid=me;Pwd={F4kePass9};",
            "F4kePass9",
        ),
        (
            "odbc braces ; inside",
            "Driver={SQL};Uid=me;Pwd={F4ke;Pass9=x};",
            "F4ke;Pass9=x",
        ),
        // the quote or bracket the name sits in
        (
            "unbalanced ( open",
            "(password=F4kePass9word",
            "F4kePass9word",
        ),
        (
            "name in json string, escaped quote in value",
            "[\"password=F4kePa\\\"ss9word\"]",
            "F4kePa\\\"ss9word",
        ),
        (
            "name in single-quoted, '' in value",
            "'password=F4kePa''ss9word'",
            "F4kePa''ss9word",
        ),
        (
            "quoted never closes",
            "password=\"F4kePass9word and more",
            "F4kePass9word",
        ),
        // the password of an address
        (
            "pg %2F",
            "postgres://fakeuser:F4ke%2FPass9@db.fake.test/app",
            "F4ke%2FPass9",
        ),
        (
            "pg user %40",
            "postgres://fakeuser%40fakeserver:F4kePass9@fake.postgres.database.azure.com/app",
            "F4kePass9",
        ),
        (
            "https %2F",
            "https://fakeuser:F4ke%2FPass9@git.fake.test/r.git",
            "F4ke%2FPass9",
        ),
        (
            "pg %2F%40 mix",
            "postgres://u%40s:F4%2Fke%40Pa%3Ass9@db.fake.test/app",
            "F4%2Fke%40Pa%3Ass9",
        ),
        (
            "pg password with literal space? no; tab",
            "postgres://u:F4kePass9@db",
            "F4kePass9",
        ),
    ] {
        p(&mut bad, l, t, s);
    }
    // the body of a key
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
        "email inside pw",
        "postgres://u:F4ke.me@fake.io@db.fake.test/x",
        "F4ke.me@fake.io",
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
fn a_value_that_looks_like_a_stand_in_but_is_real_is_found_whole() {
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
            "mysecretpassword",
            "POSTGRES_PASSWORD=mysecretpassword",
            "mysecretpassword",
        ),
        (
            "secret_key django",
            "SECRET_KEY = 'django-insecure-secret-key-9x'",
            "django-insecure-secret-key-9x",
        ),
        (
            "token own + 3 digits",
            "token=mytoken_A1b2C3zz",
            "mytoken_A1b2C3zz",
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
