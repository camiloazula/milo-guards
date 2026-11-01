//! What a reviewer's probe found, kept as rows: every kind of key in the
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
fn the_probe_rows_of_recall_are_found_whole() {
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
    p(
        &mut bad,
        "aws secret named",
        &format!("aws_secret_access_key = {awssec}"),
        &awssec,
    );
    p(
        &mut bad,
        "aws secret env",
        &format!("export AWS_SECRET_ACCESS_KEY={awssec}"),
        &awssec,
    );
    p(
        &mut bad,
        "aws secret yaml",
        &format!("AWS_SECRET_ACCESS_KEY: \"{awssec}\""),
        &awssec,
    );
    p(
        &mut bad,
        "aws secret json camel",
        &format!("{{\"SecretAccessKey\": \"{awssec}\"}}"),
        &awssec,
    );
    p(
        &mut bad,
        "aws secret beside id csv",
        &format!("{aws},{awssec}"),
        &awssec,
    );
    p(
        &mut bad,
        "aws secret beside id ini",
        &format!("[default]\naws_access_key_id={aws}\naws_secret_access_key={awssec}\n"),
        &awssec,
    );
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
        "netrc",
        "machine api.fake.test login fakeuser password F4kePassw0rdZ",
        "F4kePassw0rdZ",
    );
    p(
        &mut bad,
        "netrc multiline",
        "machine api.fake.test\n  login fakeuser\n  password F4kePassw0rdZ\n",
        "F4kePassw0rdZ",
    );
    p(
        &mut bad,
        "docker auths",
        &format!("{{\"auths\": {{\"https://index.docker.io/v1/\": {{\"auth\": \"{basic}\"}}}}}}"),
        basic,
    );
    p(&mut bad, "pypirc", "[pypi]\nusername = __token__\npassword = pypi-AgEIcHlwaS5vcmcFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFake0123456789\n", "pypi-AgEIcHlwaS5vcmcFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFake0123456789");
    p(
        &mut bad,
        "pypirc plain password",
        "[pypi]\nusername = fakeuser\npassword = F4kePassw0rdZ\n",
        "F4kePassw0rdZ",
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
    // generic name=value with escapes that decode to separators
    p(
        &mut bad,
        "generic %26 in query value",
        "https://api.fake.test/login?user=me&password=F4kePa%26ss9word&next=/",
        "F4kePa%26ss9word",
    );
    p(
        &mut bad,
        "generic %20 in value",
        "password=F4kePass9%20more9",
        "F4kePass9%20more9",
    );
    p(
        &mut bad,
        "generic json escaped quote",
        "{\"password\": \"F4kePass9\\\"tail0123\"}",
        "F4kePass9\\\"tail0123",
    );
    p(
        &mut bad,
        "generic json \\u0022",
        "{\"password\": \"F4kePass9\\u0022tail0123\"}",
        "F4kePass9\\u0022tail0123",
    );
    p(
        &mut bad,
        "generic yaml single",
        "db_password: 'F4kePass9'",
        "F4kePass9",
    );
    p(
        &mut bad,
        "generic env export",
        "export DB_PASSWORD=F4kePass9",
        "F4kePass9",
    );
    p(
        &mut bad,
        "generic --password=",
        "run --password=F4kePass9 now",
        "F4kePass9",
    );
    p(
        &mut bad,
        "generic value with ;",
        "password=F4ke;Pass9word",
        "F4ke;Pass9word",
    );
    p(
        &mut bad,
        "generic value with &",
        "SECRET=F4ke&Pass9word",
        "F4ke&Pass9word",
    );
    p(
        &mut bad,
        "generic value with |",
        "SECRET=F4kePass9|tail0123",
        "F4kePass9|tail0123",
    );
    p(
        &mut bad,
        "generic value with ( )",
        "SECRET=F4ke(Pass9)word",
        "F4ke(Pass9)word",
    );
    p(
        &mut bad,
        "generic value with backtick",
        "SECRET=F4ke`Pass9word",
        "F4ke`Pass9word",
    );
    p(
        &mut bad,
        "generic value with comma",
        "SECRET=F4ke,Pass9word",
        "F4ke,Pass9word",
    );
    p(
        &mut bad,
        "generic quoted with newline-escape",
        "password = \"F4ke\\nPass9word\"",
        "F4ke\\nPass9word",
    );
    p(
        &mut bad,
        "client_secret azure",
        "client_secret=F4ke8Q~abcdefghijklmnopqrstuvwxyz0123456",
        "F4ke8Q~abcdefghijklmnopqrstuvwxyz0123456",
    );
    p(
        &mut bad,
        "api-key header",
        "x-api-key: F4keApiKey0123456789abcdef",
        "F4keApiKey0123456789abcdef",
    );
    p(
        &mut bad,
        "api_key yaml",
        "api_key: F4keApiKey0123456789abcdef",
        "F4keApiKey0123456789abcdef",
    );
    p(
        &mut bad,
        "apiKey js",
        "const apiKey = 'F4keApiKey0123456789abcdef';",
        "F4keApiKey0123456789abcdef",
    );
    p(
        &mut bad,
        "OPENAI_API_KEY env",
        "OPENAI_API_KEY=F4keApiKey0123456789abcdef",
        "F4keApiKey0123456789abcdef",
    );
    p(
        &mut bad,
        "stripe sk_live",
        &format!("sk_live_{}", fill("F4keStripe0123", 24)),
        &format!("sk_live_{}", fill("F4keStripe0123", 24)),
    );
    p(
        &mut bad,
        "gitlab",
        &format!("glpat-{}", fill("F4keGitlab_0123-xy", 20)),
        &format!("glpat-{}", fill("F4keGitlab_0123-xy", 20)),
    );
    p(
        &mut bad,
        "openai proj",
        &format!("sk-proj-{}", fill("F4keOpenAi_0123-xy", 120)),
        &format!("sk-proj-{}", fill("F4keOpenAi_0123-xy", 120)),
    );
    p(
        &mut bad,
        "openai old T3Blbk",
        &format!(
            "sk-{}T3BlbkFJ{}",
            fill("F4keOpenAi0123", 20),
            fill("F4keOpenAi0123", 20)
        ),
        &format!(
            "sk-{}T3BlbkFJ{}",
            fill("F4keOpenAi0123", 20),
            fill("F4keOpenAi0123", 20)
        ),
    );
    p(
        &mut bad,
        "google key",
        &format!("AIza{}", fill("F4keGoogle_0123-xy", 35)),
        &format!("AIza{}", fill("F4keGoogle_0123-xy", 35)),
    );
    p(
        &mut bad,
        "age",
        &format!(
            "AGE-SECRET-KEY-1{}",
            fill("QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L", 58)
        ),
        &format!(
            "AGE-SECRET-KEY-1{}",
            fill("QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L", 58)
        ),
    );
    // base64-wrapped once
    p(
        &mut bad,
        "k8s secret b64 of password",
        "data:\n  password: RjRrZVBhc3M5d29yZA==\n",
        "RjRrZVBhc3M5d29yZA==",
    );
    // multibyte neighbours
    p(
        &mut bad,
        "gh next to emoji",
        &format!("😀{gh}é\u{301}"),
        &gh,
    );
    p(&mut bad, "gh next to cjk", &format!("密钥{gh}已"), &gh);
    p(
        &mut bad,
        "card visa",
        "card 4242 4242 4242 4242 exp",
        "4242 4242 4242 4242",
    );
    nothing_wrong(&bad);
}

#[test]
fn the_probe_rows_of_precision_are_safe() {
    let mut bad = Vec::new();
    s(
        &mut bad,
        "git sha",
        "commit 3f786850e387550fdab836ed7e6dc881de23001b\nMerge: a1b2c3d e4f5a6b",
    );
    s(
        &mut bad,
        "uuid",
        "id = \"550e8400-e29b-41d4-a716-446655440000\"",
    );
    s(&mut bad, "npm integrity", "\"integrity\": \"sha512-z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg==\"");
    s(&mut bad, "sri", "<script src=\"x.js\" integrity=\"sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC\" crossorigin=\"anonymous\"></script>");
    s(&mut bad, "go.sum", "golang.org/x/text v0.3.7 h1:olpwvP2KacW1ZWvsR7uQhoyTYvKAupfQrRGBFM352Gk=\ngolang.org/x/text v0.3.7/go.mod h1:u+2+/6zg+i71rQMx5EYifcz6MCKuco9NR6JIITiCfzQ=");
    s(
        &mut bad,
        "docker digest",
        "image: nginx@sha256:0d17b565c37bcbd895e9d92315a05c1c3c9a29f762b011a10c54a66cd53c9b31",
    );
    s(
        &mut bad,
        "css",
        ".a{color:#ff00aa;background:#0a0b0c}.b{color:rgba(0,0,0,.5)}",
    );
    s(&mut bad, "minified js", "!function(e,t){\"object\"==typeof exports?module.exports=t():e.x=t()}(this,function(){var n={token:void 0,key:function(e){return e+1}};return n.passwordField=\"pwd1\",n});");
    s(&mut bad, "base64 fixture", "const FIXTURE: &str = \"SGVsbG8sIFdvcmxkISBUaGlzIGlzIGEgZml4dHVyZSBmb3IgdGVzdGluZyAwMTIzNDU2Nzg5\";");
    s(
        &mut bad,
        "placeholder <your-key>",
        "api_key = \"<your-key>\"",
    );
    s(
        &mut bad,
        "placeholder xxxx",
        "API_KEY=xxxxxxxxxxxxxxxx\nTOKEN=XXXXXXXXXX",
    );
    s(
        &mut bad,
        "placeholder ${}",
        "password: ${DB_PASSWORD}\ntoken = \"${API_KEY}\"",
    );
    s(
        &mut bad,
        "placeholder changeme",
        "password=changeme\nPASSWORD: changeme123",
    );
    s(
        &mut bad,
        "placeholder your-api-key-here",
        "OPENAI_API_KEY=your-api-key-here",
    );
    s(&mut bad, "placeholder sk-...", "OPENAI_API_KEY=sk-...");
    s(
        &mut bad,
        "placeholder ghp_xxx",
        "GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
    s(
        &mut bad,
        "placeholder dummy",
        "password = \"dummy_password\"\nsecret: test-secret-value",
    );
    s(
        &mut bad,
        "placeholder REPLACE_ME",
        "CLIENT_SECRET=REPLACE_ME\nAPI_TOKEN=TODO",
    );
    s(
        &mut bad,
        "placeholder <token>",
        "Authorization: Bearer <token>\nAuthorization: Bearer YOUR_TOKEN_HERE",
    );
    s(&mut bad, "rust code", "fn login(password: &str) -> Result<Token, Error> {\n    let token = self.client.token()?;\n    let secret_key = config.secret_key.clone();\n    let api_key = env::var(\"API_KEY\")?;\n    if password == stored_password { }\n}");
    s(&mut bad, "python code", "def auth(self, password=None, token=DEFAULT_TOKEN):\n    self.token = token or os.environ['TOKEN']\n    secret = get_secret('name')\n");
    s(
        &mut bad,
        "kwargs",
        "client = Client(api_key=api_key, secret_key=settings.SECRET_KEY, token=token)",
    );
    s(
        &mut bad,
        "ts types",
        "interface Creds { password: string; token?: string; apiKey: string | undefined }",
    );
    s(
        &mut bad,
        "semver/date",
        "version 2024.10.31 released 2024-10-31T12:00:00Z build 20241031",
    );
    s(
        &mut bad,
        "cargo.lock checksum",
        "checksum = \"a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90\"",
    );
    s(&mut bad, "yarn.lock", "  resolved \"https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#679591c564c3bffaae8454cf0b3df370c3d6911c\"");
    s(&mut bad, "pnpm lock", "  /lodash@4.17.21:\n    resolution: {integrity: sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg==}");
    s(
        &mut bad,
        "token count",
        "max_tokens: 4096\ntotal_tokens=123456\nprompt_token_count: 99",
    );
    s(
        &mut bad,
        "csrf meta",
        "<meta name=\"csrf-token\" content=\"{{ csrf_token() }}\">",
    );
    s(
        &mut bad,
        "password field html",
        "<input type=\"password\" name=\"password\" placeholder=\"Password\">",
    );
    s(&mut bad, "ssh pubkey", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl user@laptop");
    s(&mut bad, "public key pem", "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfakefakefakefakefakefakefakefakefakefake\n-----END PUBLIC KEY-----");
    s(&mut bad, "cert pem", "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUfakefakefakefakefakefakefakefake0123456789\n-----END CERTIFICATE-----");
    s(
        &mut bad,
        "hex color long",
        "fill=\"#aabbcc\" stroke=\"#112233\"",
    );
    s(
        &mut bad,
        "k8s configmap",
        "data:\n  key: value\n  token_ttl: 3600s\n  password_min_length: 12",
    );
    s(&mut bad, "aws example", "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
    s(
        &mut bad,
        "url with port",
        "http://localhost:8080/api and https://user@github.com/x and git@github.com:org/repo.git",
    );
    s(
        &mut bad,
        "ipv6/time",
        "at 12:30:45 on ::1 and fe80::1 and std::string::String",
    );
    s(
        &mut bad,
        "jwt-like doc",
        "A JWT looks like eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature",
    );
    s(
        &mut bad,
        "password in prose",
        "Your password: must be 12 characters long. The token: expires in 3600 seconds.",
    );
    s(
        &mut bad,
        "env var refs",
        "export TOKEN=$(cat /run/secrets/token)\nPASSWORD=\"$(vault read -field=pw secret/db)\"",
    );
    s(&mut bad, "build number", "build +20240101");
    s(&mut bad, "base64 image", "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==");
    s(
        &mut bad,
        "windows path",
        "C:\\Users\\fake\\AppData\\Local\\token_cache.bin",
    );
    s(
        &mut bad,
        "sql",
        "SELECT password_hash FROM users WHERE token = $1 AND secret IS NULL;",
    );
    s(
        &mut bad,
        "password=****",
        "password=********\nsecret: \"••••••••\"",
    );
    s(&mut bad, "go struct tags", "Password string `json:\"password\" yaml:\"password\"`\nToken string `json:\"token,omitempty\"`");
    s(
        &mut bad,
        "generic: key with digit word",
        "secret_name: prod-db-2\ntoken_type: bearer1",
    );
    s(
        &mut bad,
        "helm values",
        "auth:\n  secretKey: postgres-password\n  existingSecret: my-secret",
    );
    s(
        &mut bad,
        "github actions",
        "token: ${{ secrets.GITHUB_TOKEN }}\npassword: ${{ secrets.PW }}",
    );
    s(
        &mut bad,
        "terraform",
        "password = var.db_password\nsecret_key = random_password.x.result",
    );
    nothing_wrong(&bad);
}

#[test]
fn the_probe_rows_of_overlap_are_found_whole() {
    let mut bad = Vec::new();
    let aws = format!("AKIA{}", "Q7FAKE2TESTK3YZW");
    p(
        &mut bad,
        "aws inside longer password",
        &format!("password=Xy9!{aws}/tail9"),
        &format!("Xy9!{aws}/tail9"),
    );
    let gh = format!("ghp_{}", fill("FakeGitHubToken0123x", 36));
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
    nothing_wrong(&bad);
}
