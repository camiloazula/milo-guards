//! The ticket's tables: what is safe, what is risky and under which rule,
//! and the words and the target each finding carries.

use milo_guards_core::testing::{check, posix, rules};
use milo_guards_url::{judge, Assessment, Rule};

fn on_posix(url: &str) -> Assessment {
    judge(url, &posix())
}

#[test]
fn a_public_host_over_the_web_is_safe() {
    check(
        &[
            "https://example.com/",
            "http://example.com",
            "https://docs.rs/url",
            "https://EXAMPLE.com/Path?Q=1#frag",
            "HTTP://example.com/",
            "https://example.com:8443/api?x=1",
            "https://example.com:443/",
            "https://sub.domain.example.co.uk/a/b/c.html",
            "https://xn--r8jz45g.jp/",
            "https://例え.jp/",
            "https://münchen.de/",
            "https://a-b.example.org/",
            "https://example.com./",
            "http://93.184.216.34/",
            "http://93.184.216.34:8080/x",
            "http://8.8.8.8/",
            "http://1.1.1.1/",
            "https://[2606:2800:220:1:248:1893:25c8:1946]/",
            "https://[2001:4860:4860::8888]/",
            "http://[::ffff:93.184.216.34]/",
            "http://[64:ff9b::5db8:d822]/",
            "http://[2002:5db8:d822::1]/",
            "https://example.com/a%20b?q=%7Bx%7D",
            "https://example.com/path/with\\backslash",
            "https://example.com/?next=http://127.0.0.1/",
            "https://example.com/#http://localhost/",
            "  https://example.com/  ",
            "\thttps://example.com/\n",
            "https://localhost.example.com/",
            "https://notlocalhost.com/",
            "https://example.com/localhost",
            "https://local.example.com/",
            "https://home.example.com/",
            "https://internal.example.com/",
            "https://www.example.org:80/",
        ],
        &[],
        on_posix,
    );
}

#[test]
fn the_ticket_rows_are_what_it_says() {
    check(
        &[
            "https://example.com/",
            "https://docs.rs/url",
            "http://93.184.216.34/",
            "https://例え.jp/",
            "https://example.com:8443/api?x=1",
        ],
        &[
            ("http://localhost:9090/", Rule::LocalAddress),
            ("http://127.1/", Rule::LocalAddress),
            ("http://2130706433/", Rule::LocalAddress),
            ("http://0177.0.0.1/", Rule::LocalAddress),
            ("http://0x7f000001/", Rule::LocalAddress),
            ("http://[::ffff:127.0.0.1]/", Rule::LocalAddress),
            ("http://192.168.1.1/", Rule::LocalAddress),
            ("http://10.0.0.5:8080/", Rule::LocalAddress),
            ("http://printer.local/", Rule::LocalAddress),
            ("http://box/", Rule::LocalAddress),
            ("http://169.254.169.254/latest/meta-data/", Rule::Metadata),
            ("http://metadata.google.internal/", Rule::Metadata),
            ("https://me:hunter2@example.com/", Rule::Credentials),
            ("file:///home/me/.ssh/id_rsa", Rule::LocalFile),
            ("ftp://example.com/", Rule::Scheme),
            ("javascript:alert(1)", Rule::Scheme),
            ("", Rule::Unreadable),
            ("http://", Rule::Unreadable),
            ("not a url", Rule::Unreadable),
            (
                &format!("http://example.com/{}", "a".repeat(70_000)),
                Rule::Unreadable,
            ),
        ],
        on_posix,
    );
}

#[test]
fn a_local_machine_is_a_local_address() {
    check(
        &[],
        &[
            ("http://localhost/", Rule::LocalAddress),
            ("http://LOCALHOST/", Rule::LocalAddress),
            ("http://localhost./", Rule::LocalAddress),
            ("http://foo.localhost/", Rule::LocalAddress),
            ("http://a.b.localhost:3000/", Rule::LocalAddress),
            ("http://127.0.0.1/", Rule::LocalAddress),
            ("http://127.255.255.254/", Rule::LocalAddress),
            ("http://[::1]/", Rule::LocalAddress),
            ("http://[::1]:8080/", Rule::LocalAddress),
            ("http://[0:0:0:0:0:0:0:1]/", Rule::LocalAddress),
            ("http://0.0.0.0/", Rule::LocalAddress),
            ("http://[::]/", Rule::LocalAddress),
            ("http://0/", Rule::LocalAddress),
            ("http://10.0.0.1/", Rule::LocalAddress),
            ("http://10.255.255.255/", Rule::LocalAddress),
            ("http://172.16.0.1/", Rule::LocalAddress),
            ("http://172.31.255.255/", Rule::LocalAddress),
            ("http://192.168.0.1/", Rule::LocalAddress),
            ("http://169.254.1.1/", Rule::LocalAddress),
            ("http://100.64.0.1/", Rule::LocalAddress),
            ("http://100.127.255.255/", Rule::LocalAddress),
            ("http://[fc00::1]/", Rule::LocalAddress),
            ("http://[fd12:3456:789a::1]/", Rule::LocalAddress),
            ("http://[fe80::1]/", Rule::LocalAddress),
            ("http://[febf::1]/", Rule::LocalAddress),
            ("http://[fec0::1]/", Rule::LocalAddress),
            ("http://router.lan/", Rule::LocalAddress),
            ("http://nas.home.arpa/", Rule::LocalAddress),
            ("http://printer.local./", Rule::LocalAddress),
            ("http://api.internal/", Rule::LocalAddress),
            ("http://host.docker.internal:8080/", Rule::LocalAddress),
            ("http://intranet/", Rule::LocalAddress),
            ("http://wiki.corp/", Rule::LocalAddress),
            ("http://app.test/", Rule::LocalAddress),
            ("http://nas.localdomain/", Rule::LocalAddress),
            ("http://127.0.0.1.nip.io/", Rule::LocalAddress),
            ("http://10-0-0-5.sslip.io/", Rule::LocalAddress),
            ("http://anything.localtest.me/", Rule::LocalAddress),
            ("http://lvh.me/", Rule::LocalAddress),
        ],
        on_posix,
    );
}

#[test]
fn an_address_in_no_public_range_is_a_local_address() {
    check(
        &[],
        &[
            ("http://192.0.2.1/", Rule::LocalAddress),
            ("http://198.51.100.7/", Rule::LocalAddress),
            ("http://203.0.113.9/", Rule::LocalAddress),
            ("http://198.18.0.1/", Rule::LocalAddress),
            ("http://198.19.255.255/", Rule::LocalAddress),
            ("http://192.0.0.8/", Rule::LocalAddress),
            ("http://224.0.0.1/", Rule::LocalAddress),
            ("http://239.255.255.250/", Rule::LocalAddress),
            ("http://240.0.0.1/", Rule::LocalAddress),
            ("http://255.255.255.255/", Rule::LocalAddress),
            ("http://0.1.2.3/", Rule::LocalAddress),
            ("http://[2001:db8::1]/", Rule::LocalAddress),
            ("http://[2001::1]/", Rule::LocalAddress),
            ("http://[2001:2::1]/", Rule::LocalAddress),
            ("http://[ff02::1]/", Rule::LocalAddress),
            ("http://[100::1]/", Rule::LocalAddress),
            ("http://[3fff::1]/", Rule::LocalAddress),
            ("http://[64:ff9b:1::1]/", Rule::LocalAddress),
            ("http://[4000::1]/", Rule::LocalAddress),
        ],
        on_posix,
    );
}

#[test]
fn an_ipv4_address_inside_an_ipv6_one_is_judged_by_the_ipv4_inside() {
    check(
        &[
            "http://[::ffff:8.8.8.8]/",
            "http://[::ffff:5db8:d822]/",
            "http://[64:ff9b::808:808]/",
            "http://[2002:808:808::]/",
        ],
        &[
            ("http://[::ffff:127.0.0.1]/", Rule::LocalAddress),
            ("http://[::ffff:7f00:1]/", Rule::LocalAddress),
            ("http://[0:0:0:0:0:ffff:7f00:1]/", Rule::LocalAddress),
            ("http://[::ffff:10.1.2.3]/", Rule::LocalAddress),
            ("http://[::ffff:192.168.1.1]/", Rule::LocalAddress),
            ("http://[::ffff:0.0.0.0]/", Rule::LocalAddress),
            ("http://[::127.0.0.1]/", Rule::LocalAddress),
            ("http://[::10.0.0.1]/", Rule::LocalAddress),
            ("http://[::a00:1]/", Rule::LocalAddress),
            ("http://[64:ff9b::7f00:1]/", Rule::LocalAddress),
            ("http://[64:ff9b::a00:1]/", Rule::LocalAddress),
            ("http://[64:ff9b::192.168.1.1]/", Rule::LocalAddress),
            ("http://[2002:7f00:1::]/", Rule::LocalAddress),
            ("http://[2002:a00:1::1]/", Rule::LocalAddress),
            ("http://[2002:c0a8:101::]/", Rule::LocalAddress),
            ("http://[::ffff:169.254.169.254]/", Rule::Metadata),
            ("http://[::a9fe:a9fe]/", Rule::Metadata),
            ("http://[64:ff9b::a9fe:a9fe]/", Rule::Metadata),
            ("http://[2002:a9fe:a9fe::]/", Rule::Metadata),
        ],
        on_posix,
    );
}

#[test]
fn a_metadata_service_wins_over_a_local_address() {
    for url in [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254:80/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata/",
        "http://[fd00:ec2::254]/latest/meta-data/",
        "http://100.100.100.200/latest/meta-data/",
        "http://169.254.170.2/v2/credentials",
        "http://192.0.0.192/opc/v2/instance/",
        "http://metadata.azure.com/",
        "http://instance-data/latest/meta-data/",
    ] {
        assert_eq!(rules(url, on_posix), [Rule::Metadata], "{url}");
    }
}

#[test]
fn the_reason_says_what_it_is() {
    let reason = |url: &str| on_posix(url).findings()[0].reason.clone();
    assert_eq!(reason("http://127.0.0.1/"), "fetches your own machine");
    assert_eq!(reason("http://localhost/"), "fetches your own machine");
    assert_eq!(reason("http://0.0.0.0/"), "fetches your own machine");
    assert_eq!(
        reason("http://192.168.1.1/"),
        "fetches a machine on your own network"
    );
    assert_eq!(
        reason("http://printer.local/"),
        "fetches a machine on your own network"
    );
    assert_eq!(
        reason("http://box/"),
        "fetches a machine on your own network"
    );
    assert_eq!(
        reason("http://192.0.2.1/"),
        "fetches an address that is not on the public internet"
    );
    assert_eq!(
        reason("http://127.0.0.1.nip.io/"),
        "fetches a name that can point at your own network"
    );
    assert_eq!(
        reason("http://169.254.169.254/"),
        "fetches the cloud metadata service (AWS, Google Cloud, Azure, DigitalOcean and OpenStack), which hands out credentials"
    );
    assert_eq!(
        reason("javascript:alert(1)"),
        "uses the javascript scheme, which is not a web page"
    );
    assert_eq!(
        reason("https://me:pw@example.com/"),
        "sends a user name or a password in the URL"
    );
}

#[test]
fn the_target_is_the_host_as_the_parser_reads_it() {
    let target = |url: &str| on_posix(url).findings()[0].target.clone();
    assert_eq!(target("http://2130706433/").as_deref(), Some("127.0.0.1"));
    assert_eq!(target("http://0x7f.1:8080/x").as_deref(), Some("127.0.0.1"));
    assert_eq!(target("http://LocalHost./").as_deref(), Some("localhost."));
    assert_eq!(
        target("http://[::ffff:127.0.0.1]/").as_deref(),
        Some("[::ffff:7f00:1]")
    );
    assert_eq!(target("ftp://example.com/x").as_deref(), Some("ftp"));
}

#[test]
fn credentials_never_show_the_password() {
    for (url, target) in [
        ("https://me:hunter2@example.com/", "https://…@example.com/"),
        (
            "https://me@example.com/a?b=c#d",
            "https://…@example.com/a?b=c#d",
        ),
        ("https://:hunter2@example.com/", "https://…@example.com/"),
        ("http://a:b@c@example.com/", "http://…@example.com/"),
        (
            "http://me:p%40ss@example.com:8080/x",
            "http://…@example.com:8080/x",
        ),
        ("HTTP://Me:Hunter2@Example.COM/", "http://…@example.com/"),
    ] {
        let assessment = on_posix(url);
        let found = &assessment.findings()[0];
        assert_eq!(found.rule, Rule::Credentials, "{url}");
        assert_eq!(found.target.as_deref(), Some(target), "{url}");
        for password in ["hunter2", "Hunter2", "p%40ss", "p@ss"] {
            assert!(
                format!("{assessment:?}").find(password).is_none(),
                "{url} echoed {password}"
            );
        }
    }
}

#[test]
fn credentials_and_the_host_are_both_found() {
    assert_eq!(
        rules("http://me:pw@127.0.0.1/", on_posix),
        [Rule::Credentials, Rule::LocalAddress]
    );
    assert_eq!(
        rules("http://example.com@127.0.0.1/", on_posix),
        [Rule::Credentials, Rule::LocalAddress]
    );
    assert_eq!(
        rules("ftp://me:pw@169.254.169.254/", on_posix),
        [Rule::Scheme, Rule::Credentials, Rule::Metadata]
    );
}

#[test]
fn a_password_in_an_unreadable_url_is_not_repeated() {
    for url in [
        "https://me:hunter2@exa mple.com/",
        "https://me:hunter2@exa\u{0}mple.com/",
        "https://me:hunter2@[fe80::1%25en0]/",
        "https://me:hunter2@host:99999/",
    ] {
        let assessment = on_posix(url);
        assert_eq!(rules(url, on_posix), [Rule::Unreadable], "{url}");
        assert!(!format!("{assessment:?}").contains("hunter2"), "{url}");
    }
}

#[test]
fn a_scheme_that_is_not_the_web_is_a_finding() {
    check(
        &[],
        &[
            ("ftp://example.com/", Rule::Scheme),
            ("gopher://example.com/", Rule::Scheme),
            ("javascript:alert(1)", Rule::Scheme),
            ("JavaScript:alert(1)", Rule::Scheme),
            ("data:text/html,<script>1</script>", Rule::Scheme),
            ("ssh://git@github.com/x/y", Rule::Scheme),
            ("ws://example.com/socket", Rule::Scheme),
            ("wss://example.com/socket", Rule::Scheme),
            ("mailto:me@example.com", Rule::Scheme),
            ("view-source:https://example.com/", Rule::Scheme),
            ("blob:https://example.com/uuid", Rule::Scheme),
            ("localhost:9090/admin", Rule::Scheme),
            ("chrome://settings", Rule::Scheme),
        ],
        on_posix,
    );
}

#[test]
fn a_host_is_judged_whatever_the_scheme() {
    check(
        &[],
        &[
            ("ftp://127.0.0.1/", Rule::LocalAddress),
            ("ws://localhost:8080/", Rule::LocalAddress),
            ("ssh://0x7f.1/", Rule::LocalAddress),
            ("ssh://git@192.168.1.5/x", Rule::LocalAddress),
            ("gopher://metadata.google.internal/", Rule::Metadata),
            ("ftp://[::1]/", Rule::LocalAddress),
        ],
        on_posix,
    );
}

#[test]
fn what_cannot_be_read_is_unreadable() {
    check(
        &[],
        &[
            ("", Rule::Unreadable),
            ("   ", Rule::Unreadable),
            ("\n", Rule::Unreadable),
            ("http://", Rule::Unreadable),
            ("https://", Rule::Unreadable),
            ("http:///", Rule::Unreadable),
            ("not a url", Rule::Unreadable),
            ("example.com", Rule::Unreadable),
            ("example.com/path", Rule::Unreadable),
            ("127.0.0.1:8080", Rule::Unreadable),
            ("//127.0.0.1/", Rule::Unreadable),
            ("//example.com/", Rule::Unreadable),
            ("/etc/passwd", Rule::Unreadable),
            ("http://exa mple.com/", Rule::Unreadable),
            ("http://example.com:99999/", Rule::Unreadable),
            ("http://example.com:80:80/", Rule::Unreadable),
            ("http://[::1/", Rule::Unreadable),
            ("http://[fe80::1%25en0]/", Rule::Unreadable),
            ("http://[fe80::1%en0]/", Rule::Unreadable),
            ("http://1.2.3.4.5/", Rule::Unreadable),
            ("http://256.1.1.1/", Rule::Unreadable),
            ("http://foo.1/", Rule::Unreadable),
            ("http://a..b/", Rule::Unreadable),
            ("http://./", Rule::Unreadable),
            ("http://localhost../", Rule::Unreadable),
            ("http://exa_mple.com/", Rule::Unreadable),
            ("http://exa!mple.com/", Rule::Unreadable),
            ("http://xn--localhost-/", Rule::Unreadable),
            ("http://example.com\u{0}/", Rule::Unreadable),
            ("http://exam\u{0}ple.com/", Rule::Unreadable),
            ("http://example.com/\u{1}", Rule::Unreadable),
            ("http://example.com/\u{7f}", Rule::Unreadable),
            ("http://example.com/\u{85}", Rule::Unreadable),
            ("\u{0}http://example.com/", Rule::Unreadable),
            ("http://exa\tmple.com/", Rule::Unreadable),
            ("http://exa\nmple.com/", Rule::Unreadable),
            ("ht\ntp://example.com/", Rule::Unreadable),
            ("http://127.0.0.1\n.example.com/", Rule::Unreadable),
            (
                &format!("https://example.com/{}", "a".repeat(8_200)),
                Rule::Unreadable,
            ),
            (
                &format!("https://{}.com/", "a".repeat(64)),
                Rule::Unreadable,
            ),
        ],
        on_posix,
    );
}

#[test]
fn a_url_at_the_limit_is_read() {
    let path = "a".repeat(8_192 - "https://example.com/".len());
    let at = format!("https://example.com/{path}");
    assert_eq!(at.len(), 8_192);
    assert!(on_posix(&at).is_safe());
    assert!(!on_posix(&format!("{at}a")).is_safe());
}

#[test]
fn a_finding_for_an_unreadable_url_carries_no_copy_of_it() {
    for url in ["", "not a url", "http://exa mple.com/", "http://[::1/"] {
        let assessment = on_posix(url);
        assert!(
            assessment.findings().iter().all(|f| f.target.is_none()),
            "{url}"
        );
    }
}
