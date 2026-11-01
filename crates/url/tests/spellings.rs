//! The spellings a reviewer tries, each a permanent row: whatever the URL
//! parser reads as the host is the host, and a spelling a client could read
//! differently is unreadable. A fix must never silently reopen one.

use milo_guards_core::testing::{check, posix, rules};
use milo_guards_url::{judge, Assessment, Rule};

fn on_posix(url: &str) -> Assessment {
    judge(url, &posix())
}

/// Every URL in `urls` breaks `rule`.
fn all_break(rule: Rule, urls: &[&str]) {
    let rows: Vec<(&str, Rule)> = urls.iter().map(|url| (*url, rule)).collect();
    check(&[], &rows, on_posix);
}

#[test]
fn loopback_in_every_ipv4_spelling() {
    all_break(
        Rule::LocalAddress,
        &[
            // Decimal, hex, octal as one number.
            "http://2130706433/",
            "http://0x7f000001/",
            "http://0X7F000001/",
            "http://017700000001/",
            // Dotted, with parts in other bases or shortened.
            "http://0177.0.0.1/",
            "http://0177.0.0.01/",
            "http://0177.0000.0000.0001/",
            "http://0x7f.1/",
            "http://0x7f.0.0.1/",
            "http://0x7f.0x0.0x0.0x1/",
            "http://0x7F.0X0.0x0.0x01/",
            "http://127.1/",
            "http://127.0.1/",
            "http://127.000.000.001/",
            "http://127.0.0.1./",
            "http://127.0.0.1:80/",
            "http://127.0.0.1:0/",
            "http://127.0.0.0/",
            "http://127.1.2.3/",
            // Escaped, full-width, other full stops.
            "http://%31%32%37.0.0.1/",
            "http://127%2e0%2e0%2e1/",
            "http://１２７.０.０.１/",
            "http://127。0。0。1/",
            "http://127．0．0．1/",
            "http://127｡0｡0｡1/",
            // The unspecified address.
            "http://0/",
            "http://0x0/",
            "http://0.0.0.0/",
            "http://00.0.0.0/",
            "http://0x/",
            // In IPv6.
            "http://[::ffff:127.0.0.1]/",
            "http://[::FFFF:127.0.0.1]/",
            "http://[::ffff:7f00:1]/",
            "http://[0:0:0:0:0:ffff:127.0.0.1]/",
            "http://[0000:0000:0000:0000:0000:ffff:7f00:0001]/",
            "http://[::127.0.0.1]/",
            "http://[::7f00:1]/",
            "http://[::1]/",
            "http://[0::1]/",
            "http://[0000:0000:0000:0000:0000:0000:0000:0001]/",
            "http://[::0001]/",
        ],
    );
}

#[test]
fn a_private_or_link_local_address_in_other_spellings() {
    all_break(
        Rule::LocalAddress,
        &[
            "http://3232235777/",
            "http://0xc0a80001/",
            "http://0300.0250.0.1/",
            "http://192.168.1/",
            "http://192.11010049/",
            "http://10.1/",
            "http://0xa.1/",
            "http://167772161/",
            "http://0xa000001/",
            "http://012.0.0.1/",
            "http://172.0x10.0.1/",
            "http://2886729729/",
            "http://[::ffff:192.168.1.1]/",
            "http://[::ffff:c0a8:101]/",
        ],
    );
}

#[test]
fn the_metadata_address_in_every_spelling() {
    for url in [
        "http://169.254.169.254/",
        "http://2852039166/",
        "http://0xa9fea9fe/",
        "http://0251.0376.0251.0376/",
        "http://0xa9.0xfe.0xa9.0xfe/",
        "http://169.254.43518/",
        "http://169.16689662/",
        "http://169.254.169.254./",
        "http://%31%36%39.254.169.254/",
        "http://１６９.２５４.１６９.２５４/",
        "http://[::ffff:a9fe:a9fe]/",
        "http://[::ffff:169.254.169.254]/",
        "http://[::169.254.169.254]/",
        "http://[64:ff9b::169.254.169.254]/",
        "http://[2002:a9fe:a9fe::]/",
        "http://[fd00:ec2::254]/",
        "http://[FD00:EC2:0:0:0:0:0:254]/",
        "http://[fd00:0ec2::0254]/",
    ] {
        assert!(
            rules(url, on_posix).contains(&Rule::Metadata),
            "{url}: {:?}",
            on_posix(url).findings()
        );
    }
}

#[test]
fn an_address_spelled_in_a_form_clients_read_differently_is_unreadable_even_when_public() {
    // `010.0.0.1` is `8.0.0.1` to the parser and `10.0.0.1` to a client that
    // reads every number as decimal; the others are one address spelled so
    // that a client may not read it at all.
    all_break(
        Rule::Unreadable,
        &[
            "http://010.0.0.1/",
            "http://0127.0.0.1/",
            "http://00000127.0.0.1/",
            "http://0x08080808/",
            "http://0x8.8.8.8/",
            "http://134744072/",
            "http://8.8.8/",
            "http://8.8.8.8./",
            "http://8.8.8.08/",
            "http://８.８.８.８/",
            "http://%38.8.8.8/",
            "http://1.1.1/",
            "http://0254.0.0.1/",
        ],
    );
    assert!(on_posix("http://8.8.8.8/").is_safe());
    assert!(on_posix("http://8.8.8.8:80/").is_safe());
}

#[test]
fn the_host_is_the_one_the_parser_reads_not_the_one_the_text_shows() {
    for (url, expected) in [
        // User-info: the host is what follows the last `@`.
        (
            "http://example.com@127.0.0.1/",
            vec![Rule::Credentials, Rule::LocalAddress],
        ),
        (
            "http://example.com:80@127.0.0.1/",
            vec![Rule::Credentials, Rule::LocalAddress],
        ),
        (
            "http://example.com%2f@127.0.0.1/",
            vec![Rule::Credentials, Rule::LocalAddress],
        ),
        (
            "http://a@b@127.0.0.1/",
            vec![Rule::Credentials, Rule::LocalAddress],
        ),
        ("http://127.0.0.1@example.com/", vec![Rule::Credentials]),
        ("http://localhost:80@example.com/", vec![Rule::Credentials]),
        (
            "http://user:pass@localhost/",
            vec![Rule::Credentials, Rule::LocalAddress],
        ),
        // The fragment, the query and the path end the host.
        ("http://127.0.0.1#@example.com/", vec![Rule::LocalAddress]),
        ("http://127.0.0.1?@example.com/", vec![Rule::LocalAddress]),
        ("http://127.0.0.1/@example.com/", vec![Rule::LocalAddress]),
        (
            "http://127.0.0.1:80#@example.com/",
            vec![Rule::LocalAddress],
        ),
        ("http://example.com#@127.0.0.1/", vec![]),
        ("http://example.com?@127.0.0.1/", vec![]),
        ("http://example.com/@127.0.0.1/", vec![]),
        ("http://example.com/http://127.0.0.1/", vec![]),
        ("https://example.com/?u=http://169.254.169.254/", vec![]),
    ] {
        assert_eq!(rules(url, on_posix), expected, "{url}");
    }
}

#[test]
fn a_spelling_the_parser_and_another_client_read_differently_is_unreadable() {
    all_break(
        Rule::Unreadable,
        &[
            // A backslash ends the authority for the parser and not for a
            // client that follows the RFC: two hosts.
            "http://example.com\\@127.0.0.1/",
            "http://example.com\\.evil.example/",
            "https://example.com\\/path",
            "http://example.com\\",
            "http:\\\\example.com/",
            "http:\\\\127.0.0.1",
            "http://\\\\example.com/",
            "http:\\/example.com/",
            "http:/\\example.com/",
            // A scheme with no or one slash is a path to a client that
            // follows the RFC.
            "http:/example.com/",
            "http:example.com/",
            "http:///example.com/",
            "http:////example.com/",
            "https:example.com",
            "https:/127.0.0.1",
            // A percent-encoded host is plain text to some clients.
            "http://%65xample.com/",
            "http://exa%6dple.com/",
            "http://example%2ecom/",
            "http://user@%65xample.com/",
        ],
    );
    // A backslash after the authority is a path character and no concern.
    assert!(on_posix("https://example.com/a\\b").is_safe());
    assert!(on_posix("https://example.com/?q=a\\b").is_safe());
}

#[test]
fn a_odd_spelling_of_a_local_host_still_says_which_host() {
    for url in [
        "http:\\\\127.0.0.1",
        "http:/127.0.0.1",
        "http:127.0.0.1",
        "http://127.0.0.1\\@example.com/",
        "http://%6c%6f%63alhost/",
    ] {
        let found = rules(url, on_posix);
        assert!(found.contains(&Rule::LocalAddress), "{url}: {found:?}");
        assert!(found.contains(&Rule::Unreadable), "{url}: {found:?}");
    }
}

#[test]
fn white_space_and_control_characters() {
    check(
        &[
            " https://example.com/",
            "https://example.com/ ",
            "\thttps://example.com/",
            "\nhttps://example.com/\r\n",
            "\u{c}https://example.com/\u{c}",
        ],
        &[
            ("  http://127.0.0.1/  ", Rule::LocalAddress),
            ("\nhttp://localhost/\n", Rule::LocalAddress),
            // Inside, a tab or a newline is dropped by the parser and kept by
            // a client that does not.
            ("http://exa\tmple.com/", Rule::Unreadable),
            ("http://exa\nmple.com/", Rule::Unreadable),
            ("http://exa\rmple.com/", Rule::Unreadable),
            ("ht\ttp://example.com/", Rule::Unreadable),
            ("http://127.0.0.1\n.example.com/", Rule::Unreadable),
            ("http://127.\t0.0.1/", Rule::Unreadable),
            ("http://localhost\t.example.com/", Rule::Unreadable),
            ("http://example.com/a\nb", Rule::Unreadable),
            ("http://example.com/\u{0}", Rule::Unreadable),
            ("\u{0}http://example.com/", Rule::Unreadable),
            ("http://example.com/\u{1b}[31m", Rule::Unreadable),
            ("http://example.com/\u{7f}", Rule::Unreadable),
            ("http://example.com/\u{80}", Rule::Unreadable),
            // Other white space is not trimmed by the parser.
            ("\u{a0}https://example.com/", Rule::Unreadable),
            ("\u{3000}http://example.com/", Rule::Unreadable),
            ("http://exam ple.com/", Rule::Unreadable),
        ],
        on_posix,
    );
}

#[test]
fn names_in_other_spellings() {
    all_break(
        Rule::LocalAddress,
        &[
            "http://LOCALHOST/",
            "http://LocalHost/",
            "http://localhost./",
            "http://localhost.:9090/",
            "http://Localhost.LOCALDOMAIN/",
            "http://foo.LOCALHOST./",
            "http://%6c%6f%63%61%6c%68%6f%73%74/",
            "http://ｌｏｃａｌｈｏｓｔ/",
            "http://ＬＯＣＡＬＨＯＳＴ/",
            "http://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ/",
            "http://localhost\u{200b}/",
            "http://local\u{ad}host/",
            "http://localhost。/",
            "http://foo。localhost/",
            "http://printer.LOCAL/",
            "http://printer。local/",
            "http://BOX/",
            "http://xn--r8jz45g.localhost/",
            "http://例え.local/",
            "http://a.b.c.d.e.f.internal/",
        ],
    );
}

#[test]
fn international_names_are_safe_unless_they_decode_to_a_local_one() {
    check(
        &[
            "https://例え.jp/",
            "https://xn--r8jz45g.jp/",
            "https://XN--R8JZ45G.JP/",
            "https://münchen.de/",
            "https://пример.рф/",
            "https://xn--e1afmkfd.xn--p1ai/",
            "https://ı.com/",
            "https://日本語.example.com/",
        ],
        &[
            // A name that is not valid is not read.
            ("http://xn--localhost-/", Rule::Unreadable),
            ("http://xn--/", Rule::Unreadable),
            ("http://xn--a/", Rule::Unreadable),
            ("http://xn--r8jz45g.jp.xn--/", Rule::Unreadable),
        ],
        on_posix,
    );
}

#[test]
fn zone_ids_and_malformed_ip_literals_are_unreadable() {
    all_break(
        Rule::Unreadable,
        &[
            "http://[fe80::1%25en0]/",
            "http://[fe80::1%en0]/",
            "http://[fe80::1%25]/",
            "http://[::1%25lo]/",
            "http://[::1/",
            "http://::1/",
            "http://[::1]x/",
            "http://[::g]/",
            "http://[1:2:3:4:5:6:7:8:9]/",
            "http://[]/",
            "http://[127.0.0.1]/",
            "http://1.2.3.4.5/",
            "http://1.2.3.256/",
            "http://256.256.256.256/",
            "http://4294967296/",
            "http://0x100000000/",
            "http://09.0.0.1/",
            "http://1.2.3.4.5.6.7.8/",
        ],
    );
}

#[test]
fn ports_do_not_change_the_host() {
    check(
        &[
            "https://example.com:1/",
            "https://example.com:65535/",
            "http://93.184.216.34:8080/",
        ],
        &[
            ("http://127.0.0.1:65535/", Rule::LocalAddress),
            ("http://localhost:1/", Rule::LocalAddress),
            ("http://[::1]:443/", Rule::LocalAddress),
            ("http://169.254.169.254:8080/", Rule::Metadata),
            ("http://example.com:65536/", Rule::Unreadable),
            ("http://example.com:-1/", Rule::Unreadable),
            ("http://example.com:abc/", Rule::Unreadable),
        ],
        on_posix,
    );
}

#[test]
fn a_metadata_name_in_other_spellings() {
    for url in [
        "http://metadata.google.internal./",
        "http://METADATA.GOOGLE.INTERNAL/",
        "http://Metadata.Google.Internal:80/computeMetadata/v1/",
        "http://metadata.google.internal。/",
        "http://ｍｅｔａｄａｔａ.google.internal/",
        "http://metadata./",
        "http://METADATA/",
        "http://instance-data.ec2.internal./",
        "http://Instance-Data/",
        "http://metadata.azure.com./",
        "http://metadata.tencentyun.com/",
    ] {
        assert_eq!(rules(url, on_posix), [Rule::Metadata], "{url}");
    }
    // Not a metadata name: a name under one is an ordinary one.
    assert_eq!(
        rules("http://evil.metadata.google.internal/", on_posix),
        [Rule::LocalAddress]
    );
    assert!(on_posix("https://metadata.example.com/").is_safe());
}

#[test]
fn a_name_the_two_idna_standards_read_differently_is_judged_both_ways() {
    // `ß` is `ss` to IDNA2003 clients (Python's `idna` codec, older
    // libraries) and itself to the parser: `127.0.0.1.ßlip.io` is
    // `127.0.0.1.sslip.io`, a rebinding service, to them.
    for url in [
        "http://127.0.0.1.ßlip.io/",
        "http://ßlip.io/",
        "http://a.ßlip.io:8080/x",
        "http://me@127.0.0.1.ßlip.io/",
        "http://loca\u{3c2}lhost/",
        "http://localhos\u{3c2}.localhost/",
    ] {
        let found = rules(url, on_posix);
        assert!(found.contains(&Rule::Unreadable), "{url}: {found:?}");
    }
    for url in [
        "http://127.0.0.1.ßlip.io/",
        "http://ßlip.io/",
        "http://a.ßlip.io:8080/x",
    ] {
        assert!(rules(url, on_posix).contains(&Rule::LocalAddress), "{url}");
    }
    // The name the older reading gives is the host judged, too.
    assert_eq!(
        rules("http://169.254.169.254.ßlip.io/", on_posix),
        [Rule::LocalAddress, Rule::Unreadable]
    );
    // The differential is a finding even for an ordinary name: an accepted
    // false alarm.
    assert_eq!(rules("https://faß.de/", on_posix), [Rule::Unreadable]);
    assert_eq!(rules("https://straße.de/", on_posix), [Rule::Unreadable]);
    // The same text in a path, or as a punycode label, is no differential.
    assert!(on_posix("https://example.com/straße").is_safe());
    assert!(on_posix("https://xn--fa-hia.de/").is_safe());
}

#[test]
fn the_names_of_known_local_services() {
    all_break(
        Rule::LocalAddress,
        &[
            "http://localho.st/",
            "http://a.localho.st/",
            "http://localhost.direct/",
            "http://a.localhost.direct/",
            "http://1u.ms/",
            "http://a.1u.ms/",
            "http://7f000001.c0a80001.rbndr.us/",
            "http://rbndr.us/",
            "http://kubernetes.default.svc/",
            "http://my-service.my-namespace.svc/",
            "http://kubernetes.default.svc.cluster.local/",
            "http://svc/",
        ],
    );
    assert!(on_posix("https://svc.example.com/").is_safe());
}
