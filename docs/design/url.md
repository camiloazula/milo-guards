# URL

`milo-guards-url` judges one fetch of an address, before it happens. An agent
fetches pages and drives a browser by URL, and a fetch is a read-only call a
caller lets run unasked. The shell guard never sees it.

```rust
judge(url, &paths) -> Assessment
```

`paths` comes from `Paths::new(cwd, home, workspaces)` and is there for a
`file:` URL, whose path is placed like any other path, and for nothing else.
The answer is `Safe`, or `Risky` with every finding: a rule, a reason a prompt
can show, and the part of the URL it is about. The guard reads the text and
never fetches anything: it does no lookup, touches neither the network nor the
file system, and reads no environment.

**The guard judges the address, never the page.** What a page says is not an
input a guard can see. Exfiltration by shell is the shell guard's; running a
downloaded script is its `run_downloaded`.

The guard only reports. What to do about a finding is the caller's choice. The
types are core's; see [Core](core.md).

## How it works

1. **Read** the URL with the WHATWG parser (the `url` crate). The host the
   parser reads is the host judged, whatever the text looked like.
2. **Judge** the scheme, the user-info and the host.
3. **Check the spelling** of an `http` or `https` URL, for a form that
   another client could read differently.

The URL is trimmed of white space at both ends, since that changes no host. It
is `unreadable` when it is empty, longer than 8 192 bytes, holds a control
character (a tab or a newline inside it too: the parser drops them and a
client that does not would read another URL), or does not parse.

## Rules

| Rule | Wire name | A fetch that |
| --- | --- | --- |
| `LocalAddress` | `local_address` | goes to a host that is not public |
| `Metadata` | `metadata` | goes to a cloud metadata service |
| `Credentials` | `credentials` | carries a user name or password in the URL |
| `LocalFile` | `local_file` | is a `file:` URL |
| `Scheme` | `scheme` | uses a scheme other than `http`, `https` and `file` |
| `Unreadable` | `unreadable` | cannot be read, or can be read as two hosts |

A wire name never changes once a caller uses it. `Rule` is exhaustive, with
`Rule::ALL`. A finding's reason and target:

| Rule | Reason | Target |
| --- | --- | --- |
| `local_address` | `fetches your own machine`, `fetches a machine on your own network`, `fetches an address that is not on the public internet`, `fetches a name that is not on the public internet` or `fetches a name that can point at your own network` | the host as the parser reads it: `http://2130706433/` names `127.0.0.1` |
| `metadata` | `fetches the cloud metadata service (AWS), which hands out credentials` | the host |
| `credentials` | `sends a user name or a password in the URL` | the URL with the user-info replaced by `…`, built from what the parser read, so no spelling of the password is left |
| `local_file` | `reads {where the path lands}`: `reads your SSH keys`, `reads a path inside the workspace` | the path, with escapes undone |
| `scheme` | `uses the ftp scheme, which is not a web page` | the scheme |
| `unreadable` | what is wrong: `is empty`, `holds a control character`, `cannot be read as a URL` | none: what cannot be read may hold a password |

A URL can have several findings, in the order it reads: the scheme, the
user-info, the host (the path for a `file:` URL), then a spelling problem.
The host of any URL that has one is judged, whatever its scheme.

## What is safe

A public host over `http` or `https`, whatever the port, path or query, and
however the address is spelled when it comes out public: `https://example.com/`,
`https://docs.rs/url`, `http://93.184.216.34/`, `https://例え.jp/`,
`https://example.com:8443/api?x=1`. A raw public IP literal is safe. A punycode
or international name is safe unless it decodes to a name the rules below know.

## The host

**A host is public only by a whitelist.** A host the guard cannot place is a
finding, never safe.

### Spellings

The parser reads every spelling of an address into one host, and the guard
judges that host: decimal (`2130706433`), octal (`0177.0.0.1`), hex
(`0x7f.1`), shortened (`127.1`), mixed, with leading zeros, with a trailing dot,
percent-escaped (`%31%32%37.0.0.1`), in full-width digits or with the
ideographic full stop (`127。0。0。1`), and IPv6 with an IPv4 inside. For a name,
case is folded, a trailing dot is dropped, full-width letters are mapped to plain
ones and a soft hyphen is removed before it is judged (`ｌｏｃａｌｈｏｓｔ` is
`localhost`), and an international name is its `xn--` form. A zero-width
joiner (U+200C, U+200D) makes the URL unreadable; see [Spelling](#spelling). A
zone id (`[fe80::1%25en0]`) is not a URL to the parser, so it is unreadable.

### Addresses

IPv4 is public unless it is in one of the special ranges. Which are
`local_address`, and the words:

| Range | Is | Reason says |
| --- | --- | --- |
| `127.0.0.0/8`, `0.0.0.0`, `::1`, `::` | this machine | your own machine |
| `10/8`, `172.16/12`, `192.168/16`, `169.254/16`, `100.64/10`, `fc00::/7`, `fe80::/10`, `fec0::/10` | a neighbour: private, link-local, the carriers' shared space (which VPN overlays use too), unique-local, the retired site-local | a machine on your own network |
| rest of `0.0.0.0/8`, `192.0.0.0/24`, `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `192.88.99.0/24`, `198.18.0.0/15`, `224.0.0.0/4`, `240.0.0.0/4` (broadcast included) | a range no public host has: protocol assignments, documentation, benchmarking, multicast, reserved | an address that is not on the public internet |
| IPv6 outside `2000::/3`, and inside it `2001::/23` (Teredo among it), `2001:db8::/32`, `3fff::/20`, `3ffe::/16`; multicast `ff00::/8` | the same | an address that is not on the public internet |

Documentation, benchmarking and reserved ranges are a finding although no
public host is there: on a local network a device can be (benchmarking is also
what some VPN clients answer a name with), and "safe because nothing is
there" is not a thing a guard can know.

An IPv4 address carried inside an IPv6 one is judged by the IPv4 address
inside it: mapped (`::ffff:127.0.0.1`), compatible (`::127.0.0.1`), NAT64's
well-known prefix (`64:ff9b::/96`) and 6to4 (`2002::/16`). A public one inside
is public. Teredo is judged not public whatever it carries.

### Names

A name is judged by its spelling alone, after the parser has lowercased it and
turned it into ASCII.

- `localhost` and every name under it are this machine.
- **A name with no dot is a name on a local network** (`http://box/`,
  `http://intranet/`), decided as `local_address` and not safe: every public
  host has at least a name under a top-level one.
- A name ending in `.local`, `.internal`, `.home.arpa`, `.lan`, `.localdomain`,
  `.intranet`, `.svc` (a Kubernetes service), `.corp`, `.home`, `.private`, `.test` or
  `.example` is a name only a local network answers. (`.test` and `.example` are reserved for tests,
  and local development servers answer for them.)
- A name under a **rebinding service** answers with the address written in it,
  or with loopback, so the name says nothing about where the request goes:
  `nip.io`, `sslip.io`, `xip.io`, `traefik.me`, `localtest.me`, `lvh.me`,
  `vcap.me`, `lacolhost.com`, `local.gd`, `localdev.me`, `fuf.me`, `localho.st`,
  `localhost.direct`, `1u.ms`, `rbndr.us`. A name under
  one is `local_address`, whole: reading the embedded address out of the name
  would be a second parser to get wrong, and nothing a fetch is for needs it.
- Otherwise the name is public only when its last label is two to 63 letters, or
  an `xn--` label. `example.c0m` and `foo.bar-baz` are findings.

A name the parser lets through that no resolver reads one way is `unreadable`:
an empty label, one over 63 bytes, a name over 253, a character that is not a
letter, digit or hyphen (`exa_mple.com`, `exa!mple.com`).

### Metadata

A metadata service hands out the machine's credentials to anything on the
machine that asks, so it is its own rule and wins over `local_address`: the
reason says what it is. One table in the crate (`tables.rs`) lists them, with the
provider beside each row, and a test walks it:

| Where | Provider |
| --- | --- |
| `169.254.169.254` | AWS, Google Cloud, Azure, DigitalOcean and OpenStack |
| `169.254.170.2` | AWS ECS task credentials |
| `100.100.100.200` | Alibaba Cloud |
| `192.0.0.192` | Oracle Cloud |
| `168.63.129.16` | Azure host |
| `fd00:ec2::254` | AWS |
| `metadata.google.internal`, `metadata` | Google Cloud |
| `instance-data`, `instance-data.ec2.internal` | AWS |
| `metadata.azure.com` | Azure |
| `metadata.tencentyun.com` | Tencent Cloud |
| `metadata.platformequinix.com` | Equinix Metal |

The IPv4 inside an IPv6 address is looked up too: `[::ffff:169.254.169.254]`,
`[64:ff9b::a9fe:a9fe]` and `[2002:a9fe:a9fe::]` are `metadata`.

## Credentials

A user name or a password in the URL (`https://user:pass@host/`) is a finding,
and the URL is judged by its host as well: `http://example.com@127.0.0.1/` is
`credentials` and `local_address`. The target is the URL with the user-info
replaced by `…`, never the password.

## `file:` URLs

A `file:` URL is always a finding, since a page fetch is not how a file is
meant to be read. Its path is percent-decoded and placed through core's
resolver like any path, so `file:///home/me/.ssh/id_rsa` `reads your SSH keys`
and `file:///home/me/work/repo/x.rs` `reads a path inside the workspace`. The
place only sharpens the words: the path of a caller's protected file reads in
the caller's words, and one the resolver cannot place reads `a path only known
when it runs`. A Windows machine (the home directory has a drive) reads
`/C:/Users` as `C:/Users`. A `file:` URL with a host names a file on another
machine, which a Windows client reaches over the network: `reads a file from
another machine`, and the host is judged too.

## Spelling

For an `http` or `https` URL the guard also reads how the host is spelled, only
to find a form where two clients could read two hosts. Such a URL is
`unreadable`, in addition to what the host gives:

- a backslash that ends the authority (`http://example.com\@127.0.0.1/`: the
  parser's host is `example.com` and a client that follows the RFC's is
  `127.0.0.1`), or `http:\\host`;
- no `//` right before the host (`http:/host`, `http:host`, `http:///host`);
- a percent sign in the host;
- a name with a character the two IDNA standards read differently: `ß` is
  `ss` to an IDNA2003 client (Python's `idna` codec, older libraries) and
  itself to the parser, so `127.0.0.1.ßlip.io` is `127.0.0.1.sslip.io` to one
  and `xn--lip-4ka.io` to the other. `ß`, `ς` and the joiners U+200C and U+200D
  are read the older way as well (`ss`, `σ`, dropped), that name is judged
  too, and the URL is `unreadable` whatever it says;
- an IPv4 address spelled any way but four plain decimal numbers with no leading
  zero. `010.0.0.1` is `8.0.0.1` to the parser and `10.0.0.1` to a client that
  reads every number as decimal; `0x7f.1` and `2130706433` are one address,
  `127.0.0.1`, which clients also read differently. A local address spelled so
  has `local_address` as well.

## Dependency

The guard's own parser is the [`url`](https://crates.io/crates/url) crate (MIT
or Apache-2.0) and its tree, which holds the WHATWG host rules, the
international-name tables (`idna`, UTS 46) and `percent-encoding`. A parser
written here is where the bypasses live: full-width and mapped characters need
the Unicode tables. The tree brings the ICU crates, whose licence is
`Unicode-3.0`; it is permissive and OSI-approved, and `deny.toml` allows it
with the reason beside it. Everything is from crates.io, and `just deny` is
green. The guard's source never names `std::net`: it reads the parser's host
through its octets and groups.

## Known limits

- **No lookup.** A public name whose own DNS points at a private address, or
  at a metadata service, is safe: telling it needs the network. A caller that
  must stop it checks the address it connects to.
- **The address is the guard's, not the connection's.** A redirect, a
  proxy or a page that fetches another is the caller's business.
- **The list of names is what is known.** The local endings and the rebinding
  services are lists, and a new service is a new row.
- **Accepted false alarms**, each a finding where a public name was meant: a
  public name that ends in a local ending (`.corp`, `.home`, `.test`), a name
  from a rebinding service whatever it embeds, an underscore in a host name, a
  public IPv4 address spelled in hex, octal, decimal, with a trailing dot or
  with a leading zero, a percent-encoded host, an address in a documentation
  range, a name with `ß`, `ς` or a joiner (`https://faß.de/`, which is
  `unreadable` for the differential alone), a URL with no scheme (`example.com`)
  or longer than 8 192 bytes.
- **An odd but public IPv6** (a compatible address with a public IPv4 inside,
  `::1.2.3.4`) is safe, as a client reaches nothing local by it.
- Ports are not judged: `http://example.com:22/` is safe.

## Tests

The cases are in case files, one URL and its answer to a line
([CONTRIBUTING.md](../../CONTRIBUTING.md#case-files)), each checked by the
test file of its name: `tests/cases/urls.cases` has what is safe, what is
risky and under which rule, the reasons and the targets (and `tests/urls.rs`
holds every answer of it to never show a password); `spellings.cases` is
every spelling a reviewer tried, each a permanent case; `file.cases` is the
`file:` URLs. Every case is also held to carry no target on a finding that
the URL is unreadable. `tests/cases.rs` tests the runner. `tests/names.rs`
checks the wire names and `Rule::ALL`, and `tests/robust.rs` feeds noise and
very long URLs and checks that nothing panics, an unreadable URL is never
safe and carries no copy of itself, and a password is never shown.
