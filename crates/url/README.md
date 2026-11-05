# milo-guards-url

Reads a URL an agent is about to fetch and says whether it is safe to fetch
without asking, or risky and why. The URL guard of [milo-guards](https://github.com/camiloazula/milo-guards).

A fetch is a read-only call a caller lets run unasked, and the shell guard
never sees it. What matters about one is few and well known: the machine
itself and its neighbours, the cloud metadata services that hand out
credentials, a URL that carries a password, and a scheme that is not the
web. The classic way past such a check is a differently spelled address
(`http://2130706433/`, `http://0x7f.1/`, `http://[::ffff:127.0.0.1]/`), so
the guard judges the host a WHATWG URL parser reads, never the text: `judge`.

- **The parser decides the host.** Decimal, octal, hex and shortened IPv4,
  IPv6 with an IPv4 inside, percent-escapes, full-width digits, international
  names: all become one host before it is judged. A spelling where another
  client could read another host is `unreadable`.
- **The host is public only by a whitelist.** A public name, or an address
  in none of the special ranges. A host this cannot place is a finding, never
  safe.
- **No lookup.** A name is judged by its spelling alone; nothing here touches
  the network. A `file:` URL's path is placed against the `Paths` the caller
  passes, like any other path.

## Install

Through the front door, where it is the `url` feature (on by default):

```toml
[dependencies]
milo-guards = "0.1"
```

Or on its own:

```toml
[dependencies]
milo-guards-url = "0.1"
```

## Example

```rust
use milo_guards_url::{judge, Rule};
use milo_guards_core::Paths;

let paths = Paths::new("/work/app", "/home/me", ["/work/app"]);

assert!(judge("https://docs.rs/url", &paths).is_safe());

let assessment = judge("http://2130706433:9090/admin", &paths);
let finding = &assessment.findings()[0];
assert_eq!(finding.rule, Rule::LocalAddress);
assert_eq!(finding.reason, "fetches your own machine");
assert_eq!(finding.target.as_deref(), Some("127.0.0.1"));

// The password is never echoed.
let assessment = judge("https://me:hunter2@example.com/", &paths);
assert_eq!(assessment.findings()[0].rule, Rule::Credentials);
assert_eq!(assessment.findings()[0].target.as_deref(), Some("https://…@example.com/"));
```

## Contract

Like every milo-guards crate: no I/O and no environment reads, deterministic
(the same input gives the same answer on every machine), no policy (it
reports, and what to do with a finding is the caller's), what cannot be read
is risky, and nothing it is given makes it panic. The rules are on the
repository's [guidelines](https://github.com/camiloazula/milo-guards/blob/main/GUIDELINES.md).

## License

MIT or Apache-2.0, at your option
([LICENSE-MIT](https://github.com/camiloazula/milo-guards/blob/main/LICENSE-MIT),
[LICENSE-APACHE](https://github.com/camiloazula/milo-guards/blob/main/LICENSE-APACHE)). Part of
[milo-guards](https://github.com/camiloazula/milo-guards); the API is on
[docs.rs](https://docs.rs/milo-guards-url).
