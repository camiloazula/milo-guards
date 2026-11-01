# milo-local-guards

Guards for AI agents working on your own machine. Each guard reads what an
agent is about to do and says whether it is safe to do without asking, or
risky and why.

This repository is private and nothing is released yet.

## Local

The guards are built for small local models, so they ask nothing of the
network or of a model. They run offline, give the same answer for the same
input, and make no model calls. A guard is a plain function: you hand it what
the agent wants to do and the places it is allowed to work in, and you get a
verdict back in microseconds.

## The guards

- **shell** judges a shell line: POSIX shells, PowerShell and cmd. It parses the
  line and judges the programs, flags, operands and redirects, never the raw
  text. `rm -rf ~` is risky ("deletes your home directory"); `ls src` is safe.
  Beside that verdict, `effect` says whether a line only reads, changes
  something or cannot be told: `git status` only reads, `mkdir build` is safe
  and changes the disk, `./script.sh` cannot be told.
- **file** judges one read or write of a path through a file API, which no shell
  line shows. It resolves the path by its spelling alone (`~`, `..`, Windows
  drives, shares, long paths, short names, any case): a read of
  `~/.ssh/id_ed25519` is risky ("reads your SSH keys"), a read of `src/main.rs`
  is safe, a write beyond the workspace or to a startup file or the
  repository's history is risky, and a path that is not one literal path (a
  wildcard, a variable) is unreadable.
- **url** judges a URL an agent is about to fetch, by the host a URL parser reads
  and never by how it is spelled. `http://2130706433/` is `127.0.0.1`, so it is
  risky ("fetches your own machine"), like `http://192.168.1.1/` and
  `http://169.254.169.254/` (a cloud metadata service); a URL with a password
  in it (shown without the password), a `file:` URL and a scheme that is not the
  web are risky too. `https://docs.rs/url` is safe.
- **secrets** reads a text for what it must not carry: private keys, the keys and
  tokens of cloud and API providers, JWTs, `Basic` and `Bearer` credentials,
  passwords in connection strings and URLs, passwords written as `name=value`,
  card numbers, id numbers, emails, phone numbers and public IP addresses. A
  finding never holds the secret (`AKIA… (20 chars)`), and `find_spans` gives
  the byte ranges so a caller can scrub them. It is not in the default
  features. A commit SHA, a UUID and a lockfile hash are safe; a
  `postgres://app:fakePass0word1@db/app` string is risky.

More guards will sit beside them.

## Use

Depend on `milo-local-guards` by git. The `shell`, `file` and `url` features are on by
default; `secrets` is opt in, because most callers want the others and not a table of
patterns in their binary.

```toml
[dependencies]
milo-local-guards = { git = "https://github.com/camiloazula/milo-local-guards", rev = "<commit>" }
# With the secrets guard as well:
# milo-local-guards = { git = "…", rev = "<commit>", features = ["secrets"] }
```

```rust
use milo_local_guards::shell::{classify, Shell};
use milo_local_guards::Paths;

// Where the agent is: its working directory, your home, its workspace folders.
let paths = Paths::new("/work/app", "/home/me", ["/work/app"]);

assert!(classify("ls src", Shell::Posix, &paths).is_safe());

let assessment = classify("rm -rf ~", Shell::Posix, &paths);
assert!(!assessment.is_safe());
for finding in assessment.findings() {
    // Ask, refuse or let it through: that is your call.
    println!("{}: {}", finding.rule.name(), finding.reason); // delete: deletes your home directory
}

// The same places judge a read or a write of one path through a file API.
use milo_local_guards::file::{judge, Access};

assert!(judge(Access::Write, "src/main.rs", &paths).is_safe());

for finding in judge(Access::Read, "~/.ssh/id_ed25519", &paths).findings() {
    println!("{}: {}", finding.rule.name(), finding.reason); // read_secret: reads your SSH keys
}
```

What to do with a risky finding is the caller's choice. A guard only reports.

## The contract

Every guard keeps these promises. This is what enforces each, and where:

- **No I/O and no environment reads**: `crates/guards/tests/contract.rs`
  scans every crate's source, and its `build.rs` if it has one, for the file
  system, environment, process, network, thread, clock, terminal and OS APIs
  and for the print macros. Clippy refuses the same calls, and the include and
  environment macros too, through the `disallowed-*` lists in `clippy.toml`.
- **A guard depends on `core` and its own parsers only**, never on another
  guard: `contract.rs` reads every `Cargo.toml`.
- **Never panics**: each guard's `tests/robust.rs` feeds it random lines, and
  clippy warns on `unwrap`, `expect` and `panic!` outside tests.
- **What cannot be read is risky**: each guard's `tests/robust.rs` checks that
  a line too long or too deeply nested comes back risky as unreadable. The
  other cases are covered by the guard's own tables of risky lines.
- **Deterministic** and **no policy** have no test of their own. No clock, no
  environment and no I/O make a guard deterministic, and the first rule is
  checked. A guard's API only reports findings: policy stays with the caller.

How the crates fit together is in [docs/design/architecture.md](docs/design/architecture.md).
The rules for changing them are in [GUIDELINES.md](GUIDELINES.md), and how to
build, test and submit a change is in [CONTRIBUTING.md](CONTRIBUTING.md).

## Licence

Copyright (c) 2026 Camilo Azula. Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE)), or
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. Unless you explicitly state otherwise, any contribution
intentionally submitted for inclusion in the work by you, as defined in the
Apache-2.0 license, shall be dual licensed as above, without any additional
terms or conditions.
