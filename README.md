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

More guards will sit beside it.

## Use

Depend on `milo-local-guards` by git. The `shell` feature is on by default.

```toml
[dependencies]
milo-local-guards = { git = "https://github.com/camiloazula/milo-local-guards", rev = "<commit>" }
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
