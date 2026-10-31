# AGENTS.md

## Architecture in seven lines

1. `milo-local-guards` is a set of guards for AI agents on your own machine: a Rust Cargo workspace in `crates/`. Each guard reads what an agent is about to do and says it is safe, or risky and why.
2. `core` (`milo-guards-core`) is what every guard shares: the `Paths` a command is judged against (cwd, home, workspace folders), the verdict types (`Assessment`, `Finding`, the `RuleName` trait with stable wire names), the path model (where a path lands), and a test kit behind the `testing` feature.
3. `shell` (`milo-guards-shell`) is the shell guard, `classify(line, Shell, &Paths)`: it parses POSIX shell, PowerShell and cmd with tree-sitter and judges programs, flags, operands and redirects, never the raw text.
4. `guards` (`milo-local-guards`) is the one crate a caller depends on; it re-exports each guard behind a feature (`shell`, on by default).
5. Every guard keeps the contract: no I/O and no environment reads, deterministic, no policy, what cannot be read is risky, never panics. Enforced, and where: no I/O and no environment reads by `crates/guards/tests/contract.rs` (a scan of each crate's source and `build.rs`) and the `disallowed-*` lists in `clippy.toml`; never panics, and a line too long or too deep comes back risky, by each guard's `tests/robust.rs`. Deterministic and no policy have no test of their own: they follow from no I/O and from an API that only reports.
6. A guard depends on `core` and its own parsers only, never on another guard (`contract.rs` reads every `Cargo.toml`, including renamed and path dependencies); policy (what to do with a risky finding) is the caller's.
7. tree-sitter is held at 0.26 because callers that also link tree-sitter hold it there, and its `links` key allows one version per lockfile; `just verify` is the one gate, with the one Rust `rust-toolchain.toml` pins.

## Before you change code

- Read `GUIDELINES.md`: the rules, each with a link to its detail in `docs/design/`. Its rules win on any conflict.
- Read `CONTRIBUTING.md` before you run the gates or open a pull request: how to build, test and submit, and the only place the gates are described.
