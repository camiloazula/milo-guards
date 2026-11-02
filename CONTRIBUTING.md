# Contributing to milo-local-guards

Thanks for your interest in contributing. This page is how to build, test and
submit a change. How the code is organised, and the rules it follows, are in
[GUIDELINES.md](GUIDELINES.md).

## Building

Requires [`just`](https://github.com/casey/just) and rustup; plain `just`
lists the recipes.

One Rust builds everything: `rust-toolchain.toml` pins it (rustup installs it,
with clippy, rustfmt and `llvm-tools-preview`, the first time `cargo` runs
here), so every contributor gets the same clippy verdicts. It is also the
minimum supported version (`rust-version` in `Cargo.toml`) and the version CI
runs (`RUSTUP_TOOLCHAIN` and each Rust install step's `toolchain:` input in
`.github/workflows/ci.yml`); a test fails when they differ. Bump them
together, to the newest stable. Edition 2021.

Run commands with the pinned toolchain: `cargo --version` in the repo should
print the version in `rust-toolchain.toml`. A Homebrew-installed Rust earlier on
`PATH` ignores that pin, uses its own clippy, and has no `llvm-tools-preview`.
Put `~/.cargo/bin` before Homebrew on `PATH`, or remove the Homebrew Rust.

## The gates

`just verify` is the gate: the only check that decides whether a change can
merge. Run it locally, and paste its result in the pull request. Never push
while it fails. It runs, in order, over the whole workspace:

| Recipe | What it checks |
|---|---|
| `just format-check` | `cargo fmt --all --check` |
| `just lint` | clippy, `--all-targets --all-features`, zero warnings (`cargo lint` runs the same) |
| `just coverage` | every unit and integration test, `--all-features --locked`, run once in an instrumented build, and line coverage against the floor in the `justfile` (`--fail-under-lines`); raise it as coverage lands, never lower it to pass |
| `just timing` | every test, in an optimized build (`cargo test --release --workspace --all-features --locked`): the tests that time the guard compare against limits that describe an optimized build, so they are ignored under coverage (`cfg(coverage)`) and run here |
| `just doc-test` | every doctest, README example included (`cargo test --doc --workspace --all-features --locked`), which coverage does not run |
| `just doc` | rustdoc on the workspace with warnings denied, so a broken intra-doc link fails (`--all-features --no-deps --locked`) |
| `just no-inline` | the shell guard without its `inline` feature (no readers of Python and JavaScript, no grammars): clippy on all its targets with zero warnings, and `tests/inline_off.rs`, which holds every inline line to `unknown`; `--all-features` never builds it that way |
| `just deny` | the dependency gates in `deny.toml`: permissive licences only, crates.io only, no banned crates (`cargo deny check bans licenses sources`) |

The code is compiled by clippy's check pass, by the one instrumented build
every unit and integration test but the timing tests runs from, and by one
optimized build that runs every test; the doctests and rustdoc build what they
need on top, and the shell guard is built once more without its `inline`
feature (`just no-inline`). `just test` runs every test, doctests included,
without coverage, quicker while working.

`just advisories` is not part of `just verify`. It checks the RustSec database
(`cargo deny check advisories`), which needs the network and changes without a
commit, so CI runs it as its own job and a failure there is not a code
failure. Run it when you add or update a dependency.

Clippy reads `rust-version` and its `incompatible_msrv` lint fails on an API
newer than it, so no gate needs a second compiler.

This is a library and ships no binary, so there is no notices file here. The
third-party notices travel with the binaries of the programs that use it.

`just verify` needs two tools beyond Rust, and `just advisories` needs the
second. Install them once:

```sh
cargo install cargo-llvm-cov   # for just coverage
cargo install cargo-deny       # for just deny and just advisories
```

## Submitting a change

- `main` takes pull requests only. The commits that set the repository up are
  the one exception.
- Commit messages describe the change and why. No tool trailers (no
  `Co-Authored-By` or "Generated with" lines) on commits or pull request
  descriptions.
- A new rule comes with table tests of safe and risky lines
  ([GUIDELINES.md](GUIDELINES.md)), and a rule's wire name never changes once
  a caller uses it.
- A test goes in the file named by what it checks, never in one named after
  a ticket or a review; a fix adds rows to that file
  ([GUIDELINES.md](GUIDELINES.md#tests)). A test of a source file's own
  helpers goes in that file's `#[cfg(test)] mod tests`; a test of what a crate
  does and of its edge cases in `crates/<crate>/tests/<what-it-checks>.rs`,
  with shared helpers in `tests/common`; a test of the front door from end to
  end in `crates/guards/tests`.
- Nothing is released yet, and the repository is private. Callers depend on a
  git commit.

## How a change reaches a caller

A caller depends on `milo-local-guards` by git at a fixed `rev`, and its own
policy decides what to do with each rule. So a change here reaches a caller by
a pull request in that caller that bumps the `rev`, after the change has merged
to `main` here. A new rule is new to the caller too: it decides what to do with
it in that same pull request.

To work on a caller and a guard at once, point the caller at a checkout of this
repository without editing its `Cargo.toml`. From the caller's checkout, with
this one beside it:

```sh
cargo test --config 'patch."https://github.com/camiloazula/milo-local-guards".milo-local-guards.path="../milo-local-guards/crates/guards"'
```

The same `--config` works with `cargo build` and `cargo clippy`. It lasts one
command and changes no file. Run the caller's own checks without it before its
pull request, so it is tested against the commit it will depend on.

## Reporting issues

Use GitHub issues for bugs and feature requests. For security vulnerabilities,
including a line a guard judges safe that should not be, follow
[SECURITY.md](SECURITY.md) instead of opening a public issue.

## License

By contributing, you agree that your contributions are dual licensed under the
MIT license and the Apache License, Version 2.0, as described in
[README.md](README.md), unless you explicitly state otherwise.
