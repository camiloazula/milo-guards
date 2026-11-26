# Run `just <target>`. Install just with `brew install just` on macOS,
# `winget install --id Casey.Just --exact` on Windows, or `cargo install just`
# anywhere. On Windows its recipes need `sh` on PATH (CONTRIBUTING.md).
#
# Every recipe that builds builds the whole workspace with the Rust in
# rust-toolchain.toml, but `oldest-rust`, which builds it with the one below.
# This is a library and ships no binary, so there are no notices recipes: a
# binary's third-party notices travel with the binary, in the programs that
# use these crates.

# The oldest Rust the crates support: `rust-version` in Cargo.toml, which
# names it, and `crates/guards/tests/toolchain.rs` keeps this the same.
oldest_rust := "1.90"

# Plain `just` lists the available recipes.
_default:
    @just --list --unsorted

# The gate, and the only one (CONTRIBUTING.md). It compiles three times:
# clippy's check pass, one instrumented build of every test, which runs them
# and measures coverage, and one optimized build of the timing tests, which
# runs them alone. CI runs every recipe but `timing` in its `verify` job and
# `timing` in a job of its own, both required checks, both on Linux, and
# `test` on Windows and macOS in its `test` job. Advisories are not part of
# it: they change without a commit, so they are their own recipe and their
# own CI job.
# Nor is `oldest-rust`, which needs a second Rust: CI runs it in a job of
# its own. Nor is `semver`, which needs the network as advisories do and
# has a job of its own, nor `mutants`, which is run by hand.
# Every check: format, clippy, tests with coverage, timing tests, doctests, rustdoc, the shell guard without its inline reader, dependencies.
verify: format-check lint coverage timing doc-test doc no-inline deny

# The `cargo lint` alias in .cargo/config.toml runs the same.
# Clippy on the whole workspace, warnings denied.
lint:
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

# Fail if anything isn't rustfmt-clean.
format-check:
    cargo fmt --all --check

# Apply rustfmt in place.
format:
    cargo fmt --all

# Every crate packaged as crates.io will see it, and built from its package:
# a manifest field a registry needs, a file the package lacks, or a path the
# package resolves differently fails here, before a release.
package:
    cargo package --workspace --locked

# Publish every crate to crates.io, in dependency order, at the version in
# Cargo.toml. The release workflow runs it on a release tag with a token
# crates.io hands that job, and with `--no-verify`, since `just package`
# built every crate from its package in the job before; by hand it needs
# `cargo login`.
publish *flags:
    cargo publish --workspace --locked {{flags}}

# `just verify` runs them again in its one instrumented build, apart from
# the doctests, which `just doc-test` runs, and the timing tests, which
# `just timing` runs: a debug build ignores them, so no test here reads the
# clock. `--locked`: fail if Cargo.lock would need updating. CI's `test` job
# runs it on Windows and macOS: just runs this line with `sh` there too
# (Git for Windows has one), and it is a plain `cargo` command line, so it
# reads the same to any shell.
# Every test but the timing ones, without coverage: quicker while working.
test:
    cargo test --workspace --all-features --locked

# The everyday answers (CONTRIBUTING.md): the commands that
# `crates/guards/tests/cases/everyday_answers.templates` makes, judged by the
# shell guard, against the record of their answers beside it,
# `everyday_answers.cases`. It fails when an answer differs from the record.
# `just verify` runs the same test (in `coverage`), and shows the report only
# when it fails.
# The share of everyday commands the shell guard asks about, and every answer that differs from the record.
everyday:
    cargo test -p milo-guards --all-features --locked --test everyday_answers -- --exact everyday_answers_are_as_recorded --nocapture

# On purpose only, and committed with the change that moved the answers: a
# release's changelog says what the diff of the record shows. It prints the
# report of what moved, then writes the record. The variable is what lets
# it write: `cargo test -- --ignored` runs the same test, which then only
# prints the report.
# Rewrite the record of the everyday answers with the answers the guard gives today.
everyday-record:
    MILO_EVERYDAY_RECORD=1 cargo test -p milo-guards --all-features --locked --test everyday_answers -- --ignored --exact record --nocapture

# Not part of `verify`, which needs only the Rust in rust-toolchain.toml:
# this needs the oldest supported one too (`rustup toolchain install` it,
# CONTRIBUTING.md). CI runs it in its `oldest-rust` job, on Linux, and a
# release runs it by hand. Clippy's `incompatible_msrv` finds a library API
# newer than `rust-version`, but not a language feature, nor a dependency
# that asks for a newer Rust: a build with that Rust does. The builds are
# what a caller compiles: default features, with no `testing` (which only
# the dev-dependencies turn on), and the shell guard without `inline`. The
# tests are `just test`'s, with every feature, and `no-inline`'s test.
# `--locked`: with Cargo.lock as it is, whose versions bound how old a Rust
# can be.
# What a caller builds, and every test but the timing ones, with the oldest supported Rust.
oldest-rust:
    cargo +{{oldest_rust}} build --workspace --locked
    cargo +{{oldest_rust}} build -p milo-guards-shell --no-default-features --locked
    cargo +{{oldest_rust}} test --workspace --all-features --locked
    cargo +{{oldest_rust}} test -p milo-guards-shell --no-default-features --test inline_off --locked

# Raise the floor as coverage lands, never lower it to pass. A failing test
# fails it too. Only the last run's coverage data is removed, not the build
# (`--no-clean`): cargo rebuilds what changed, so a run after a small change
# does not compile the whole workspace again. cargo-llvm-cov does not run
# doctests, so `doc-test` does.
# Every test, run once in an instrumented build, with the line-coverage floor.
coverage:
    cargo llvm-cov clean --profraw-only
    cargo llvm-cov --no-clean --workspace --all-features --locked --fail-under-lines 90

# Every test that reads the clock is in a crate's `tests/timing.rs`, and only
# there. They compare against limits that describe an optimized build, and the
# instrumented build of `coverage` and the debug build of `test` are several
# times slower, so they are ignored there
# (`cfg(any(coverage, debug_assertions))`) and run here, alone: no other test
# binary runs beside them. `--show-output` prints what each test that passes
# printed: every timed row's share of its bound, for the timing job's log.
# The stack tests (`tests/stack.rs`) read no clock and run in every build,
# each on a thread whose stack fits the build; here they run again in the
# build a caller runs, on a thread of 1 MiB.
# The timing tests, and the stack tests, in an optimized build.
timing:
    cargo test --release --locked --all-features -p milo-guards-shell --test timing -- --show-output
    cargo test --release --locked --all-features -p milo-guards-secrets --test timing -- --show-output
    cargo test --release --locked --all-features -p milo-guards-code -p milo-guards-script -p milo-guards-shell --test stack

# The examples in the documentation and the README, compiled and run.
# Every doctest.
doc-test:
    cargo test --doc --workspace --all-features --locked

# A broken link or a bare URL in the documentation fails the build.
# rustdoc on the whole workspace, warnings denied.
doc:
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked

# `--all-features` never builds the shell guard without its `inline` feature,
# which pulls in the readers of Python and JavaScript and their grammars. Off,
# every inline line is `unknown` and the guard must still build and lint clean;
# `tests/inline_off.rs` is the one test target that is only compiled there (the
# others test the reader).
# The shell guard without its inline reader: lint clean, and every inline line unknown.
no-inline:
    cargo clippy -p milo-guards-shell --no-default-features --all-targets --locked -- -D warnings
    cargo test -p milo-guards-shell --no-default-features --test inline_off --locked

# Metadata only, no build. The fuzz tool's lockfile is read too: its
# harness (`libfuzzer-sys` and what it builds on) is in no build of the
# workspace, and every other package of it is the workspace's
# (`crates/guards/tests/contract.rs`).
# Dependency gates (deny.toml): bans, licences and sources, of the workspace and the fuzz tool.
deny:
    cargo deny check bans licenses sources
    cargo deny --manifest-path tools/fuzz/Cargo.toml check bans licenses sources

# Needs the network (the RustSec database), and the answer changes without a
# commit, so `just verify` does not run it; CI runs it as its own job.
# Dependency advisories (deny.toml): RustSec and yanked crates, of the workspace and the fuzz tool.
advisories:
    cargo deny check advisories
    cargo deny --manifest-path tools/fuzz/Cargo.toml check advisories

# Whether a change since the last release breaks a caller's build: empty
# while none does, and `minor` from the pull request whose change does (it
# says so in CHANGELOG.md's Unreleased section) to the release, whose
# commit empties it again, since its version then says the bump
# (CONTRIBUTING.md, Releasing). It is not the bump the next release makes:
# an addition makes it a minor one too, and leaves this empty.
# `crates/guards/tests/ci_jobs.rs` holds it to one of the two, and empty
# when the Unreleased section is. That check is one-sided, and accepted so:
# `minor` set beside entries that break nothing passes it, and keeps the
# semver job green for the rest of the cycle.
next_bump := ""

# Needs the network (crates.io), so `just verify` does not run it; CI runs
# it as its own job, advisory, and a release runs it by hand after its
# version bump, where it must pass (release.yml does not run it). About two
# minutes from a cold build. cargo-semver-checks builds the rustdoc JSON of
# each crate here and of its last release on crates.io, and fails on a
# change that breaks a caller's build (an item removed or renamed, a
# signature changed, a variant added to an exhaustive enum, which a new
# rule is) that the bump does not allow. At `0.x` it calls 0.1 to 0.2 a
# major release, as Cargo does: `next_bump` set to `minor` is its
# `--release-type major`, and empty, the bump is read from the versions,
# the last release's to Cargo.toml's (none between releases: a compatible
# 0.1.x). What breaks no build passes here (an addition, a raise of
# `rust-version`, a rule's wire name, what a guard answers) and is judged by
# hand (CONTRIBUTING.md, The gates). A crate not yet on crates.io has no
# release to be compared with: it is left out with `--exclude` until the
# release that publishes it, and the pull request after that release
# removes the `--exclude`. Every crate is on crates.io today.
# The public API against the last release on crates.io: nothing breaks a caller's build unless `next_bump` allows it.
semver:
    cargo semver-checks --workspace {{ if next_bump == "minor" { "--release-type major" } else { "" } }}

# How many mutants `just mutants` builds and tests at once: `just jobs=2
# mutants <crate>`, or `--jobs N` among its flags, which then wins.
jobs := "4"

# Not part of `verify`, nor of CI: a run builds the crate once for each
# mutant and runs all its tests. The budget: the URL guard's 183 mutants
# take about two minutes at four jobs here, and three to four at two or
# three jobs on a machine busy with other builds; the file guard
# has 57, the script guard 341, the secrets guard about 900, core and the
# code reader 1,100 and 1,900, and the shell guard 18,000, each running its
# whole suite, which is many hours: run it on what changed (`--file`,
# `--in-diff`). So it is run by hand, one crate at a time, before a release
# and when a guard's rules change (CONTRIBUTING.md, The gates). A missed
# mutant becomes a case line, a written reason in `.cargo/mutants.toml`
# (which holds the settings too), or a private report (SECURITY.md).
# `crate` is a package of the workspace (`_member`): cargo-mutants itself
# takes a name it does not find, tests nothing and passes. `flags` go to
# cargo-mutants as they are (`--output DIR`, `--file crates/url/src/host.rs`,
# `--in-diff changes.diff`).
# Mutation testing of one crate (`just mutants milo-guards-url`): the changes to its code that no test of it fails on.
mutants crate *flags: (_member crate)
    cargo mutants --package {{crate}} {{ if flags =~ '(^|\s)(-j|--jobs)' { "" } else { "--jobs " + jobs } }} {{flags}}

# Fails unless `crate` is the name of a package of the workspace: the
# `name` of `crates/<folder>/Cargo.toml`, where the folder is the name
# without `milo-guards-`, and `guards` for `milo-guards`.
_member crate:
    @{{ if path_exists(join(justfile_directory(), "crates", if crate == "milo-guards" { "guards" } else { trim_start_match(crate, "milo-guards-") }, "Cargo.toml")) != "true" { error("`" + crate + "` is not a package of the workspace") } else if read(join(justfile_directory(), "crates", if crate == "milo-guards" { "guards" } else { trim_start_match(crate, "milo-guards-") }, "Cargo.toml")) !~ ('(?m)^name = "' + crate + '"$') { error("`" + crate + "` is not a package of the workspace") } else { "true" } }}

# On macOS, where `just grammars` runs: the tool's tests and the tool itself
# run under `sandbox-exec`, through cargo's runner, with the profile the tool
# prints (`--sandbox-profile`): no network, no read under /Users but of this
# checkout, no write but to the temporary folder and /dev. Elsewhere there is
# no sandbox: only the layers of the tool's rooms (CONTRIBUTING.md).
grammars_sandbox := if os() == "macos" { "--config \"target.'cfg(target_os = \\\"macos\\\")'.runner=['/usr/bin/sandbox-exec','-f','" + justfile_directory() + "/target/grammar-check/sandbox.sb']\"" } else { "" }
grammars_sandboxed := if os() == "macos" { "1" } else { "" }

# The tool in `tools/grammar-check`, a package of its own the workspace
# excludes: formatted, linted and tested first, its tests the canaries that
# show no line runs, then run, with `flags` (`--private`, `--with pwsh`,
# `--require bash`, `--entries`). It starts bash, only parsing, and
# PowerShell only with `--with pwsh`, and its answer depends on which are
# installed and at what version, so `just verify` does not run it; CI runs
# it as its own job, which is not a required check (CONTRIBUTING.md).
# The shell guard's grammars beside how bash parses every line of the case files.
grammars *flags:
    cargo fmt --manifest-path tools/grammar-check/Cargo.toml --check
    cargo clippy --manifest-path tools/grammar-check/Cargo.toml --target-dir target/grammar-check --all-targets --locked -- -D warnings
    cargo run --manifest-path tools/grammar-check/Cargo.toml --target-dir target/grammar-check --locked --quiet -- --sandbox-profile target/grammar-check/sandbox.sb
    GRAMMAR_CHECK_SANDBOXED={{grammars_sandboxed}} cargo test --manifest-path tools/grammar-check/Cargo.toml --target-dir target/grammar-check --locked {{grammars_sandbox}}
    cargo run --manifest-path tools/grammar-check/Cargo.toml --target-dir target/grammar-check --locked {{grammars_sandbox}} -- {{flags}}

# The fuzz targets in `tools/fuzz`, a package of its own the workspace
# excludes: formatted, linted and tested first with the pinned Rust, then
# the runner seeds `target` from the case files, builds it with cargo-fuzz
# and the nightly `tools/fuzz/rust-toolchain.toml` names (both installed
# once, CONTRIBUTING.md), and runs it for `seconds` under libFuzzer, each
# input held to five seconds and 2 GB. It prints none of what libFuzzer
# prints, which names an input it found: that goes to a log beside what it
# found, in `target/fuzz/found/<target>`, a security report (SECURITY.md).
# `flags`: `--keep-going` (run the whole time past a find), `--private`
# (print the log, on a machine of your own), `--out DIR`. `just verify`
# does not run it: it needs a nightly, and what it finds depends on how
# long it runs; `tests/promises.rs` holds the same promises in the gate,
# and CI runs every target weekly in `.github/workflows/fuzz.yml`.
# One fuzz target, seeded from the case files and run for a time (`just fuzz shell_posix 300`).
fuzz target seconds="300" *flags:
    cargo fmt --manifest-path tools/fuzz/Cargo.toml --check
    cargo clippy --manifest-path tools/fuzz/Cargo.toml --target-dir target/fuzz/tool --all-targets --locked -- -D warnings
    cargo test --manifest-path tools/fuzz/Cargo.toml --target-dir target/fuzz/tool --locked
    cargo run --manifest-path tools/fuzz/Cargo.toml --target-dir target/fuzz/tool --locked --quiet -- run {{target}} {{seconds}} {{flags}}
