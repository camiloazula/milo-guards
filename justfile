# Run `just <target>`. Install just with `brew install just`.
#
# Every recipe that builds builds the whole workspace with the one Rust in
# rust-toolchain.toml. This is a library and ships no binary, so there are no
# notices recipes: a binary's third-party notices travel with the binary, in
# the programs that use these crates.

# Plain `just` lists the available recipes.
_default:
    @just --list --unsorted

# The gate, and the only one (CONTRIBUTING.md). It compiles three times:
# clippy's check pass, one instrumented build of every test, which runs them
# and measures coverage, and one optimized build, which runs the tests that
# time the guard. Advisories are not part of it: they change without a
# commit, so they are their own recipe and their own CI job.
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

# `just verify` runs them again in its one instrumented build, apart from
# the doctests, which `just doc-test` runs, and the timing tests, which
# `just timing` runs: a debug build ignores them. `--locked`: fail if
# Cargo.lock would need updating.
# Every test but the timing ones, without coverage: quicker while working.
test:
    cargo test --workspace --all-features --locked

# Raise the floor as coverage lands, never lower it to pass. A failing test
# fails it too. Only the last run's coverage data is removed, not the build
# (`--no-clean`): cargo rebuilds what changed, so a run after a small change
# does not compile the whole workspace again. cargo-llvm-cov does not run
# doctests, so `doc-test` does.
# Every test, run once in an instrumented build, with the line-coverage floor.
coverage:
    cargo llvm-cov clean --profraw-only
    cargo llvm-cov --no-clean --workspace --all-features --locked --fail-under-lines 90

# The tests that time the guard compare against limits that describe an
# optimized build, and the instrumented build of `coverage` and the debug
# build of `test` are several times slower, so they are ignored there
# (`cfg(any(coverage, debug_assertions))`) and run here.
# Every test, in an optimized build: the timing tests among them.
timing:
    cargo test --release --workspace --all-features --locked

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

# Metadata only, no build.
# Dependency gates (deny.toml): bans, licences and sources.
deny:
    cargo deny check bans licenses sources

# Needs the network (the RustSec database), and the answer changes without a
# commit, so `just verify` does not run it; CI runs it as its own job.
# Dependency advisories (deny.toml): RustSec and yanked crates.
advisories:
    cargo deny check advisories
