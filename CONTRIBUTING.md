# Contributing to milo-guards

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

## Case files

A plain case, a line and the answer it must get, is written in a case file,
not as a row of a Rust table, and a fix or a new rule adds its cases as lines
there, not as Rust. The cases of a behaviour are in
`crates/<crate>/tests/cases/<what-it-checks>.cases`, beside the test file of
the same name, `tests/<what-it-checks>.rs`, which checks them all with one
call: `common::cases::check("<what-it-checks>")`. What is not a plain case
stays in that Rust file: cases made in a loop, long or nested input, timing,
tests of the API itself, and tests that check a structure (the paths a line
lists, the tree `explain` draws). The shell, file, URL and secrets guards,
the path model in `core` and the `code` reader read case files; the secrets
guard's cases hold no value shaped like a real key, which its tests build in
Rust so that none sits in the repository. The front door's
`crates/guards/tests/everyday.rs` reads its `tests/cases/everyday.cases` with
the shell guard's runner, and judges each line through
`milo_guards::shell` too.

One case to a line, and nothing else on it:

```text
# A comment: its first character is `#`. Blank lines are skipped.
posix safe | cd ../.. < .ssh/id_rsa
posix finds=read_secret | cd sub < ../../.ssh/id_rsa
cmd finds=overwrite | cd sub > ..\\x.txt
posix effect=changes | cd sub > ../x
posix finds=delete reason="deletes your home directory" | tar -cf x.tar ~ --remove-files
posix safe | cd sub <<EOF > out.txt\nx\nEOF
paths home cwd=/home/me home=/home/me workspace=/home/me
posix@home finds=delete | rm -rf .ssh
```

The words before ` | ` say how the line is judged and what it must get. The
text after it, from one space after the bar to the end of the line, is the
command line, and it may hold anything, a ` | ` included.

- **The shell and the paths.** The first word is the shell, `posix`,
  `powershell` or `cmd`, and may name the paths after an `@`: `posix`, `macos`
  or `windows` (core's test machines), or a name a `paths` line declared
  earlier in the file. Without one, a POSIX line is judged on `posix` and the
  others on `windows`.
- **The answer.** `safe`, or one or more fields: `finds=RULES` (each rule is
  found; `a/b` is either of two), `rules=RULES` (exactly these, in order),
  `first=RULE` (the first finding), `lacks=RULES` (none of them),
  `reason="..."` (the reason of the `first` finding, or of the one rule of
  `finds`), `instead="..."` (what that same finding says to do instead, or
  `instead=none` for no advice) and `effect=` with `reads_workspace`,
  `reads_beyond`, `changes` or `unknown`. A rule is its wire name; a list is
  comma separated. A value with a space is quoted. Every case is also held
  to the agreement checks: its `effect`, `explain` and `effect_paths` agree
  with `classify`; and every finding's reason and `instead` are each one
  plain sentence, with no trailing period.
- **A `paths` line** names a machine: `base=MACHINE`, or `cwd=` and `home=`;
  then `workspace=` for each workspace folder (added to the base's), and
  `folder=` or `file=` for a protected path, each followed by its `words=`.
- **Escapes.** A backslash starts one of `\\` (a backslash), `\n`, `\t`, `\r`,
  `\s` (a space) and `\u{HEX}` (any character), and `\"` in a quoted value.
  A Windows path doubles its backslashes, as in a Rust string. Any other
  character, non-ASCII included, is written as it is.

A case file is refused, every bad line named by its file and line, for a
raw tab, carriage return or other control character, a space at the start or
end of a line or of a command line (write `\s`), an unknown escape, an unknown
word, field, shell, rule, effect or paths name, an answer that is not whole
(no answer, `safe` with a rule, `reason` or `instead` without its one rule,
a field twice), a case without its `| LINE`, and a case that repeats another (the
same shell, paths, line and answer). A missing file fails its test, and
`tests/cases.rs` fails for a case file no test file checks and for a case
that repeats one in another file checked in the same build (a test file that
starts `#![cfg(...)]`, as `tests/inline_off.rs` does, is checked in another,
where the same line may get the same answer). A case that gets another answer
is named by its file and line with what it got.

To list every case, one to a line (where it is, the shell, the paths, the
answer and the line as Rust writes a string, tab separated):

```sh
cargo test -p milo-guards-shell --all-features --test cases -- --ignored --nocapture dump
```

The file guard's case files are the same but for the first word and the
text: a case is `ACCESS[@PATHS] ANSWER... | PATH`, where `ACCESS` is `read`
or `write`, a case without `@PATHS` is judged on `posix`, there is no
`effect=`, and the text is the path the file API is given. Every case is also
held to name the path as written in each finding (none past the longest path
judged). Its dump is `cargo test -p milo-guards-file --all-features --test
cases -- --ignored --nocapture dump`.

```text
read@windows finds=read_secret | C:\\Users\\me\\.ssh\\id_rsa
paths home cwd=/home/me home=/home/me workspace=/home/me
write@home rules=write_sensitive first=write_sensitive reason="writes to a shell startup file" | .bashrc
```

The URL guard's case is `[@PATHS] ANSWER... | URL`: no first word but the
paths, `posix` without them, no `effect=`, and `target="..."` beside
`reason=` (the target of the same finding). Every case is also held to carry
no target on a finding that the URL is unreadable. The secrets guard's case
is `ANSWER... | TEXT`: no paths, no `effect=`, `target=` as the URL guard's,
`span="..."` (the text has one span, and it covers exactly this) and
`covers="..."` (every byte of the first place this is in the text is in a
span); every case is also held to spans that agree with the findings, one
for one, in order and apart. Their dumps are the same command with
`-p milo-guards-url` and `-p milo-guards-secrets`.

```text
first=local_address target="127.0.0.1" | http://2130706433/
@windows first=local_file reason="reads a file from another machine" | file://server/share/x
rules=generic_secret span="F4kePass9" | password=F4kePass9&x=1
covers="F4kePassw0rdZ" | machine api.fake.test login fakeuser password F4kePassw0rdZ
```

The path model's case is `FLAVOUR[@PATHS] [home] [hidden] [deep]
ANSWER... | PATH`: `FLAVOUR` is `posix` or `windows`, how the path is
spelled, judged on `posix` or `windows` without `@PATHS` (declared as the
shell guard's). `home` gives the path as `Spelling::Home`, the part below the
home directory; `hidden` says a wildcard matches a leading dot, and `deep`
that a folder is read whole. The answer is one or more questions asked of the
`Resolver`, each with the answer it must give: `place=`, `into=`
(`place_into`) and `place_hidden=` give a place (`inside`, `outside`,
`unknown`, `disk`, `null`, `registry`, `temp`, `in_temp`, `workspace`,
`holds_workspace`, `home`, `holds_home`, or `top:`, `secret:`, `startup:`,
`history:` and `protected:` with the words); `startup=`, `below=`
(`startup_below`), `picks=` (`picks_secret`), `holds=` (`holds_protected`),
`kernel=` and `git=` give the words or `none`; `absolute=` and `opened=` the path or `none`; `reaches=`
(`reaches_secret`) and `network=` give `yes` or `no`. The code reader's case
is `WHAT ANSWER... | CODE`: `WHAT` is `python`, `javascript`, `python2`
(`understand_python2`) or `module` (a module specifier), and the answer is
`acts="..."` (the acts `read` finds, as `tests/common` spells them),
`understand=yes|importing|no`, `other_encoding=yes|no` (Python), and
`data_url=yes|no` and `foreign=yes|no` (a module). Their dumps are the same
command with `-p milo-guards-core` and `-p milo-guards-code`.

```text
posix@macos place="secret:your SSH keys" | /Volumes/Macintosh HD/Users/me/.ssh/id_rsa
windows home absolute=C:\\Users\\me\\AppData | \\AppData
posix hidden picks="your SSH keys" | /home/me/*
python acts="remove /home/me" understand=no | import shutil\nshutil.rmtree('/home/me')
```

The reading of the format is shared, in `crates/core/tests/common/cases.rs`
(tested by `crates/core/tests/cases.rs`); what the words mean for a guard,
and the runner, are in its `tests/common/cases.rs` (for the path model,
`crates/core/tests/common/runner.rs`, which its tests call
`common::cases`).

## Submitting a change

- `main` takes pull requests only. The commits that set the repository up are
  the one exception.
- Commit messages describe the change and why. No tool trailers (no
  `Co-Authored-By` or "Generated with" lines) on commits or pull request
  descriptions.
- A new rule comes with cases of safe and risky lines
  ([GUIDELINES.md](GUIDELINES.md), [Case files](#case-files)), and a rule's
  wire name never changes once a caller uses it.
- A fix adds a case line, not Rust: the line that was judged wrong and the
  answer it must get, in the case file of what it checks
  ([Case files](#case-files)). It writes Rust only for what a case file
  cannot hold.
- A test goes in the file named by what it checks, never in one named after
  a ticket or a review ([GUIDELINES.md](GUIDELINES.md#tests)). A test of a
  source file's own
  helpers goes in that file's `#[cfg(test)] mod tests`; a test of what a crate
  does and of its edge cases in `crates/<crate>/tests/<what-it-checks>.rs`,
  with shared helpers in `tests/common`; a test of the front door from end to
  end in `crates/guards/tests`.
- Nothing is released yet, and the repository is private. Callers depend on a
  git commit.

## How a change reaches a caller

A caller depends on `milo-guards` by git at a fixed `rev`, and its own
policy decides what to do with each rule. So a change here reaches a caller by
a pull request in that caller that bumps the `rev`, after the change has merged
to `main` here. A new rule is new to the caller too: it decides what to do with
it in that same pull request.

To work on a caller and a guard at once, point the caller at a checkout of this
repository without editing its `Cargo.toml`. From the caller's checkout, with
this one beside it:

```sh
cargo test --config 'patch."https://github.com/camiloazula/milo-guards".milo-guards.path="../milo-guards/crates/guards"'
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
