# Contributing to milo-guards

Thanks for your interest in contributing. This page is how to build, test and
submit a change. How the code is organised, and the rules it follows, are in
[GUIDELINES.md](GUIDELINES.md).

## Building

Requires [`just`](https://github.com/casey/just) and rustup; plain `just`
lists the recipes.

One Rust builds everything the gate runs: `rust-toolchain.toml` pins it
(rustup installs it, with clippy, rustfmt and `llvm-tools-preview`, the first
time `cargo` runs here), so every contributor gets the same clippy verdicts.
It is the version CI runs (`RUSTUP_TOOLCHAIN` and each Rust install step's
`toolchain:` input in `.github/workflows/ci.yml` and `release.yml`); a test
fails when they differ. Bump them together, to the newest stable. Edition
2021.

The oldest Rust the crates support is another, lower version: `rust-version`
in `Cargo.toml`, Rust 1.90 today, the one the crates declare to a caller
([Versions](README.md#versions)). `just oldest-rust` builds with it what a
caller builds (the workspace with its default features, so without the
`testing` features only the dev-dependencies turn on, and the shell guard
without `inline`) and runs every test but the timing ones with it (`cargo
+` the `oldest_rust` of the `justfile`), all against `Cargo.lock`; CI's
`oldest-rust` job runs that recipe, and a release runs it by hand
([Releasing](#releasing)). `just verify` does not, and needs only the
pinned Rust. To run
`just oldest-rust` locally, install that Rust once, with no component:
`rustup toolchain install 1.90 --profile minimal`.
`crates/guards/tests/toolchain.rs` holds each copy of it to `rust-version`:
`oldest_rust`, the job's `RUSTUP_TOOLCHAIN` and `toolchain:` input, the
README and this page; it fails when the job is gone, when another job
overrides the pinned Rust, and when `rust-version` is above the pin.

`rust-version` is raised only when a dependency, a language feature or a
library API the code needs requires it, never just because a new Rust is
out, and a raise is a minor bump at `0.x` ([Releasing](#releasing)): a
caller on the old Rust can no longer build the crates. Raise it with each
copy above, and say so in `CHANGELOG.md`. The pinned Rust is separate and
moves freely.

Run commands with the pinned toolchain: `cargo --version` in the repo should
print the version in `rust-toolchain.toml`. A Homebrew-installed Rust earlier on
`PATH` ignores that pin, uses its own clippy, and has no `llvm-tools-preview`.
Put `~/.cargo/bin` before Homebrew on `PATH`, or remove the Homebrew Rust.

The grammars are C, compiled by the system's C compiler: the Xcode command
line tools on macOS, a C compiler on Linux, and MSVC (Visual Studio's C++
build tools, which rustup's MSVC toolchain needs anyway) on Windows. On
Windows, `just` runs a recipe's lines with `sh`, as everywhere: Git for
Windows has one, in its `bin` folder, which must be on `PATH`. A clone
made since `.gitattributes` came in has every text file with LF line
endings, on Windows too: the tests read the case files and the sources as
text. A clone made before it, with `core.autocrlf=true` (Git for Windows'
default), keeps the CRLF files it has, and `git status` still shows them
clean; clone again, or rewrite them from the index with
`git rm --cached -r . && git reset --hard` (which drops any uncommitted
change).

## The gates

`just verify` is the gate: the only check that decides whether a change can
merge. Run it locally, and paste its result in the pull request. Never push
while it fails. It runs, in order, over the whole workspace:

| Recipe | What it checks |
|---|---|
| `just format-check` | `cargo fmt --all --check` |
| `just lint` | clippy, `--all-targets --all-features`, zero warnings (`cargo lint` runs the same) |
| `just coverage` | every unit and integration test, `--all-features --locked`, run once in an instrumented build, and line coverage against the floor in the `justfile` (`--fail-under-lines`); raise it as coverage lands, never lower it to pass |
| `just timing` | the timing tests, and nothing else, in an optimized build: `cargo test --release --locked --all-features -p <crate> --test timing -- --show-output` for each crate with a `tests/timing.rs` (the shell guard and the secrets guard). Every test that reads the clock is in one of those files, and no other test does; they compare against limits that describe an optimized build, so they are ignored in the instrumented and debug builds (`cfg(any(coverage, debug_assertions))`) and run here |
| `just doc-test` | every doctest, README example included (`cargo test --doc --workspace --all-features --locked`), which coverage does not run |
| `just doc` | rustdoc on the workspace with warnings denied, so a broken intra-doc link fails (`--all-features --no-deps --locked`) |
| `just no-inline` | the shell guard without its `inline` feature (no readers of Python and JavaScript, no grammars): clippy on all its targets with zero warnings, and `tests/inline_off.rs`, which holds every inline line to `unknown`; `--all-features` never builds it that way |
| `just deny` | the dependency gates in `deny.toml`: permissive licences only, crates.io only, no banned crates (`cargo deny check bans licenses sources`) |

The code is compiled by clippy's check pass, by the one instrumented build
every unit and integration test but the timing tests runs from, and by one
optimized build of the timing tests alone; the doctests and rustdoc build what
they need on top, and the shell guard is built once more without its `inline`
feature (`just no-inline`). `just test` runs every test but the timing
tests, doctests included, in a debug build without coverage, quicker while
working. No recipe but `just timing` reads a clock.

CI runs the gate in two jobs. The `verify` job runs every recipe above but
`just timing`, in the same order: it reads no clock, so it gives the same
answer on any machine. The ruleset on `main` requires it: a pull request
whose `verify` job is red, or has not finished, cannot merge. The `timing`
job runs `just timing` alone, and it is required too: a guard that hangs on
a crafted line is a vulnerability ([SECURITY.md](SECURITY.md)), so a red
`timing` run is a change that cannot merge, as a red `verify` run is. Each
timed row prints how near it came to its bound (`timing: 41.0% <the row>`),
and `just timing` shows it for a test that passes too, so the job's log
holds every row's margin on the runner: a row past half of its bound there
is held to how its time grows or to a count of work, not given a wider
bound (below). Locally, `just verify` still runs both. Those two jobs run
on Linux (x86_64).

For the owner: the ruleset on `main` requires two checks, `verify` and
`timing`. `timing` is added beside `verify` in its required status checks
(Settings, Rules, the `main` ruleset, "Require status checks to pass", add
the check `timing` from GitHub Actions) once the job has passed on 10 runs
on `main` in a row.

The `test` job runs `just test` on Windows and on macOS, with the pinned
Rust and without coverage: `windows-latest` (x86_64, MSVC) and
`macos-latest` (arm64), one job for each, and one failing does not stop
the other. The crates have no platform code of their own, but the grammars
are C, built by each system's compiler, and a caller on Windows or a Mac
builds them there; this job builds and tests them there first. `just test`
reads no clock (a debug build ignores the timing tests), so a slow runner
cannot fail it. It is advisory for now: the ruleset on `main` does not
require it, and a red run is a time to look, not a change that cannot
merge. Once it has passed on `main` steadily and its time on these runners
is known, its two checks, `test (windows-latest)` and `test (macos-latest)`,
are added to the ruleset's required checks beside `verify`. Then the
systems are pinned to the runner labels of that day's images (such as
`windows-2025` and `macos-26`), and the checks' names with them: a
`-latest` label moves to a new system without a commit here, and a
required check should not.
The `oldest-rust` job runs `just oldest-rust` on Linux, with the oldest Rust
the crates support (above) where every other job uses the pinned one. It is
advisory for now: the ruleset on `main` does not require it, and a red run
is a time to look, not a change that cannot merge. It is to become a
required check: once it has passed on `main` steadily, its check,
`oldest-rust`, is added to the ruleset's required checks beside `verify`.
Until then nothing keeps a red run from merging or from being released
(the release workflow builds with the pinned Rust only), so a release runs
`just oldest-rust` by hand ([Releasing](#releasing)).
`crates/guards/tests/ci_jobs.rs` holds each job to its recipes: `verify` to
every recipe of `just verify` but `timing`, `timing` to `just timing`,
`test` to `just test` alone, on those two systems, `oldest-rust` to
`just oldest-rust` alone, on Linux, `grammars` to `just grammars
--require bash --entries` alone, and `advisories` and `semver` each to the
recipe of its name alone, on Linux; `just verify` runs none of those three
(below).

A timing test lives in its crate's `tests/timing.rs`, and only there. It
reads the clock in an optimized build only, with
`#[cfg_attr(any(coverage, debug_assertions), ignore = "timing: ...")]`, so a
slow build or a busy machine does not fail it. A test that checks both what
the guard answers for a line and how long it takes is two tests: the answer
beside the rules it checks, run in every build, and the time in `timing.rs`,
with the line made once in the crate's `tests/common` (the shell guard's
random noise in its `tests/noise`) so both read the same one. Where it
checks that a shape is read in time that grows with its length, it compares
a line of 16 KB with one of 64 KB (`assert_linear` in the shell guard's
`tests/timing.rs`, over `assert_linear_by` in its `tests/common`), not one
line with a fixed limit. A shape the guard reads only to a count, and stops
past it, can make the longer line the quicker one, so two lengths do not
show how it grows: `assert_linear` fails when the longer takes less than
half the time of the shorter, and such a shape is held at each of several
lengths, below and past the count, to the line four times as long taking
at most ten times as long instead (`steady_by` in the shell guard's
`tests/common`, the rows of `Stops` in its `tests/timing.rs`), which a
machine's speed cancels out of as well. Where it holds a line to a fixed
limit, the limit leaves room for a machine several times slower and busy
with another gate: about ten times what an optimized build takes here, and
never less than four times what it takes with another gate running beside
it. A row that comes nearer its bound, past half of it on GitHub's runner,
or that ever failed there, is not given a wider one: it is held to how its
time grows instead, or to a count of work, or made quicker. Each timed row
prints its share of its bound (`report` and `under` in the shell guard's
`tests/common`, `under` in the secrets guard's `tests/timing.rs`), and
`just timing` passes `--show-output`, so the timing job's log shows every
row's share, the ones that pass too: `grep 'timing: '` in it, sorted,
gives the rows nearest their bounds.

A shape cmd's grammar reads in quadratic time below the budget of what its
lexer is handed (`MAX_LEXED` in the shell guard's `src/unit.rs`), which stops
it, is held to that count, not to the clock: its time grows with the square
of its length up to the budget, so neither two lengths nor a fixed limit
holds it honestly, and how much slower a machine reads this grammar is not
how much slower it is on the rest (cmd's statements after a `;` took about
twenty times as long on GitHub's runner as here, where rows read in linear
time took two to four times). A count of work is the same on every machine,
so such a test is no timing test: it runs in every build, in a file named by
what it checks. The shell guard's `tests/lexer_budget.rs` holds every such
shape, each with its answer pinned: `cd x; echo y > NUL; `,
`echo y > NUL; `, `echo y & `, `echo ` then `$((1<<2)); echo `,
`for %%i in (a) do `, `@`, `()` and `(echo) ` repeated. It holds the bytes
handed within `MAX_LEXED` and within a written ceiling, so a raise of the
budget fails there, and reads them through the crate's `testing` feature,
which only its own tests turn on and which is not for callers. PowerShell's
`${` left open and nested is held there too, to the exact bytes handed at
each depth: the recoveries counted and the depth a nest is read to bound
it, far below the budget, and the runner took about thirty times as long
on it as here. The POSIX
grammar's shapes that reach the same budget stay timed until the runner
shows them out of line with the machine. A timed table names every row that
is over its bound before it fails, so one run on the runner shows them all.

`just advisories` is not part of `just verify`. It checks the RustSec database
(`cargo deny check advisories`), which needs the network and changes without a
commit, so CI runs it as its own job and a failure there is not a code
failure. Run it when you add or update a dependency.

`just semver` is not part of `just verify` either: it needs the network.
cargo-semver-checks builds the rustdoc JSON of each crate here and of its
last release on crates.io, and fails on a change that breaks a caller's
build (an item removed or renamed, a signature changed, a variant added to
an exhaustive enum, which a new rule is) when the next release is not a
minor bump. It takes about two minutes from a cold build. Between releases
`Cargo.toml` still holds the last release's version, so the versions cannot
say whether a minor bump is due; `next_bump` in the `justfile` says whether
a change since the last release breaks a caller's build. Empty, none does,
and the check allows a compatible release only (0.1.4 to 0.1.5); `minor`,
one does, and it allows any change (0.1 to 0.2, which cargo-semver-checks
calls major at `0.x`, as Cargo does). It is not the bump the next release
makes: an addition makes that a minor one too, and leaves `next_bump`
empty, so the Unreleased section can already call the next release a minor
while it is. The pull request whose change breaks a caller's build sets it
to `minor`, and says so in the Unreleased section of `CHANGELOG.md`. It
stays `minor` until the release, whose commit empties it, since the version
it bumps to then says the bump ([Releasing](#releasing)). `ci_jobs.rs`
fails when it is `minor` and the Unreleased section is empty, as it is in
that commit. That check is one-sided: `minor` set beside entries that break
nothing passes it, and keeps the job green for the rest of the cycle. That
is accepted: the release's own run of the recipe, read from the versions,
still checks the bump it makes.

CI's `semver` job runs `just semver` on every pull request and push to
`main`. It is advisory: the ruleset on `main` does not require it, and a
release runs the recipe by hand, where it must pass (`release.yml` does
not run it). Read a red run on a pull request as: this change breaks a
caller's build, and no change before it since the last release did. If the
change is meant, set `next_bump` and write it in the changelog in the same
pull request, and the job passes; if not, change it so it breaks nothing.
Once `next_bump` is `minor`, no change needs a bigger bump at `0.x`, so the
job passes on every pull request until the release, which checks the bump
it makes. The job is read against `next_bump` rather than the versions
alone because between releases the versions are the same, and every pull
request after the first change that breaks a build would be red for a
change that is not its own.

What breaks no build passes it, and is judged by hand, in the changelog
([Versions](README.md#versions)): an addition (a new type, function,
feature or crate, a field of a `#[non_exhaustive]` struct such as `Paths`),
which is a minor bump; a raise of `rust-version`, a minor bump too; a
change of a rule's wire name, which never happens once a caller uses it
([GUIDELINES.md](GUIDELINES.md)); and a change of what a guard answers,
which is a patch. A crate that is not on crates.io yet
(`milo-guards-script` today) has no release to compare with, so the recipe
leaves it out (`--exclude`) until the release that publishes it.

`just mutants <crate>` is not part of `just verify`, nor of CI. The
coverage floor counts a line that runs, but a line that runs is not a line
a test checks. cargo-mutants changes one place in the crate's code at a
time (a `==` made `!=`, a `&&` made `||`, a match arm deleted, a function
made to return a default), builds it, and runs the crate's tests: a change
no test fails on is a missed mutant, a branch no case would catch going
wrong. Run it by hand, one crate at a time, before a release and when a
guard's rules change; a run of a crate's files that changed
(`just mutants milo-guards-shell --file crates/shell/src/startup.rs`) or
of a diff (`--in-diff`) is quicker. `crate` is a package's name, and the
recipe refuses any other (cargo-mutants alone would test nothing and
pass). It runs four jobs at once (`just jobs=2 mutants <crate>`, or
`--jobs 2` among the flags, for fewer) and puts its report in
`mutants.out` (`--output DIR` for another folder), whose `missed.txt` lists
what it found. The URL guard's 183 mutants take about two minutes here at
four jobs, and three to four minutes at two or three on a machine busy with
other builds; the file guard has 57, the script guard 341, the secrets
guard about 900, core 1,100, the code reader 1,900 and the shell guard
18,000, each of which runs its whole test suite: many hours, so the shell
guard is run by the files that changed.

A missed mutant becomes one of three things. A case line, in the case file
of what it checks: the input on which the changed code answers wrong, with
the answer it must get (long input, as a name at a length limit, in the
Rust test beside the others of its kind). A written reason, when no input a
caller gives can tell it from the code as written: an entry in
`exclude_re` in `.cargo/mutants.toml` that says which inputs would, so the
next run does not report it again. Or a private report, when it shows a
line the guard judges safe and should not: that is a vulnerability, so
report it as [SECURITY.md](SECURITY.md) says, and write no case or reason
for it in the open before the fix.

Clippy reads `rust-version`, and in `just lint` its `incompatible_msrv`
lint fails on a standard library API newer than it, in the library and, with
`check-incompatible-msrv-in-tests` in `clippy.toml`, in the tests too. It
does not see a language feature newer than it (an `if let` guard on a
`match` arm, stable since 1.95, passed it with `rust-version` at 1.90), nor
a dependency whose own `rust-version` is higher: a build with that Rust
does, which is why `just oldest-rust` needs a second compiler and is not
part of the gate.

This is a library and ships no binary, so there is no notices file here. The
third-party notices travel with the binaries of the programs that use it.

`just verify` needs two tools beyond Rust, and `just advisories` needs the
second; `just semver` and `just mutants` need one each, at the version
given here. Install them once:

```sh
cargo install cargo-llvm-cov   # for just coverage
cargo install cargo-deny       # for just deny and just advisories
cargo install --locked cargo-semver-checks@0.51.0   # for just semver
cargo install --locked cargo-mutants@27.1.0         # for just mutants
```

CI's `semver` job installs the same cargo-semver-checks, and `ci_jobs.rs`
fails when the two differ. It reads the rustdoc JSON of the pinned Rust,
whose format changes with Rust's releases: when a bump of the pinned Rust
makes it fail to read that JSON (it says which format it reads), bump it
here and in the job together.

### The grammars beside the real shells

`just grammars` is not part of `just verify` either. It holds the shell
guard's grammars to how bash parses each POSIX line of the case files and of
a generated set
([Shell](docs/design/shell.md#the-grammars-beside-the-real-shells) says what
it compares and what it cannot), so its answer depends on bash's version. It
needs `bash`; a shell that is not on `PATH` is skipped, and the report says
so and which version it compared against (`just grammars --require bash`
refuses the run instead, as CI's job does). zsh is not used: its no-exec mode
still expands words, so it is neither parse-only nor an answer of accept or
reject. PowerShell's half is in the tool but has not been proven: it runs
only with `--with pwsh`, CI does not run it, and its first runs are a
maintainer's, on a machine of their own, read with `--private`. CI runs
`just grammars --require bash --entries` in its own job, `grammars`, on
Linux (bash 5); the job is not a required check, and a red run there is a
difference to look at, not a change that cannot merge.

It prints every difference, sorted, and fails on one on a line of the case
files that is not in `tools/grammar-check/known.cases`, and on an entry there
that no difference matches for a shell and version that ran. A new
difference that is cautious (bash accepts a line the grammar does not read
whole) or that only says bash refuses the text goes on that list with its
reason and the versions it was seen on, or is fixed in the grammar's
reading; `--entries` prints each new one as an entry, its version filled in
and its reason left to write, so CI's report gives the entries for its bash.
A case line you add may give one: add its entry in the same change.
Differences on generated lines are printed apart and do not fail the run: a
word you add to a case file may change which lines are generated, and you
need do nothing about them unless one is a split or a line the guard answers
safe without reading it whole. Those two always fail the run, wherever they
are found, and are never put on the list or in an issue: without `--private`
the run says only that it found something to report privately (no kind, no
count, no line), `just grammars --private` shows them, on a machine of your
own and never in CI, and they are reported as [SECURITY.md](SECURITY.md)
says.

It never runs a line. bash parses each with `-n`, its startup files and the
environment it is started from kept out, in a room of empty folders, its
input closed, with a time limit and a cap on what it prints, and the run
stops at once if a folder of the room stops being empty, a program it left
holds its output open, or bash prints anything. The recipe runs the tool's
tests first, which show each of those on canary lines and plain programs
(`tools/grammar-check/tests/`), and runs it only when they pass. On macOS the
recipe runs the tests and the tool under `sandbox-exec` too, through cargo's
runner, with the profile the tool writes to
`target/grammar-check/sandbox.sb` (`--sandbox-profile`): no network, no read
under `/Users` but of the checkout, wherever it is, and no write but to the
temporary folder, where the rooms are, and `/dev`. Run any other way on
macOS (`cargo run --manifest-path tools/grammar-check/Cargo.toml`), the tool
starts no shell while it can read `/Users`, unless it is given
`--unsandboxed`, which the recipe never gives. On Linux there is no such
sandbox: the layers of the room and `-n` are all there is, which is why CI
runs it on a runner that is thrown away after the job.

The tool is a package of its own, in `tools/grammar-check`, which the
workspace excludes: it starts processes, which no crate under `crates/` may,
and it is never published, so no gate of the workspace builds it and
`just package`, `just publish` and the release workflow never see it. The
recipe formats, lints, tests and runs it. `just oldest-rust` does not build
it: it is not published, so no caller compiles it with an older Rust. Its
`rust-version` and `edition` are the workspace's (`contract.rs` holds them),
so clippy's `incompatible_msrv` holds its code, tests included, to the
oldest Rust as it holds the crates'. Its `Cargo.lock` is its own, and
`crates/guards/tests/contract.rs` holds every package in it to `Cargo.lock`,
at the same version and from the same source, and the recipe builds it
`--locked`, so it builds what the gates build and `just advisories` audits; after a change to `Cargo.lock` (a new
dependency, an update, a release's version bump), bring it in step with

```sh
cp Cargo.lock tools/grammar-check/Cargo.lock
cargo metadata --manifest-path tools/grammar-check/Cargo.toml --format-version 1 > /dev/null
```

which keeps every version and leaves out what the tool does not use.

## Case files

A plain case, a line and the answer it must get, is written in a case file,
not as a row of a Rust table, and a fix or a new rule adds its cases as lines
there, not as Rust. The cases of a behaviour are in
`crates/<crate>/tests/cases/<what-it-checks>.cases`, beside the test file of
the same name, `tests/<what-it-checks>.rs`, which checks them all with one
call: `common::cases::check("<what-it-checks>")`. What is not a plain case
stays in that Rust file: cases made in a loop, long or nested input, timing,
tests of the API itself, and tests that check a structure (the paths a line
lists, the tree `explain` draws). The shell, file, URL, secrets and script guards,
the path model in `core` and the `code` reader read case files; the secrets
guard's cases hold no value shaped like a real key, which its tests build in
Rust so that none sits in the repository. The front door's
`crates/guards/tests/everyday.rs` reads its `tests/cases/everyday.cases` with
the shell guard's runner, and judges each line through
`milo_guards::shell` too; `tests/everyday_answers.rs` reads the record of
[the everyday answers](#the-everyday-answers) the same way.

One case to a line, and nothing else on it:

```text
# A comment: its first character is `#`. Blank lines are skipped.
posix safe | cd ../.. < .ssh/id_rsa
posix finds=read_secret | cd sub < ../../.ssh/id_rsa
cmd finds=overwrite | cd sub > ..\\x.txt
posix effect=changes | cd sub > ../x
posix finds=delete reason="deletes your home directory" | tar -cf x.tar ~ --remove-files
posix first=delete range="~" at=28 covering=target | echo "~" && bash -c 'rm -rf ~'
posix safe | cd sub <<EOF > out.txt\nx\nEOF
paths home cwd=/home/me home=/home/me workspace=/home/me
posix@home finds=delete | rm -rf .ssh
paths env base=posix secret_file=/home/me/work/repo/.env words="the project's environment file"
posix@env finds=read_secret reason="reads the project's environment file" | cat .env
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
  `instead=none` for no advice), `range="..."` (the text of the range
  `locate` gives that same finding), `at=N` (where that range starts, in
  bytes of the line, for a text the line holds more than once),
  `covering=target`, `part` or `line` (what that range covers) and `effect=`
  with `reads_workspace`, `reads_beyond`, `changes` or `unknown`. A rule is
  its wire name; a list is comma separated. A value with a space is quoted.
  Every case is also held to the agreement checks: its `effect`, `explain`,
  `effect_paths` and `locate` agree with `classify`; every range `locate`
  gives is inside the line, on its character boundaries and not empty, and
  one that covers its finding's target reads as the target; and every
  finding's reason and `instead` are each one plain sentence, with no
  trailing period.
- **A `paths` line** names a machine: `base=MACHINE`, or `cwd=` and `home=`;
  then `workspace=` for each workspace folder (added to the base's),
  `folder=` or `file=` for a protected path, and `secret_folder=` or
  `secret_file=` for a secret the caller names (`Paths::secrets`), each
  followed by its `words=`; `drive_mount=` for each folder the machine
  mounts drives in (`Paths::drive_mounts`), and `windows_home=`
  (`Paths::windows_home`). Every guard reads a `paths` line the same way
  (`format::declaration` in the shared reading).
- **Escapes.** A backslash starts one of `\\` (a backslash), `\n`, `\t`, `\r`,
  `\s` (a space) and `\u{HEX}` (any character), and `\"` in a quoted value.
  A Windows path doubles its backslashes, as in a Rust string. Any other
  character, non-ASCII included, is written as it is.

A case file is refused, every bad line named by its file and line, for a
raw tab, carriage return (`.gitattributes` keeps a Windows checkout from
adding one) or other control character, a space at the start or
end of a line or of a command line (write `\s`), an unknown escape, an unknown
word, field, shell, rule, effect or paths name, an answer that is not whole
(no answer, `safe` with a rule, `reason`, `instead`, `range`, `at` or
`covering` without its one rule,
a field twice, a `words=` with no path before it, a named path without its
`words=`, `windows_home=` twice), a case without its `| LINE`, and a case
that repeats another (the same shell, paths, line and answer). A missing
file fails its test, and
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
`reason=` (the target of the same finding). A case whose first word is
`address` is `address ANSWER... | ADDRESS`, judged by `judge_address`, with
no paths. Every case is also held to carry no target on a finding that the
URL or the address is unreadable. The secrets guard's case
is `ANSWER... | TEXT`: no paths, no `effect=`, `target=` as the URL guard's,
`span="..."` (the text has one span, and it covers exactly this) and
`covers="..."` (every byte of the first place this is in the text is in a
span); every case is also held to spans that agree with the findings, one
for one, in order and apart. Their dumps are the same command with
`-p milo-guards-url` and `-p milo-guards-secrets`.

```text
first=local_address target="127.0.0.1" | http://2130706433/
address rules=local_address first=local_address target="[::1]" | [::1]:443
@windows first=local_file reason="reads a file from another machine" | file://server/share/x
rules=generic_secret span="F4kePass9" | password=F4kePass9&x=1
covers="F4kePassw0rdZ" | machine api.fake.test login fakeuser password F4kePassw0rdZ
```

The script guard's case is `LANGUAGE[@PATHS] ANSWER... | CODE`: `LANGUAGE`
is `python` or `javascript`, a case without `@PATHS` is judged on `posix`,
there is no `effect=`, `target="..."` sits beside `reason=` as for the URL
guard and `instead="..."` (or `instead=none`) as for the shell guard, and
the text is the code. Every case is also held to reasons that are each one
plain sentence with no trailing period, and to the same answer twice. Its
dump is the same command with `-p milo-guards-script`.

```text
python finds=delete reason="deletes your home directory" | import shutil; shutil.rmtree('/home/me')
paths env base=posix secret_file=/home/me/work/repo/.env words="the project's environment file"
python@env finds=read_secret reason="reads the project's environment file" | print(open('.env').read())
javascript finds=run_program target="git status" | require('child_process').spawnSync('git', ['status'])
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
`named=` (`named_secret`), `kernel=` and `git=` give the words or `none`;
`absolute=` and `opened=` the path or `none`; `reaches=` (`reaches_secret`)
and `network=` give `yes` or `no`. The code reader's case is `WHAT ANSWER... | CODE`: `WHAT` is
`python`, `javascript`, `python2` (`understand_python2`) or `module` (a
module specifier), and the answer is `acts="..."` (the acts `read` finds,
as `tests/common` spells them),
`understand=yes|importing|no`, `other_encoding=yes|no` (Python), `parses=yes|no`
`input=yes|no` (`gives_input`) and `shell_list=yes|no` (`gives_shell_a_list`;
Python and JavaScript), and
`data_url=yes|no` and `foreign=yes|no` (a module). Their dumps are the same
command with `-p milo-guards-core` and `-p milo-guards-code`.

```text
posix@macos place="secret:your SSH keys" | /Volumes/Macintosh HD/Users/me/.ssh/id_rsa
windows home absolute=C:\\Users\\me\\AppData | \\AppData
posix hidden picks="your SSH keys" | /home/me/*
python acts="remove /home/me" understand=no | import shutil\nshutil.rmtree('/home/me')
```

The reading of the format is shared, in `crates/core/tests/common/cases.rs`
(tested by `crates/core/tests/cases.rs`), the first word of a case too
(`head`: `KIND[@PATHS]` as its two parts, which the script guard's runner
reads its language and paths with); what the words mean for a guard,
and the runner, are in its `tests/common/cases.rs` (for the path model,
`crates/core/tests/common/runner.rs`, which its tests call
`common::cases`).

## The everyday answers

`crates/guards/tests/cases/everyday.cases` holds the everyday lines that
must stay safe. The everyday answers are a larger set, about three thousand
lines of what coding agents run all day, each with the answer the shell
guard gives it today, safe or not. They are the measure of how often the
guard asks about a harmless line (the false-alarm share: the lines it
finds anything in), and of what a release changes in what it answers.

- **The templates** are the source:
  `crates/guards/tests/cases/everyday_answers.templates`, grouped by task
  (building and testing, git, reading and searching, editing in the
  workspace, running and inspecting, formatting, chains), for a POSIX
  shell, PowerShell and cmd, each in its own idiom. Its header gives the
  format: `group NAME`; `fill NAME | A | B` for a list of fillers;
  `SHELL | TEMPLATE`, where `«NAME»` takes each filler of a list and
  `«A|B»` each alternative written in it, and a template makes a line for
  each way of filling its slots, at most 32. Nothing is random, so the same
  templates always make the same lines; the lines are written here, never
  copied from a transcript or a dataset, and hold no private data and no
  secret.
- **The record** is `everyday_answers.cases` beside them, in the case-file
  format: every line the templates make, in their order, under a comment for
  each group, as `SHELL safe | LINE` or `SHELL rules=… first=…
  reason="…" | LINE` (every rule found, in order, and the reason of the
  first). It is written by `just everyday-record`, never by hand: that
  recipe sets `MILO_EVERYDAY_RECORD=1`, and without it the test that writes
  the record (`record`, which `cargo test -- --ignored` also runs) only
  prints the report.
- **`just everyday`** judges the whole set and prints the report: the lines
  of each shell, the share that is safe, the lines each rule is found on,
  the same for each group, and every line whose answer is not the recorded
  one (the answer it had, the one it gets, and the template that makes
  it). It fails when one differs, when a line is made that is not recorded
  or recorded that is not made, and when the record is not exactly what
  `just everyday-record` would write.
- **`just verify`** runs the same test, in `just coverage`, and checks the
  record as the shell guard's runner checks every case file (each case gets
  the answer it holds, and goes through the agreement checks). In the
  instrumented build of `just coverage` its test file took three seconds
  here on a quiet machine and eight on a busy one (most of it the agreement
  checks over the record; the comparison alone under one). That cost is
  held by a count, not by the clock: `MOST_LINES` in
  `tests/everyday_answers.rs` (4,000) bounds the lines the templates may
  make, and is raised only with a reason.

To add lines, add templates or fillers: what an agent really runs, with
realistic flags, paths inside the workspace and quoting, and harmless where
it runs. Keep out a line that is risky on purpose, and do not tune a line
to pass: write what an agent would run and record what the guard says. A
line the guard finds risky is recorded, not dropped: a false alarm that is
plainly a bug is an issue to open; one where the guard is right on
reflection was not harmless, and is dropped. A line the guard calls safe
that should not be is never written down: report it as
[SECURITY.md](SECURITY.md) says. Then run `just everyday-record` and commit
the templates and the record together.

A change to a guard that moves an everyday answer fails the gate until the
record is rewritten on purpose: run `just everyday-record`, read what it
prints, and commit the record with the change. A reviewer reads the diff of
`everyday_answers.cases`: each line that changed is an answer that moved. A
line that turned risky is a new false alarm, which the pull request
explains; one that turned safe is a false alarm fixed; a changed reason is a
change to what a permission prompt shows; a line added or removed comes from
a template the same pull request changes. The pull request gives the
report's first line (the false-alarm share) before and after.

## Submitting a change

- `main` takes pull requests only. The commits that set the repository up are
  the one exception. A ruleset on `main` refuses a direct push, a force-push
  and a deletion, so a pull request is the only way in, and it merges only
  once CI's `verify` and `timing` jobs have passed on it; the release tags
  (`v*`) are created, moved or deleted by the owner only.
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
- Callers depend on a release from crates.io, or on a git tag; a merged
  change reaches them in the next release ([Releasing](#releasing)).

## Releasing

The crates are published to crates.io together, at the one version in
`[workspace.package]`, each internal dependency naming that version beside
its path. A release is:

1. Bump `version` in `Cargo.toml` and the `version` of every
   `milo-guards-*` entry under `[workspace.dependencies]`, to the same
   number, and bring `tools/grammar-check/Cargo.lock` in step with
   `Cargo.lock` ([the command](#the-grammars-beside-the-real-shells);
   `just verify` fails until it is): a new rule, a raise of `rust-version`
   or any other change to what a caller compiles against is a minor bump at
   `0.x`; a change to what a guard answers with the same API is a patch
   ([Versions](README.md#versions)). Before choosing, check:
   - `next_bump` in the `justfile`: `minor` says a change since the last
     release breaks a caller's build, so this release is a minor bump.
   - The changelog's Unreleased section, for what `just semver` does not
     see: an addition, a raise of `rust-version` or another change to what
     a caller compiles against is a minor bump too.
   - The `--exclude` list of `just semver` in the `justfile`: it names only
     crates not yet on crates.io. Remove a crate an earlier release
     published (`milo-guards-script`, once the release that adds it is
     out), so it is checked against its release.
2. Move the changelog's `Unreleased` section under the new version, with the
   date, in `CHANGELOG.md`, and empty `next_bump` in the `justfile`: the
   version now says the bump. What the changelog says about the answers
   that changed comes from [the everyday answers](#the-everyday-answers),
   not from memory: `git diff vPREVIOUS -- crates/guards/tests/cases/everyday_answers.cases`
   is every everyday line whose answer moved since the last release (the
   false alarms fixed, the new ones, the reasons reworded), beside the
   lines that templates added or removed since then, which are changes to
   the set and not to an answer, and `just
   everyday` gives the false-alarm share the release leaves, overall and for
   each shell.
3. `just verify` and `just oldest-rust`, then `just package`: every crate
   packaged and built from its package, as crates.io will build it, with
   the case files left out (`exclude` in each crate's manifest). The
   release workflow builds with the pinned Rust only, and the `oldest-rust`
   job is not yet a required check, so `just oldest-rust` here is what
   keeps a release from declaring a `rust-version` it does not build with.
   Then `just semver`, which must pass: each crate against its last
   release, with the bump read from the versions, so a patch that breaks a
   caller's build fails it ([The gates](#the-gates)). It does not see what
   breaks no build, which step 1 reads in the changelog. Run `just mutants`
   on each guard whose rules changed since the last release too, and turn
   each missed mutant into a case line, a written reason or a private
   report ([The gates](#the-gates)).
4. Merge, tag the merge commit `vX.Y.Z` and push the tag. Only the owner
   can create a release tag.
5. The tag starts `.github/workflows/release.yml`, which does the rest. It
   refuses a tag that is not `v` and the version in `Cargo.toml`, a commit
   that is not one `main` took from a pull request (a commit inside the
   merged branch is refused), and a commit whose `verify` job did not pass
   on `main`; a tag pushed right after the merge waits for that job. Then
   it runs `just package`, and `just publish --no-verify`:
   `cargo publish --workspace`, which uploads the crates in dependency
   order (`core`, `code`, `shell`, `file`, `url`, `secrets`, `script`,
   `milo-guards`).

Those checks are shell inside the workflow's steps, the one exception to
"Rust only" in [GUIDELINES.md](GUIDELINES.md): a Rust tool would be compiled
in the job that holds the publishing token. `just verify` does not run
them, so a change to them is tried by hand against real commits and
crates.io's index, and the pull request says how.

The workflow holds no crates.io token. Each crate names this repository,
`release.yml` and the `release` environment as its trusted publisher at
crates.io, and crates.io hands the publish job a token that lasts thirty
minutes. crates.io does not look at which branch or tag ran the workflow:
the `release` environment does, and it admits `v*` tags only.

A version on crates.io cannot be replaced, and one version comes from one
commit: a release tag is pushed once and never moved. If the workflow stops
after some crates were uploaded and what stopped it is outside the
repository (a setting at crates.io or on GitHub), mend it and run the failed
`publish` job again from the run's page: it leaves out every crate that is
already on crates.io at that version and publishes the rest. If the mend
needs a commit, it is the next version, with a tag of its own; the workflow
refuses a new run for a version that is already on crates.io. When crates.io
answers that the token "is not valid for crate" one of them, that crate's
trusted publisher is missing or names another repository, workflow or
environment.

crates.io refuses a new crate from that token, and sets a trusted publisher
only on a crate that exists. So the release that adds a crate to the
workspace stops at it: publish the new crate by hand from the tagged commit
(`cargo login`, then `cargo publish -p <crate> --locked`), give it the same
trusted publisher, and run the `publish` job again for the rest. Until it
is on crates.io, `just semver` has no release to compare it with and leaves
it out (`--exclude` in the `justfile`); the first pull request after that
release removes the `--exclude`, so the crate is checked from then on.

## How a change reaches a caller

A caller depends on `milo-guards` from crates.io at a version, or by git at
a fixed `rev`, and its own policy decides what to do with each rule. So a
change here reaches a caller by a release, or a pull request in that caller
that bumps the `rev`, after the change has merged to `main` here. A new rule
is new to the caller too: it decides what to do with it in that same pull
request, which is why a new rule is a minor bump.

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
