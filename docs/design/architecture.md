# Architecture

This page says what the crates are, which way they point, what every guard
promises, and how to add a guard.

## The crates

There are four kinds of crate: the core, the guards, a reader that guards build
on, and the front door.

| Folder | Package | What it is |
| --- | --- | --- |
| `crates/core` | `milo-guards-core` | What every guard shares: `Paths`, the verdict types, the path model, the test kit. [Core](core.md). |
| `crates/code` | `milo-guards-code` | A reader, not a guard: Python and JavaScript code in, the acts it is certain to do out, or that it is not understood. [Code](code.md). |
| `crates/shell` | `milo-guards-shell` | The shell guard. [Shell](shell.md). |
| `crates/file` | `milo-guards-file` | The file guard: one read or write of a path. [File](file.md). |
| `crates/url` | `milo-guards-url` | The URL guard. [URL](url.md). |
| `crates/secrets` | `milo-guards-secrets` | The secrets guard: a text in, what it holds out, masked. [Secrets](secrets.md). |
| `crates/guards` | `milo-guards` | The front door. The one crate a caller depends on. |

Package names start with `milo-guards-`. Folder names drop the prefix.

The front door has no logic of its own. It re-exports the types every guard
shares: `Paths` with its `Protected`, `Assessment`, `Finding` and the trait
`RuleName`. It does not
re-export `Place`: a caller reads a finding's rule and reason, never where a
path landed. It re-exports each guard as a module behind a cargo feature:
`shell` is `milo_guards::shell`, `file` is `milo_guards::file`, `url`
is `milo_guards::url`, `code` is `milo_guards::code` and `secrets` is
`milo_guards::secrets`; the first four are on by default and `secrets` is
not, because most callers want the others and not a table of patterns in their
binary. A caller who wants one guard switches the rest off. The shell guard
reads inline Python and JavaScript with the code reader whether or not the
front door shows it as `code`; the shell crate's own `inline` feature (on by
default) is what links it, and off, every inline line is `unknown`.

Core's trait is called `RuleName`, not `Rule`, because each guard names its own
enum of rules `Rule` (`shell::Rule`), and the front door's root and a guard's
module would otherwise show two different things under one name. The trait is
for code that handles any guard's rules alike; a caller that holds a guard's
`Rule` reads its wire name with the enum's own `name` method and imports
nothing.

## Which way they point

```text
milo-guards        ──►  milo-guards-shell  ──►  milo-guards-core
        │                      │                        ▲
        │                      └──►  milo-guards-code   │   (the shell's `inline` feature)
        ├──►  milo-guards-code                          │
        ├──►  milo-guards-file  ────────────────────────┤
        ├──►  milo-guards-url  ─────────────────────────┤
        ├──►  milo-guards-secrets  ─────────────────────┤
        └───────────────────────────────────────────────┘
```

- A guard depends on `milo-guards-core` and on its own parsers. Nothing else,
  but a reader.
- A guard never depends on another guard. If two guards need the same thing,
  that thing moves into core. The one exception is a reader: `milo-guards-code`
  reads code of another language, judges nothing, and any guard may build on
  it as on a parser (the shell guard does, behind its `inline` feature, on by
  default). A reader depends on its own parsers only, never on a guard or on
  another reader; the code reader needs nothing of the core and does not depend
  on it.
- Core depends on nothing but `std`.
- A crate may be a dev-dependency of itself (`path = "."`), to turn on a
  feature only its own tests read: the shell guard's `testing`, which shows
  its tests the count of bytes its grammars' lexers are handed. It is the same
  crate, not another, and a caller's build never has the feature.
- The front door depends on core, on every guard and on the readers, behind
  features.
- Nothing depends on the front door.

A guard that needs another guard's answer is not a guard. The caller asks both
and combines the answers, because deciding what to do with them is the
caller's job. Where two guards must give one answer, the front door tests it:
`crates/guards/tests/agree.rs` runs every path of the file guard's case files
through the shell guard, and neither guard knows of the other.

`crates/guards/tests/contract.rs` reads every `Cargo.toml` and fails when a
guard depends on another guard, or when core depends on anything. It reads
`package = "..."` and `path = "..."` values too, and the root manifest's
`[workspace.dependencies]`, so a renamed dependency, a path dependency or a
renamed workspace dependency on another guard is caught as well. A reader (the
folders listed in `READERS`, today `code`) is not a guard for it: a guard may
depend on one, and a reader may depend on no guard and no other reader.

## The contract

Every guard keeps these five promises.

1. **No I/O, no environment.** A guard never reads a file, a variable, the
   clock or the network. It never starts a process or a thread and never
   writes to the terminal. It takes text and the `Paths` it is given, and it
   returns an answer. Paths are judged by how they are spelled, never by what
   is on disk, so a Windows line is judged the same on every host.
2. **Deterministic.** The same input gives the same answer, on every run and
   on every machine.
3. **No policy.** A guard says what it found. It never decides to ask, to
   refuse or to allow, and it has no modes. What to do with a risky answer is
   the caller's choice, and the caller can choose a different one for each
   rule.
4. **What cannot be read is risky.** A program that is only known when it runs,
   a script a guard does not read, a line the grammar cannot parse, input that
   is too deep or too long: all come back risky, with a reason. A guard never
   answers safe because it gave up.
5. **Never panics.** Whatever the input, a guard returns. A guard runs on every
   action an agent takes, and a panic there would fail the agent's turn.
   `unwrap`, `expect` and `panic!` are warned about in the code and allowed in
   tests.

What enforces each promise, and where:

| Promise | Enforced by |
| --- | --- |
| No I/O, no environment | `contract.rs` and the `disallowed-*` lists in `clippy.toml` |
| Dependency direction | `contract.rs` |
| Never panics | each guard's `tests/robust.rs` (seeded random noise through every grammar), and for the shell guard also `tests/timing.rs` (wider noise, and the time a line may take); clippy warns on `unwrap`, `expect` and `panic!` outside tests |
| What cannot be read is risky | each guard's `tests/robust.rs` for a line that is too long or too deeply nested; for the shell guard also `tests/limits.rs` for a line left open and for the limits; the guard's own tables of risky lines for the rest |
| Deterministic | no test of its own: it follows from the first promise |
| No policy | no test of its own: a guard's API only reports findings |

The code reader ([Code](code.md)) is not a guard but keeps the promises the
same way: no I/O and no environment (the same contract test and clippy lists),
deterministic, no policy (it says what code does, and never whether that is
risky), never panics (its `tests/robust.rs`), and, for the fourth, what it
cannot read is not understood, never understood by default.

The contract test reads the source of every crate under `crates/`, and each
crate's `build.rs` if it has one, and fails on any use of `std::fs`,
`std::env`, `std::process`, `std::net`, `std::thread`, `std::os`,
`std::time::SystemTime`, `std::time::Instant`, `std::io::stdin`,
`std::io::stdout`, `std::io::stderr`, or a print macro. It reads the code, not
the comments or strings. It also catches grouped imports such as
`use std::{env, fs};`, and `self` in a group (`use std::io::{self}`), which
imports a module that holds a forbidden item as a whole. It is a text scan,
the backstop; clippy is the first line. `clippy.toml` lists the disallowed
methods, types and macros by what they resolve to, so a renamed import does
not get past it: the file-system, environment, process, network, thread,
clock, terminal and Unix `std::os` calls, and the `println!`, `dbg!`, `env!`,
`option_env!` and `include*!` macros. A test that must read a file allows the
lint at the top of its own file, with a reason.

Each guard's tests run random lines through every grammar and check that it
returns without a panic. A line that is too long or too deeply nested must
come back risky and unreadable.

The secrets guard reads any text, so it has no unreadable answer. Its
`robust.rs` checks instead the answer a hostile text of a megabyte gets, and
its `timing.rs` that the text is read inside a bound and in time linear in its
length, with the clock in the test and none in the crate.

The workspace also forbids `unsafe`, and the dependency check allows only
permissive licences.

## Where a test goes

A test file is named by what it checks (`cd.rs`, `drop_data.rs`,
`found_whole.rs`), never by the ticket, the issue or the review that asked
for it. A fix adds a case line to the case file of what it checks
(`tests/cases/<what-it-checks>.cases`, the format in
[CONTRIBUTING.md](../../CONTRIBUTING.md#case-files)), not Rust; a second file
for one thing is only for a large one (`stop_processes.rs` and
`stop_processes_windows.rs`). A case is kept once, and the runner refuses a
repeat: the same input under the same shell and paths with the same answer is
a duplicate, the same input under another shell, other paths or for another
answer is not. There are three kinds of test, and each has its place:

- A test of a source file's own helpers is in that file's
  `#[cfg(test)] mod tests`.
- A test of what a crate does, and of its edge cases, is in
  `crates/<crate>/tests/<what-it-checks>.rs`, one thing to a file, with the
  helpers the files share in `tests/common`.
- A test of the front door from end to end is in `crates/guards/tests`:
  `agree.rs` (the shell and the file guard give one answer), `ci_jobs.rs`
  (CI's jobs run the recipes of `just verify`), `contract.rs` (the contract
  and the direction of the dependencies), `everyday.rs` (the everyday
  commands stay safe, its lines in `tests/cases/everyday.cases`) and
  `toolchain.rs` (the places that name the Rust version agree).

Some names are read by other files: `just no-inline` runs
`crates/shell/tests/inline_off.rs` by name, `agree.rs` reads every case file
in the file guard's `tests/cases`, and each guard's, core's and the code
reader's `tests/cases.rs` holds
each case file in its `tests/cases` to the test file of its name, which
checks it ([CONTRIBUTING.md](../../CONTRIBUTING.md#case-files)).

## Why tree-sitter is held at 0.26

The shell guard and the code reader parse with tree-sitter. Cargo lets a
lockfile hold one version of a crate that has a `links` key, and tree-sitter's
runtime has one. So the version the guard uses is the version of every caller
that also parses with tree-sitter. A caller that holds it at 0.26 cannot take a
guard that needs 0.27.

For that reason the workspace holds tree-sitter at 0.26 and moves it only when
the callers move. The grammars depend only on `tree-sitter-language`, so any
grammar release built for the 0.26 runtime fits. The pins live in the root
`Cargo.toml`, with the reason beside them.

## Adding a guard

A new guard is a new crate. Follow these steps.

1. **Write the crate.** Make `crates/<name>` with package `milo-guards-<name>`.
   Depend on `milo-guards-core` and on the parsers it needs, using
   `workspace = true`. Add it to `members` and to `[workspace.dependencies]`
   in the root `Cargo.toml`.
2. **Name the rules.** Write one enum of rules, named `Rule`, and implement
   core's `RuleName` for it. Give it an inherent `pub const fn name(self)` (the
   trait delegates to it) and a `pub const ALL` listing every rule. Give each
   rule a wire name in `snake_case`. The name never changes once a caller uses
   it. Keep the enum exhaustive: do not mark it `#[non_exhaustive]`.
3. **Judge.** Write one public function that takes what the agent wants to do,
   plus `&Paths` when paths matter, and returns `Assessment<YourRule>`. Export
   type aliases `Assessment` and `Finding` for your rule, as the shell guard
   does, so a caller does not write the type parameter.
4. **Keep the contract.** What cannot be read is risky. Read structure, not raw
   text. Reasons are a few plain words a permission prompt can show.
5. **Test it.** Write its safe inputs, and its risky inputs each with the
   rule it must break, in case files
   ([CONTRIBUTING.md](../../CONTRIBUTING.md#case-files)), read by a runner in
   its `tests/common` on core's shared reading of the format; core's `testing`
   module (a dev-dependency with the `testing` feature) checks what is made
   in Rust. Add a test that walks `Rule::ALL` and checks
   the wire names are what you documented. Add a `robust.rs` that feeds it
   noise and checks that it never panics.
6. **Add it to the front door.** In `crates/guards/Cargo.toml` add an optional
   dependency and a feature (`<name> = ["dep:milo-guards-<name>"]`), add it to
   `default` if it should be on by default, and re-export it in `src/lib.rs`
   behind the feature: `pub use milo_guards_<name> as <name>;`. Do not name a
   module `core`.
7. **Write its page.** Add `docs/design/<name>.md`, and list the guard in the
   README.

The contract test finds the new crate by itself. Nothing there needs editing.
The README's example is compiled as a doctest in `crates/guards`; if it shows
the new guard, it is checked there too.
