# Guidelines

`milo-local-guards` is a set of guards for AI agents working on your own
machine, written in Rust. A guard reads what an agent is about to do and says
whether it is safe to do without asking, or risky and why. Guards are built
for small local models: offline, deterministic, no model calls.

This page is the short version of how the code is organised and the rules that
keep it that way. Each rule links to the page that explains it. These rules win
on any conflict with other guidance. How to build, test and submit a change is
in [CONTRIBUTING.md](CONTRIBUTING.md).

## How it fits together

The workspace has these kinds of crate: the core, the guards, a reader of code
that guards build on, and the front door:

- `crates/core` (`milo-guards-core`) - what every guard shares: the `Paths` a
  command is judged against, the verdict types (`Assessment`, `Finding`, the
  `RuleName` trait with its stable wire names), the path model, and a test kit
  behind the `testing` feature. [Its design](docs/design/core.md).
- `crates/code` (`milo-guards-code`) - a reader, not a guard: `read` and
  `understand`. It reads Python and JavaScript and says what the code is
  certain to do, or that it does not understand it. It judges nothing; the
  shell guard builds on it for inline code, behind its `inline` feature.
  [Its design](docs/design/code.md).
- `crates/shell` (`milo-guards-shell`) - the shell guard, `classify`. It
  parses POSIX shell, PowerShell and cmd and judges programs, flags, operands
  and redirects. [Its design](docs/design/shell.md).
- `crates/file` (`milo-guards-file`) - the file guard, `judge`. It judges one
  read or write of a path through a file API. [Its design](docs/design/file.md).
- `crates/url` (`milo-guards-url`) - the URL guard, `judge`. It reads a URL with
  a WHATWG parser and judges the host the parser reads, never the spelling,
  with its scheme and user-info. [Its design](docs/design/url.md).
- `crates/secrets` (`milo-guards-secrets`) - the secrets guard, `find`. It reads
  a text with a table of credential shapes and returns what it holds and where,
  masked, never the secret. [Its design](docs/design/secrets.md).
- `crates/guards` (`milo-local-guards`) - the one crate a caller depends on.
  It re-exports each guard behind a feature; `secrets` is the one that is off by
  default.

A caller hands a guard what the agent wants to do and the places it may work
in, and gets an assessment back. What to do with it is the caller's. How the
crates depend on each other and how that is enforced is in
[docs/design/architecture.md](docs/design/architecture.md).

## Rules

### The contract

- **Every guard keeps the contract**: no I/O and no environment reads,
  deterministic, no policy, what cannot be read is risky, never panics. No
  I/O and the direction of the dependencies are enforced by `contract.rs` and
  clippy; never panics and unreadable-is-risky by each guard's `robust.rs`.
  [Architecture](docs/design/architecture.md)
- **Policy stays with the caller.** A guard reports findings; it never decides
  to ask, refuse or allow, and has no modes.
  [Architecture](docs/design/architecture.md)
- **What cannot be read is risky**, never safe by default.
  [Architecture](docs/design/architecture.md)

### Structure

- **A guard depends on `core` and its own parsers only**, never on another
  guard. A caller gets them together through `crates/guards`. The one
  exception is a reader of code (`crates/code`), which judges nothing and
  depends on no guard: a guard may build on it as on a parser.
  [Architecture](docs/design/architecture.md)
- **Code that is not understood is never harmless.** The code reader keeps
  every act it finds, and says `Understood` only for a few plain statements it
  reads in full; a caller that finds no act in code that is not understood says
  unknown. [Code](docs/design/code.md)
- **Every shell rule reads structure, never raw text**: the program, its flags,
  operands and redirects, and where each path lands. [Shell](docs/design/shell.md)
- **The secrets guard judges the value, never the spelling, and never shows
  it.** Escapes are read before the table runs, a shape that is common never
  decides alone, and a finding carries a masked target and offsets, not the
  text. [Secrets](docs/design/secrets.md)
- **A rule's wire name never changes once a caller uses it.** Add a new rule
  rather than renaming one. [Core](docs/design/core.md)
- **A guard's `Rule` enum is exhaustive**, never `#[non_exhaustive]`: a new
  rule must break each caller's `match` at compile time, so the caller decides
  what to do with it. The shell guard's `Effect` (the answer of `effect`:
  reads only, changes, unknown) and the `Reach` of a reads-only answer are
  exhaustive for the same reason.
  [Shell](docs/design/shell.md)
- **Reasons are a few plain words a permission prompt can show**, such as
  `deletes your home directory`. [Core](docs/design/core.md)

### Dependencies

- **No `unsafe`.** The workspace forbids it. [Architecture](docs/design/architecture.md)
- **Permissive dependencies only** (MIT, Apache-2.0, BSD and the like); no GPL,
  AGPL, LGPL or source-available licence, and `just deny` fails on one.
  [Architecture](docs/design/architecture.md)
- **tree-sitter moves only with its callers.** Its `links` key allows one
  version in a lockfile, so a caller that also links it holds it to the same
  version; a bump here is a bump there. [Architecture](docs/design/architecture.md)
- **Rust only.** Checks and tools are Rust tests or binaries, never scripts in
  another language. [Architecture](docs/design/architecture.md)

### Tests

- **A new rule comes with table tests of safe and risky lines**, each line
  with the verdict and the reason it should get. [Shell](docs/design/shell.md)
- **A test file is named by what it checks, never by a ticket, an issue or a
  review**, and a fix adds its rows to that file. A source file's own helpers
  are tested in its `#[cfg(test)] mod tests`; what a crate does and its edge
  cases in `crates/<crate>/tests/<what-it-checks>.rs`, with shared helpers in
  `tests/common`; the front door end to end in `crates/guards/tests`.
  [Architecture](docs/design/architecture.md#where-a-test-goes)
- **Do not re-enable the disabled clippy lints**, and gate a deliberate panic
  behind `#[allow(..., reason = "...")]`.
  [Architecture](docs/design/architecture.md)
- **The coverage floor never goes down.**
  [CONTRIBUTING.md](CONTRIBUTING.md#the-gates)

## Where to look

- Design pages: [docs/design/](docs/design/). [Architecture](docs/design/architecture.md),
  [core](docs/design/core.md), [code](docs/design/code.md),
  [shell](docs/design/shell.md) and [file](docs/design/file.md).
  [url](docs/design/url.md) and [secrets](docs/design/secrets.md).
- What belongs here: only what the code and `cargo`/`clippy` cannot tell you.
- A convention a coding agent gets wrong: add the fix here, as one line, with
  its detail on a design page.
