# milo-guards-shell

Reads a shell command line (POSIX shell, PowerShell or cmd) and says whether
it is safe to run without asking, or risky and why. The shell guard of
[milo-guards](https://github.com/camiloazula/milo-guards).

It works in three steps:

1. **Split** the line into units, one per program it runs, with the grammar
   of the shell that runs it (`Shell`). Chains, pipes, substitutions, loops
   and blocks are walked, every branch whether or not it would run; wrappers
   (`sudo`, `env`, `xargs`, `find -exec`) are taken off, and a shell started
   with a script (`bash -c`, `eval`, `cmd /c`, `powershell -Command`) has
   that script split in its own grammar. Python and JavaScript given inline
   (`python3 -c`, `node -e`, a here-document) are read with their own
   grammars, through `milo-guards-code`.
2. **Detect** with rules that read a unit's program, flags, operands and
   redirects, never the raw text, and judge each path by where it resolves
   against the `Paths` the caller passes.
3. **Combine**: the line is safe only when no unit is risky, and a risky line
   carries every finding.

Three functions answer three questions of the same reading: `classify`,
whether the line is safe; `effect`, whether it only reads (and whether the
reads stay in the workspace), changes something, or cannot be told; and
`explain`, how the line was read, unit by unit, drawn as a short tree for a
person to see.

What cannot be read is risky: a program or a script known only when it runs,
a line the grammar cannot parse, shells nested past a limit. Nothing here
touches the file system or the environment: a Windows line is judged on macOS
as it would be on Windows.

## Install

Through the front door, where it is the `shell` feature (on by default):

```toml
[dependencies]
milo-guards = "0.1"
```

Or on its own:

```toml
[dependencies]
milo-guards-shell = "0.1"
```

The `inline` feature (on by default) reads the Python and JavaScript a line
gives an interpreter; off, such a line is still found but none of its code is
read, every inline line is `unknown`, and neither grammar is built. If your
program also links tree-sitter, it has to be on the 0.26 runtime.

## Example

```rust
use milo_guards_shell::{classify, effect, Effect, Paths, Reach, Rule, Shell};

let paths = Paths::new("/home/me/work/repo", "/home/me", ["/home/me/work/repo"]);

// Building inside the workspace is the agent's own business.
assert!(classify("cargo build && rm -rf target", Shell::Posix, &paths).is_safe());

// Deleting the home directory is not, and the answer says why.
let assessment = classify("rm -rf ~", Shell::Posix, &paths);
let finding = &assessment.findings()[0];
assert_eq!(finding.rule, Rule::Delete);
assert_eq!(finding.target.as_deref(), Some("~"));

// Whether a line only reads is a second answer, from the same split.
assert_eq!(effect("git status", Shell::Posix, &paths), Effect::ReadsOnly(Reach::Workspace));
assert_eq!(effect("mkdir build", Shell::Posix, &paths), Effect::Changes);
assert_eq!(effect("./script.sh", Shell::Posix, &paths), Effect::Unknown);
```

## Contract

Like every milo-guards crate: no I/O and no environment reads, deterministic
(the same input gives the same answer on every machine), no policy (it
reports, and what to do with a finding is the caller's), what cannot be read
is risky, and nothing it is given makes it panic. The rules are on the
repository's [guidelines](https://github.com/camiloazula/milo-guards/blob/main/GUIDELINES.md).

## License

MIT or Apache-2.0, at your option
([LICENSE-MIT](https://github.com/camiloazula/milo-guards/blob/main/LICENSE-MIT),
[LICENSE-APACHE](https://github.com/camiloazula/milo-guards/blob/main/LICENSE-APACHE)). Part of
[milo-guards](https://github.com/camiloazula/milo-guards); the API is on
[docs.rs](https://docs.rs/milo-guards-shell).
