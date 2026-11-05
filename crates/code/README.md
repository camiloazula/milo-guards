# milo-guards-code

Reads Python and JavaScript code and says what it is certain to do to files
and what it runs, or that it does not understand it. Part of
[milo-guards](https://github.com/camiloazula/milo-guards); a reader, not a guard.

A shell line can hand an interpreter code (`python3 -c`, `node -e`), and an
agent can write a script or run a snippet directly. What matters to a guard
is which files the code deletes, writes, reads and moves, and what it runs.
This crate reads Python and JavaScript (Node, Bun and Deno) with their own
tree-sitter grammars and answers two questions of a piece of code:

- **What is it certain to do?** `read` gives the `Act`s the code makes, in
  order: a delete, a write, a read, a move, a program started, an
  environment changed, each with the paths it names. What the reader cannot
  follow comes out as `Act::Unread`, never left out.
- **Does it understand the code?** `understand` holds the code to a strict
  allow-list: a few plain statements whose every call, name and import is on
  a short list that only computes. Anything else is
  `Understanding::NotUnderstood`, and a caller must not take "no acts" for
  "does nothing" for such code.

The reader judges nothing. Whether a delete of a path is risky is the
caller's: the shell guard of milo-guards turns an act into what it already
judges (a delete is `rm -rf PATH`, a command line a script a shell reads).

## Install

Through the front door, where it is the `code` feature (on by default) and
what the shell guard reads inline code with:

```toml
[dependencies]
milo-guards = "0.1"
```

Or on its own:

```toml
[dependencies]
milo-guards-code = "0.1"
```

If your program also links tree-sitter, it has to be on the 0.26 runtime:
tree-sitter allows one version per lockfile.

## Example

```rust
use milo_guards_code::{read, understand, Act, Arg, Language, Understanding};

// A snippet that computes is understood, and does nothing to a file.
let code = "print(1 + 1)";
assert!(read(Language::Python, code).acts.is_empty());
assert_eq!(
    understand(Language::Python, code),
    Understanding::Understood { imports: true },
);

// A delete is an act with the path it names, kept whatever the code is.
let code = "import shutil\nshutil.rmtree('/home/me')";
let reading = read(Language::Python, code);
assert!(matches!(&reading.acts[..], [Act::Remove(Arg::Known(path))] if path == "/home/me"));
assert_eq!(understand(Language::Python, code), Understanding::NotUnderstood);

// A name only known when the code runs is an argument it does not know.
let reading = read(Language::JavaScript, "require('fs').rmSync(process.argv[1])");
assert!(matches!(&reading.acts[..], [Act::Remove(Arg::Unknown(_))]));
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
[docs.rs](https://docs.rs/milo-guards-code).
