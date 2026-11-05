# milo-guards-core

What every guard of [milo-guards](https://github.com/camiloazula/milo-guards) shares: the verdict types, the path
model and the test kit.

A guard reads what an agent is about to do and says whether it is safe to do
without asking, or risky and why. This crate holds the parts of that which do
not depend on what is being read:

- **The verdict.** `Assessment` is `Safe`, or `Risky` with a `Finding` for
  each reason. A finding names a rule of the guard's own enum (which
  implements `RuleName`, with a stable wire name), the reason in words, the
  target it is about, and where there is one, what to do instead.
- **The directories everything is judged against.** `Paths`: the working
  directory, the home directory and the workspace folders, with the files
  the caller gates (`Protected`).
- **The path model.** `Resolver` says where a path spelled out as text lands
  (`Place`), by its spelling alone, for POSIX and Windows (`Flavour`), on
  whatever host it runs.
- **For guard crates**, helpers that take a path's spelling apart
  (`spelling`), and behind the `testing` feature the table checker and the
  sample directories the guards test themselves with.

It depends on nothing beyond `std`, and does no I/O.

## Install

A caller of the guards depends on [`milo-guards`](https://docs.rs/milo-guards),
which re-exports this crate's types; depend on this crate directly only to
write a guard of your own.

```toml
[dependencies]
milo-guards-core = "0.1"
```

## Example

```rust
use milo_guards_core::{Flavour, Paths, Place, Resolver, Spelling};

let paths = Paths::new("/home/me/work/repo", "/home/me", ["/home/me/work/repo"]);
let resolver = Resolver::new(&paths);
let place = |path| resolver.place(Spelling::Plain(path), Flavour::Posix);
assert_eq!(place("src/../target"), Place::Inside);
assert_eq!(place("/home/me"), Place::Home { exact: true });
assert_eq!(place("/etc/hosts"), Place::Top("a system folder"));
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
[docs.rs](https://docs.rs/milo-guards-core).
