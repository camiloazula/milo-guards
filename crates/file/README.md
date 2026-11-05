# milo-guards-file

Judges one read or write of a path through a file API and says whether it is
safe without asking, or risky and why. The file guard of
[milo-guards](https://github.com/camiloazula/milo-guards).

A shell line shows what a shell is about to do; an agent also reads and
writes files through a file API, and no line shows those calls. This guard
takes the two things such a call has, an `Access` and the path as the agent
wrote it, and judges them: `judge`.

The path is one literal path, resolved by its spelling alone against the
`Paths` the caller passes: relative to the working directory, `~` as the home
directory, `..` applied, and the Windows spellings (drives, shares, long
paths, short names, any case) read as Windows reads them, whatever host the
guard runs on. Nothing is read from the disk, so a symlink is judged by its
own name.

- A **read** is safe wherever it lands, except a key or a credential
  (`read_secret`). An agent reads widely, and reading is what a caller lets
  run unasked.
- A **write** (an edit, a create, an append, a rename's target) is safe
  inside a workspace folder, to a temporary file and to the null device.
  Anywhere else is a finding: beyond the workspace (`write_outside`), to a
  key, a startup file, a file a tool runs on its own or the repository's
  history (`write_sensitive`), or to what the caller gates
  (`write_protected`).
- A path that is not one literal path, or that cannot be placed, is
  `unreadable`; one on another machine is `network_share`.

## Install

Through the front door, where it is the `file` feature (on by default):

```toml
[dependencies]
milo-guards = "0.1"
```

Or on its own:

```toml
[dependencies]
milo-guards-file = "0.1"
```

## Example

```rust
use milo_guards_file::{judge, Access, Paths, Rule};

let paths = Paths::new("/home/me/work/repo", "/home/me", ["/home/me/work/repo"]);

assert!(judge(Access::Read, "src/main.rs", &paths).is_safe());
assert!(judge(Access::Write, "src/main.rs", &paths).is_safe());

let assessment = judge(Access::Read, "~/.ssh/id_ed25519", &paths);
assert_eq!(assessment.findings()[0].rule, Rule::ReadSecret);
assert_eq!(assessment.findings()[0].reason, "reads your SSH keys");

let assessment = judge(Access::Write, "../other/x", &paths);
assert_eq!(assessment.findings()[0].rule, Rule::WriteOutside);
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
[docs.rs](https://docs.rs/milo-guards-file).
