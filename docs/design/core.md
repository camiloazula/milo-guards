# Core

`milo-guards-core` holds what every guard shares. It depends on nothing but
`std`, and it does no I/O. This page covers the types, the path model, and the
test kit.

## The types

**`Paths`** is the directories a guard judges paths against. Build one with
`Paths::new(cwd, home, workspaces)`; the struct is `#[non_exhaustive]`, so a
field added later does not break a caller. The fields stay public to read.

- `cwd`: where the work happens. Relative paths resolve from here.
- `home`: the user's home directory.
- `workspaces`: the folders the agent may change.

Paths are judged by how they are spelled, so these must be spelled the way the
paths being judged will be. Give them absolute, and either all canonical or
all as the user wrote them. A relative `cwd` puts every relative path outside
the workspace. So does a `cwd` read through a symlink (`/private/tmp/...`) when
the workspace is spelled without it (`/tmp/...`). With no workspace at all,
every path is outside.

**`Assessment<R>`** is the answer: `Safe`, or `Risky(Vec<Finding<R>>)` with
every finding, in the order the input reads. `is_safe()` and `findings()` read
it. `findings()` is empty when the answer is safe. As a guard builds it, a
`Risky` always holds at least one finding: a guard that found nothing answers
`Safe`. The type is `#[must_use]`, so ignoring an answer is a warning.

**`Finding<R>`** is one reason something is risky. It is a plain struct, so a
caller can build one:

- `rule`: the rule that found it.
- `reason`: what it would do, in a few plain words a permission prompt can
  show, such as `deletes your home directory`.
- `target`: the part of the input it is about, as written, where there is one,
  such as `~`.

**`RuleName`** is a trait that a guard's enum of rules implements. The enum is
the guard's, and each guard calls it `Rule`; the trait is not called `Rule` so
the two never clash where both are in scope, as at the front door's root. The
trait asks for `Copy + Eq + Hash + Debug` and one method,
`name(self) -> &'static str`: the rule's stable name on the wire. It is for
generic code, such as the test kit. A guard's enum also has an inherent `name`,
so a caller that holds the enum imports nothing.

- A wire name is `snake_case`: `delete`, `wipe_disk`, `git_history`.
- It never changes once a caller uses it, whatever the variant is called in
  code. To change what a rule means, add a new rule.
- Each guard tests that its names are what its page says.

A reason is for a person. A wire name is for a program. A caller matches on
the rule and shows the reason.

The types `Assessment` and `Finding` do not bound their rule type, so they work
for any type; the test kit asks for `RuleName` where it needs the names.

## The path model

The path model answers one question: where does this path land, and so what
does touching it mean? The answer is a **`Place`**.

| Place | Meaning |
| --- | --- |
| `Inside` | Inside a workspace folder. The agent's to change. |
| `Temp { exact }` | A temporary directory itself, or a path under one. |
| `Null` | A device that discards or echoes: `/dev/null`, `NUL`. |
| `Workspace { exact }` | A workspace folder itself, or a folder holding one. |
| `Home { exact }` | The home directory itself, or a folder holding it. |
| `Top(words)` | The root of a disk, a system folder, or a top-level folder. |
| `Sensitive(words)` | Keys, credentials, shell startup files, the repository's history. |
| `Disk` | A disk device. |
| `Registry` | The Windows registry. |
| `Outside` | Anywhere else beyond the workspace. |
| `Unknown` | Known only when the input runs. |

`harmless()` says whether touching a place is the agent's own business: inside
a workspace, a temporary file, or the null device. `words()` gives the place in
the words of a reason, so a rule can say `deletes {words}`.

`Place` is `#[non_exhaustive]`: a place may be added, so a `match` on it needs
a fallback arm. A fallback should treat the new place as not harmless.

`Resolver::new(&Paths)` builds a resolver. `place(path, flavour)` says where a
path lands. `key(path, flavour)` gives a string that is the same for two
spellings of one file, which a guard uses to notice a script that a line both
writes and runs. It is `None` when the path is not one definite file: a device
or a wildcard.

### What a path is

Core takes a path that is already spelled out as text. It does not know what
shell, tool or language the text came from. Two things come with it.

**A `Flavour`**, `Posix` or `Windows`, says how the text is spelled.

- `Posix`: `/` separates. A backslash or a colon is part of a file name.
- `Windows`: `/` and `\` separate. A path can start with a drive letter
  (`C:`) or a share (`\\server\share`). Names compare without case. `NUL`,
  `CON` and `\\.\` are devices.

The flavour follows the system the path will be used on, not the host the
guard runs on. That is why a Windows line is judged the same on every host.

**A `Spelling`** says where the text starts. `Plain(text)` is a path as
written, absolute or from the working directory. `Home(rest)` is the part
below the home directory, however it starts. A guard whose input has a way to
say "my home" (`~` in a shell) gives core `Home` and keeps the syntax to
itself.

### What core judges

- `.` and `..` are applied. A `..` at the top is dropped.
- A path is compared with the directories in `Paths`: the home directory, the
  workspaces, the temporary folders, the system folders, and a list of
  sensitive places under the home directory (SSH keys, cloud credentials,
  shell startup files, keychains, the PowerShell profile). A workspace's own
  `.git` is sensitive.
- Windows paths compare without case. POSIX paths compare with it.
- A part with a wildcard (`*`, `?`, `[`) stands for one entry, so a `..` after
  it still climbs: `src/*/../../x` is outside `src`. What a pattern matches
  lies in the folder before its first wildcard part. `glob::shape` says how
  much of it: a pattern whose last part is a catch-all (`*`, `?*`, `*/*`)
  takes the whole folder, a pattern that picks names (`*.log`) touches files
  inside it, and a part that starts with `.` can match `.git`.
- Devices are told by their spelling. On POSIX the path's `.` and `..` are
  applied first, then the name must be exactly one of `/dev/null`,
  `/dev/stdout`, `/dev/stderr`, `/dev/tty`, `/dev/zero`, `/dev/random`,
  `/dev/urandom`, `/dev/fd/<digits>` (and nothing else under `/dev/fd`), or a
  disk under `/dev`. A path that climbs out of a device is no device:
  `/dev/fd/../../Users/me` is the home directory, and is judged as such. A
  name followed by `/` or `/.` is no device either, since descriptor 3 could
  be a folder. On Windows, `/dev` is a real folder on the current drive, so
  only the plain `/`-separated spellings above count, never normalised
  (`/dev\null` and `/dev/./null` are files), plus `NUL`, `CON` and `\\.\`;
  the `\\.\` namespace is a root that `..` cannot leave, so everything
  spelled below it is a disk. A text with a `{` can expand to paths it does
  not show, so it is never a device; the shell guard checks for a brace list
  before it asks whether a path is a device.
- Nothing reads the file system. A symlink is judged by its own name.

Core never answers `Unknown` or `Registry`. A path spelled out as text is a
file path. A guard that reads the syntax around it says when a path is not
one.

### What the guard keeps

A guard keeps everything that depends on the syntax of its input. The shell
guard keeps these:

- Its `Arg` type, which says whether an argument's value is known.
- `~` and `~user`: it hands core `Home` for the first and answers `Unknown` for
  the second.
- `$HOME`, `%USERPROFILE%` and `$env:TEMP`: it turns each into the place it
  names before it asks, unless the line sets that variable.
- PowerShell's provider paths and drives, such as `HKLM:` and
  `FileSystem::C:\x`. A registry drive is `Registry`; any other drive is
  `Outside`.
- `$null`, and brace lists such as `{~,x}`, which are `Unknown`.
- `within`, which joins a path to the folder an earlier `cd` moved to.
- `listed`, which says what a listing hands on to the next command.

The seam is the text of a path. Above it is everything the input's syntax
decides. Below it is only how a path is spelled on a system.

### The spelling helpers

Some guards need to take a path's spelling apart before they hand it to the
resolver. Those helpers are in the `spelling` module, not at the crate root,
and are for guard crates, not callers: `parts` (the parts of a relative path,
dots applied), `device` (the device a path names) and the `glob` module
(`has_wildcard`, and `shape` with its `Shape`, which is `#[non_exhaustive]`).
The root holds only `Paths`, the verdict types, `Place`, and the resolver with
its `Flavour` and `Spelling`.

## The test kit

The `testing` module is behind the `testing` cargo feature. A guard takes it
as a dev-dependency:

```toml
[dev-dependencies]
milo-guards-core = { workspace = true, features = ["testing"] }
```

It has three sample `Paths`, built with `Paths::new`: `posix()`, `macos()` and
`windows()`, each with the workspace in the user's folder.

It has `check(safe, risky, judge)`. `safe` is a list of inputs that must come
back safe. `risky` is a list of inputs each with the rule it must break.
`judge` is a closure that runs the guard. `check` runs every row and names all
the wrong ones at once, so one failing run shows everything to fix. It is
generic over the rule and the judge, so every guard tests the same way.

And it has `rules(input, judge)`, the rules an input breaks, in order, for a
test that wants to assert more than one.

A guard wraps `check` in a small helper that fixes the judge, and writes its
tests as tables.
