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
- `protected`: what the caller gates with, such as its own settings and rules.
  Empty from `Paths::new`; add to it with `Paths::with_protected`, which
  takes `Protected` values and can be called again to add more.

**`Protected`** is a path, the words a reason calls it by, and whether it is a
file or a folder (`kind`, a `ProtectedKind`): a plain struct
`{ path, words, kind }`, built with `Protected::file(path, words)` or
`Protected::folder(path, words)`. The caller knows which it protects, and that
costs the guard no I/O; only a folder has something below its name, which is
what a pattern is read by (below). `words` is
`&'static str`, as in `Place::Sensitive`, and follows the verb of a reason
(`the agent's settings`: "deletes the agent's settings"). A guard never names
its caller, so the caller passes in the files it gates with, and neither core
nor any guard knows what they are.

Paths are judged by how they are spelled, so these must be spelled the way the
paths being judged will be. Give them absolute, and either all canonical or
all as the user wrote them. A protected path is spelled the same way as the
workspace. A relative `cwd` puts every relative path outside
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
| `Sensitive(words, kind)` | Keys, credentials, shell startup files, the repository's history; `kind` is a `Sensitivity`. |
| `Protected(words)` | A path the caller named in `Paths::protected`, in the caller's words. |
| `Disk` | A disk device. |
| `Registry` | The Windows registry. |
| `Outside` | Anywhere else beyond the workspace. |
| `Unknown` | Known only when the input runs. |

`harmless()` says whether touching a place is the agent's own business: inside
a workspace, a temporary file, or the null device. `Protected` is never
harmless. `words()` gives the place in
the words of a reason, so a rule can say `deletes {words}`.

`Place` is `#[non_exhaustive]`: a place may be added, so a `match` on it needs
a fallback arm. A fallback should treat the new place as not harmless.

**`Sensitivity`** says what touching a `Sensitive` place means, so a guard can
tell reading a key from reading a startup file without matching on the words:

| Kind | What it is | A read | A write |
| --- | --- | --- | --- |
| `Secret` | A key or a credential: SSH, GPG, cloud and registry logins, keychains, the system's password hashes and host keys. | Exposes it. | Replaces it. |
| `Startup` | A file that runs, or sets how something runs, later: shell startup files, git's settings, the PowerShell profile, what Windows, macOS and a desktop start at login. | Harmless. | Plants a command. |
| `History` | The repository's history: a workspace's own `.git`. | The agent's everyday work. | Loses work. |

`Sensitivity` is exhaustive, unlike `Place`: what a read of each kind means is
a guard's policy, so a kind added later must break each guard's `match` at
compile time instead of falling into a fallback arm that reads it as harmless.

`Resolver::new(&Paths)` builds a resolver. `flavour()` says how paths are
spelled on the machine `Paths` describes: `Windows` when the home directory is
a Windows path (a drive, a share), `Posix` otherwise. `place(path, flavour)` says where a
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
  sensitive places. The list is of places known to hold something, not a
  proof that nowhere else does:
  - under the home directory, with a `Sensitivity` each: keys and credentials
    (`.ssh`, `.gnupg`, `.aws`, `.azure`, `.kube`, `.docker`, `.netrc`,
    `.git-credentials`, `.npmrc`, `.pypirc`, `.vault-token`, `.oci`,
    `.password-store`, `.config/gh`, `.config/gcloud`, `.cargo/credentials*`,
    `.pgpass`, `.my.cnf`, `.s3cfg`, `.gem/credentials`, `.m2/settings.xml`,
    `.terraform.d/credentials.tfrc.json`, `.config/rclone`, `.config/op`,
    `.config/sops/age`, `.config/hub`, keyrings, macOS keychains, GitHub CLI,
    gcloud and GnuPG under `AppData\Roaming`, Windows saved logins, vaults and
    encryption keys) are `Secret`; shell startup files, `.gitconfig`,
    `.config/git/config`, fish's config, the PowerShell profile (also under
    `.config/powershell` and `OneDrive\Documents`), `Library/LaunchAgents`,
    `.config/autostart`, `.config/systemd/user` and the Windows Startup folder
    are `Startup`;
  - the same places in any other user's home directory and in the root
    user's (`/root`, `/var/root`). The folders under `/home`, `/Users` and
    `C:\Users` are always homes, and so are the entries of the folder that
    holds this home directory, whatever this user's own home is (`/root`,
    `/var/lib/ci`);
  - the system's own secrets, as `Secret`: `/etc/shadow` and its kin, the
    host SSH keys, private TLS keys, WireGuard and Kerberos keys, saved
    network passwords, the macOS keychains and password database (under
    `/private` too), a container's `/run/secrets` and `/var/run/secrets`, the
    memory a system keeps on disk (`/var/vm`, `sleepimage` and the swap files),
    and on Windows the account database in
    `System32\config`, the DPAPI keys and `ProgramData\ssh`.

  A workspace's own `.git` is `History`.
  - **A workspace that holds a sensitive place does not make it the agent's.**
    When the home directory is the workspace (or a folder above it, or
    another user's home), `.ssh/id_rsa` is `Secret` and `.git` stays
    `History`; only a workspace inside a sensitive folder
    (`~/.docker/proj`) keeps its own paths `Inside`. A sensitive place is
    also judged before a temporary folder.
- Windows paths compare without case. POSIX paths compare with it, except
  the home directory, the sensitive places and protected paths, which compare
  without case on every host: a macOS file system ignores it, and a name that
  differs only by case is the same folder there. Case is the widest fold
  there is, the Unicode simple fold of each character, as APFS reads it: the
  long s `ſ` is an `s`, the Kelvin sign `K` a `k`, the Ångström sign `Å` an
  `å`, the Ohm sign `Ω` an `ω` and the capital sharp s `ẞ` a `ß` (`.ſsh` is
  `.ssh`). NTFS does not fold the signs. So the wide fold is used only where
  matching too much fails closed: the home directory, the sensitive places,
  protected paths and `.git`. The workspace and the temporary folders compare
  as spelled on POSIX and by ASCII case on Windows, where matching too much
  would make another folder the agent's own: `C:\Users\me\worK` is not the
  workspace `C:\Users\me\work`.
- A name is also its Windows 8.3 short name, in the home directory and the
  sensitive places as for a protected path: `C:\Users\CAMILO~1\SSH~1\id_rsa`
  is `C:\Users\Camilo Azula\.ssh\id_rsa`. A POSIX name has no short form.
- macOS's links to the root are read: `/System/Volumes/Data/...`,
  `/Volumes/Macintosh HD/...` and `/Volumes/Macintosh HD - Data/...` are
  `/...`, as often as they come. Where matching too much fails closed (a
  secret, the home directory, another user's home, a protected path) they are
  dropped on every system, which costs noise: `/Volumes/Macintosh HD/etc/shadow`
  is a secret on Linux too. For the workspace and the temporary folders they
  are dropped only on a Mac (a home directory under `/Users`, or root's,
  `/var/root` or `/private/var/root`): elsewhere those paths do not exist, a
  write to one creates folders, and it is not the workspace's. Every path is made absolute first (`~`
  and `..` applied, the working directory prepended), and then the links are
  dropped, so `../../../../System/Volumes/Data/Users/me/.ssh` and `~/../..`
  spellings are read as `/Users/me/.ssh`. Their names compare as a Mac's file
  system does, by the widest fold: `/Syſtem/Volumes/Data` is the same folder.
- A protected path, and anything under it, is `Protected`. **Protected wins over
  the workspace**, and over a temporary folder: a protected file inside a
  workspace folder is `Protected`, not `Inside`, because the caller named it on
  purpose. Only a device and the home directory itself (or a folder holding it)
  are judged before it. It is its own place, not `Sensitive`, so a guard can
  tell a caller's own files from keys and a caller can decide differently for
  each. Like everything here it is spelling alone: the caller spells a
  protected path the way it spells the workspace, and a symlink to one is
  judged by its own name.
  - **A verdict that would otherwise be harmless is checked again against the
    protected paths**, and a protected path wins when the path holds one (is
    an ancestor folder of it) as well as when it is one or under one: a
    delete of `conf` is a delete of the protected `conf/app/x.yaml`. A verdict
    that is already risky keeps its own place and words, so `rm -rf ~` still
    says it deletes the home directory and `rm -rf .` at the workspace root
    says the workspace; a path that is a protected one, or under it, is the
    exception, since it is the caller's file whatever else it is (a protected
    file in the home directory is `Protected`, not `Outside`). This
    replaces an earlier choice not to cover a folder holding a protected path.
  - **A write into a folder is not a write of what it holds.**
    `Resolver::place_into` is `place_hidden` without the holding rule, for a
    path something is written into (a copy's destination, a redirect's
    target): `cp a.txt conf/` and `touch conf/new.txt` stay the agent's own
    beside a protected `conf/app/x.yaml`, while a write to the protected path
    or a pattern that picks it is still protected. The shell guard asks it for
    writes and `place_hidden` for everything else. A copy, move or link into a
    folder puts each file at its own name there, so the shell guard also
    judges that landing path (the destination plus the source's last part,
    a pattern for a wildcard or unknown source, both readings of a
    destination that may be a file or a folder): `cp x.yaml conf/app/` writes
    the protected `conf/app/x.yaml`, and `cp *.yaml conf/app/` can. A
    recursive copy or mirror (`cp -r`, `-R`, `-a`, `rsync -a`, `Copy-Item
    -Recurse`, `robocopy /E`, `xcopy /s`) can replace anything below its
    destination, so there the full `place` is used, holding rule included.
    What other rules own stays theirs: `rsync --delete` and `robocopy /MIR`
    delete through the delete rule, and unpacking an archive is not read.
  - **Names compare without case on every host**, not only Windows: a macOS
    or Windows file system ignores it, and the caller names a path as it
    knows it. A protected name is also matched, on Windows, by its 8.3 short
    name (`AGENT~1` for `.agent`, `SETTIN~1.YAM` for `settings.yaml`, or two
    characters, four hex digits and `~1`), the way a workspace's `.git` is,
    from one rule for both. A POSIX name has no short form.
  - **A pattern that can pick a protected path or a folder holding it is
    protected.** The pattern's parts, from its first wildcard part, are matched
    against the path's names below the folder the pattern starts in, one for
    one, without case (`set*` and `*.yaml` pick `repo/settings.yaml`, `.a*`
    picks `repo/.agent` where wildcards match hidden names, `AGENT~*` picks
    `.agent` on Windows). A pattern that reaches the path, or goes below a
    protected folder (`cfg*/x`), picks it, and wins over any place
    but the workspace or a temporary folder itself. One that stops at a folder
    holding it picks that folder (`c*` for `repo/conf/app/x.yaml`), which
    counts only where the verdict would be harmless. A part of two or more
    stars alone may stand for any number of names a `*` could match, the
    protected name itself included, and all the rest when it is the last part
    (`**/x.yaml`, `conf/**`). **Only a folder lets a pattern go below the
    protected name**: the stars can take a protected folder `cfg` and what
    follows goes into it, so `**/*.rs` and `**/rules` are protected, and so is
    `*/x` for a protected folder `conf`; a protected file is matched only as
    the last part, so with a protected file `conf/app/x.yaml`, `**/x.yaml` and
    `conf` are protected but `**/y.yaml`, `**/*.rs` and `**/*.pyc` are not.
    The holding rule (ancestor folders) and the landing rule for a copy apply
    to both kinds. **The two mistakes fail differently.** A folder marked as a
    file opens patterns below its name: with `cfg` a folder marked as a file,
    `c*/rules` and `**/rules` come back safe. A file marked as a folder only
    adds noise: `**/*.rs` is a finding. So when the caller is unsure, it
    should say `folder`. This is why the caller says which it protects, and why
    there is no constructor that does not: without it every `**/<name>` would
    be a finding wherever a protected file exists. A catch-all at the workspace root is
    still the workspace. Without this a glob inside a workspace would reach a
    protected file that its spelling does not name.
- Windows names are normalised before they are compared, so a spelling that
  Windows resolves to a protected name is judged as that name. Core does this
  in the `Windows` flavour only; a POSIX name keeps every character. `.` and
  `..` are applied first, as Windows does, and then:
  - **The last part** loses every trailing dot and space, so `.git.` and
    `.git ` are `.git`, and `notes.txt.` is `notes.txt`. Only a plain space
    (U+0020) counts: a no-break space (U+00A0) or an ideographic one (U+3000)
    is part of the name.
  - **A part before the last** loses one trailing dot, and nothing else, so
    `.git.\objects` is `.git\objects`.
  - **A part with a wildcard** is not trimmed: what a pattern like `.g*.` can
    match is judged by `glob`, which does not yet read the trailing dot.
  - **Short names.** A part directly in a workspace folder that is `GIT~N`, or
    `GI`, four hex digits and `~N` (the form Windows hashes a name to once
    names collide), may be the 8.3 short name of `.git`, which drops the dot.
    It is judged as the repository's history. Any other `NAME~N` is a plain
    name (`PROGRA~1`, `GITHUB~1`), as is a `GIT~1` deeper down, like a `.git`
    there.
  - **Known only when it runs.** The path is `Unknown`, since the spelling
    does not say which name it is, when a part:
    - holds a `:` below the drive or share: a stream of a file or folder
      (`x.txt:stream`, `.git::$INDEX_ALLOCATION`). The drive (`C:`), the share
      and the devices (`NUL:`) are read first; a shell's own provider prefix
      (`HKLM:`) is the shell's, read before the path reaches core. One letter
      and a colon is a drive, as Windows reads it;
    - is on a drive's own working directory, on a drive other than the
      working directory's (`D:x`, `D:`: a letter, a colon and no separator).
      Which folder that is depends on the process. On the drive the working
      directory is on it is relative to it (`C:..\..\.ssh` from
      `C:\Users\me\dev\repo` is the home directory's `.ssh`), and `C:\x` with
      its separator is the drive's root;
    - is nothing but dots and spaces, and not exactly `.` or `..`
      (`...`, `. `, `.. `), wherever it is;
    - is before the last and still ends in a dot or a space once its one
      trailing dot is gone (`x `, `x..`, `x .`, `repo \x`). A path that ends
      in a separator has its last name before the last part, so `.git \` is
      one of these.
- A part with a wildcard (`*`, `?`, `[`) stands for one entry, so a `..` after
  it still climbs: `src/*/../../x` is outside `src`. What a pattern matches
  lies in the folder before its first wildcard part. `glob::shape` says how
  much of it: a pattern whose last part is a catch-all (`*`, `?*`, `*/*`)
  takes the whole folder, a pattern that picks names (`*.log`) touches files
  inside it, and a part that starts with `.` can match `.git`.

  A PowerShell or cmd wildcard also matches a name's leading dot, so on the
  `Windows` flavour a wildcard part directly in a workspace folder can pick
  `.git` (`*git`, `?git`, `????`), and the resolver answers the repository's
  history for it. `glob::reaches_git` tells it. The first wildcard part must
  match `.git`. When it is the last part (and not a catch-all, which is the
  whole folder) it takes `.git` itself. When more follows, the next part
  must match one of `.git`'s own entries (`HEAD`, `config`, `index`,
  `objects`, `refs`, `hooks`, `info`, `logs`, `packed-refs`, `modules`, `lfs`,
  `worktrees`, `shallow`, `ORIG_HEAD`, `MERGE_HEAD`, `rebase-merge`,
  `rebase-apply`, `sequencer`): `*\objects`, `*\modules` and `????\HEAD` reach
  it, `*\bin` and `*\obj` do not. Only the part after the one that matches
  `.git` is read, so `*\logs` or `*\config` at the workspace root is judged
  risky even if the `*` picks a folder of that name that is not `.git`; that
  is accepted as rare. Deeper than the workspace
  folder (`src\*git`, `src\*\bin`) only the workspace's own `.git` is the
  model's to protect, so they stay the agent's. On the `Posix` flavour a
  wildcard does not match a leading dot, so `*git` and `?git` pass, unless
  the caller says hidden names match: `Resolver::place_hidden(path, flavour,
  hidden)` reads the pattern as the `Windows` flavour does (`place` is the same
  with `hidden` off). A shell guard sets it from the line, for a shell that
  has switched on bash's `dotglob`, zsh's `globdots`, or a non-empty
  `GLOBIGNORE`; it changes nothing on `Windows` or for a path without a
  wildcard. Only the leading dot changes: case and `[!x]` negation still read
  as POSIX. Under a workspace folder `*git`, `?git`, `*.*` and `*/objects`
  then reach the repository's history.

  `glob::matches` is the matcher behind it: one pattern part against one name
  (`*`, `?`, `[...]`, ranges). On `Windows` it reads PowerShell's rules, with
  no negation in a class (`!` and `^` are members, so `[!.]git` matches
  `.git`) and a backtick making the next character itself, and compares
  names without case by the Unicode case of each character, class members
  included (a dotless `i`
  counts as `i`). On `Posix` `[!x]` and `[^x]` negate and case counts. Its
  `hidden` flag says whether a wildcard may match a leading dot; the resolver
  sets it on `Windows`, and on `Posix` when the caller passes it to
  `place_hidden`.
  On `Windows`, `*.*` as a last part is a catch-all like `*`. That is cmd's
  meaning; in PowerShell it needs a dot in the name, so taking it as every
  entry is the wider reading.
- A Windows **long path** is the drive or the share it names: `\\?\C:\x` is
  `C:\x`, and `\\?\UNC\server\share\x` is `\\server\share\x`, with either
  separator (`//?/C:/x`) and any case. A long path that names neither
  (`\\?\GLOBALROOT\...`, `\\?\Volume{...}\...`, `\\?\C:x`) is in a namespace
  of its own, a `Disk`, like everything below `\\.\`. The folders in `Paths` may be
  spelled as long paths too (a canonical path on Windows is): the prefix is
  read the same way.
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

Core never answers `Registry`. A path spelled out as text is a file path. A
guard that reads the syntax around it says when a path is not one. Core
answers `Unknown` for the Windows spellings it cannot read to a name, listed
under "What core judges".

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
- `listed`, which says what a listing hands on to the next command: a pattern
  as written, so it is judged as a delete of it would be.

The file guard keeps less: a file API takes one literal path, so it answers
`Unreadable` for a wildcard, a variable and `~user` itself, and hands core
`Home` for a `~` at the start (and the literal reading of the same text as
well).

The seam is the text of a path. Above it is everything the input's syntax
decides. Below it is only how a path is spelled on a system.

### The spelling helpers

Some guards need to take a path's spelling apart before they hand it to the
resolver. Those helpers are in the `spelling` module, not at the crate root,
and are for guard crates, not callers: `parts` (the parts of a relative path,
dots applied), `device` (the device a path names) and the `glob` module
(`has_wildcard`, `matches`, `reaches_git`, and `shape` with its `Shape`, which
is `#[non_exhaustive]`), `network` (whether a text names a place on another
machine: a share, spelled with two separators or as a long path or device path;
`false` on `Posix`) and `verbatim` (what follows a `\\?\` prefix, either
separator).

Two questions are `Resolver` methods, since a guard needs them resolved: the
path made absolute, with the working directory and `~` applied.

- `kernel(path, flavour)` is `Some(words)` for what a POSIX kernel serves that
  is a file only by name: anything under `/dev` that is not `null`, `zero`,
  `random`, `urandom`, `tty`, `stdin`, `stdout`, `stderr` or descriptors 0 to
  2, and anything under `/proc` that is not one of the machine's own facts
  (`cpuinfo`, `meminfo`, `version`, `loadavg`, `uptime`, `filesystems`): a
  process's environment, memory, command line and maps, and `root` and `cwd`,
  which lead to any file. It is a whitelist of what is safe, never a list of
  what is not. It answers `None` on Windows, where the device namespace is a
  `Disk`. It does not change `place`, so the shell guard's verdicts stay
  what they were.
- `git(path, flavour)` is `Some(words)` for a path in a git repository's own
  folder at any depth, `vendor/x/.git/hooks/pre-commit` and not only the
  workspace's `.git`: `a git hook, which runs code` for `hooks`, and `the
  repository's history` for the rest. `place` still reads only the
  workspace's own `.git`, so the shell guard's verdicts are unchanged.
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
