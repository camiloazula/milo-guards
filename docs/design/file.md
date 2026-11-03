# File

`milo-guards-file` judges one read or write of one path, the way an agent does
it through a file API rather than a shell line.

```rust
judge(access, path, &paths) -> Assessment
```

`access` is an `Access`, `Read` or `Write`. An edit, a create, an append and a
rename's target are all `Write`: the guard has no finer verbs. `path` is the
one argument as the agent wrote it. `paths` comes from `Paths::new(cwd, home,
workspaces)`, with `with_protected` for what the caller gates with. The answer
is `Safe`, or `Risky` with every finding: a rule, a reason a prompt can show,
and the path as written.

The guard never touches the disk. The path is resolved by its spelling alone
with core's path model (see [Core](core.md)): relative to the working
directory, `~` as the home directory, `.` and `..` applied, and Windows
spellings read as Windows reads them whatever host the guard runs on. A
symlink is judged by its own name.

The guard only reports. What to do about a finding is the caller's choice. The
rule `write_protected` exists so that a caller can refuse a write to what it
gates with and only ask about the others. Which of a caller's tools makes the
call is the caller's business: the guard takes an access and a path, never a
tool name.

## What it judges

A **read** is safe wherever it lands, except a key or a credential. An agent
reads widely, and reading is what a caller lets run unasked. A **write** is safe
inside a workspace folder, to a temporary file and to the null device, and
nowhere else.

| Wire name | What it finds |
| --- | --- |
| `read_secret` | A read of a key or a credential: a place core marks `Secret`, or a path under one, or a disk. |
| `write_outside` | A write beyond the workspace: outside it, a system folder, the home directory, the workspace folder itself, a temporary folder itself, a disk. |
| `write_sensitive` | A write to a key, a credential, a shell startup file, a file a tool runs on its own, or the repository's history. |
| `write_protected` | A write to a path the caller protects, in the caller's words. |
| `network_share` | A read or a write that reaches a network share (`\\server\share`). Added to the rule the place itself breaks. |
| `unreadable` | A path that is not one literal path, or that cannot be placed. |

The wire names never change. The enum is exhaustive on purpose, like the shell
guard's: a rule added later breaks each caller's `match`, so the caller
decides.

Reasons follow the verb of the access: `reads your SSH keys`, `reads the
system's password hashes`, `reads a disk, and every key on it`, `writes to a
path outside the workspace`, `writes to your home directory`, `writes to the
whole workspace`, `writes to a shell startup file`, `writes to a file a tool
runs on its own`, `writes to the repository's history`, `writes to the
agent's settings`, `reaches a network
share`. An unreadable path says why: `is empty`, `is too long to read`, `has a
control character`, `starts with a space`, `has a wildcard`, `has a variable
or a command`, `is another user's home directory`, `has a pattern that can
name more than one file`, `is a path only known when it runs`.

### Reading

| Place | A read |
| --- | --- |
| `Sensitive(_, Secret)` | `read_secret`. |
| `Disk` | `read_secret`: the bytes of a disk hold every key on it, and `\\.\C:\x` and `\\?\GLOBALROOT\...` name a file by another route. |
| A device or a kernel file (core's `Resolver::kernel`) | `read_secret`, whatever it holds: anything under `/dev` except `null`, `zero`, `random`, `urandom`, `tty`, `stdin`, `stdout`, `stderr` and descriptors 0 to 2, and anything under `/proc` except the machine's own facts (`cpuinfo`, `meminfo`, `version`, `loadavg`, `uptime`, `filesystems`). `/proc/self/environ` holds the agent's own API keys, `/dev/mem` and `/dev/loop0` hold every file, and `/proc/self/root` and `cwd` lead anywhere. They are `read_secret` and not `unreadable`: the guard can read the path (it knows what it is) and what it leads to is as risky as the secrets it can reach, so the caller's policy for secrets is the one that applies. |
| `Sensitive(_, Startup)`, `Sensitive(_, History)` | Safe: a startup file is read for what it says, the history is everyday work. |
| `Protected` | Safe: reading the caller's own settings is not what it gates. |
| `Unknown` | `unreadable`. |
| anything else | Safe, wherever it lands. |

What counts as a secret is core's table of places known to hold one, with its
`Sensitivity` kind, never a match on words: see [Core](core.md#what-core-judges).
Reading the repository's history and the caller's own settings stays safe on
purpose.

The shell guard gives the same answer for the same file: `cat <path>` is its
`read_secret` exactly when a read of `<path>` is this guard's. A test in the
front door (`crates/guards/tests/agree.rs`) holds them to it on every path of
this guard's case files; see [Shell](shell.md#reading-a-key).

### Writing

A write to a path that is not harmless is `write_protected` for a protected
path, `write_sensitive` for a sensitive one, `unreadable` for an unknown one,
and `write_outside` for every other place (an unknown new place included).

A write to a git repository's own folder, at any depth, is `write_sensitive`
too, not only the workspace's `.git` (`vendor/x/.git/hooks/pre-commit`). A hook
is a program git runs later, so its reason says what it is: `writes to a git
hook, which runs code`; the rest of `.git` is `writes to the repository's
history`. A write to a device that is not safe (`/dev/fd/3` is any file the
process has open) is `write_outside`.

A write to a workspace's own file that a tool runs on its own is
`write_sensitive` too, at any depth: `.vscode/tasks.json`, `.envrc`,
`.husky/pre-commit`, `.github/workflows/ci.yml`, `.gitlab-ci.yml`,
`.devcontainer/devcontainer.json`, `.mcp.json` and the rest of core's list
(see [Core](core.md#what-core-judges)), with the reason `writes to a file a
tool runs on its own`. A read of one is safe, and so is a write to a file that
only runs when someone asks (`Makefile`, `justfile`, `package.json`). The rule
is read for the workspace's own paths only: beyond it the place already says
so, and the repository's history, a protected path and a key keep their own
words. `~/.envrc` is also read as a folder named `~` in the working directory,
as every `~` path is, and that reading is the workspace's own.

A file API names the file itself, so the path is judged by core's full rule,
the holding rule included: a write to `conf` is a finding when `conf/app/x.yaml`
is protected, where `cp a.txt conf/` in the shell guard is not (that one writes
*into* `conf`). The only false alarm this costs is a write to a name that is a
folder, which fails anyway.

## The path

- **`~` at the start is the home directory.** Most file APIs do not expand it,
  but agents write it meaning home, so it is read as home; and, since an API
  that does not expand it would use a folder named `~` in the working
  directory, that reading is judged too and either one is a finding. `~user`
  is another user's home directory, which the spelling does not name, so it is
  `unreadable` (`~$x.docx` and `~foo.tmp` are accepted false alarms).
- **A machine is Windows when the home directory is a Windows path**, as in
  core, and then `/` and `\` separate and names compare without case. A POSIX
  machine's backslash is part of a name.
- **The caller's own folders may be spelled any way core reads as one name**:
  `C:\Users\me\x`, `\\?\C:\Users\me\x` and `C:x` (from a working directory on
  `C:`) are one file, and the directories in `Paths` may be long paths too, as
  a canonical path on Windows is.

### Not one literal path

A file API takes one literal path, so these are `unreadable`, never judged:

- empty, longer than `MAX_PATH_LEN` (4096 bytes: Linux's `PATH_MAX`, longer than
  a name any system takes), a control character (a NUL byte, a newline, an
  escape), or leading white space;
- a wildcard, `*` or `?` (a long path's own `\\?\` excepted);
- a variable or a command: `$` and what follows it (`$HOME`, `${X}`, `$(cmd)`,
  `$env:X`), `%name%`, or a backtick. A `$` is plain only at the end of the
  path or before a separator, a space or a dot (`price$.txt`, `dir$/x`), and a
  `%` only when no `%` closes a name after it (`100%.md`, `a%20b`);
- `~user`;
- a bracket class (`app/[id]/page.tsx`, a route folder) is read as the resolver
  reads a pattern: inside the workspace it is the agent's own and judged as a
  literal path, anywhere else it can name more than one file and is
  `unreadable`;
- a path core cannot read to one name: a Windows stream (`x.txt:s`,
  `.git::$INDEX_ALLOCATION`), a name of dots and spaces, a folder name that ends
  in a space, and a drive-relative path on a drive other than the working
  directory's (`D:x`).

## Spellings it holds against

Every spelling a review could try is a permanent case in the tests
(`tests/cases/posix.cases`, `windows.cases`, `protected.cases`); core's own
rows are in `crates/core/tests`.

- **Case**: a Mac and Windows ignore it. The home directory, the sensitive
  places and the protected paths compare without case on every host, by Unicode
  simple fold (`.ſsh` is `.ssh`). The workspace compares as spelled on POSIX,
  so another case is judged outside: a false alarm on a write, never a miss.
- **Windows short names** (`SSH~1`, `CAMILO~1`, `AGENT~1`, `GIT~1`), for the
  home directory, the sensitive places, protected paths and `.git`.
- **`/` against `\`, doubled and trailing separators, `.`, `..`**, and `..`
  climbing out of the workspace (and past the root, which stays the root).
- **`~`, relative, rooted (`\Users\me`) and drive-relative (`C:x`)** paths.
- **Windows trailing dots and spaces** on a name (`.ssh.`, `id_rsa `).
- **UNC and device paths**: `\\host\share`, `//host/share`, `\\?\UNC\...`,
  `\\.\UNC\...`, `\\?\GLOBALROOT\...`; long paths to a drive (`\\?\C:\...`,
  `//?/C:/...`), which are that drive's path; the device namespace
  (`\\.\C:\x`, `\\.\PhysicalDrive0`, `\\?\Volume{...}\x`) is a disk.
- **A prefix that is another name's prefix**: `.agent` against `.agentx`,
  `.ssh` against `.sshx`, are compared by whole names.
- **A workspace that holds a key** (the home directory as the workspace):
  `.ssh/id_rsa` stays a secret.
- **Another user's home directory and the root user's**, and the system's own
  secrets (`/etc/shadow`, `/etc/ssh/ssh_host_*`, `C:\Windows\System32\config\SAM`).
  The folders under `/home`, `/Users` and `C:\Users` are always homes, whatever
  the user's own home directory is.
- **macOS's links to the root** (`/System/Volumes/Data/Users/me/...`,
  `/Volumes/Macintosh HD/...`), spelled absolute, relative (`../../..`) or from
  `~`: every path is made absolute first.
- **The kernel's files**: `/proc/self/environ`, `/dev/mem`, `/proc/self/root/...`.
- **A letter that looks like another** (`K` the Kelvin sign for `k`): NTFS does
  not fold it, so it is not the workspace's letter; the home directory, the
  sensitive places and protected paths fold it, where matching too much fails
  closed.

### The network share rule

Reading a file on `\\server\share` makes Windows offer the user's login to the
server, which is how a name and a password hash leave the machine. A read of
an ordinary file anywhere else is safe, so without a rule a read of a share
would be the one read that is not; `read_secret` would be wrong (it says a
key). So `network_share` is its own rule, and a caller can refuse it where it
only asks about the rest. It applies to a read and to a write, and comes
beside the rule the place breaks (a write to a share is also
`write_outside`; `\\.\UNC\host\share` is also a disk). The spelling is read by
core's `spelling::network`, which the shell guard's reads-only answer uses too.
A share the caller's workspace or protected path is on is the caller's own and
not a finding. `GLOBALROOT` counts as a share, since
`\\?\GLOBALROOT\Device\Mup\host\share` is one: a read of a shadow copy through
it is both a disk and a share.

## Accepted false alarms

A false alarm asks once more; a miss lets a secret out. These are accepted,
each with its test row:

- `~/.ssh/id_ed25519.pub`, `known_hosts` and `config` are `read_secret`: a place
  is a secret by what it is under, not by which file. The same for
  `~/.docker/contexts`, `~/.config/gh/config.yml` and `/etc/ssh/sshd_config`.
- A path with a `$name` or a `%name%` in it is `unreadable` though a file may
  be named so: Remix's `routes/$id.tsx`, Java's `Outer$Inner.class`, Office's
  `~$doc.docx`.
- `~foo.tmp` and `~$x.docx` (a `~` that is not the home directory).
- A write to a file named like one a tool runs on its own, in a folder that is
  not its tool's (`docs/examples/Jenkinsfile`, `fixtures/.envrc`): the names
  are found at any depth, as a `.git` is.
- A bracket class outside the workspace (`/etc/[h]osts`) is `unreadable`, and
  so is `[.]git/config` inside it (it can pick `.git`).
- A write by another case than the workspace is spelled with
  (`/Users/me/DEV/repo/x` for a workspace `/Users/me/dev/repo`) is
  `write_outside` on a Mac, where it is the same folder.
- A workspace named by its Windows short name is beyond the workspace.

## Known limits

Not covered, on purpose, and what to do:

- **Files a tool runs that are not on the list.** Core lists the places known
  to run code on their own; `.vscode/extensions.json`, `.cargo/config.toml`, a
  tool's own config and a script a `package.json` names are not in it, and a
  write to one is safe here. `lefthook.json` and `lefthook.toml` are not
  either (a `*.json` pattern would otherwise be a finding); `lefthook.yml` and
  `lefthook.yaml` are.
- **Symlinks.** A symlink is judged by its own name, so a link in the
  workspace to `~/.ssh` and a Windows junction are the caller's to refuse
  (the caller who can read the disk can resolve first, and hand the result in).
  The links the system itself makes are read by name: a Mac's links to the
  root and the kernel's `/proc/self/root`.
- **Places that are findings though they are not secrets**: `/dev`, `/dev/fd`
  and `/proc/self/status` are `read_secret` (the whitelist is of what is safe),
  and a workspace directly under `/home` is another user's home directory to
  core, so its own `.npmrc` is `read_secret`.
- **A Mac's links on any system.** A secret, the home directory and a
  protected path are looked up with `/System/Volumes/Data` and
  `/Volumes/Macintosh HD` dropped on every system, so on Linux
  `/Volumes/Macintosh HD/etc/shadow` is a `read_secret`. The workspace is
  matched by the links only on a Mac.
- **A workspace of `/`** makes a write anywhere Safe, since the caller said the
  agent may write there; keys, startup files and `.git` stay findings. That is
  the caller's choice to make.
- **A Windows folder moved by a company's OneDrive** (`OneDrive - Org\Documents`)
  is not `OneDrive\Documents`.
- **What is not in the table.** Core lists places known to hold secrets. A
  `.env` file, a token in a project's own files, a browser's cookie store, a
  password manager's vault are not in it: a read of them is safe. Nor is a
  path as another system spells it: WSL's `/mnt/c/Users/...` on a POSIX
  machine, Git Bash's `/c/Users/...` on a Windows one, each read as the system
  it runs on reads it. A secret in a text is the business of a
  guard that reads text.
- **Unicode normal forms.** A file system that treats `é` and `e` plus an
  accent as one name is not read that way: the path is still beyond the
  workspace, but is `write_outside` and not the caller's `write_protected`.
  (A secret in another user's home directory is a secret whatever that
  folder's name.)
- **Windows reserved names** (`COM1`, `PRN`, `AUX`, `LPT1`) are not devices
  here: a write to one in the workspace is judged as a file.
- **A relative working directory** puts every relative path outside the
  workspace, as core says; the caller passes absolute directories.

## The tests

The cases are in case files, one for each thing they check (the format is in
[CONTRIBUTING.md](../../CONTRIBUTING.md#case-files)): `tests/cases/posix.cases`
(a POSIX machine and a Mac), `windows.cases`, `protected.cases`,
`startup.cases` (the files a tool runs on its own) and `limits.cases` (what
the guard does not see), each checked by the test file of its name. A case is
a read or a write of a path and the answer it must get, safe or the rules it
must find, over core's `testing::posix()`, `macos()` and `windows()` or a
machine a `paths` line declares. `names.rs` holds the wire names over
`Rule::ALL`, `robust.rs` feeds noise, a thousand `..` segments and very long
paths, and `posix.rs` keeps the paths at and past the longest judged.
