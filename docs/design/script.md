# Script

`milo-guards-script` judges Python or JavaScript code an agent runs directly,
through a tool that runs code with no shell line around it: a Python tool, a
notebook, a JavaScript sandbox.

```rust
judge(language, code, &paths) -> Assessment
```

`language` is the code reader's `Language`, `Python` or `JavaScript` (Node,
Bun and Deno), re-exported here. `code` is the code as the tool is given it.
`paths` comes from `Paths::new(cwd, home, workspaces)`, with `with_protected`
for what the caller gates with and `with_secrets` for the files it knows hold
a secret; the code runs from `cwd`. The answer is `Safe`, or `Risky` with
every finding: a rule, a reason a prompt can show, and the part of the code it
is about.

Without this guard, a caller whose agent runs code directly has to wrap the
code in a made-up shell line (`python3 -c '…'`), quote it for a shell and fit
it in the shell guard's 64 KB line. The guard takes the code as it is.

## How the code is run

The answer holds for the code however the tool runs it: from a file, from
the interpreter's input, or as a string (`exec`, `python3 -c`, `node -e`).
Where those differ, the guard takes the one that does more. Python honours a
coding declaration (`# coding: utf-7`) when it reads code from a file or its
input, and then reads other text than the reader sees; such code is `unknown`
(`runs code the guard does not read`), as the shell guard holds the same code
fed to an interpreter's input. Handed as a string, Python does not read the
declaration, which is why the shell guard calls `python3 -c` of such code
safe where it is read whole.

## How it works

The code is read by the code reader, `milo-guards-code` ([Code](code.md)),
which says what the code is certain to do (`read`: the acts), whether it
reads the code whole (`understand`), whether it parses (`parses`), whether it
declares another encoding (`declares_other_encoding`), whether it may give a
program it starts input (`gives_input`) and whether it hands a shell a list of
words (`gives_shell_a_list`). The guard builds on the reader as
on a parser, which [the architecture](architecture.md#which-way-they-point)
allows a guard; it depends on core and on the reader only, never on the shell
guard, and the shell guard does not depend on it.

Each act is judged here, against core's path model (`Resolver`), as the shell
guard judges the same act in the code a line hands an interpreter
([Shell, Inline code](shell.md#inline-code)): a delete as `rm -rf PATH` is, a
write as a redirect's, a read as `cat PATH`'s, a move as `mv`'s, a link as
`ln -s`'s, a change of mode or owner as `chmod`'s and `chown`'s. The rules have
the shell guard's wire names where they mean the same, and for the same act
the reasons are the shell guard's, `instead` included, so a caller sees one
voice; the reasons this guard says alone are listed under [Rules](#rules). The
judging is this guard's own code, not the shell guard's: the two are held
together by a test in the front door (see [Tests](#tests)).

Then whether the code is read whole. Code that is not is `unknown`, with the
reason `runs code the guard does not read fully` and the start of the code as
the target, unless a finding of its own already asks (a delete, a key, code
the reader does not follow): where the shell guard says it for the same code.
A `run_program` finding is not one that asks: what the program does is the
shell guard's to say, so code that starts a program is always `unknown`
beside it.

## Rules

| Wire name | What it finds | The shell guard's name |
| --- | --- | --- |
| `delete` | A delete or a move of a path beyond the workspace, the workspace itself, a folder holding it, a key, a startup file, the repository's history, a protected path, or a path only known when the code runs: `deletes your home directory`, `moves your SSH keys`, `deletes the agent's settings`. Beyond the workspace it says what to do instead: `delete inside the workspace, or ask the user`. | the same |
| `wipe_disk` | A write over a disk (`writes over a disk`), or a delete of one. | the same |
| `overwrite` | A write to, a make of or a link to a file beyond the workspace, a key, a startup file, a file a tool runs on its own (`.envrc`, `.vscode/tasks.json`, a CI workflow), the repository's history, a protected path, or a file only known when the code runs: `writes to a file outside the workspace`, `writes to a shell startup file`, `links to your SSH keys`. A move into a folder also writes the name it lands at there. | the same |
| `permissions` | A change of the permissions or the owner of a path beyond the workspace or a sensitive one (`changes permissions of your SSH keys`), or a mode that opens a file to everyone (`lets everyone change it`). | the same |
| `read_secret` | A read of a key or a credential: a place core marks `Secret`, a secret the caller names (in the caller's words), a disk, what the kernel serves, another user's keys (`~alice/.ssh/id_rsa`), or the home directory read all the way down (`reads your SSH keys`, `reads the project's environment file`). | the same |
| `run_downloaded` | Code that runs code it downloads (`import('https://…')`): `runs code it downloads`, with what to do instead. | the same |
| `run_program` | Code that starts a program (`runs a program`: `subprocess.run([…])`, `child_process.spawn`, `os.kill`) or runs a command in a shell (`runs a command in a shell`: `os.system`, `child_process.exec`). | none: see below |
| `unknown` | Code the guard does not read: what the reader does not follow (`eval` of a name, code loaded from outside the workspace, a path handed to a call it has no row for), a path, a program or a directory only known when the code runs, a read of a path that cannot be placed, code that declares another encoding, and code not read whole. | the same |
| `unreadable` | Code longer than `MAX_LEN` (3 KiB, the reader's limit), nested deeper than the reader walks, running code inside code deeper than `MAX_DEPTH` (8) or more than the nested budget, that does not parse, or that the reader stops on, past the work its grammar may do for it. | the same |

The `Rule` enum is exhaustive, with `Rule::ALL`, an inherent `name` and core's
`RuleName`, as every guard's.

The reasons this guard says and the shell guard does not: `runs a program`
and `runs a command in a shell` (`run_program`); `gives a program input the
guard does not show` and `starts a program the guard cannot write as a
command line` (`unknown`, below); and `does not parse`, `runs code inside code
too deeply to read` and `runs too much code inside code to read`
(`unreadable`). The shell guard's inline reading says `runs code the guard
does not read` (`unknown`) for code that does not parse, and for code the
reader stops on, as a nested piece of such code is here. `takes too long to
read` (`unreadable`) is the shell guard's reason for a line its own grammars
are stopped on.

After a move (`os.chdir`, `process.chdir`, a program's `cwd`), what an act
finds from where the code was before it, beyond what it finds where the code
moved to, ends `… if a cd before it failed or did not run`, as the shell guard
says it: a `chdir` raises an error the code may catch, and the code goes on
where it was. Those folders are kept as the shell guard keeps them for a
`cd`, each once and not the one the code moved to, at most eight; past
eight, and from then on, the code may be anywhere: one folder only known when
it runs, from which a path is one only known when it runs too. (The shell
guard holds that a `cd` that only goes up does not fail; in code, a `..`
makes the code anywhere already, so that never comes up.) For a write, what
the same write finds from any place the code may be in is what it finds there.

### A program is the shell guard's

`run_program` is this guard's own rule. Whether a program is risky is what the
shell guard judges (`git push --force`, `rm -rf ~`, `kill -- -1`), and a guard
never depends on another, so this guard does not judge it: it says the code
starts one, and gives the command as the finding's `target`, a line a caller
hands to the shell guard's `classify`, adding what it finds to the answer, as
[the architecture](architecture.md#which-way-they-point) says a caller does.

Code that starts a program is never inside the reader's strict subset, so the
answer always holds an `unknown` for the code beside `run_program`. The
target tells a caller which program, and what the shell guard finds in it is
more to ask about; a safe answer for every target never makes the code safe.

Which shell reads a target is the machine's, by the `Paths`, and
`target_shell(&paths)` says which: `TargetShell::Posix` or
`TargetShell::Cmd`, an exhaustive enum of the guard's own (it cannot name the
shell guard's `Shell`), for the caller to turn into the shell guard's.

- **On a POSIX machine** (a Mac too), `Shell::Posix`. A command run in a shell
  (`os.system('rm -rf ~')`) is the line itself. A program and its arguments
  (`subprocess.run(['git', 'commit', '-m', 'a message'])`) are its words: as
  they are when every character is one a shell reads as itself or as a
  pattern (letters, digits, `/ . _ - ~ * ? [ ] { } , = : @ % + ^`),
  single-quoted otherwise (`git commit -m 'a message'`), and single-quoted
  when a word is one the shell reads as its own (`{`, `}`, `!`, `if`, `while`
  and the other reserved words), or a program's name that holds a `=`. A `~`,
  a wildcard and a brace list are left bare on purpose: the code reader reads
  `~` as the home directory wherever it comes, and the shell guard reads the
  code's paths as shell words, so it reads the command as it reads the code.
- **On a Windows machine**, `Shell::Cmd`: `os.system`, `shell=True` and
  `child_process.exec` run `cmd.exe` there. A target is only ever words that
  cmd and the C runtime both read as themselves; anywhere else the program has
  no target, and a second `unknown` says so: `starts a program the guard
  cannot write as a command line`. When in doubt there is no target: an
  `unknown` is honest, and a line that reads safe would not be.
  - A command run in a shell is the line as the code wrote it, unless it
    starts with a `"` (`cmd /c` takes off the outer quotes as its own rules
    say, so the line that runs is another), or the code, at any depth, may hand
    a shell a list of words (`subprocess.run(['del', 'x'], shell=True)`, or
    `shell` handed by `**kw`, by `*rest`, by position, or in JavaScript options
    that are not an object written out: Windows joins the words into the line,
    which no act gives; the reader's `gives_shell_a_list` answers "may"):
    those have no target.
  - A program started without a shell, whatever the program is (cmd, a batch
    file, a launcher such as `conhost` may hand its line on to cmd), is its
    words joined as Windows joins them (`list2cmdline`): each bare, or in
    plain double quotes when it holds a space or a tab (`git commit -m "a
    message"`, `cmd /c rd /s /q C:\Users\me`). It has no target when any word
    holds a character cmd reads as its own (`& | < > ( ) ^ % ! "`) or a control
    character, when a quoted word ends in a backslash (which the C runtime
    reads as escaping the quote), when a word is only known when the code
    runs, in whole or in part, when the program's name is one cmd reads as its
    own (`if`, `for`, `rem`, a leading `@`, `/` or `-`: `executable='/bin/rm'`),
    and when the code, at any depth, may hand a shell a list.
  - Run from another directory, the line starts `cd /d DIR && ` (`cd /d DIR &&
    cmd /c "…"` for a command line, which has no target when it holds a
    `"`). A directory that starts with `/` or `-` would be read as a switch,
    and a directory only known when it runs has no word in cmd the shell
    guard reads as one: neither has a target.

  The front door's `tests/script_targets.rs` holds that cmd's reading of the
  targets finds the delete (`rd /s /q C:\Users\me`, `rm -rf C:\Users\me`,
  `cmd /c "rd …"`, and `cmd /c rd /s /q C:\Users\me,x`, which cmd reads as two
  names), the read of a key (`type C:\Users\me\.ssh\id_rsa`), the write (`echo
  x > …\authorized_keys`) and the wipe (`format D: /y`);
  `windows_programs.cases` holds each shape that has no target.
- **Run from another directory** on a POSIX machine (`cwd='/tmp'`, after
  `os.chdir`), the line starts by moving there: `cd -- DIR && ` and, for a
  command line, `cd -- DIR && sh -c '…'`. A directory only known when it runs
  is `"$UNKNOWN"`.
- **A word only known when the code runs** is written as a variable no shell
  sets, `"$UNKNOWN"` (on a POSIX machine; on Windows such a program has no
  target), which the shell guard reads as
  a word only known when the line runs (`rm -rf "$UNKNOWN"` is a delete of a
  path only known when it runs); a word whose start is known is that start
  followed by it (`'/home/me/.ssh/'"$UNKNOWN"`). Such a program is `unknown`
  too (`runs a program with an argument only known when the code runs`).
- **A program whose name, or a command line, only known when it runs** gives
  no command to ask about: it is `unknown` (`runs a program only known when it
  runs`, `runs a script only known when it runs`).
- **Input the code gives the program** (`input=`, `stdin=`, `communicate`,
  `{ input }`, `child.stdin`) is not in the reader's act, so not in the
  target: the code is also `unknown`, `gives a program input the guard does
  not show`.

## What is safe

Code read whole that does none of the above: the strict subset of
[Code](code.md#the-strict-subset) (a few plain statements whose every call,
name and import is on a short list that only computes, and `open`), with
every act it makes harmless. `print(1)`, `console.log(1)`,
`import sys; print(sys.version)`, `open('out.txt', 'w')` in the workspace,
`open('/tmp/x', 'w')`, `print(open('/home/me/.zshrc').read())` (reading a
startup file is everyday work) are safe.

Python looks for a module in the folder it runs in first, even with no
`import` (an uncaught exception imports `traceback`): the reader says so with
`Understood { imports: true }`. Python is safe only when the working
directory is the workspace's own (inside a workspace folder, or the folder
itself), as the shell guard holds the code of a line. JavaScript read whole
imports nothing.

Python is judged as Python 3: the guard has no Python 2 (`time` and
`itertools` are files there; `understand_python2`). A caller that runs Python
2 code gets an answer for Python 3.

## Paths

A path is the text the reader gives: a literal, or one the code builds from
names (`os.path.join`, `Path(…) / …`, `os.path.expanduser('~')`,
`Path.home()`, `os.homedir()`, `os.environ['HOME']`, `process.env.HOME`,
string `+`, f-strings and template literals made of those). It is placed by
core's `Resolver`, by its spelling alone, on the machine `Paths` describes:
POSIX paths on a POSIX machine and a Mac, Windows paths (drives, `\`, any
case) on a Windows one. `~` and `~/…` are the home directory, as the reader
gives them. `~alice/…` is another user's home directory, which the spelling
does not place: a read of it is read wherever a system keeps homes
(`/home/alice`, `/Users/alice`, and `/root` and `/var/root` for `root`; on
Windows `C:\Users\alice`), as the shell guard reads it, and a delete or a
write of it is of a path only known when it runs. On Windows, a name the
spelling does not settle is read for the file it is a name of: a stream
(`id_rsa::$DATA`, `.ssh::$INDEX_ALLOCATION\id_rsa`), a part that ends in a
space or a dot (`.ssh \id_rsa`, and a stream of a path in the home
directory, `~\.ssh\id_rsa::$DATA`), and the NT prefix `\??\`, which is the
object namespace the file API opens the rest in, as `\\?\` is: `\??\C:\…`
is the path on `C:`, `\??\PhysicalDrive0` a disk, `\??\UNC\…` a share,
`\??\GLOBALROOT\Device\…` a volume by its device name, each placed as its
`\\?\` spelling is.

A read of a path that cannot be placed (on another drive's own working
directory, `D:x`; another user's home directory that holds no key) is
`unknown`: `opens a file whose path is only known when the code runs`. So is
a read of a path the code knows only in part, unless the part it knows is in
a folder of keys: `open('/home/me/.ssh/id_' + n)` is a read of a key.

The directory the code moves to (`os.chdir`, `process.chdir`, a program's
`cwd`) is where the paths after it are read from. Where the code may be in
more than one place when it makes an act (a function defined before a
`chdir` and called after it), each act is judged from each, as the shell
guard does; where it may be anywhere (`chdir('..')` twice, a directory only
known when it runs, nested code that moves, more than six moves), a relative
path is only known when it runs, a read of one is `unknown`, and a name that
is a key in the home directory or a secret the caller named is still a read
of it.

What the caller names is honoured as in a shell line: a delete, a move, a
write or a change of mode of a protected path is `delete`, `overwrite` or
`permissions` in the caller's words, inside the workspace too, and reading
one is safe; a read of a named secret is `read_secret` in the caller's words;
a path named both keeps its protected finding for a write or a delete, and a
read of it is a read of the secret. So is how the caller says the machine
spells another system's drives ([Core](core.md#drive-mounts)): on WSL with
the mount named (`Paths::drive_mounts`), `open('/mnt/c/Users/me/.ssh/id_rsa')`
is `read_secret`, and the code is judged on the paths as spelled too, every
finding of both kept. The cases are in `tests/cases/drives.cases`. A path
through a link the caller names (`Paths::links`) is judged where it lands, a
`chdir` into one included (`os.chdir('keys')` then `open('id_rsa')`, with
`keys` a link to `~/.ssh`, is a read of a key), and a folder read whole
holds what a link below it lands on: `shutil.copytree` follows the links it
meets, and so does `shutil.make_archive` in the zip format for a link to a
file; `tarfile`, `make_archive` in a tar format and Node's `fs.cp` copy
them as links, a false alarm the guard accepts. `shutil.rmtree` acts on the links
themselves. The cases are in `tests/cases/resolved_links.cases`.

## What cannot be read is risky

- **Too long.** Code longer than `MAX_LEN` (3 KiB, the reader's limit, a
  deliberate limit of 0.2.0: see
  [Code: The length limit](code.md#the-length-limit)) is not read:
  `unreadable`, `is too long to read`, with no target. A script longer than
  that, as many real ones are, is not judged act by act.
- **Too deep.** Code the reader does not walk in full (`Reading::deep`) is
  `unreadable`, `nests too deeply to read`, beside what the reader found.
  Code that runs code (`exec("…")`, `eval("…")`) is read in its own language
  at each depth, to `MAX_DEPTH`; past it, `runs code inside code too deeply to
  read`. The nested code read for one piece of code is held to four times
  `MAX_LEN` in all, past which it is `runs too much code inside code to
  read`.
- **Does not parse.** Code whose grammar reads an error (the reader's
  `parses`) is `unreadable`, `does not parse`, with the start of the code as
  the target. It is not read through the error, so nothing in it is found
  (for code the interpreter refuses too, it raises before it runs a thing;
  code in syntax newer than the grammars know, such as Python 3.15's `lazy
  import`, runs, and is a known limit: see [Code: Errors](code.md#errors)): `import shutil;
  shutil.rmtree('/home/me'); if 1:` is `unreadable` alone. The reader stops
  its parse where tree-sitter starts to recover from the error, so code whose
  recovery would go round the same tokens with no end, or wrap an error never
  closed again at each token, is answered so in some milliseconds. Nested
  code that does not parse is code the guard does not read (`unknown`). Python's
  grammar reads an empty block (`if 1:`) with no error, which Python refuses:
  such code is not read whole, so it is `unknown`.
- **Too costly to read.** Every reading the guard makes of a piece of
  code, and of the code it runs inside it (and its judging again on each other set of the
  paths (`Paths::also_judged_on`), which reads the code from
  what the budget kept), draws from one `Budget` of the reader's, made for the code's length and counted as the grammars and the
  reader's walk go, never by a clock (see [Code: Limits](code.md#limits)).
  Code whose own parse the reader stops on (its `parses` does not call it
  parsed, and the budget is spent) is `unreadable`, `takes too long to
  read`, with the start of the code as the target: it is not read at all, so
  nothing in it is found, and the guard asks the reader nothing more of it.
  Code the reader stops on further in, the code it runs read at a depth, is
  code the guard does not read (`unknown`), and the whole is `unreadable`,
  `takes too long to read`, beside it. JavaScript the grammar reads two ways
  at once, code
  nested past the depth the reader walks, a lexer that goes
  over the same text again and again (a run of comment lines in a block
  longer than 182 to 755 lines after code longer than a kilobyte or two, by
  the length of its lines and of the code before it; see
  [Code: Limits](code.md#limits)), and a chain of calls named again from each link, each of which
  took seconds, are answered so on every machine; and so is code that runs
  piece after piece of code each read whole within the bounds of one parse,
  which the one budget adds up. Python the grammar reads two ways at once
  holds a star where Python allows none, and is code that does not parse.
- **Empty.** Code that is empty or only a comment holds no statement, so it
  is not read whole: `unknown`.

The guard never panics, never reads the disk, the environment or the clock,
and gives the same answer for the same code on every machine. Its own work
is bounded: it judges each act from at most twelve places, and from each
folder a move that may have failed left it in, at most eight and one only
known when it runs; a directory and a name are joined into at most 4 KiB (a
longer path is one only known when it runs), and the paths joined for one
act, from every place and folder, into at most 16 KiB, past which every path
of the act is read as from a folder only known when it runs (a delete or a
write of it is of a path only known when it runs, and a read of a name that
is a key in the home directory or a secret the caller named is still a read
of it); it counts the places before it builds them, so a thousand `chdir`s
cost what two do; and it reads nested code to the budget above. So the work
of its own grows with the number of acts the reader gives. The reader's own
time is the reader's: it bounds what it works out from names, but its time on
some shapes is not linear in the code's length, and that is the reader's
to bound (see [Code: Limits](code.md#limits)), not this guard's. `tests/work.rs` holds the work to those counts, through the crate's
`testing` feature, not to the clock: the acts judged, the places built, and
the bytes joined for each act.

## Known limits

- **A program is not judged here.** `run_program` says the code starts one;
  whether it is risky is the shell guard's answer for the target. A caller
  that does not ask it still gets `unknown` for the code, but not what the
  program does.
- **The reader's limits are the guard's.** What the reader does not find,
  the guard does not judge. `open(path, 'r+')` is a write and not a read (the
  reader gives a write for any mode that writes), so `open('~/.ssh/id_rsa',
  'r+')` is `overwrite`, not `read_secret`; it is risky either way. Input a
  program is given is found by name only (`gives_input`). Node's
  `windowsVerbatimArguments` is not read, so a program started with it on a
  Windows machine gets a target whose words are quoted where Node would
  pass them as written.
- **On a Windows machine, ordinary code can cost a program its target.**
  Whether code may hand a shell a list (`gives_shell_a_list`) is asked of
  the whole code and answers for any call given a list and more, not only
  for a call that starts a program: beside `print(max([1, 2], [3]))` or
  `console.log([1, 2], 3)`, `subprocess.run(['git', 'status'])` has no
  target and the `unknown` that says so. It is never the other way: no
  target is given that the question would withhold. A POSIX machine keeps
  the target.
- **Python 2 is read as Python 3** (see [What is safe](#what-is-safe)).
- **Paths are spelled as on the machine `Paths` describes.** The shell guard
  reads the paths of inline code as POSIX shell words whatever the machine.
  So on a Windows machine the two read a Windows-spelled path of inline code
  differently: this guard places `C:\Users\me` where the machine has it
  (`shutil.rmtree('C:\\Users\\me')` is `delete`, `deletes your home
  directory`; `machines.cases` holds its answers), and the shell guard's
  inline reading does not. A program
  the code starts is a POSIX
  unit to the shell guard's inline reading, where this guard gives a line for
  cmd. The agreement test holds this guard's answer, with cmd's reading of
  each target, to every file act the shell guard finds in such code (see
  [Tests](#tests)).
- **A brace list in a path is a name.** The shell guard spells a `{a,b}` in a
  path of inline code out, as a shell does; Python and JavaScript do not, and
  nor does this guard: `open('/home/me/{.ssh/id_rsa,x}')` opens the one file
  of that name, so this guard calls a read of it safe where the shell guard's
  inline reading says `read_secret` for `/home/me/.ssh/id_rsa`. No case of
  either guard holds such a path.

## Tests

`crates/script/tests/` holds the guard's cases, in case files (`tests/cases`,
the format is in [CONTRIBUTING.md](../../CONTRIBUTING.md#case-files)), each
checked by the test file of its name: `safe.cases` (code read whole that does
nothing risky), `delete.cases`, `overwrite.cases` (with the writes over a
disk and where a move lands), `permissions.cases`, `read_secret.cases` (with
other users' home directories), `run_program.cases` (with the `unknown` beside
a program, reserved words and input), `run_downloaded.cases`, `unknown.cases`
(with coding declarations), `unreadable.cases`, one for each rule in each
language; `protected.cases` (protected paths and named secrets),
`built_paths.cases` (paths built from names), `open_modes.cases` (`open()`'s
modes and `fs` flags), `directories.cases` (`chdir` and `cwd`),
`machines.cases` (a Mac and a Windows machine, Windows spellings) and
`windows_programs.cases` (targets for cmd). `cases.rs` tests the runner,
holds every rule to cases in each language (but `run_downloaded` in Python,
whose reader finds no code downloaded), and dumps every case; `names.rs`
walks `Rule::ALL` and pins the wire names; `robust.rs` runs seeded noise and
every case of the code reader's case files through both languages (no panic,
the same answer twice, safe only for code read whole) and holds code too long,
too deep or that runs code too deeply to `unreadable`, never safe; `work.rs`
holds the work to counts, and the code the reader stops on, at each size to
the length limit and on a POSIX and a Windows machine, and code inside code
four deep, to the one budget of its readings, never safe; the unit tests of `src/judge.rs` hold the depth and
the nested budget and the quoting.

The front door's `crates/guards/tests/agree_code.rs` holds this guard and the
shell guard to one answer for the same code, judged as `judge(language,
code)` and as `classify("python3 -c '<code>'")` or `node -e`: every `python`,
`python2` and `javascript` case of the code reader's case files and every
POSIX line of the shell guard's inline case files written whole as `python3
-c WORD` or `node -e WORD` (both on a POSIX machine, a Mac and a Windows one,
or on the paths a case declares), and code made there (each act on files after
one to eight moves to places risky and harmless from the start, what the kernel
serves, and every act on protected paths, named secrets and paths that are
both). The whole answers are compared, every rule with its reason and
`instead`: this guard's answer as a caller combines it, each `run_program`
replaced by the shell guard's answer for its target (cmd on Windows), against
the shell guard's for the whole code. What differs by design is listed in the
test with why, and a case is held to differ only so: code that declares
another encoding (`unknown` here, safe after `python3 -c`); input given to a
program and a program cmd cannot carry (an `unknown` only here); the
`unknown` for a word known in part where the shell guard finds the program
reads a key (which it then drops); a read of a path that cannot be placed
(`unknown` here, not judged by the shell guard's inline reading); a Windows
path on a Windows machine that this guard finds risky where the shell guard,
placing it as a POSIX name, finds nothing. Each of these says more here,
never less. A program on a Windows machine is compared on what matters to a
caller: both answers risky, and every finding about a file act the shell
guard gives for the whole code is in this guard's answer combined with
cmd's reading of each target, or this guard has no target for the program
and says so (`starts a program the guard cannot write as a command line`);
what the two say of the program beyond its file acts (`elevated` as root or
as administrator, `stop_system`, the reason of an `unknown`) is not
compared, since the shell guard's inline reading judges a POSIX unit where
cmd runs the line. No Windows shape is mapped away from that rule today.
`does not parse` and `takes too long to read` here are the shell
guard's `runs code the guard does not read`. Code with a NUL in it has no shell line and is not compared.
What still differs otherwise is listed in the test with both answers: code
that writes a script and runs it (`sh x.sh`), where both say `unknown` for
different reasons; and, on a Windows machine, `os.system` of a `python3 -c`
that runs a delete through two more `os.system`s, whose target is the line
that runs but which the shell guard's cmd reading only calls `unknown`.

`crates/guards/tests/script_targets.rs` holds the targets to the shell
guard's reading of them: on Windows, cmd's reading finds the delete, the read
of a key, the write and the wipe; on a POSIX machine, the delete, the read and
the delete from another directory; and a safe target never leaves the code
safe.
