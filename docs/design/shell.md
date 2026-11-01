# Shell

`milo-guards-shell` judges a shell line before it runs. It reads POSIX shells
(`sh`, `bash`, `zsh` and the ones that share their syntax), PowerShell and
Windows `cmd`.

```rust
classify(line, shell, &paths) -> Assessment
```

`shell` is a `Shell` (`Posix`, `PowerShell` or `Cmd`), which is
`#[non_exhaustive]`: a shell with a grammar of its own may be added, so a
caller's `match` on it needs a fallback arm. `paths` comes from
`Paths::new(cwd, home, workspaces)`.
The answer is `Safe`, or `Risky` with every finding: a rule, a reason a prompt
can show, and the argument it is about. The guard reads the line and never runs
it. It touches neither the file system nor the environment.

The guard only reports. What to do about a finding is the caller's choice, and
nothing here knows about asking, refusing or modes. The types are core's; see
[Core](core.md).

## How it works

A line is judged in three steps.

1. **Split** the line into units, one for each program it runs.
2. **Detect**: rules read each unit and judge each path.
3. **Combine**: the line is safe only when no unit is risky. A risky line
   carries every finding.

The modules follow the steps. `posix`, `powershell` and `cmd` split a line with
their grammar. `launch` takes wrappers off and reads scripts handed to shells.
`unit` holds the unit and the helpers that read its arguments. `detect` holds
the rules. `path` is the shell's side of the path model.

## Splitting

The line is split with the grammar of the shell that runs it. The caller says
which shell, with `Shell::Posix`, `Shell::PowerShell` or `Shell::Cmd`.
`Shell::for_program` maps a name such as `/bin/zsh` or `pwsh.exe` to one. The
parsers are tree-sitter's bash, PowerShell and batch grammars.

- Chains (`&&`, `||`, `;`), pipes, substitutions (`$(...)`), loops, blocks and
  subshells are walked.
- **Every branch counts**, whether or not it would run. `false && rm -rf ~` is
  risky.
- Where a grammar reads a line differently from the shell, the shell wins.
  A POSIX line's backslash-newlines are joined first, so `r\<newline>m` is
  `rm`. cmd's built-ins also split arguments at `,`, `;` and `=`. PowerShell's
  `--%` ends at `|`. A cmd "comment" that hides a command cannot be read.
- Fish has no grammar here. Its line is read as POSIX, which is still safe:
  what the grammar cannot parse comes back risky.

### Wrappers and scripts

Wrappers come off: `sudo`, `env`, `nice`, `timeout`, `xargs`, `find -exec`,
`Start-Process`, `start`. `sudo rm` is `rm`, run as root.

A script handed to a shell is split again, in its own grammar: `bash -c`,
`eval`, `cmd /c`, `powershell -Command`, `Invoke-Expression`. A nested script
counts as far as a depth limit, and the text of all the nested scripts read
for one line as far as a budget a few times the longest line. Past either, the
line is unreadable.

### Actions that run later

Some commands only register a script, which runs when something happens
rather than now. The script is read where it is written, in its own grammar,
and its findings are the line's, since the shell runs it as the same user.

- **`trap`** in a POSIX shell: `trap 'ACTION' SIGNAL…`, also `trap -- 'ACTION'
  …`, whichever signal (`EXIT`, `0`, `INT`, `TERM`, `ERR`, `DEBUG`, `RETURN`,
  `HUP`, a number, several at once). The action is read like an `eval`'s
  script: `trap 'rm -rf ~' EXIT` deletes the home directory. A double-quoted
  action is expanded when the trap is set and its result read as code when it
  runs, as `eval "…"` is, so whatever an expansion holds becomes code: `trap
  "echo $d" EXIT` is `unknown`, with the reason `runs a script only known when
  it runs`, like `eval "$x"`, and so is `trap "$x" EXIT`. The text around the
  expansions is still read, so `trap "rm -rf $d" EXIT` also carries the
  `delete` of `$d`, a path known only when it runs. `$HOME`, `$PWD` and
  `$TMPDIR` are the places the guard names and are not counted as
  expansions. A single-quoted action is not expanded when set and is read as
  written: `trap 'rm -f "$tmp"' EXIT` is `rm -f "$tmp"`, and `trap 'echo $d'
  EXIT` is safe.
- **Nothing runs** for `trap - EXIT` and `trap -- - INT` (put the default
  back), `trap '' INT` (ignore the signal), `trap -p`, `trap -l` and a bare
  `trap`.
- **PowerShell**: the block of `trap { … }`, and the block given with
  `-Action` to `Register-EngineEvent`, `Register-ObjectEvent`,
  `Register-WmiEvent` and `Register-CimIndicationEvent`. The grammar reads a
  block in place, so its commands are judged as if they stood on the line,
  and an action that is not a block written out is a script known only when
  it runs, which is `unknown`: `-Action $block`, `-Action ([scriptblock]::Create($t))`,
  an action given by position (`Register-EngineEvent X $block`) and any splat
  (`Register-EngineEvent @p`). By position, the action is the last of the
  parameters the command's names leave to be given by position, in the docs'
  order: source then action for `Register-EngineEvent`; object, event, source
  then action for `Register-ObjectEvent`; class or query, source then action
  for `Register-WmiEvent` and `Register-CimIndicationEvent`.
  `Register-ObjectEvent $timer Elapsed`, with no action, is safe.
- cmd has nothing like it.

The action runs in this shell, later: after the line's last command, or
between its commands (`DEBUG`, `ERR`, `RETURN`, a signal). It is judged as the
line leaves things, whichever is more conservative and needs the least state:

- **Where it runs.** Its relative paths are judged from where the line was
  at the `trap`. A `cd` (or `pushd`, `popd`, `Set-Location`) after it, anywhere
  in the line, makes those paths known only when it runs: `trap 'rm -rf
  build' EXIT; cd ~` deletes a path known only when it runs. A `cd` inside
  the action may run before the next command, so the rest of the line is read
  from somewhere unknown too. An absolute path or `~` is the same wherever the
  line has moved. A `cd` in a subshell, `$(…)` or a script in a process of
  its own is not a move of this shell, as it is not for any later path, so
  `trap 'rm -f lock' EXIT; (cd sub && make)` still runs `rm -f lock` from
  where it was set. `eval` runs in this shell, so its `cd` is a move.
  The exception is a trap a subshell copies: `ERR` and `DEBUG` (zsh also
  `ZERR`) in zsh, `ERR` with `set -E` and `DEBUG` and `RETURN` with `set -T` in
  bash, also in `$(…)`. It runs from where the subshell has moved to as
  well, so for these (and for a signal the guard does not know, or one known
  only when it runs) any `cd` after the `trap` counts, subshell or not:
  `trap 'rm -rf build' DEBUG; (cd /; true)` is a delete of a path known only
  when it runs. `EXIT` and the ordinary signals are reset in a subshell and
  keep the rule above.
- **Names in a finding.** A double-quoted action is read from its text with
  each expansion replaced by a placeholder variable; a finding about it names
  the action as written, never the placeholder.
- **Hidden names.** The action is a body (see Bodies below): when the line
  turns `dotglob` on anywhere, even after the `trap`, its wildcards match
  hidden names. An off switch inside it changes nothing for the rest of the
  line, and an on switch inside it stays on.
- **Nesting.** A `trap` inside a script, a `bash -c` or another `trap` counts
  as far as the depth limit. A `$(…)` in a double-quoted action is read where
  it stands, when the trap is set, and is a placeholder variable in the text
  the action is read from, so it is not read twice.

### Where a line is

A `cd` (or `pushd`, or `Set-Location`) moves the rest of the line. A later
relative path is judged from where it moved to. A `cd` inside a subshell or a
nested script in a process of its own does not reach the rest of the line;
`eval` runs in this shell, so its `cd` does; in a pipeline only zsh runs the
last stage in this shell, but, as for a `cd`, any stage counts. Where a `cd` went is
unknown when its target is, and then so is every relative path after it.

A variable that names a place (`$HOME`, `%TEMP%`, `$env:TEMP`) stops naming it
once the line sets it anywhere: `TMPDIR=$HOME`, `set TEMP=...`, `unset HOME`.

### Hidden names

A POSIX wildcard skips a name that starts with a dot, so `rm -rf *git` leaves
`.git` alone. A line can switch that off, and then `*git` takes `.git`: bash's
`shopt -s dotglob`, zsh's `setopt globdots` (also spelled `dotglob`),
`set -o globdots`, and a non-empty `GLOBIGNORE` (bash turns `dotglob` on for
it). Once a POSIX line has turned one on, every later pattern in that shell is
judged as core judges a PowerShell or cmd wildcard: it can match a leading dot
(see [Core](core.md)). Each unit and each redirect carries the flag, like the
folder a `cd` moved to.

- **On.** `shopt -s dotglob` (also with `nullglob` and the like, `-sq`);
  zsh's `setopt globdots`, `GLOB_DOTS`, `glob_dots`, `dotglob` and `DOT_GLOB`
  (zsh ignores case and underscores), `unsetopt noglobdots` and `unsetopt
  nodotglob`; `set -o globdots`, `set -o dotglob`; zsh's flag `-4` for
  `set` and `setopt` (`+4` undoes it); `setopt -m` and `unsetopt -m` with any
  pattern, which may name it. An option name or flag only known when it runs
  counts as on.
- **`GLOBIGNORE`** turns it on when it is not empty: as `GLOBIGNORE=x` on a
  line of its own, after `export`, `declare`, `typeset`, `local` or `readonly`
  (quoted too: `export "GLOBIGNORE=x"`), with `+=`, as `let GLOBIGNORE=1` or
  `(( GLOBIGNORE=1 ))`, as `read GLOBIGNORE` or `printf -v GLOBIGNORE`, or as
  a `for` variable. An empty value turns nothing on. A command with
  `GLOBIGNORE=x` in front of it, or after `env`, was expanded by the shell
  before the variable applies, so only a script it starts (`GLOBIGNORE=x bash
  -c '…'`) is judged with it on. `BASHOPTS=dotglob` does the same for the bash
  it starts; as a statement it counts as on.
- **A shell's own start-up options** turn it on for the script that shell runs:
  `bash -O dotglob -c '…'`, `zsh -o globdots -c '…'`, `zsh -o dotglob`, `zsh -4`,
  `zsh --globdots`, and a name only known when it runs.
- **`source` and `.`** run a file the guard cannot read, which may turn it on,
  so a line that sources one is judged with it on afterwards.
- **Two flags.** The guard keeps bash's option and zsh's apart, and hidden
  names match when either is on. Bash's is turned on by `shopt -s`,
  `GLOBIGNORE` and `BASHOPTS`, and off by `shopt -u` and `unset GLOBIGNORE`
  (`unset -f GLOBIGNORE` removes a function and changes nothing). zsh's is
  turned on by `setopt`, `unsetopt no…`, `set -o globdots` or `dotglob`, and
  `-4`, and off by their opposites. `source`, a shell started with the option
  on, and a name only known when it runs turn both on. An off switch clears only
  its own flag, since in the other shell it is an error: `setopt globdots;
  shopt -u dotglob; rm -rf *git` and `shopt -s dotglob; unsetopt globdots; rm
  -rf *git` are still risky.
- **Off.** `shopt -u dotglob`, `unsetopt globdots`, `set +o globdots` and
  `unset GLOBIGNORE` turn their flag off, but only where the line is sure to run
  them in this shell. They count when the unit is reached directly or through
  `command`, `builtin`, `time`, `!` or `eval`. Behind `env`, `nohup`,
  `timeout`, `nice`, `stdbuf`, `sudo` or `find -exec` they run in a process of
  their own and change nothing. In a pipeline, after `&`, on the right of `&&`
  or `||`, in an `if`, `case`, loop or function body, they change nothing
  either: the line may not run them, or runs them in a subshell, so the rest
  stays judged with the option on.
- **Where it reaches.** It stays on for the rest of the line. A subshell,
  `$(…)`, and a script in a process of its own (`bash -c '…'`) give it back as
  it was: an option set inside `bash -c 'shopt -s dotglob'` does not reach the
  units after it. A script started while it is on inherits it, since an
  exported `GLOBIGNORE` would reach it. `eval` runs in this shell, so its change
  stays, except that an `eval` that is a stage of a pipeline runs in a subshell
  and can turn the option on but not off. An on switch in any pipeline stage
  reaches the units after it, which is conservative: zsh runs the last stage in
  the current shell, so `setopt globdots | cat; rm -rf *git` is risky.
- **Bodies.** A function body or a loop may run after the option is on, whenever
  it is called or comes round again. The guard records the units and redirects
  in them, and after the whole line is read, if the line ever turned the option
  on (anywhere, a script it ran included, even if it turned it off again), it
  judges them with it on: `f() { rm -rf *git; }; eval 'shopt -s dotglob'; f`.
  A script started with the option on (`bash -O dotglob -c f`, `GLOBIGNORE=x
  bash -c f`) counts, since the line may have exported a function to it, and so
  does a `GLOBIGNORE=x` in front of a call to a function the line defines
  (`GLOBIGNORE=x f`), which sets it while the body runs. A
  line that never turns it on is not changed by a body that only mentions the
  name (`echo dotglob`).
- **Listings.** A listing hands its pattern on with the flag it was written
  under, so `shopt -s dotglob; ls -d *git | xargs rm -rf` is the delete of
  `*git` with hidden names matching.

Not read, so the caller has to account for them: an option set by `~/.zshenv`
or `~/.bashrc`, a `BASH_ENV` file, an inherited `GLOBIGNORE` or `BASHOPTS`
from the environment the guard's caller runs in, and a `GLOBIGNORE` set by
`${GLOBIGNORE:=x}`. zsh's `(D)` glob qualifier (`rm -rf *git(D)`) is not read
either.

## The rules

A rule reads a unit's program, its flags, its operands and its redirects. It
never reads the raw text. `echo "rm -rf /"` is safe, because the program is
`echo`.

| Wire name | What it finds |
| --- | --- |
| `delete` | Deletes files beyond the workspace, the workspace itself, a sensitive file, or a path known only when it runs; archives such files with an option that deletes what it archives. |
| `wipe_disk` | Formats, repartitions or writes over a disk. |
| `overwrite` | Writes into a file beyond the workspace, or a sensitive one; unpacks an archive into such a folder. |
| `git_discard` | Throws away work git cannot give back: uncommitted changes, untracked files, stashes, unmerged branches, tags, a submodule's changes. |
| `git_remote` | Rewrites or deletes branches on a remote. |
| `git_history` | Rewrites the repository's history, or what git keeps to recover it. |
| `permissions` | Changes permissions or ownership beyond the workspace, or opens files to everyone. |
| `system_settings` | Changes how the system runs: the registry, boot settings, restore points, accounts, the firewall, antivirus, script policy; on macOS and Linux also security switches, services the system runs, Time Machine backups and machine-wide preferences ([below](#machine-settings-on-macos-and-linux)). |
| `elevated` | Runs as root or administrator. |
| `run_downloaded` | Runs a script it downloads, through a pipe or `Invoke-Expression`. |
| `run_input` | Runs commands read from its input (a pipe, a here-document), which the line does not show. |
| `stop_system` | Shuts the computer down, restarts it, or stops every process, or one the system needs. |
| `unknown` | Runs a program or a script known only when it runs. |
| `unreadable` | The line, or part of it, cannot be read. |

The wire names never change. A reason is a few plain words that follow from
the rule: `deletes your home directory`, `runs code the guard does not read`.

### Stopping processes by name

`killall`, `pkill`, `taskkill` and `Stop-Process` (also `kill`, `spps`) are
judged one way. Stopping a process by a plain name is everyday work (your own
dev server, `killall Finder`) and is safe: `killall node` and `pkill node` are
the same line. It is `stop_system` when the line stops more than a name:

- **Every process.** A pattern that matches every process: `pkill -f .`,
  `pkill ''`, `pkill '.*'`, `killall -r .`, `Stop-Process -Name *`,
  `taskkill /IM *`. `pkill` and `killall -r` read a regular expression, and the
  guard asks whether every match must hold a letter or digit the expression
  spells out; `a*`, `(a|)`, `^` and `\w` do not. An expression it cannot read
  (an unclosed `(` or `[`) counts as matching everything. `Stop-Process -Name`
  and `taskkill /IM` read a wildcard (`*`, `?`, `[a-z]`), judged the same way
  after a trailing `.exe` is dropped. `killall5` and `pkill -v` (every
  process but the ones named) are always `stop_system`.
- **Every process of a user, a group or a terminal.** `pkill -u me`, `-U`,
  `-G`, `killall -u me`, `killall -t ttys000`, `killall -Z context`,
  `taskkill /FI "USERNAME eq me"`, given no name. With a name
  (`pkill -u me node`) it is the name that is judged. `killall -c name` is a
  name too, judged as the operands are (`killall -c loginwindow`,
  `killall -m -c .`).
- **Every process a selection picks.** `pkill` given no pattern stops whatever
  its selection picks: `-P`/`--parent`, `-s`/`--session` and `-g`/`--pgroup` of
  0 or 1, or of a value only known when it runs (`pkill -P 1`, the children of
  `launchd` or `init`, which is every app and daemon; `pkill -s 0`, the
  session of the shell that runs the line, which is the terminal's processes;
  `pkill -P "$(pgrep -x launchd)"`), and `-O`/`--older`, `-r`/`--runstates`,
  `--cgroup`, `--ns`, `--nslist`, `--env`, `-t`/`--terminal` with any value
  (`pkill --older 1`, `pkill -t ttys000`). `pkill -P $$` (the shell's own
  children, read by its source text), `pkill -F pids.txt`, `pkill -s 1234` and
  `pkill -P 1 node` (the name is judged) are not. A value an option takes is
  never a pattern (`pkill -q 1 -u me`, `-r R`).
- **Every process a filter picks.** `taskkill` given a filter and no `/IM` or
  `/PID` stops whatever the filter picks: `/FI "STATUS eq RUNNING"`, `/FI
  "MEMUSAGE gt 1"`, `/FI "PID gt 0"`. Only `IMAGENAME eq name` (judged as
  `/IM name` is), `USERNAME` (above) and `STATUS eq NOT RESPONDING`, which
  stops the programs that hang, are read; with `/IM`, `/PID` or an
  `IMAGENAME eq` filter, the other filters only narrow what is named, and the
  names are judged.
- **A process the system needs.** `launchd`, `systemd`, `init`, `kernel_task`,
  `kthreadd`, `WindowServer`, `loginwindow`, `explorer`, `csrss`, `winlogon`,
  `wininit`, `lsass`, `smss`, `services` and `svchost`, in any case and with
  `.exe` or a folder in front (`killall /sbin/init` picks the process by its
  file, so the last part of the name is the name). `pkill` and `killall
  -r`/`-m` search their regular expression in the name, so it is compared two
  ways, per alternative: whole, without its anchors and brackets (`^init$`,
  `/sbin/init`, `Explorer`); and as a regular expression, asking whether it
  can match a system name at all. A name is searched for in the system name:
  `pkill login`, `pkill launch` and `pkill Window` stop `loginwindow`,
  `launchd` and `WindowServer`. A leading `^` wants the name to start with it,
  a trailing `$` to end with it, `-x` both. The case counts, so `pkill -f
  server` is not `WindowServer`, unless it is ignored (`pkill -i`, `killall
  -I`). The expression is read with its syntax, never skipped for having
  some: `.`, a `[…]` set and an escape are one character, a group and `|` are
  read as they are, a `*`, `?` or `{0,…}` lets what it follows match nothing
  and `*`, `+` or `{n,m}` repeat it. Where the syntax is only known roughly
  (an escape, a collating element, `\b`, a back reference) it is read as
  matching more, so `pkill '[l]aunchd'`, `pkill 'log.n'`, `pkill 'login(window)?'`,
  `pkill 'a+'` and `pkill '[[:alpha:]]x'` are `stop_system` while `pkill
  '[n]ode'` and `pkill -f 'node.*server'` are not. Without `-f` a `/` ends
  a folder, so what follows it is the name (`pkill '/sbin/[i]nit'`); `-f`
  matches the whole command line, so there the pattern is also searched, `/`
  and all, in the usual command lines of the system processes
  (`/sbin/launchd`, `/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow console`,
  the `WindowServer -daemon` in SkyLight, `/sbin/init`, `/lib/systemd/systemd`,
  `/usr/lib/systemd/systemd`), with the arguments launchd starts the first
  two with (its jobs for them run `loginwindow console` and `WindowServer
  -daemon`), and a match that is still going at the end of the line and can
  go on into a space counts, since any further arguments are not known:
  `pkill -f /System/Library`, `pkill -f System`, `pkill -f console`, `pkill
  -f -- -daemon`, `pkill -f 'WindowServer -daemon'` and `pkill -f 'systemd
  --user'` are `stop_system` while `pkill -f 'node server.js'`, `pkill -f
  vite`, `pkill -f 'rails console'` and `pkill -f ./target/debug/myapp` are
  not. `killall` without
  `-r` compares whole names only. A PowerShell or `taskkill` wildcard that
  matches one is the same (`Stop-Process -Name s*`).
- **A name only known when it runs.** `killall $NAME`, `pkill "$PATTERN"`,
  `xargs pkill`.
- **A listing into `Stop-Process`.** `Stop-Process` is read by its own
  parameters: `-Name` and its alias `-ProcessName`, `-Id`, `-InputObject`,
  `-Force`, `-PassThru`, `-WhatIf`, `-Confirm` and the common ones, each
  written in full or as any prefix that is not another's (`-N`, `-Proc`).
  With no `-Name`, `-Id` or `-InputObject`, it stops what the first stage
  lists: `Get-Process node | Stop-Process` is the name `node`, and any other
  first stage (`$procs | Stop-Process`) is known only when it runs. A
  `Get-Process` that is given `-Id` or `-InputObject` picks processes, as
  `Stop-Process -Id` does, and is safe; one given no name lists every
  process. A stage between the listing and `Stop-Process` is never "every
  process": `Where-Object` is read when it only compares `Name` or
  `ProcessName` with `-eq` or `-like` (`Where-Object { $_.ProcessName -eq
  'node' }`, `Where-Object Name -like 'node*'`), and judged by that name;
  `Sort-Object` and a `Select-Object` that only picks (`-First`, `-Last`,
  `-Property Name`) keep some of the same processes; a `Select-Object` given
  `-ExpandProperty` (`-exp`, `-expa`) or a calculated property (a hashtable
  or a script block) hands on other objects, such as a process's parent, and
  is any other stage. Any other filter is "picked by a filter only known when
  it runs", and any other stage, which may hand on other processes, is known
  only when it runs. What follows a named listing, when it only picks from it,
  can only narrow it, so the names are judged.
  The same holds when the listing is in the arguments: `-InputObject (Get-Process)`,
  `-Id (Get-Process).Id`, `-Id $(Get-Process node)`, and `$_`, `$PSItem` or
  `$_.Id` given to `-Id` or `-InputObject` inside a `ForEach-Object` block
  of a pipeline that starts with `Get-Process`. Any other `-Id` or
  `-InputObject` value (`$pid`, `(Get-NetTCPConnection …).OwningProcess`) picks
  processes the guard does not read and is safe. Only a member that is the
  process's own passes the listing on: `.Id`, `.Name` and `.ProcessName`, in
  any case. Any other member (`.Parent`, `.Threads`) hands on other objects,
  as `-ExpandProperty` does, and is any other stage: `Stop-Process
  -InputObject (Get-Process notepad).Parent` stops `explorer.exe`, which is
  an app's usual parent, and is `stop_system` as `((Get-Process
  node).Parent)` and `(Get-Process node).Parent | Stop-Process` are. A
  `Get-Process` anywhere else in the arguments, inside another command or a
  block, is read as one such listing, once, however many there are: the
  arguments are read in one pass that never goes below a command, so the time
  is the line's length however deeply they nest.
- **A fork bomb.** A function that calls itself in the background or as one
  side of a pipeline (`:(){ :|:& };:`, `f() { f & }`, `f() { f | f; }`) is
  `stop_system` however it is called, even when the line only defines it, and
  however the call is written: `\f`, `"f"` and `'f'` call the function `f`, as
  `\rm` is read as `rm`. A
  function defined inside another is judged on its own, by its own name, and
  its commands are not also read as the outer one's. A bomb split over two
  functions that call each other is not read.

`killall`'s and `pkill`'s options are read as they read them: bundled letters,
`-u me` or `-ume`, `--user me` or `--user=me`, a signal (`-9`, `-HUP`,
`-SIGHUP`, `-USR1`; any other run of capitals is options, so `-P1` is `-P 1`
and `-U0` is `-U 0`), long options abbreviated to any prefix that fits one
(`--pa 1` is `--parent 1`; a prefix that fits several is read as the
riskier). Options written after the first name are read both ways, because
the programs differ: GNU `pkill` reads on, while the macOS and BSD `killall`
and `pkill` stop reading options at the first name, so every later word is a
name too, a `-u` and its user included. Every word after the first name is
therefore also a name, with the value an option takes, and the options are
read as well, so the riskier reading counts: `killall node -u loginwindow`,
`killall node -s WindowServer` and `pkill node -u launchd` are `stop_system`
(the names `loginwindow`, `WindowServer` and `launchd`), while `killall node -s
HUP` and `pkill vite -9` are not. `pgrep` stops nothing and is safe.

A caller that used to stop on `killall node` stops seeing it: it was
`stop_system` ("stops every process with a name") and is now safe.

### Unpacking archives

An archive unpacked into a folder writes into that folder, and the folder is
judged as the destination of `cp` is, by where it resolves (see Paths). With
no folder given, it is the working directory, as moved by a `cd`. The paths
stored inside the archive are not in the line and are not read.

| Program | Folder | Writes nothing |
| --- | --- | --- |
| `tar`, `gtar`, `bsdtar` | `-C dir`, `-Cdir`, `--directory dir`, `--directory=dir`, `--one-top-level=dir` (every one given); an old-style first argument (`tar xf x.tar -C dir`) is read too | no `-x`/`--extract`/`--get`; `-t`, `-c`, `-r`, `-u`, `-A`, `-d`; `-O`/`--to-stdout` |
| `unzip` | `-d dir`, `-ddir`, inside a bundle (`-qod dir`) | `-l`, `-v`, `-t`, `-Z`, `-p`, `-c`, `-z` |
| `7z`, `7za`, `7zr`, `7zz` | `-oDIR` (every one given); `x` and `e` only | any other command (`l`, `a`, `t`) |
| `Expand-Archive` | `-DestinationPath`, or the second positional argument (the first when `-Path` or `-LiteralPath` is named) | |

`tar` takes a long option written as a unique prefix, which the guard reads
for the modes and `--to-stdout` as well as `--directory`: `--ext` and `--extr`
are `--extract` (at least three letters; `--to-s` is `--to-stdout`). A tar line
whose mode is only known when it runs (`tar "$mode" -f x.tar -C ~`, `tar $mode
-C ~`) is judged as if it extracted, unless a mode letter or long mode is
read: `tar -czf "$out" -C ~ .` writes no folder, as `-c` is read.

The reasons say `unpacks into your home directory`, `unpacks into a folder
outside the workspace`, `unpacks into a folder only known when it runs`. A
folder that is the workspace, inside it or a temporary file is not risky.

### Archiving that removes what it archives

Three options make the archiver delete each file once it has packed it:
`tar --remove-files`, `zip -m` (`--move`) and `7z a`/`7z u` with `-sdel`. The
members named on the line are judged as the operands of `rm` are (see
Paths), with the same reasons: `tar -cf x.tar ~ --remove-files` deletes
your home directory, `tar -cf x.tar * --remove-files` is judged as `rm -rf *`,
and `tar -cf x.tar src` and `tar -cf x.tar src --remove-files` are safe.
Packing without the option deletes nothing and is safe whatever it packs
(`tar -cf x.tar ~`).

| Program | Option | Members |
| --- | --- | --- |
| `tar`, `gtar`, `bsdtar` | `--remove-files` (a prefix of three letters or more), when the mode makes or adds to an archive: `-c`, `-r`, `-u` or their long forms | the operands, and `--add-file` (`--add-file=f`); an operand after `-C dir` (`-Cdir`, `--directory`) is under `dir`, and a later `-C` is under the one before, up to 512 bytes, past which it is a path known only when it runs; a long option that is a prefix of `--incremental` (`--inc`) takes no value, though bsdtar's `--include` does; every operand after `--`; `-T`/`--files-from` name members in a file the line does not show, which is a path known only when it runs |
| `zip` | `-m` anywhere in a bundle (`-mr`, `-rm`), `--move` | the operands after the archive's name, except those that follow a bare `-x`/`--exclude` up to a lone `@` or the end of the line (`-xpat`, `-x=pat` and `--exclude=pat` are one value and open no list); with none, the patterns that follow a bare `-i`/`--include`; `-@`/`--names-stdin` names members the line does not show; `-db`, `-sb`, `-ws` and `-li` are flags that take no value; `-UN` (`-UN=v`, `-UNv`, `-UN v`) and `--unicode` take a value, which is not an option |
| `7z`, `7za`, `7zr`, `7zz` | `-sdel` (any case), with command `a` or `u` | the operands after the archive's name, `-i!pattern` (also `-ir!`, `-ir0!`), and `@list` files, whose members the line does not show; with no operand and no `-i`, `a` and `u` pack everything in the working directory, so the member is `*` |

A `tar` mode that is only known when it runs (`tar "$mode" -f x.tar ~
--remove-files`) is judged as if it packed. A `tar` option that takes a value
in the next argument (`--exclude ~`, `--file x.tar`) does not make that value
a member. An operand only known when it runs is a member known only when it
runs; with `zip`, so is a first operand that is, since it may be the archive
and the members together. A pipeline's input (`ls | xargs zip -m x.zip`) is
the files the stage before it lists. With `7z`, an argument whose readable
start is `-` (`-p"$PASS"`) is a switch, not an operand; one wholly unknown
(`$OPTS`) may be a switch too, so the default `*` stays among the members when
the operands that are certain are only the command and the archive. With
`zip`, an argument only known when it runs inside a `-x` or `-i` list may
start with `-` or be `@`, which end the list, so the names after it are
operands again.

`7z` matches a wildcard itself, quoted or not, and a name that starts with a
dot is among the matches. `zip` does so on Windows; on Unix it matches
wildcards only for `-x`, `-i`, `-R` (the patterns of a recursive add) and the
names inside the archive, so there `zip -m x.zip 'a*'` and
`zip -mr x.zip '*git'` delete nothing. The guard judges the members of `zip` and `7z` alike, with the wildcards matching names that start
with a dot, whatever the shell. For `zip` on Unix this is a cautious choice,
not how the program behaves: `zip -mr x.zip '*git'` is judged as a delete of
`.git`, and so is the unquoted `zip -mr x.zip *git`.

`tar` is given the names the shell expands, so `tar -cf x.tar *git
--remove-files` leaves `.git` as `rm -rf *git` does.

### Git tags and submodules

`git tag -d` and `git tag --delete` are `git_discard` ("deletes a tag"): a tag
has no reflog to bring it back from. `git submodule deinit -f` (or `--force`)
is `git_discard` too: it throws away the submodule's changes; without `-f`
git refuses when there are some. Deleting a tag on a remote (`git push
--delete origin v1`, `git push origin :refs/tags/v1`) is `git_remote`.

### Running a download through `Invoke-Expression`

`iex (iwr url)` is `run_downloaded`, like `iwr url | iex` and `curl url | sh`.
`Invoke-Expression` (`iex`) is given a download when one of its arguments holds
a download cmdlet (`Invoke-WebRequest`, `Invoke-RestMethod`, `iwr`, `irm`,
`curl` and `wget`, which PowerShell aliases) or a .NET `Download…` call
(`(New-Object Net.WebClient).DownloadString(…)`) or `GetStringAsync`
(`HttpClient`), and then it is not also `unknown`. `Encoding.GetString` decodes
bytes and downloads nothing: `iex ([Text.Encoding]::UTF8.GetString(…))` is
`unknown`. A script held in a variable (`$s = iwr url; iex $s`) is still
`unknown`.

### Machine settings on macOS and Linux

`system_settings` also covers the changes to the machine that `sudo` does not
show. The guard keeps to what is system-wide or turns protection off; reading
a setting and a user's own settings stay safe. Callers treat the rule as one
of their strictest, so each family below was added on that test.

- **Security switches.** `spctl --master-disable`, `--global-disable` and
  `--disable` (Gatekeeper); `csrutil disable`, `authenticated-root disable`
  and `enable --without …` (System Integrity Protection); `setenforce` to
  anything but `1` or `Enforcing`; any write to `/etc/selinux/config` or
  `/etc/sysconfig/selinux`, whatever the program (a redirect, `tee`, `sed -i`,
  `cp`); `nvram` that sets, deletes or clears a variable (`boot-args`). A
  value only known when it runs is risky. `spctl --master-enable`, `csrutil
  status`, `setenforce 1`, `getenforce`, `nvram -p` and reading the files are
  safe.
- **The firewall.** `iptables` and `ip6tables` (and their `-legacy` and
  `-nft` builds) with `-F`/`--flush`, `-X`/`--delete-chain` or a default
  policy of ACCEPT (`-P chain ACCEPT`, `--policy`) for `INPUT`, `FORWARD` or
  a chain only known when it runs; the chain may be attached (`-PINPUT`,
  `-nPINPUT`, `--policy=INPUT`), and then the policy is the next argument.
  `OUTPUT` accepting is the default, so it is not read. `nft` joins its
  arguments with spaces and reads them as one line, so each command in
  them (split at whitespace, `;` and newlines, whichever argument it is in,
  `nft 'flush ruleset'` as well) is read: `flush ruleset|table|chain` and
  `delete|destroy table|chain` are risky, and so is a `flush`, `delete` or
  `destroy` of an object not known to be a set, map, rule or the like
  (`nft flush $what`), or a command word only known when it runs; `-d` and
  `--debug` take a level, as `-f` and `-I` take a value. `ufw disable`,
  `reset` and `default allow` for `incoming`, `routed`, no direction (which
  means incoming) or an unknown one; `ufw default allow outgoing` is ufw's
  stock default and is safe. `firewall-cmd --panic-on` and
  `--set-default-zone`; `pfctl -d` and `-F` with `all`, `rules` or `nat`,
  which may be abbreviated (`-F a`) and attached (`-Fa`, `-qFrules`), or
  with a modifier only known when it runs; `socketfilterfw --setglobalstate
  off`. Adding or deleting one rule, `-P chain DROP`, listing, `ufw allow`,
  `ufw enable` and `firewall-cmd --panic-off` are safe. Loading a ruleset
  from a file (`iptables-restore`, `nft -f`, `pfctl -f`) is not read: the
  file's content is not in the line. Long options may be abbreviated as
  `getopt_long` programs take them (`iptables --fl`).
- **Services the system runs.** `systemctl disable` and `mask`, unless
  `--user` is the last of `--user` and `--system`; `launchctl bootout`,
  `unload`, `remove` and `disable`. The one thing read as the workspace's own
  is a plist inside the workspace: `launchctl unload ./x.plist` and
  `launchctl bootout gui/501 ./x.plist` are safe, `bootout gui/501/com.x`
  (a label), `bootout system/…`, and any plist in `/Library/LaunchDaemons` or
  `~/Library/LaunchAgents` are not. `launchctl unload -D domain` unloads
  every plist in that search path (`-D system`, `-D all`), so it is risky
  whatever the domain. A command word only known when it runs
  (`systemctl $verb x`) is risky. `systemctl` options that take a value
  (`-t`, `--message`, `--capsule`, `--what`, `--timestamp`, `--image`,
  `--legend` and the like, also abbreviated) do not count as the verb, and
  are not read as `--user` or `--system` either: one walk of the arguments
  skips the values and finds those two (`systemctl -p --user disable x` is
  a system-wide disable). `timedatectl -p NTP set-ntp false` skips its
  `-p`/`--property` value the same way.
- **Stopping a service.** `systemctl stop`, `systemctl kill` and `service …
  stop` are safe, because `stop docker` is a common development step, and
  `stop` is not a change to what the system runs at boot; `launchctl stop` and `start`,
  `restart`, `enable` and `reload` are safe too. The exception is a unit
  that protects the machine (`firewalld`, `ufw`, `nftables`, `iptables`,
  `ip6tables`, `apparmor`, `auditd`, `fail2ban`), whose stopping is the same
  as turning that protection off, so it is risky. `systemctl kill` sends
  SIGTERM by default, which ends the daemon as `stop` does (and `auditd`
  refuses `stop`, so `kill` is how it is stopped), so it is read through the
  same rule: `systemctl kill firewalld`, `kill -s KILL auditd` and `kill
  'fire*'` are risky, `kill docker` is safe. `systemctl` matches a
  unit name holding `*`, `?` or `[` against the loaded units, so a pattern
  (`systemctl stop 'firewall*'`) is risky too. For `service name action`, an
  action only known when it runs may be `stop`, so it is risky when the name
  protects the machine or is only known when it runs (`service ufw
  $action`); `service nginx $action` is safe, as `service nginx stop` is.
- **Backups.** `tmutil delete`, `deletelocalsnapshots`, `deleteinprogress`,
  `thinlocalsnapshots`, `disable`, `disablelocal` and `removedestination`;
  `listbackups`, `status`, `startbackup` and `enable` are safe.
- **Machine-wide preferences.** `defaults delete <domain>` with no key,
  `defaults import` (the reason says "deletes" for a delete with no key and
  "replaces" for an import), and any `defaults write`, `delete`, `import` or
  `rename` whose domain is a path in a system folder
  (`/Library/Preferences/…`); `pmset` with `-a`, `-b`, `-c` or `-u`, or with
  any first operand but the actions that only act or read (`sleepnow`,
  `displaysleepnow`, `touch`, `noidle`, `boot`), because the flag is
  optional in `pmset sleep 0` and the operand is then a setting; `-g` reads;
  `networksetup` and `systemsetup` options that start `-set`, `-add`,
  `-remove`, `-create`, `-delete`, `-rename`, `-duplicate`, `-order`,
  `-import`; `scutil --set`; `hostnamectl set-…` and `timedatectl set-…`,
  and the verbs `hostnamectl` has since systemd 249 (`hostname`,
  `icon-name`, `chassis`, `deployment`, `location`) when given a value
  (`hostnamectl hostname newname`; with none they print); `hostname name`
  and `hostname -F`. An application's own keys
  (`defaults write com.example.app key value`, `defaults delete com.apple.dock
  persistent-apps`), a path in the workspace or the user's own folder,
  `defaults read`, `pmset -g` and the `-get`/`-list` options are safe.

`hostname` and `service` are read in POSIX shells only: in PowerShell and cmd
they are Windows programs and are left alone.

### The rule enum is exhaustive on purpose

`shell::Rule` is not `#[non_exhaustive]`. A caller decides what to do with each
rule (ask, refuse, allow), so a rule added here must break every caller's
`match` at compile time. With a fallback arm instead, the new rule would pass
through whatever policy the fallback has, and nobody would have chosen it. So a
new rule is a change a caller meets when it bumps its `rev` and fails to
compile, and it decides then; see
[how a change reaches a caller](../../CONTRIBUTING.md#how-a-change-reaches-a-caller).
(`Shell`, core's `Place` and `Shape` are the other way round: they are
`#[non_exhaustive]`, because a caller reads them rarely and a new one is not a
policy decision.)

`Rule::name` is an inherent `const fn`, so a caller needs no trait import, and
core's `RuleName` trait delegates to it. `Rule::ALL` lists every rule once.
Both are in the order of the table above.

## Paths

A path is judged by where it resolves against the working directory (moved by
any `cd`), the home directory and the workspace folders. The path model is
core's; see [Core](core.md). This guard adds what only a shell's syntax gives
a path.

- `~` is the home directory. `~user` is another user's, which the spelling
  does not say, so it is unknown.
- `$HOME`, `%USERPROFILE%` and `$env:TEMP` are the places they name.
- A PowerShell drive such as `HKLM:` is the registry. Any other drive, such as
  `Env:`, is outside the workspace. The drive is read before a wildcard, so
  `HKCU:*` is the registry like `HKCU:\*`.
- A drive-relative path (`C:x`, `C:*`: a letter, a colon, and no separator) is
  from that drive's own working directory, and so is a bare `C:`. On the drive
  the working directory is on, it is relative to it; on any other drive it is
  outside the workspace. After a `cd` it is unknown, except that after `cd C:`
  a relative path is `C:x`, a path on that drive.
- A listing hands its pattern on as written, so it is read the same way: the
  drive is not part of the pattern (`Get-ChildItem C:* | Remove-Item` takes the
  whole working directory), and a provider-qualified one
  (`Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER*`) is judged on the
  provider's own path.
  A drive's root listed (`C:\*`) is the root, not the drive's working directory.
- A PowerShell provider-qualified path (`FileSystem::C:\x`) is its provider's
  own path.
- A path built at run time, or by a brace list such as `{~,x}`, is unknown.
- `$null` and `NUL` are the null device.
- In PowerShell and cmd a name is read the way Windows reads it: `.git.`, `.git `
  and `GIT~1` are the repository's history, and `x.txt:stream` is known only
  when it runs (see [Core](core.md#what-core-judges)).

Inside a workspace or a temporary directory is the agent's own. Not the agent's
own: the home directory, a system folder, the root of a disk, the workspace
itself, its `.git`, keys and shell startup files.

A wildcard part stands for one entry, so a `..` after it still climbs:
`src/*/../../../x`. A part that starts with `.` can match `.git`; in PowerShell
and cmd, whose wildcards also match a leading dot, so can a part directly in
the workspace folder that fits the name (`*git`, `?git`, `*\objects`), though
`*\bin` cannot. A pattern whose last part is a catch-all (`*`, `?*`, `*/*`, and
`*.*` on Windows) takes the whole folder. One that picks names (`*.log`,
`*/*.o`) touches files inside it. [Core](core.md) has the rule.

## What cannot be read is risky

A line is never safe because the guard gave up on it. These come back risky:

- A program or script known only when it runs: `$CMD`, `eval "$x"`, `trap "$x" EXIT`, `iex $s`,
  `-EncodedCommand`.
- Code handed to an interpreter: `python3 -c`, `node -e`, a script piped into
  one.
- A .NET call that deletes, writes or starts a program.
- A path built at run time or by a brace list.
- A line the grammar cannot parse.
- Shells nested past a limit, a parse tree nested too deep, or a line longer
  than the limit.

`unknown` is for a program or a script. `unreadable` is for a line the guard
could not read.

## Reading more than one unit at a time

Some risks only show when units are read together.

- **Links.** A link judges its target too. `ln ~/.zshrc z` is risky, since a
  later write to `z` lands on the startup file.
- **A script a line writes and then runs.** It is risky however it was
  written: a redirect, a download (`curl -o`, `curl -O`, `wget`), a copy or
  `tee`. `curl -fsSLo i.sh URL && sh i.sh` is `run_downloaded`. The guard
  matches the two by the file they name (core's `key`).
  When the line writes a file (a device such as `/dev/null` does not count),
  a script whose path cannot be placed (after a `cd` to somewhere unknown, or
  `bash C:x` after a `cd`) is `unknown`, since it may be the one the line wrote.
  A line that writes nothing has no such script.
- **A listing piped into a delete.** It hands on what it picks. `ls *.bak |
  xargs rm` and `Get-ChildItem *.log | Remove-Item` delete files in the
  workspace. A whole folder listed (`ls | xargs rm -rf`) is as much as the
  folder. A listed pattern is judged as the delete of that pattern is, `..`
  and all: `ls -d src/*/../../.g* | xargs rm -rf` is risky.
- **`find`.** It acts on the folder it searches when its name filter can match
  `.git`, or when it negates or alternates its filters (`!`, `-not`, `-o`).
- **Git config that makes git run a command.** `-c alias.x=!...`,
  `core.pager`, `core.sshCommand`, and `git config` setting them. Reading
  them is fine.
- **In-place edits.** `perl -pi -e` is an edit like `sed -i`, judged by the
  files it edits, when its code is only substitutions (`s/a/b/g`, `tr/.../.../`)
  that run nothing. An `/e` flag, `@{[...]}`, backticks or any other code make
  it risky.

## Tests

The tests are tables: `tests/posix.rs` for POSIX lines, `tests/windows.rs` for
PowerShell and cmd, built on core's test kit. Each table has a list of safe
lines and a list of risky lines with the rule each must break. A new rule
comes with rows of both kinds.

`tests/names.rs` walks `Rule::ALL` and checks the wire names, that each rule is
listed once, and that the trait gives the same name as the method. Its list of
expected names is a `match` with no fallback arm, so a new rule does not compile
until it is named there. `tests/robust.rs` feeds the guard random lines and
checks that it never panics, and that a line too long or too nested comes back
unreadable.
