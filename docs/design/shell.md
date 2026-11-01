# Shell

`milo-guards-shell` judges a shell line before it runs. It reads POSIX shells
(`sh`, `bash`, `zsh` and the ones that share their syntax), PowerShell and
Windows `cmd`.

```rust
classify(line, shell, &paths) -> Assessment
effect(line, shell, &paths) -> Effect
```

`shell` is a `Shell` (`Posix`, `PowerShell` or `Cmd`), which is
`#[non_exhaustive]`: a shell with a grammar of its own may be added, so a
caller's `match` on it needs a fallback arm. `paths` comes from
`Paths::new(cwd, home, workspaces)`.
The answer is `Safe`, or `Risky` with every finding: a rule, a reason a prompt
can show, and the argument it is about. The guard reads the line and never runs
it. It touches neither the file system nor the environment.

`effect` is a second answer from the same split: does the line only read? See
[Reads only](#reads-only).

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
| `delete` | Deletes files beyond the workspace, the workspace itself, a sensitive or protected file, or a path known only when it runs. |
| `wipe_disk` | Formats, repartitions or writes over a disk. |
| `overwrite` | Writes into a file beyond the workspace, or a sensitive or protected one. |
| `git_discard` | Throws away work git cannot give back: uncommitted changes, untracked files, stashes, unmerged branches. |
| `git_remote` | Rewrites or deletes branches on a remote. |
| `git_history` | Rewrites the repository's history, or what git keeps to recover it. |
| `permissions` | Changes permissions or ownership beyond the workspace or of a protected file, or opens files to everyone. |
| `system_settings` | Changes how the system runs: the registry, boot settings, restore points, accounts, the firewall, antivirus, script policy. |
| `elevated` | Runs as root or administrator. |
| `run_downloaded` | Runs a script it downloads. |
| `run_input` | Runs commands read from its input (a pipe, a here-document), which the line does not show. |
| `stop_system` | Shuts the computer down, restarts it, or stops every process. |
| `unknown` | Runs a program or a script known only when it runs. |
| `unreadable` | The line, or part of it, cannot be read. |

The wire names never change. A reason is a few plain words that follow from
the rule: `deletes your home directory`, `runs code the guard does not read`.

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
itself, its `.git`, keys and shell startup files, and the paths the caller
protects.

### Protected paths

A caller names what it gates with (its settings, its rules, the folder it keeps
state in) in `Paths::protected` (see [Core](core.md)), and core answers
`Place::Protected` with the caller's words for it, even inside a workspace.
The guard needs no rule of its own: wherever a rule reads a place it takes
anything that is not harmless, so `Protected` is judged as `Sensitive` is, with
the caller's words in the reason. Reading is not a finding; what a read of a
protected file means is not decided here.

With `Protected::folder("/home/me/.agent", "the agent's settings")`:

| Line | Rule | Reason |
| --- | --- | --- |
| `rm ~/.agent/config.yaml`, `rm -rf ~/.agent` | `delete` | deletes the agent's settings |
| `mv ~/.agent/rules /tmp/x` | `delete` | moves the agent's settings |
| `echo x > ~/.agent/config.yaml`, `cp x ~/.agent/rules` | `overwrite` | writes to the agent's settings |
| `sed -i s/a/b/ ~/.agent/rules` | `overwrite` | edits the agent's settings |
| `chmod 777 ~/.agent/rules` | `permissions` | changes permissions of the agent's settings |
| `cat ~/.agent/config.yaml`, `ls ~/.agent` | safe | |

With the same path inside the workspace (`/home/me/work/repo/.agent`), `rm
.agent/rules` from the repository is a `delete`, `rm src/main.rs` stays safe,
and `rm -rf *` is still a delete of the whole workspace. A PowerShell or cmd
line on `C:\Users\me\.agent` is judged the same way, without regard to case
(on every host: `rm -rf .AGENT` is a delete on macOS too), and `AGENT~1` is the
protected name too.

A folder that holds a protected path is protected as well, so the whole folder
cannot be deleted or moved. With `Protected::file("/home/me/work/repo/conf/app/x.yaml", ..)`:

| Line | Verdict |
| --- | --- |
| `rm -rf conf`, `cd conf && rm -rf app`, `mv conf /tmp/x`, `rm -rf c*`, `rm -rf **/x.yaml` | `delete`, in the caller's words |
| `Remove-Item -Recurse conf`, `rd /s /q conf` | `delete`, in the caller's words |
| `touch conf/new.txt`, `rm conf/other.txt`, `rm -rf src`, `cp a.txt conf/`, `cp a.txt conf/app`, `mkdir -p conf/app` | safe: a write into a folder is not a write of it |
| `cp x.yaml conf/app/`, `cp -t conf/app x.yaml`, `mv x.yaml conf/app`, `install x.yaml conf/app/`, `ln -sf other/x.yaml conf/app/`, `cp *.yaml conf/app/`, `Copy-Item x.yaml conf\app`, `Copy-Item y.yaml,x.yaml conf\app`, `copy /y x.yaml conf\app`, `copy y.yaml+x.yaml conf\app` | `overwrite`: the file lands at its own name, which is the protected one |
| `cp -r other/. conf`, `cp -a app conf`, `rsync -a src/ conf/`, `Copy-Item -Recurse src conf`, `robocopy src conf /E`, `xcopy /s /y src conf` | `overwrite`: a recursive copy can replace anything below the folder |
| `rm -rf **/y.yaml`, `rm -rf **/*.rs` | safe: a protected file has nothing below its name (with a protected folder `cfg` they are `delete`) |
| `rm -rf .`, `rm -rf ~` | the workspace, the home directory: a risky place keeps its own words |

How the copy reads its operands: `Copy-Item` and `Move-Item` bind `-Path` at
position 0 and `-Destination` at position 1, and a comma list of sources is
flattened into the arguments, so with no `-Destination` each operand after the
first is read as the destination in turn, the rest as sources, and a risky
reading wins. The value of a parameter, a common one included (`-ErrorAction
Stop`, `-ea 0`, `-OutVariable o`), is never an operand. A source that comes
only from a pipeline (`gci src | cpi -Destination conf\app`), is unknown, or
is what `find -exec`, `-execdir` or `-ok` found (`{}`) lands as a name that
could be anything, which a protected name in the folder can be. The rows are
all kept in `tests/protected.rs`.

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

## Reads only

`classify` says whether a line is safe to run without asking. A caller that
asks on every line in a careful mode has a second question: does this line only
read? `ls`, `git status`, `cat src/main.rs` and `rg TODO` change nothing, and a
caller may run them without a question where it asks on `mkdir build`, which is
safe but changes the disk. Safe and reads-only are different answers, so
`effect` answers the second beside `classify`, and it is not a rule: it adds
nothing to `Rule`, and what a caller does with it is its policy.

```rust
effect(line, shell, &paths) -> Effect   // ReadsOnly(Reach), Changes or Unknown
```

| Answer | When |
| --- | --- |
| `ReadsOnly(Reach)` | Every unit is a known reader run with reading flags on files the guard can name, no redirect writes a file (the null device is not one), no `cd` the guard cannot follow, and the rules found nothing but an elevation. The [`Reach`](#reach) says where it reads. |
| `Changes` | Any unit is a known writer, a package manager or a build tool, any redirect writes a file, or a rule found the line risky for what it changes (`delete`, `wipe_disk`, `overwrite`, `git_discard`, `git_remote`, `git_history`, `permissions`, `system_settings`, `stop_system`). |
| `Unknown` | Anything is not understood: a program the table does not know, a program or script known only when it runs, a nested script, a line that cannot be read in full, a limit hit. Never `ReadsOnly`: what cannot be read is not reads-only. |

A line with a known writer is `Changes` whatever else it holds: `mkdir build &&
./script.sh` changes things, and not knowing the rest does not take that back.
`Unknown` is for a line with nothing known to change and something unread.

`effect` and `classify` come from one code path. A line is split once and
judged once, and both answers are read from that split and its findings, never
from the raw text, so they cannot disagree about what the units are. The
answers are independent, and a caller reads both. **Safe is not reads-only and
reads-only is not Safe**: `cat ~/.ssh/id_ed25519` reads only, beyond the
workspace (and is `ReadSecret` after #46), and `mkdir build` is safe and changes the disk. One
direction does hold, and `tests/` checks it on every row of every table and on
random noise: a line `classify` finds risky for anything but an elevation is
never `ReadsOnly`. `sudo cat /etc/hosts` is `ReadsOnly(Beyond)` and `Elevated`.

**Wrappers** come off as `classify` takes them off, and what they run decides:
`sudo cat` reads only. Only the wrappers that just run the next program are
let through (`sudo`, `doas`, `gsudo`, `pkexec`, `env`, `nice`, `ionice`,
`time`, `timeout`, `stdbuf`, `xargs`, `command`, `builtin`, and the `find` a
`-exec` makes), and only with options the guard knows: any other option
makes the line `Unknown`, since it could do anything (`sudo -e` edits a file,
`sudo -s` and `-i` start a shell, `env -P` changes where programs are found, `env -C` the folder they run in).
`time -o FILE` and `time --output=FILE` write a file, so they are `Changes`.
`flock` makes its lock file, `nohup` may make `nohup.out`, `tmux` and `screen`
start sessions: those wrap a reader into `Unknown`. A shell started with a
script (`bash -c`, `eval`, `cmd /c`, `powershell -Command`) is a program the
table does not know, so it is `Unknown` even when the script it holds only
reads.

### Reach

A caller that runs reads-only lines without asking, in its most careful mode,
needs one more answer: do the reads stay in the project? `ls src` and `cat
src/main.rs` do; `cat /etc/passwd`, `grep -r password ~` and `cat
~/.ssh/id_ed25519` do not. So `ReadsOnly` carries a `Reach`:

```rust
Effect::ReadsOnly(Reach)   // Reach::Workspace or Reach::Beyond
```

`Reach` is exhaustive on purpose, like `Effect`: a third answer would change
what a caller's careful mode means by "stays in the workspace".

- **`Workspace`**: every place the line reads is harmless, which is core's
  `Place::harmless()`: inside a workspace folder, a temporary file, or the null
  device. The workspace folder itself counts too, since that is what `ls` lists
  at the project's root.
- **`Beyond`**: at least one read lands anywhere else: the home folder, a
  system folder, a sensitive place (`~/.ssh`, `.git`), a protected path (the
  caller's own settings, even inside the workspace), a folder that holds the
  workspace (`..`), a temporary folder itself (`ls /tmp`; a file inside it is
  `Workspace`), a disk, the registry, or anywhere outside the workspace.
- A line that is `Changes` or `Unknown` has no `Reach`. A path known only when
  it runs is already `Unknown`, so it never gets one.

**What a line reads** is the places the answer already judges, each placed by
core the way a path is for `classify` (so `..`, `.`, doubled separators, `~`,
`$HOME`, case, 8.3 names and UNC paths come out as they do there):

- every file operand of a reader and the source of every `<` redirect;
- the folder of every lister (`ls ~`, `find /`, `Get-ChildItem C:\`);
- the value of an option that names a file, such as `grep -f ~/words`;
- the folder a `cd`, `pushd` or `Set-Location` goes into: going in is a read, so
  `cd ~` is `Beyond` even as a line of its own, for a caller that keeps the
  shell between lines;
- **the working directory, when a reader with no file operand reads it
  without being told.** `ls`, `du`, `fd`, `find` with no start, `rg PATTERN`,
  `grep -r PATTERN`, `Get-ChildItem` and `dir` with no path read the folder the
  line runs in: the caller's `cwd`, moved by every `cd` the guard follows, the
  way `classify` follows it. `git` reads the repository at the working
  directory, or at the folder `-C` names (chained: `-C a -C b` is `a/b`, and an
  absolute one starts over). A line run from outside the workspace, or after
  `cd ~` or a `cd ..` past the workspace's root, is `Beyond`;
- the shell's own expansion of a wildcard in an operand of a program that
  opens nothing (`echo ~/.ssh/*` lists a folder), and in PowerShell and cmd the
  folder a wildcard starts in (their wildcards can go below it);
- for `git`, the revisions and pathspecs after the subcommand, read as paths in
  the work tree, and the path in `REV:path` (`git show HEAD:.agent/config.yaml`);
  for `find`, the file `-newer`, `-anewer`, `-cnewer` and `-samefile` name.

Lines that read nothing (`echo hi`, `pwd`, `true`, `which cargo`, `basename x`,
`printf`) are `Workspace` from anywhere. So are readers of their input (`cat`,
`head`, `tail`, `wc`, `sort`, `grep PATTERN` with no file) given no operand.

Whitelist, not blacklist: only the readers known to read just their operands or
their input are left out of the working-directory rule (`cat`, `head`, `tail`,
`wc`, `stat`, `realpath`, `diff`, `sort`, `file`, `less`, `df`; in PowerShell
`Get-Content`, `Select-String`, `Get-Item`, `Test-Path`, `Resolve-Path`; in cmd
`type`, `findstr`). Any other reader, and any reader added to the table later,
is taken to read the working directory when it has no operand, and a reader
whose implicit input cannot be placed is `Beyond`: `df` with no operand reports
every mounted disk. A `grep` is recursive when it has `-r`, `-R`, `-d`,
`--recursive`, `--directories`, or an argument known only when it runs that
could be one.

**Protected paths inside the workspace.** A protected file or folder is not
harmless, so `cat .agent/config.yaml` and `ls .agent` are `Beyond`, and so is a
folder that holds one (`cat src` when `src/secret` is protected), as for a
delete. Core does not say the workspace folder itself holds it: `ls` at the
project's root only names the entries, and stays `Workspace`. A line that reads
everything below that folder does reach it, and is `Beyond` when a protected
path sits inside a workspace folder: `rg PATTERN` and `grep -r PATTERN` (from
the root, or given `.` or the root's path), `find -exec`, `findstr /s`, and any
reader handed names a lister produced (`find . | xargs cat`, `Get-ChildItem
-Recurse | Get-Content`). A reader handed what `ls` printed at the root counts
as one, though `ls` does not show hidden names: a false alarm accepted for a
rule that needs no list of names. A line that goes below a subfolder is judged
by the subfolder, which core already treats as protected when it holds the
path.

What stays open: `git diff`, `git log -p` and `git blame` read the content of
every tracked file, and a protected file that is committed is among them (`git
show HEAD:.agent/x` and a pathspec that names it are read as paths and are
`Beyond`; the bare `git diff` is not). The repository git finds above the
working directory is read too, and the guard cannot see where it is: a
workspace that is not itself a repository, inside one that is, reads beyond it.
`test`, `[` and `[[ ... ]]` check that a file exists and read nothing. A `-C`
or `cd` target through a symlink is placed by its spelling, as everywhere in
the guard.

### The readers

The table is short on purpose. A program not in it is `Unknown`. A reader that
takes a flag which writes is `Changes` when the flag is given; one that takes a
flag which runs another program, or can be handed one by an argument known only
when it runs, is `Unknown`.

| Shell | Reads only |
| --- | --- |
| POSIX | `ls`, `cat`, `head`, `tail`, `wc`, `stat`, `pwd`, `echo`, `printf`, `grep`, `egrep`, `fgrep`, `diff`, `du`, `df`, `which`, `realpath`, `basename`, `dirname`, `true`, `false`, `test`, `[`; `less`, `sort`, `file`, `rg`, `fd`, `find` and `git` with the care below; `cd`, `pushd` and `popd` when the guard follows them. |
| PowerShell | `Get-ChildItem`, `Get-Content`, `Select-String`, `Get-Item`, `Get-Location`, `Test-Path`, `Resolve-Path`, `Write-Output`, `Write-Host`, `Where-Object`, `Select-Object`, `Sort-Object`, `Measure-Object` and the aliases `cat`, `gc`, `type`, `sls`, `echo`, `pwd` (and `ls`, `dir`, `gci`, which `classify` already reads as `Get-ChildItem`); `git`; `Set-Location` when followed. |
| cmd | `dir`, `type`, `findstr`, `echo`; `git`; `cd` when followed. |

- GNU `sort`, `file` and `less` take any unambiguous prefix of a long option
  (`sort --outp=x` is `--output=x`, `file --comp` is `--compile`, `less
  --log=x` is `--log-file=x`). So a long option of theirs reads only when it
  is exactly one the guard names (`sort --reverse`, `file --brief`, `less
  --quit-if-one-screen`); a prefix of the option that writes is `Changes`
  (names compare without case, as `less` does), and any other is `Unknown`.
  The other readers have no long option that writes or runs a program, and `git`
  and `rg` refuse abbreviations.
- `sort -o` and `sort --output` write (`Changes`); `--compress-program` runs a
  program. `file -C` writes. `less -o`, `less -O` and `--log-file` write, `less -k`
  reads a lesskey file (whose `#env` section can set `LESSOPEN`), and an
  argument that starts with `+` is a `less` command. `rg --pre`, `rg
  --hostname-bin` and `rg -z` run a program; `fd -x` and `fd -X` run one.
  `printf -v NAME` sets a variable. All the others in the first group have no
  flag that writes or runs anything.
- `find` is `Changes` with `-delete`, `-fprint`, `-fprint0`, `-fprintf` or
  `-fls`. `-exec`, `-execdir`, `-ok` and `-okdir` are not a reason of their own:
  the program they run is a unit, as for `classify`, and is judged as one
  (`find . -exec cat {} +` reads only, `find . -exec rm {} +` changes).
- `git` is read for the subcommands `status`, `log`, `diff`, `show`, `blame`,
  `rev-parse` and `ls-files`, `remote` alone and `remote -v`, and `branch` and
  `tag` when they only list: every flag a listing one, and no operand that
  would create (`git branch topic` makes a branch; `git branch --list 'x*'`
  lists). `--output=FILE` writes. Each of the other reading subcommands has a
  list of the options it knows as reading ones, in `effect/git.rs`, and any
  other option is `Unknown` (`--ext-diff`, `--textconv`, `--help`, and any option
  added later); git refuses abbreviated long options, so a name matches
  exactly. `log`, `show` and `diff` share what they print about a change
  (`--stat`, `--name-only`, `-p`, `-w`, `-M`, `--color`, ...) and `log` and
  `show` what they walk (`--oneline`, `--graph`, `--decorate`, `--all`,
  `--author`, `--since`, `-n`, `-L`, ...); `status` has `-s`, `-b`,
  `--porcelain`, `-u`, `--ignored`; `blame` `-L`, `-w`, `-M`, `-C`, `-e`,
  `--porcelain`; `rev-parse` `--show-toplevel`, `--abbrev-ref`, `--git-dir`,
  `--verify`, `--short`; `ls-files` `-c`, `-d`, `-m`, `-o`, `-s`,
  `--exclude-standard`. Of these, the options that take a file are places: `blame
  --contents`, `--ignore-revs-file` and `-S`, `-O` and `--orderfile` on `diff`,
  `log` and `show`, and `ls-files -X` and `--exclude-from`; a value known only
  when it runs there is `Unknown`. An option that git takes with an optional
  value takes it only after `=` (`--pretty`, `--format`, `--date`, `--color`,
  `--stat`, `-U3`, `-M90%`, `-uno`): alone it takes nothing, so the next word is
  not swallowed. `log --show-signature` is not in the list, since it runs the
  `gpg.program` the repository's config names. `shortlog`, `describe`, `reflog`,
  `cat-file`, `ls-tree`, `grep`, `merge-base` and `rev-list` are not yet read, and
  are `Unknown`. The writing subcommands (`add`, `commit`, `push`, `checkout`, ...) are
  `Changes`, the rest `Unknown`. Only `-C`, `--no-pager`, `-P` and
  `--no-optional-locks` may come before the subcommand: `-c` and the others
  can make git run a command. What the repository's own config makes git run
  is not read, and a caller should know it: `diff.external` and textconv
  drivers (which `diff`, `show`, `log -p` and `blame` run on the files they
  show), `core.fsmonitor` (which `status` runs), and the lazy fetches of a
  partial clone (which any of them may make over the network). Each runs a
  program or touches the network from configuration the guard cannot see.
- Package managers and build tools (`cargo`, `npm`, `pip`, `make`, `brew`,
  `dotnet`, ...) are `Changes` whatever their subcommand.
- A program named with a folder is the program the shell finds by that name
  only in a system folder (`/bin`, `/usr/bin`, `/usr/local/bin`,
  `/opt/homebrew/bin`): `./cat`, `bin/ls` and `/tmp/x/ls` are `Unknown`, as are
  `cat.bat` and, in a POSIX shell, `ls.exe`.
- A variable the line sets or unsets makes it `Unknown`: `PATH=. ls`, `env
  PATH=. ls`, `env -u PATH ls`, `export PATH=...`, `GIT_PAGER=x git log`, and
  in PowerShell and cmd any assignment (`$env:PATH = ...`, `set X=1`). A
  language or a display setting is let through (`LC_ALL=C sort`, `LANG`, `TZ`,
  `TERM`, `COLUMNS`, `LINES`, `NO_COLOR`). A `for` loop's own variable is not a
  setting, unless its name could be one that changes what runs (`PATH`, or in
  zsh `path`).
- A PowerShell method call (`[IO.File]::ReadAllText(...)`, `$x.Delete()`) is
  no unit, and the rules know only some of them: it is `Unknown`. So is a
  backtick substitution in an unquoted here-document, which the grammar does
  not read and the shell runs.
- **A path known only when it runs makes the line `Unknown`.** A reader's file
  operand or the source of a `<` redirect (`cat $f`, `cat < "$F"`, `cat
  "$(pwd)/x"`, `grep x "$f"`, `type %X%`, `Get-Content $x`, `cat ~root/x`) may
  name anything, a network device or a share included, and what cannot be read
  is not reads-only. The paths the guard names stay known: `~`, `$HOME`,
  `$TMPDIR`, `$env:TEMP` and the other forms [Core](core.md) resolves, and a
  glob, which is a pattern over known folders (`cat *.rs` reads only).
- **Only a path is judged as a path.** Each reader's table entry says which
  arguments the program opens as files. A pattern, a count or an author is
  data: `grep -rn "$PATTERN" .`, `rg "$x" src`, `head -n "$N" x`, `sort -k
  "$K" x` and `git log --author="$NAME"` read only. For `grep` and `rg` the
  first operand is the pattern, unless `-e` or `-f` gives it (`-f FILE` and
  `rg --ignore-file FILE` are paths, and so is every operand of `rg --files`);
  a value of an option that takes one is data, unless the option takes a file;
  for `find`, the places are the arguments before the first test, and the
  value of `-name` and the like is data. For `git`, the places are the value
  of `-C`, what comes after `--`, and every operand of `--no-index`; the other
  operands are revisions and pathspecs inside the work tree, which git does
  not take outside it. A value counts as data only when it is known or every
  expansion in it is in double quotes: unquoted, `$x` splits into more
  arguments, options among them, and is an operand. An operand known only when
  it runs is `Unknown` for `git`, since it could be an option. What stays
  open: a quoted pattern or value could itself start with `-` and be read as an
  option.
- **Switches and options that name a file or folder are places too.** In cmd,
  `findstr` takes its switches with `/` or `-` (`/f:file`, `-f:file`) and runs
  letters together after one prefix, the one that takes a value last (`/smf:file`,
  `-if:file`); `/s/b` is two runs. A switch is never an operand. A run with a
  letter `findstr` does not know, or a value switch that is not last, makes the
  line `Unknown`. Three switches name files: `/G:file` holds the search
  strings and `/D:dir;dir` the folders to search (a list split at `;`), and
  their values are places; `/F:file` is a list of files to open, which the
  guard never sees, so it is `Unknown` whatever it names. `/C:string` and
  `/A:attr` are data. With `/G:` or `/C:` every operand is a file, where
  otherwise the first operand is what to search for (one known only when it
  runs could be a switch, so it is a place). `dir`'s `/A:`, `/O:` and `/T:` are
  data, and `type` has no switch. `//server/share` is no switch.
- **An option that reads its list of files to open from another file is
  `Unknown`, whatever its value**, since the list could name a share:
  `findstr /F:`, `wc` and `du` and `sort` `--files0-from`, `file -f` and
  `--files-from`, `find -files0-from`, and `xargs -a` and `--arg-file`. An
  option whose file holds patterns, not paths, is read as a place only:
  `grep -f`, `rg -f`, `findstr /G:`. Of GNU's other long options, `diff
  --from-file` and `--to-file`, `grep` and `rg` `--file`, `du` and `diff`
  `--exclude-from`, `sort --random-source` and `realpath --relative-to` name a
  file, and the file is a place.
- In PowerShell, `-Path` and `-LiteralPath` (`Get-ChildItem`, `Get-Item`,
  `Get-Content`, `Select-String`, `Test-Path`, `Resolve-Path`) and
  `Resolve-Path -RelativeBasePath` are places; `-Filter`, `-Include`,
  `-Exclude`, `-Stream`, `-Encoding`, `-Delimiter`, `-Tail`, `-TotalCount`,
  `-Pattern`, `-PathType` and `-OlderThan` are not. None of the readers in the
  cmd and PowerShell tables has a switch that writes; `sort /O`, `more`,
  `where` and `find` of cmd are not in them and are `Unknown`.
- **An option never swallows an option.** Whenever a reader's option takes
  its value from the next word and that word starts with `-` (a number such as
  `head -n -5` is a value), the line is `Unknown`, in every reader's option
  parser, so an option listed as taking a value that git or another program
  also takes bare can never hide a real option behind it.
- **PowerShell quotes inside a word are taken off as PowerShell takes them**
  before the word is judged: `--contents="\\evil\s"` reaches the program as
  `--contents=\\evil\s`, and a doubled quote inside quotes of its kind is one.
- **A pipeline into a reader** (`xargs cat`, and in PowerShell `Get-Item`,
  `Get-ChildItem`, `Test-Path`, `Resolve-Path`, `Get-Content` and `Select-String`
  with no path of their own) hands it paths, so the stage before it must list
  known places: `ls`, `fd`, `dir`, `Get-ChildItem`, `git ls-files`, or a `find`
  that prints only what it finds (`-printf` and `-exec` print any text), through
  stages that only select or order (`head`, `tail`, `sort`, `grep` with no file
  of its own; `Where-Object`, `Sort-Object` and `Select-Object -First`, with no
  `-Property`). `ls | xargs cat` and `Get-ChildItem | Get-Content` read only;
  `echo a | xargs cat` and `'\\evil\share' | Test-Path` do not. A
  `Select-String` also takes the text of `Get-Content` or another search.
  Programs that only print their operands (`echo`, `printf`, `basename`, `test`,
  `Write-Output`) are not readers of them.
- **A `for` over words written out** (no expansion in the list) is read with
  each word in place of the variable, as if the body were written out, the
  network check included: `for f in *.txt; do wc -l "$f"; done` reads only,
  `for f in /dev/tcp/h/80; do cat $f; done` does not. A glob stands for itself.
  Not read this way, so `Unknown`: a list with an expansion (`for f in $(ls)`),
  no list (`for f; do`), a body that sets the variable (assignment, `unset`,
  `read`, `((`, `${f:=}`, a loop of the same name) or defines a function, a
  variable in the program's own name, and a `<` redirect in the body. More than
  64 combinations of words are not read either.
- A read that contacts the network is `Unknown`, judged on the path's known
  value after quotes are resolved, never on its spelling. Every reader's
  arguments get that check, and so does every value inside one: after the
  `=` of a long option or the `:` of a switch, and attached to a short option
  (`-O//evil/s/x`, `--exclude-from=\\evil\s\x`, `/a:\\evil\s`), so the option
  nobody listed is caught too. Only the spelling of a share or a device is
  checked in a value, not whether it is known: `--author="$NAME"` still reads
  only. In PowerShell a variable inside a bare token (`--contents=$p`) is
  expanded, so such a value is a path known only when it runs. The names are: a path naming bash's
  `/dev/tcp/HOST/PORT` or `/dev/udp/HOST/PORT`, as an operand or as the source
  of a `<` redirect (`cat < /dev/tcp/evil.example/80`; a spelling that hides
  it, such as `/dev/$'\x74'cp/...` or `/dev/${X}tcp/...`, is a path known only
  when it runs); and in PowerShell and cmd a UNC path (`\\server\share`,
  `//server/share`, `\\?\UNC\server\share`, `\\.\UNC\server\share`,
  and `GLOBALROOT` after `\\?\` or `\\.\`, which reaches the share through
  the device namespace), which offers the user's credentials to the server. A
  long path or device that is a disk (`\\?\C:\x`, `\\.\PhysicalDrive0`) is
  not a share. Repeated separators and `.` parts are folded as Windows folds
  them (`\\.\\UNC\host\share`), and a path with `..` in its root counts. A
  `<` redirect is read in cmd too, with a handle in front (`0<`).
- Not read, so the caller has to account for them: an alias or function
  defined outside the line, the `PATH` the shell runs with, and an option set
  by a start-up file. A name in the table is taken to be the program that
  name means.
- `echo` and `printf` count as reading: with no redirect they change nothing.
  `echo hi > out.txt` is `Changes` through its redirect.

`effect` is an enum of its own and not a field of an explanation of the line.
It is exhaustive, as `Rule` is and for the same reason: the three answers are
the whole question, and a fourth would change what a caller's gate means by
"reads only", so it must break every caller's `match` at compile time. (A
caller that only asks whether `effect(..)` is `ReadsOnly(_)` is unaffected by one.)

## Tests

The tests are tables: `tests/posix.rs` for POSIX lines, `tests/windows.rs` for
PowerShell and cmd, built on core's test kit. Each table has a list of safe
lines and a list of risky lines with the rule each must break. A new rule
comes with rows of both kinds.

`tests/effect.rs` is the same for `effect`: a table of lines for each answer. Every
line of `posix.rs` and `windows.rs` also goes through `effect`: the shared
`check` does it for each row of a table, and the tests that name a finding's
reason judge their lines with the shared `classify` of `tests/common`, which
does it too. A line `classify` finds risky for anything but an elevation must
not be `ReadsOnly`.

`tests/names.rs` walks `Rule::ALL` and checks the wire names, that each rule is
listed once, and that the trait gives the same name as the method. Its list of
expected names is a `match` with no fallback arm, so a new rule does not compile
until it is named there. `tests/robust.rs` feeds the guard random lines and
checks that it never panics, and that a line too long or too nested comes back
unreadable (and `Unknown` for `effect`).
