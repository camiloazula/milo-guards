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

In cmd, `cd` (or `chdir`) without `/d` does not change the drive: for a path
on another drive it sets that drive's own working directory and the line stays
where it was, so `cd D:\ws\a & rd /s /q ..\..` from `C:\Users\me\repo` deletes
`C:\Users`. The line tracks the drive it is on, starting from the working
directory's. With `/d`, or on the same drive, the line moves as for any `cd`;
`pushd` and `D:` change the drive and so move it. Where the line is on is not
known after `popd`, from a working directory on no drive, or beside a `/d`
that does not come first, and a `cd` to another drive then leaves the line
somewhere unknown.

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
| `delete` | Deletes files beyond the workspace, the workspace itself, a sensitive file, or a path known only when it runs. |
| `wipe_disk` | Formats, repartitions or writes over a disk. |
| `overwrite` | Writes into a file beyond the workspace, or a sensitive one. |
| `git_discard` | Throws away work git cannot give back: uncommitted changes, untracked files, stashes, unmerged branches. |
| `git_remote` | Rewrites or deletes branches on a remote. |
| `git_history` | Rewrites the repository's history, or what git keeps to recover it. |
| `permissions` | Changes permissions or ownership beyond the workspace, or opens files to everyone. |
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
  A drive's name is whatever comes before the first `:` when that holds no
  separator, no wildcard and no `.`, so a drive made with `New-PSDrive`
  (`my_drive:*`, `my-drive:\*`) is a drive, outside the workspace, and
  `x.txt:stream` is a file's stream, not a drive.
- The item cmdlets are judged by where their path lands, as `Remove-Item` is:
  `Clear-Item`, `Rename-Item`, `Set-Item`, `New-Item`, `Move-Item`,
  `Copy-Item` (its destination), the `-ItemProperty` cmdlets and their
  aliases. A registry place is `system_settings`: `Clear-Item HKCU:\Software\x`,
  `Rename-Item HKCU:\Software\x y`, `Set-Item HKLM:\SYSTEM\x -Value 1`. A
  rename or move of what lies beyond the workspace is `delete`, and a
  `Set-Item` or `Clear-Item` on another drive (`Env:`, `Variable:`) is
  `overwrite`, as writing to it is. `Rename-Item src\a.rs b.rs` is safe. With
  no path, the four that act on an item work on what the stage before lists (or `$_`), except that a
  listing of the whole workspace by `Get-ChildItem`, `ls` or `dir`, or a
  `Get-Item` pattern such as `Get-Item *`, is its contents, not the workspace
  itself; `Get-Item .` or `Get-Item D:\ws2` hands on that folder, as written.
  `Clear-Item` and `Set-Item` take a list of paths, so each
  `-Path`/`-LiteralPath` value and each positional is judged
  (`Clear-Item src\a, HKCU:\Software\y`, `Set-Item src\a, HKLM:\x`).
  `Rename-Item`'s `-Path` and `-LiteralPath` take one string, so a list there
  makes the command fail; every positional is judged all the same, because
  the guard cannot tell which is the item when a bare `-n`, a `--` or a
  splat (`Rename-Item y @p`, where `@p` may hold `-Path`) hides it. The
  value of `Set-Item` and the new name of `Rename-Item` are judged as places
  too, since one that is a place of its own makes the command fail. The one
  exception is a new name made at run time (`Rename-Item src\a.rs $name`)
  after the first positional, unless one of those leaves it unclear
  (`Rename-Item -n y HKCU:\Software\x`). `-PSPath` and `-LP` are
  `-LiteralPath`, so `Rename-Item y -PSPath $p` renames `$p`, and
  `Clear-ItemProperty y -PSPath HKCU:\Software\x` is the registry. `Move-Item` judges every
  source: each `-Path`/`-LiteralPath` value and every positional but the
  destination, which is `-Destination` or else the last positional
  (`Move-Item -Path src\a,C:\Windows\x -Destination src\d`). `New-Item` judges
  every positional when no `-Path` is named (only `-Path` is positional, so an
  extra one only makes the command fail), and `-Type` and `-PropertyType` take
  a value. The `-ItemProperty` cmdlets judge their first positional and every
  known one, and every positional when a bare parameter that may take a value
  (`-n`), a `--` or a splat leaves the path unclear
  (`Clear-ItemProperty -n a HKCU:\Software\x`). A `--` is never a path. A
  splat is `@` and a variable name (`@p`, `@args`); `@(...)` and `@{...}` are
  not one. `Copy-Item` and
  `Move-Item` judge a splat as a possible destination when no `-Destination` is
  named (`Copy-Item @p`, `Copy-Item @p src\a`). A `Get-ChildItem` listing reads
  `-s` (`-Recurse`), `-ar` (`-ReadOnly`) and `-Name` as switches, so they do
  not take the folder listed (`gci -s HKCU:\Software | Clear-Item`). A
  `Get-ChildItem` or `Get-Item` listing that is `-Force`, `-Hidden` (`-ah`)
  or has an `-Attributes` value that may name hidden files (`Hidden`, `h`,
  `!Directory+Hidden`, or one it cannot read) hands on
  the hidden files of the workspace (`.git`) too, so
  `Get-ChildItem -Force | Rename-Item -NewName x` is a `delete`, as
  `Rename-Item .git x` is. A filter on such a listing is judged against the
  folder: a `-Filter` or `-Include` pattern that can match `.git`
  (`*`, `.g*`, `.git`) hands on `.git`. A `-Filter` is also matched by the file
  system against the 8.3 short name, `GIT~1` on the system drive, so `-Filter
  g*`, `*~1`, `GIT~?` and `?????` hand on `.git` too, read as cmd reads a
  wildcard, DOS wildcards included: `<` is a `*`, `>` a `?` that can match
  nothing, and `"` a `.` that can match nothing (`-Filter .gi<`, `<`), and a `.`
  followed by `*` or `?` can match nothing too (`-Filter HEAD.*.*` finds `HEAD`) (`-Include`
  is PowerShell's own matching, against the long name only, where these are
  plain characters). A recursive
  listing (`-Recurse`, `-Depth`) searches the folders below, so
  `-Filter config` finds `.git\config`: it hands on `.git` when a pattern can
  match one of the names `.git` holds: a top-level entry or file (`HEAD`,
  `config`, `index`), a folder below the top (`pack`, `heads`, `tags`,
  `remotes`, and the default remote `origin`), `stash` (the only reference
  to every stash entry), a branch named `main` or `master`, or an object by the shape of its name, asked as "can this pattern
  match some string of n hex digits": a loose object's folder (two digits,
  `??`), its file (thirty-eight, `1*`, `*7*`) and a pack (`pack-` and forty
  digits, then `.pack` or `.idx`); and every hidden folder when a pattern is
  not known. `bin`, `obj`, `node_modules`, `Debug`, `*.tmp`, `*.orig` and
  `*.log` hold a letter that is not a hex digit, or a dot, so they match none
  of these.
  `-Force -Filter *.tmp | Move-Item -Destination trash` stays safe, and
  `-Exclude` leaves the listing whole. So the everyday clean-ups
  `-Include bin,obj -Recurse -Force | Remove-Item -Recurse -Force`,
  `-Recurse -Force -Directory -Filter node_modules` and
  `-Force -Recurse -Include *.tmp` stay safe, as do `-Filter *.log | Remove-Item`
  and `-Recurse -Include *.tmp | Remove-Item` without `-Force`.
  `-Depth` and `-Attributes` take a value, which is never read as the path.
  A common parameter's value (`-ErrorAction 0`) is never read as the path.
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
- `del /s` and `erase /s` search every folder below the one they start in.
  From the workspace folder, a name pattern that can match one of the files
  `.git` holds (`HEAD`, `config`, `index`, `packed-refs`, `description`,
  `COMMIT_EDITMSG`, `stash`, a branch named `main` or `master`), a folder below its
  top (`pack`, `heads`, `tags`, `remotes`, `origin`), or an object by the
  shape of its name (a loose object's two-digit folder, its thirty-eight-digit
  file, a `pack-` and forty hex digits with `.pack` or `.idx`) is a
  `delete`: `del /s /q HEAD`, `del /s /q *.` (every name without an
  extension), `del /s /q ?????`, `del /s /q 1*`, `del /s /q *7*`.
  `del /s /q *.obj`, `*.tmp`, `*.pyc`, `bin`, `obj` and
  `Thumbs.db` stay safe, and so does a pattern started deeper in the
  workspace (`del /s /q src\HEAD`), since only the workspace's own `.git`
  is the model's to protect. Without `/s` the name is one file in the folder
  (`del HEAD` is safe). Whether `del /s` descends into hidden folders has
  not been checked on a Windows machine; it is taken to, since a false safe is
  the worse mistake, and the rows relax if it is found not to. The pattern is
  read by cmd's rules, not PowerShell's: a `.` followed by `*` or `?`
  also matches nothing, as cmd's DOS dot does (`del /s /q main.*` takes the
  branch `main`, `del /s /q HEAD.*.*` takes `HEAD`), a run of `?` at the end or just before a `.` can match
  nothing (`HEAD?`, `????????`), cmd's DOS wildcards are read (`<` is a
  `*`, `>` a `?` that can match nothing, `"` a `.` that can match nothing:
  `del /s /q "HEA>"`, `del /s /q "<"`), and the 8.3 short names of the long ones are
  tried too (`*.pac`, `COMMIT~1`, `PACKED~1`, and six hex digits with `~1` for
  a loose object), since the system drive creates them. `main.obj`, `*.obj`, `*.log` and `*.orig` stay safe. Only the names
  listed, their short forms and the hex shapes are tried, so a pattern that
  fits some other branch name (`dev`) is not told.
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
- PowerShell code known only when it runs: a script block that is not written
  out where a cmdlet takes it (`Invoke-Command $b`, `-ScriptBlock $b`, `Start-Job`,
  `Start-ThreadJob`, `Register-ScheduledJob`, `Set-PSBreakpoint -Action`,
  `-Process`/`-Begin`/`-End`/`-RemainingScripts` and the first block of
  `ForEach-Object`, `Where-Object -FilterScript`, `New-Module`,
  `Measure-Command`, `Trace-Command -Expression`), a hook set on `$ExecutionContext.InvokeCommand` (by
  assignment or its `set_` method, `LocationChangedAction` among them), and code built
  from text (`[scriptblock]::Create(…)`, `NewScriptBlock`, `InvokeScript`,
  `ExpandString`, whose `$( )` subexpressions run). A block
  written out is read where it stands, and so is a string written out as the
  text of the code; a method name quoted (`.'InvokeScript'(…)`) is the same
  method. A method called by a name only known when it runs
  (`.$m('…')`, `.($m)('…')`, `."Invoke$x"('…')`) may be any method, `InvokeScript`
  and `Delete` among them, so it is risky; a property read (`$row.$col`) has no
  call and is not. `Where-Object Name -eq x` takes a word first as the property
  of the comparison, so only another first argument that is not a block
  written out (`? $b`, `Where-Object $prop -eq 1`) is risky, as is
  `Trace-Command`'s second argument (`Trace-Command Name $b`) or its `-Command`.
  `ForEach-Object Name` takes a member name, not a block, and what
  follows it is the member's arguments (`$list | % Add $item` is safe), but a
  member name is judged as the call written out is: a method that is
  risky as `.Invoke()` and `.Delete()` are (`% Invoke`, `-MemberName Delete`),
  `InvokeScript`, `NewScriptBlock` and `ExpandString` (their text is read when
  written out, positionally or after `-ArgumentList`), and a hook set by
  `set_` or by its property given an argument. `Start-Job` takes
  `-InitializationScript` by position after the block, so `Start-Job { … } $init` is risky, and a named
  `-InitializationScript` on `Start-ThreadJob` or `Register-ScheduledJob` does not
  make a block given by position safe. A splat (`@p`) on these cmdlets may hold a
  block, so it is risky unless the cmdlet runs one block only and one is written
  out. A comma list stays with the parameter it follows (`-ArgumentList $x, $y`),
  and so does the argument after a parameter written with a colon
  (`-Confirm:$false`), a common parameter (`-ErrorAction Stop`) and `-Args`.
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
