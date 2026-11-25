# Code

`milo-guards-code` reads code of another language and says what it is
certain to do. It holds the readers of Python and JavaScript (Node, Bun and
Deno) that the shell guard uses for `python3 -c`, `node -e` and a
here-document fed to an interpreter, as a crate of its own: the script guard
([Script](script.md)) judges with it the code a tool runs directly, with no
shell line around it, and a guard of the files an agent writes could judge a
`.py` or `.js` file the same way.

It is a reader, not a guard. It judges nothing: it has no `Rule`, no
`Assessment`, no `Paths`. A caller turns what it finds into what it already
judges (the shell guard turns a delete into `rm -rf PATH`) and decides what
to do with that. So it keeps four of the five promises of
[the contract](architecture.md#the-contract) as they are written, and the
fifth, *what cannot be read is risky*, as *what cannot be read is not
understood*.

## The API

Two functions take a `Language` (`Python` or `JavaScript`) and the text of the
code.

- `read(language, code)` gives a `Reading`: the `acts` the code makes, in the
  order it makes them, and `deep`, whether the code nests too deeply to read
  in full. An `Act` is what the code is certain to do (a delete, a write, a
  read, a move, a program started, an environment changed) with the paths it
  names, as an `Arg`: `Known` (the code gives the value), `Unknown` (only known
  when the code runs; its source is kept) or `Below` (a path that starts as the
  code says and ends in something only known when it runs, so the folder is
  known: `'/home/me/.ssh/id_' + name`). What the reader cannot follow is an
  `Act::Unread` and never left out. What it finds is kept wherever the code
  comes from and however it is written; code with a syntax error is not read
  through the error, and gives an `Unread` alone (the interpreter raises
  before it runs a thing).
- `understand(language, code)` gives an `Understanding`: `Understood` when the
  code is nothing but a few plain statements the reader reads in full (the
  [strict subset](#the-strict-subset)), `NotUnderstood` when anything is
  outside it. That nothing was found in code is only safe to take as "does
  nothing" when it is understood.

The two are asked apart on purpose. A caller keeps every act for code it does
not understand (a delete in a function is still a delete), and says "unknown"
for it only when it found none. `Understood { imports }` also says whether the
code may load a module: all Python code does, with or without an `import`,
and it looks in the folder the code runs in first (an uncaught exception
imports `traceback`, the `idna` codec imports `stringprep`). A caller
understands Python code only where that folder is its own. An `import` is
understood only for a module built into the interpreter binary, which no file
in that folder can stand in for: `import json` is not understood, since it
runs `./json.py` when there is one. Understood JavaScript has no import at
all.

Six more functions are for what a caller meets next to the code:

- `parses(language, code)`: whether the code parses whole, its grammar reading
  it with no error, as `read` reads it. Code that does not parse is not read
  (`read` gives an `Unread` alone); a caller asks this to tell such code from
  code it parses but does not follow, as the script guard does to call it
  `unreadable`. Python's grammar reads an empty block
  (`if 1:`) with no error, which Python refuses: it parses, and is not
  understood. Code the reader stops on (see [Limits](#limits)) does not
  parse.
- `gives_input(language, code)`: whether the code may give a program it starts
  something to read on its input, which `read` does not give with the
  program: in Python a keyword argument `input` or `stdin`, or a `communicate`
  or `stdin` member; in JavaScript an option `input`, `stdin` or `stdio`, or
  a `stdin` member, a `popen` given more than its command (`os.popen('sh',
  'w')`), a `['stdin']` subscript, and a `stdin` taken apart (`const { stdin:
  s } = spawn(…)`). It is read loosely, by name, on any call, and code that
  does not parse may, as may code the reader stops on: the script guard asks
  it of code that starts a program.
- `gives_shell_a_list(language, code)`: whether code may hand a shell a list
  of words. It answers "may". In Python, a call whose first argument (or
  `args=`) is a list or a tuple and that is given `shell=` with anything but
  `False`, or arguments that may carry it (`**kw`, `*rest`, positional
  arguments past the list); in JavaScript, a call given an array of words and
  options that are not an object written out without a spread (a name, a
  call, `{ ...o }`), or any call with a spread among its arguments. On POSIX
  the shell runs the first word as the line and the rest as its arguments,
  which `read` gives as the script; on Windows the words are joined into the
  line, which no act gives. An object written out with `shell: true` is read
  where the call is: its words are joined into the script `read` gives. Code
  that does not parse may, as may code the reader stops on.

- `declares_other_encoding(code)`: Python code given as bytes (a
  here-document, the bytes literal of `exec`) honours a coding declaration in
  its first two lines that decodes it to other text than the reader sees. Such
  code is not read. UTF-8, and the ASCII-compatible encodings for a text that
  is all ASCII, read the same.
- `is_foreign_module(specifier)` and `is_data_url(specifier)`: whether a
  module a `--import` option or an `import` names is loaded from outside the
  workspace (the network, a registry that downloads it, an absolute path, one
  in the home directory, a `file:` URL, one that goes up from where the code
  runs), or is a `data:` URL, whose code runs where it is written. As the URL
  parser reads it, leading control characters and spaces and any tab or
  newline are dropped and the scheme has no case. A relative `./x.js` and an
  installed package (`fs`, `node:fs`) are not foreign.

The limits a caller holds code to are constants: `MAX_LEN` (64 KiB, the
longest code it hands the reader), `MAX_DEPTH` (8, how deep code may run
code, `exec("…")` inside `exec("…")`) and `MAX_TREE_DEPTH` (400, how deep a
parse tree is walked). `read` and `understand` refuse longer code
themselves, and a caller may refuse it first.

The work the reader may do for code is a `Budget` (see [Limits](#limits)):
`Budget::new(len)` for code or a line of `len` bytes, with `read`,
`understand`, `understand_python2`, `parses`, `gives_input` and
`gives_shell_a_list` asked through it, every reading drawing from the one
budget, and `is_spent` saying whether a reading within it was stopped. The
functions above each make one for the code they are given.

## What the reader finds

Whatever the code comes from, the reader finds these, with calls found by
their name once what `import`, `require` and destructuring bound is put back
(`from os import remove as rm`, `const { rm } = require('fs')`, `o = os`,
`getattr(os, 'remove')`):

| Does | Python | JavaScript (Node, Bun, Deno) |
| --- | --- | --- |
| Deletes (`Remove`) | `os.remove`, `unlink`, `rmdir`, `removedirs`, `shutil.rmtree`, `Path.unlink`, `Path.rmdir` | `fs.rmSync`, `rm`, `unlinkSync`, `unlink`, `rmdirSync`, `fs.promises.rm`, `Deno.remove`, `Bun.file(…).delete()`, `rimraf` |
| Writes (`Write`) | `open(path, mode)` with a mode that writes (`w`, `a`, `x`, `+`, or one only known when it runs), `Path.write_text`, `write_bytes`, `touch`, `mkdir`, `os.makedirs`, `shutil.copy*` (the destination), `extractall`, `urlretrieve` | `fs.writeFileSync`, `appendFileSync`, `createWriteStream`, `mkdirSync`, `openSync` with writing flags, `copyFileSync` (the destination), their async and `promises` forms, `Deno.writeTextFile`, `Bun.write` |
| Moves (`Move`) | `shutil.move`, `os.rename`, `os.replace`, `Path.rename` | `fs.renameSync`, `fs.promises.rename`, `Deno.rename` |
| Links, permissions (`Link`, `Chmod`, `Chown`) | `os.symlink`, `os.link`, `os.chmod`, `os.chown`, `shutil.copymode` | `fs.symlinkSync`, `chmodSync`, `chownSync`, `Deno.chmod` |
| Runs (`Script`, `Program`) | `os.system`, `os.popen`, `subprocess.run`/`call`/`Popen`/`check_call`/`check_output` | `child_process.exec`/`execSync`/`spawn`/`spawnSync`/`execFile`, `Deno.Command`, `Bun.spawn`, `execa`, `cross-spawn` |
| Kills (a `Program`, `kill -- PID`) | `os.kill`, `os.killpg` | `process.kill`, `Deno.kill` |
| Reads (`Read`, `ReadTree`) | `open(path)` with a mode that reads, `Path.read_text`, `read_bytes`, the source of `shutil.copy*`, `tarfile`, `fileinput`, `linecache`, `ConfigParser.read`, `netrc` | `fs.readFileSync`, `readFile`, `createReadStream`, `openSync` with reading flags, `Deno.readTextFile`, `Bun.file` |

A literal command string is a `Script`, to be read in the grammar of the shell
that runs it; a literal argument list (`subprocess.run(['rm', '-rf', '~'])`)
is a `Program`, `shell=True` or `{ shell: true }` making it a `Script`; `cwd`
wraps what the call does in an `In` of that directory. `exec("…")` of a
literal is a `Code` of its own language, read at any depth to the same limit.
A `chdir` is a `Chdir`, and the paths after it are read from there.

A path is a literal string, `os.path.expanduser('~…')`, `Path.home()`,
`os.environ['HOME']`, `process.env.HOME`, `os.homedir()`, `os.path.join`,
`path.join`, `Path(…) / …`, string `+`, f-strings and template literals made
only of those, or, for a read, a name the code sets to one (every string a name
is set to anywhere is read). Anything else is an `Unknown` path, and a read of
a path that starts as the code says is a `Below` of its folder. A `Path` is
text: the reader never asks the disk, and `~` is the home directory wherever it
comes, as a caller that reads a shell word has it.

A call that starts a program after the code writes to its own environment
(`os.environ[…] =`, `os.putenv`, `process.env.X =`) is a `Started` act: the
program may be given a variable that loads code (`PYTHONPATH`, `NODE_OPTIONS`,
`LD_PRELOAD`, the families `LD_*`, `DYLD_*`, `PYTHON*`, `NODE_*`, `GIT_*`). The
write itself is an `Environment`.

**What the reader itself does not follow**, and says as an `Unread` act (or
`Opaque`, `Downloaded`, `Loads`): code that does not parse; `eval`, `exec`,
`compile`, `Function` and `vm.*` of anything but a literal string; a library
call that runs the code it is given or loads code (`timeit`, `cProfile.run`,
`pickle`, `pdb`, `importlib`); `__import__`, `getattr`, `import()` and
`require` of a computed name; an assignment to a member of a module, of a
builtin class or of `process`, `Deno` or `Bun`; an alias of a call it cannot
follow (`r = os.remove`, `map(fs.unlinkSync, files)`); a module handed on as a
value; a process id only known when it runs (it may be every process); a call
it has no row for that is given a path (an `Opaque`); and code loaded from
outside the workspace: a module from the network (`Downloaded`), a file outside
it, an absolute path, a `file:` URL, `../x.js` or a `data:` URL (`Loads`), a
`sys.path` entry outside it. A name bound by nested code, and a name written
with an escape or not in ASCII, is a name the reader does not follow.

## The strict subset

`understand` holds the code to an allow-list of what the grammar may hold, never
a list of what is known to be dangerous: code that has anything else in it is
not understood, because the reader has no row for what it does. Code is
understood only when all of these hold:

1. **It parses and holds a statement.** A parse error (`python3 -c 'if 1:'`),
   code that is empty or only comments, and an empty block (`{}`, `if (1)
   {}`) are not understood. Neither is code with a control character other than
   a line feed or tab, or a Unicode line separator, which the grammar and the
   language read differently.
2. **It runs straight through.** Its statements are expression statements,
   assignments to a plain name (`x = 1`, `a, b = 1, 2`, `x += 1`, `const`,
   `let`, `var`) and `if` with `else`. A `def`, `class`, `lambda`, arrow
   function, `function`, loop, comprehension, generator expression, `try`,
   `with`, `switch`, `match`, `async`, `await`, `yield`, decorator, `new`,
   spread or `*args` is not.
3. **Every call is on the list**, and is a call: a name on the list used as a
   value (`x = print; x(1)`, `map(open, paths)`) is not understood.
   - Python: `print`, `len`, `str`, `int`, `float`, `bool`, `repr`, `abs`,
     `min`, `max`, `sum`, `round`, `sorted`, `reversed`, `list`, `tuple`,
     `dict`, `set`, `frozenset`, `range`, `enumerate`, `zip`, `any`, `all`,
     `ord`, `chr`, `hex`, `bin`, `oct`, `divmod`, `pow`, `bytes`, `bytearray`,
     `format`, `ascii`, `iter`, `next`, `complex`, `slice`; `open`, which the
     reader judges by its path and mode; `time.time`, `time_ns`, `monotonic`,
     `monotonic_ns`, `perf_counter`; and a method of a value the code made (a
     string, a list, a file from `open`, `sys.stdin`).
   - JavaScript: `parseInt`, `parseFloat`, `String`, `Number`, `Boolean`,
     `isNaN`, `isFinite`; `console.log`, `error`, `warn`, `info`, `debug`;
     `JSON.stringify` and `parse`; `Math.abs`, `ceil`, `floor`, `round`, `max`,
     `min`, `pow`, `sqrt`, `trunc`, `sign`, `cbrt`, `hypot`, `log`, `log2`,
     `log10`, `exp`, `sin`, `cos`, `tan`, `atan`, `atan2`, `random`, `PI`, `E`;
     and the methods `toString`, `toUpperCase`, `toLowerCase`, `trim`,
     `trimStart`, `trimEnd`, `split`, `join`, `slice`, `substring`, `indexOf`,
     `lastIndexOf`, `includes`, `startsWith`, `endsWith`, `replace`,
     `replaceAll`, `repeat`, `padStart`, `padEnd`, `concat`, `charAt`,
     `charCodeAt`, `push`, `pop`, `shift`, `unshift`, `reverse`, `sort`, `at`,
     `toFixed`, `test` and `match`; the only other member is `length`.
   - Anything else is not: `os.getcwd`, `os.listdir`, `sys.exit`,
     `sys.stdout.write`, `time.sleep`, `input`, `dir`, `id`, `hash`, `exit`,
     `getattr`, `glob.*`, `platform.*`, `base64.*`; `process.*`, `setTimeout`,
     `new Date()`, `Date.now()`, `Buffer.from`, `Object.*`, `require("fs").*`,
     `Bun.*`, `Deno.*`; a call of a name nothing bound, of a name the code
     set, of a call (`f()()`), or with a spread (`print(*args)`).
4. **No import, run-time code or environment write is outside the list.**
   Python imports only the modules built into the interpreter binary,
   plainly: `sys`, `errno`, `itertools` and `time` (the ones CPython's
   `Modules/Setup.bootstrap` compiles in, and `sys`, which is the interpreter
   itself). `builtins` is not one of them: it is `__builtin__` in Python 2,
   where `import builtins` searches the path, and code may use none of its
   members anyway. Python 2 (`understand_python2`) has only `sys` and `errno`
   built in; `time` and `itertools` are shared files of its `lib-dynload`,
   which the path reaches after the working folder, so a caller that may be
   running Python 2 (`python2`, and `python`, which is Python 2 on some
   systems) asks for that one. The import system tries its built-in
   finder before it looks at the import path, so no file in the folder the
   code runs in can stand in for one of them, and importing one reads
   nothing from disk. Every other module is looked up in that folder first
   (`python3 -c` puts it at the front of the path, so `import json` runs
   `./json.py` when there is one, and so does each module `json` loads in
   turn: `import re` loads `enum`), so any other import makes the code not
   understood: `json`, `re` and `math` too (`math` is a file on many builds).
   There is no table of what each module loads. No alias (`import sys as s`),
   no `from … import`. The members used are few: `sys.stdin`, `sys.argv` and
   `sys.version`; `time.time` and the four clocks above; `errno.<NAME>`; and
   none of `itertools`, so importing it is understood and using it is not. JavaScript has no
   `import`, `require` or `import()`.
   No `eval`, `exec`, `compile`, `__import__` or `Function`; no write to
   `os.environ`, `process.env` or a member of a module (`console.log = 1`); no
   name the code sets is a name above, or starts with an underscore; no member
   starts with one (`().__class__`); and every name is plain ASCII letters,
   digits, `_` and `$`, as Python reads a name in its NFKC form (a full-width
   `＿＿class＿＿` is `__class__`) and JavaScript reads `console` as
   `console`, so neither is the name the checks see. A name the code did not
   set is not understood either, so `os.getcwd()` with no `import os` is not,
   and a module on the list is a name only once the code imports it:
   `print(time.time())` with no import is not understood (it only fails, but
   the reader does not say so).

`print(1+1)`, `console.log(1)`, `import sys; print(sys.version)` and
`open('out.txt','w')` are understood. `import json; print(json.dumps(1))`,
`import re`, `import os; print(os.getcwd())`,
`process.env` and `def f(): return 1` are not, and `read` still finds a
delete, an overwrite or a key in such code (`shutil.rmtree('/home/me')` in a
function body is still a `Remove`).

## Limits

Reading ends whatever the code is, and fits a thread's stack of 1 MiB: code
nested deeper than the reader walks a tree (`MAX_TREE_DEPTH`, 400 levels) is
not read before it is parsed (see [The budget](#the-budget)), and a walk goes no
deeper. The strings worked out from names are bounded: a
string built from names is cut at 4 KB, the strings noted for all names
together and the paths read out of them are bounded, and a name that went over
a limit is dropped, not read as any string, so a few hundred bytes of
`a = a + a` cannot take seconds or gigabytes. A name that went over a limit is
an unknown path, never a known one: no limit makes code understood. A list of
arguments to a program is built in work that grows with the list: each word
is put at the end of each list as it is. A chain of assignments is followed
to its end once for the chain.

### Errors

Code the grammars read with an error is not read through the error. Python
and Node read a file whole before they run it, and a syntax error stops it
before it runs a thing; what a grammar's recovery makes of the code past an
error is a guess, and tree-sitter's recovery is the costliest work it does.
So a parse stops at the first error and the code is not read: `read` gives an
`Unread` alone, `understand` says `NotUnderstood`, `parses` says no, and
`gives_input` and `gives_shell_a_list` say it may.

The rule is exact. tree-sitter writes `resume version` in its log when the
best version of the parse has met an error and it is about to recover: every
recovery starts there (the entry that pauses one version, `detect_error`, is
written for a version that meets an error where another reads on, as in code
the grammar reads two ways, and is no error of the code). Once a version has
read the code to its end (`accept`), a recovery of another loses to it and is
no error either. The parse stops at the first progress report (each 100
steps) after the entry, and the tree a parse finishes is taken as an error if
it holds one, so the answer does not depend on where a report falls. Without
the log, the progress report's own error flag says only that a recovery left
every version in error, which is later or never: the run without the log
stops at it, and code it reads to its end is held to its tree.

Literal code that `exec` or `eval` run, with an error in it, raises before it
runs: it is the code act it is (`python if (:`), and what is beside it is
read. Code with an error spends nothing of the budget past the reports that
led to it.

**A known limit: syntax newer than the grammars.** The grammars (of
`Cargo.lock`) do not know every syntax the interpreters run, and code written
in it is read as code with an error, and not read: the cautious answer
(`Unread` alone; `unknown` in the shell guard, `unreadable`, `does not
parse`, in the script guard), where it may run and do what the earlier
reader found beside the error. Python 3.15's `lazy import x` and `lazy from x
import y` (PEP 810, in 20 modules of its own standard library), type
parameter defaults (`def f[T = int]()`), and in JavaScript `export { _null as
null }` and `export { m as in }`, a private field after a line with no
semicolon, a `[...a]` line after one with no semicolon, and some bundled
import lists: `python3 -c "lazy import shutil; shutil.rmtree('/home/me')"` is
`unknown` alone. Reading a tree whose errors are few and small, beside them,
is possible later work; it is not done, as what the grammar makes of code
past an error is a guess.

### The budget

All the other work is held to a `Budget`, counted as the grammars and the
walk go, never by the clock, so the answer is the same on every machine.
`read` and the other functions make one for the code they are given; a caller
that asks more than one question of a piece of code, reads several pieces of
one line, or the code inside code, makes one for the whole (`Budget::new` with
its length; past the length limit it is the limit) and asks each question
through it (`Budget::read`, `Budget::understand` and the others). The budget
keeps the last four trees its parses built, or that the parse met an error,
so each question asked again of the same code is answered with no parse; and
the code `exec` and `eval` run inside it draws from the one budget, so
nesting does not multiply the work. The shell guard makes one for each line
it judges, and the script guard one for each piece of code.

Before it is parsed, code is scanned, in one pass over its text with a stack
of the scan's own, that reads strings, comments, templates' text, regular
expressions and JSX's text as the grammar does: in Python a string's prefix
is any run of `f`, `t`, `r`, `b` and `u` before its quote, as
tree-sitter-python reads one, and in JavaScript `<!--` and `-->` where an
operand goes start a comment to the end of the line, and a JSX tag may hold
comments. Beside that reading, the costly marks and the depth are counted
on the bytes alone, with no reading of strings, comments, escapes or regular
expressions, so that no misreading of the text can hide them; code past
either count's bound is refused. The scan only ever refuses code, which is
then not parsed:

| What the scan counts | Bound | What it stops |
| --- | --- | --- |
| the code's length | 64 KiB (`MAX_LEN`): past it, not read | code longer than any caller should hand the reader |
| the openers left open at once: brackets; in Python each string in a format string's field, and each field; in JavaScript each template and `${…}` field, and each JSX element and `{…}` in one | 400 (`MAX_TREE_DEPTH`): past it, not read | the parser's recursion back through its stack, as deep as what is left open, as it merges the ways it reads the code |
| on the bytes alone, the brackets (`(`, `[`, `{`) left open at once, strings and comments too, each closer closing one opener and the count never below none | 400 (`MAX_TREE_DEPTH`): past it, not read | the same, where the reading of the text was misled |
| in JavaScript, on the bytes alone, the word `await` (wherever it stands, after a `.` or `...` too) followed, past anything that is not part of a name, by a `/`, in strings and comments too | 4 (`MAX_AWAITED_SLASHES`): past it, not read | an `await` read both as a name and as the keyword, which the grammar merges at a cost that grows with what is left open |
| in Python, a star (`*`, not `**`) after an operator (but an assignment, plain or augmented) or after `not`, `and`, `or`, `is`, `if`, `elif`, `else`, `while`, `with`, `assert`, `del` or `await`, in code and in format strings' fields | 4 (`MAX_STARS_AFTER_OPERATORS`): past it, code that does not parse | Python read two ways at once that never part; Python itself refuses such code |
| in Python, on the bytes alone, a star or `**` after an operator (`==`, `!=`, `<=`, `>=` and `:=` among them, but not an assignment) or one of those keywords, past anything between them that is not part of a name, an operator or a bracket, in strings and comments too | 256 (`MAX_RAW_STARS`): past it, not read | the same, where the reading of the text was misled |
| a space a grammar passes over that is not an ASCII space, tab, line end or form feed (Unicode's white space, the vertical tab, U+200B, U+2060 and U+FEFF but a byte-order mark at the start), outside the strings and comments | 4 (`MAX_ODD_SPACES`): past it, not read | a scan that reads such a space otherwise than the grammar does |
| in Python, a backtick outside the strings and comments | any: code that does not parse (Python 3 reads none) | tree-sitter-python takes one for a string's quote |

Where the scan cannot tell what the text is (a `/` after a `}`, or after
`await`, `yield`, `of` or `let`, which may divide or start a regular
expression; a `<` at the start of a line after a value, which may compare or
start JSX), it only counts more: to the end of the line every opener counts
and no closer closes, and to the end of the code if that line holds a
template, a block comment, a backslash or a `<`, which a line's end may not
end. A conditional opens no level: no costly shape needs one. Of 73,696 real
files (38,968 of Python and 34,846 of JavaScript, the corpus below and a
second corpus), the most deeply nested as the text is read is JavaScript 48
levels deep (Python 18); on the bytes alone 309 (`wasabi`'s
`test_tables.py`, a table drawn in strings; JavaScript 220, `@lezer/python`'s
tables); the most `await`s before a `/` one (in a comment of `redux`'s); the
most stars after an operator on the bytes alone 66 (CPython's
`c-analyzer/cpython/_parser.py`), and none as the text is read; no file holds
a space of those outside its strings and comments; and three copies of one
Python file hold a backtick (`lib2to3`'s `py2_test_grammar.py`, Python 2,
which does not parse either way). No real file is refused by the scan.

For a budget made for `len` bytes:

| Count | Bound | What it stops |
| --- | --- | --- |
| reports of the parser's progress (one each 100 steps) | `len / 6` and 64 in all (`REPORT_BYTES`, `REPORT_BASE`) | the backstop for a parse that moves on at a cost the counts below do not see, and a line of many pieces that each meet an error |
| bytes handed to the lexers, 256 at a time, each byte handed with the log on counted 12 times | `64 · len` and 24 MiB (`HANDED_BYTES`, `HANDED_BASE`, `LOGGED_WEIGHT`) | a lexer that goes over the same text again and again |
| drops and merges of the versions a parse keeps (`condense`), over the code the lexers move through: each counts one, each byte takes back a quarter of a thousandth, and what is left over is carried from parse to parse within the budget | 384 left over at any point, so 256 for each KB of any stretch of the code and 384 (`TANGLE_RATE`, `TANGLE_BASE`) | code the grammar reads two ways at once more densely than any real code |
| choices between the trees of two ways, as a step that goes back through versions merged before builds a tree for each (`select_…`) | 512 in one parse (`MAX_SELECTED`), 1,024 in all (`SELECTED_IN_ALL`) | steps whose work grows with the ways merged, which no count of steps sees |
| reports a parse makes without the log (below) | 32 in one parse (`MAX_QUIET`), 64 in all (`QUIET_IN_ALL`) | code read in pieces, each to its end where no count sees it |
| units of the reader's own work: each node a walk visits, each name worked out | `16 · len` and 64 Ki (`WALK_BYTES`, `WALK_BASE`) | a name worked out again from each of many links of a chain |

The log costs a parse some four times its time, so a parse is first run
without it, for at most 32 reports (and no more than are left of the
budget's 64), stopping at the first report that says it is in error: code it
reads to its end in them, as code of a kilobyte or two is, is read at the
grammar's own speed. Any other is read again from its start with the log,
which sees an error as the recovery starts and two ways of reading the code
that never part; and so code longer than those reports always keeps the log.

Past any bound the reading is stopped and the code is not read: `read` gives
an `Unread` act, `understand` says `NotUnderstood`, `parses` says it does not
parse, and `gives_input` and `gives_shell_a_list` say it may; and every
reading after it within the same budget is stopped before it starts. A
question whose own walk runs out of units part of the way answers so too.
What the reader found before the stop is kept only where there is something
beside the stopped parse to find: a parse stopped before its end gives no
tree, so code stopped in its own parse gives the `Unread` alone, while a
stopped parse of literal code the code runs (`eval("…")`, `exec("…")`) leaves
the walk of the code around it going, and what it finds there is kept. A
stopped parse of literal code is code not read, never code that does not
parse.

`tests/parse_budget.rs` holds each rule and count to the shapes it stops, at
each size up to the length limit, and `crates/shell/tests/inline.rs` and
`crates/script/tests/work.rs` hold a line and a piece of code to the bounds
in all.

**A known limit: Python that starts many statements with a call given a
starred argument.** Such a statement is read two ways (a call, and the start
of an assignment's target) and chosen between once: some 500 of them after a
kilobyte or two of other code make more choices than one parse may
(`MAX_SELECTED`), and the code is not read. No real file makes more than 44.

**A known limit: Python with a long run of comment lines in a block.**
tree-sitter-python's scanner reads the rest of such a run again at each line
of it, and a run is read up to the bytes handed. Code read without the log
(code of a kilobyte or two before the run) reads a run of up to some
thousand lines; code read with the log reads a run in or after a block of a
few hundred lines; a longer run is not read: `unknown` in the shell guard,
`unreadable`, `takes too long to read`, in the script guard. The longest run
of comment lines in a block in the real Python below is 154 lines; no real
file is stopped by it.

Real code is within every count: of 28,411 files of Python (3,641) and
JavaScript (each up to 64 KB), read and asked within one budget as a caller
does, none is stopped. The densest took a report for 21 bytes (the bound is
one for 6), the most bytes handed, weighed, were 9.5 MB (CPython 3.9's
`importlib/_bootstrap_external.py`, against 29.3 MB it may), the most drops
and merges of versions left over the code 175 (against 384: `robust-predicates`'
minified JavaScript; Python at most 17), the most choices between the trees
of two ways 38 in a file (against 512), and the most units of the walk 6 for
each byte (against 16). Of another 38,247 files (35,880 of them Python), none
is stopped or refused either. 30 of them have a syntax error as the grammars
read them, and are not read: JavaScript with Flow types (22 of
`react-window` and `global-agent`), an editor's backup of a file left
half-written, and 7 files of real, runnable JavaScript the grammar does not
read (2 files of `undici`, 3 of `zod`, npm's `base-cmd.js`, `@exodus/bytes`'s
`base58.js`). TypeScript given as JavaScript, as Bun and Deno run it, does
not parse either: it is not read.

The counts hold for the tree-sitter runtime and the grammars of `Cargo.lock`
(0.26.13, tree-sitter-python 0.25.0, tree-sitter-javascript 0.25.0): another
release may stop the same code elsewhere, and the rule and the counts read
the log by its words, which a test holds so that a change of words fails it
rather than counting nothing. What no count sees is the work inside one step
of the parser and the 100 steps between reports: the grammars' scanners move
on through the text, which ends where the bytes handed do; a step that goes
back through merged versions, at an error or at the end of the code, costs
what the merges before it do, which the drops and merges over the code hold
loosely and the scan before a parse holds for every shape of it found; and
the steps between the error and the report that stops the parse are not
counted. So the bound on the time and memory a reading takes is a measured
one, not a proven one, and every reading within the scan's bounds fits a
thread of 1 MiB in an optimized build, which `tests/stack.rs` of the reader,
the script guard and the shell guard hold, on a thread of 1 MiB in the
optimized build of `just timing` and of 2 MiB in a debug build, whose frames
take up to 1.26 MiB.

## Tests

`crates/code/tests/` holds the crate's own cases, in case files
(`tests/cases`, the format is in
[CONTRIBUTING.md](../../CONTRIBUTING.md#case-files)), each checked by the test
file of its name. `acts.cases` has code and the acts it must give, for each
language. `understand.cases` has a case for every way out of the strict
subset, and the code that stays inside it, for Python, JavaScript and
Python 2. `parses.cases` holds the code that parses and the code that
does not, `input.cases` the code that may give a program input, and
`shell_list.cases` the code that hands a shell a list. `modules.cases` holds the module specifiers and coding
declarations; `modules.rs` keeps the shape of an argument and the limits.
`cases.rs` tests the runner and dumps every case. `stack.rs` reads code at the
bounds of the scan before a parse on a thread of a small stack (1 MiB in an
optimized build), so a reading that would overflow it aborts the test and
not a caller, and holds valid code that one bound of the scan alone stops to
not being read, so that a bound taken away fails it. `robust.rs` runs seeded noise
through both grammars (no panic, the same answer twice, understood code only
ever opens a file), the code of every case changed at random and punctuation
joined at random, each held to the budget above, and checks that very deep,
very long and growing code ends. `parse_budget.rs` holds the shapes of
error to the rule that stops them, and the shapes the budget stops to it, at
each size up to the length limit, with their answers pinned (not read, not
understood); the valid literals the grammar reads two ways, dense and nested
real code, and comment runs up to the measured limit to being read whole;
and each question asked once its walk runs out to the cautious answer. It
reads the counts through the crate's `testing` feature, which only its own
tests turn on and which is not for callers. The shell guard's own cases
(`crates/shell/tests/cases/inline.cases`, the `inline_*.cases` files beside
it and the rest) judge whole lines through the reader and hold the verdicts:
the reader moved out of the shell guard with none of them changing, and the
one whose code has a syntax error beside a line's other code (a nested
`eval` of the endless recovery) now reads as code that does not parse.
