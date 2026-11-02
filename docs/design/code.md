# Code

`milo-guards-code` reads code of another language and says what it is
certain to do. It holds the readers of Python and JavaScript (Node, Bun and
Deno) that the shell guard uses for `python3 -c`, `node -e` and a
here-document fed to an interpreter, as a crate of its own: a guard of the
files an agent writes could judge a `.py` or `.js` file the same way, and a
tool that runs a snippet directly could ask without a shell line.

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
  comes from and however it is written.
- `understand(language, code)` gives an `Understanding`: `Understood` when the
  code is nothing but a few plain statements the reader reads in full (the
  [strict subset](#the-strict-subset)), `NotUnderstood` when anything is
  outside it. That nothing was found in code is only safe to take as "does
  nothing" when it is understood.

The two are asked apart on purpose. A caller keeps every act for code it does
not understand (a delete in a function is still a delete), and says "unknown"
for it only when it found none. `Understood { imports }` also says whether the
code may load a module: all Python code does, with or without an `import`,
and it looks in the folder the code runs in first (`import json` loads
`./json.py` from it; an uncaught exception imports `traceback`, the `idna`
codec imports `stringprep`). A caller understands Python code only where that
folder is its own. Understood JavaScript has no import at all.

Three more functions are for what a caller meets next to the code:

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
parse tree is walked). The reader does not check the length itself: the caller
refuses longer code first, as the shell guard does for a line.

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
     reader judges by its path and mode; `json.dumps`, `loads`, `load`, `dump`;
     `re.compile`, `match`, `search`, `fullmatch`, `sub`, `subn`, `split`,
     `findall`, `finditer`, `escape`; `math.*`; and a method of a value the
     code made (a string, a list, a file from `open`, `sys.stdin`).
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
   Python imports only `json`, `math`, `re` and `sys`, plainly: no alias
   (`import json as j`), no `from … import`; the only members of `sys` are
   `stdin` and `argv`. JavaScript has no `import`, `require` or `import()`.
   No `eval`, `exec`, `compile`, `__import__` or `Function`; no write to
   `os.environ`, `process.env` or a member of a module (`console.log = 1`); no
   name the code sets is a name above, or starts with an underscore; no member
   starts with one (`().__class__`); and every name is plain ASCII letters,
   digits, `_` and `$`, as Python reads a name in its NFKC form (a full-width
   `＿＿class＿＿` is `__class__`) and JavaScript reads `console` as
   `console`, so neither is the name the checks see. A name the code did not
   set is not understood either, so `os.getcwd()` with no `import os` is not,
   and a module on the list is a name only once the code imports it:
   `print(math.pi)` and `json.dumps(1)` with no import are not understood
   (they only fail, but the reader does not say so).

`print(1+1)`, `console.log(1)`, `import json,sys; json.load(sys.stdin)` and
`open('out.txt','w')` are understood. `import os; print(os.getcwd())`,
`process.env` and `def f(): return 1` are not, and `read` still finds a
delete, an overwrite or a key in such code (`shutil.rmtree('/home/me')` in a
function body is still a `Remove`).

## Limits

Reading ends whatever the code is. The tree is walked without recursion, so
no depth overflows the stack. The strings worked out from names are bounded: a
string built from names is cut at 4 KB, the strings noted for all names
together and the paths read out of them are bounded, and a name that went over
a limit is dropped, not read as any string, so a few hundred bytes of
`a = a + a` cannot take seconds or gigabytes. A name that went over a limit is
an unknown path, never a known one: no limit makes code understood.

## Tests

`crates/code/tests/` holds the crate's own tables. `acts.rs` has code and the
acts it must give, for each language. `understand.rs` has a row for every way
out of the strict subset, and the code that stays inside it. `modules.rs` holds
the module specifiers and coding declarations. `robust.rs` runs seeded noise
through both grammars (no panic, the same answer twice, understood code only
ever opens a file) and checks that very deep, very long and growing code ends.
The shell guard's own tables (`crates/shell/tests/inline.rs`, `issue_9.rs` and
the rest) judge whole lines through the reader and hold the verdicts: the
reader moved out of the shell guard with none of them changing.
