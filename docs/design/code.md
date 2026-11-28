# Code

`milo-guards-code` reads code of another language and says what it is
certain to do. It holds the readers of Python, JavaScript (Node, Bun and
Deno) and Ruby that the shell guard uses for `python3 -c`, `node -e`, `ruby
-e` and a here-document fed to an interpreter, as a crate of its own: the
script guard
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

Two functions take a `Language` (`Python`, `JavaScript` or `Ruby`) and the
text of the code. Ruby is read behind the crate's `ruby` feature, on by
default, and its grammar is built only with it: without it, `Language::Ruby`
is still there (a caller's `match` does not change with a feature) and no
Ruby code is read: `read` gives an `Unread` alone, `understand` says
`NotUnderstood`, `parses` says no, and `gives_input` and
`gives_shell_a_list` say it may. Perl, PHP and Lua are later work, a
language at a time, each with what `read` finds, the strict subset
`understand` accepts, a scan of its own before the parse and a feature of
its own.

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
all, and nor has understood Ruby: Ruby looks in no folder of the code's own
for what it loads by itself (its `$LOAD_PATH` holds no `.`, and RubyGems
and the gems it starts with load from where they are installed), so a
caller that keeps the options and the variables that add one (`-I`, `-r`,
`RUBYOPT`, `RUBYLIB`) apart reads it from anywhere.

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

The limits a caller holds code to are constants: `MAX_LEN` (3 KiB, the
longest code the reader reads, a deliberate limit of 0.2.0: see
[The length limit](#the-length-limit)), `MAX_DEPTH` (8, how deep code may run
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

**Ruby.** A call is found by its receiver, a constant as written
(`FileUtils::Verbose` is `FileUtils`; `Kernel.` and `self.` are none), and
its name; with `include FileUtils`, `FileUtils`'s calls by their names alone.

| Does | Ruby |
| --- | --- |
| Deletes (`Remove`) | `File.delete`, `File.unlink` (each path), `FileUtils.rm`, `rm_f`, `rm_r`, `rm_rf`, `rmtree`, `remove`, `remove_dir`, `remove_entry`, `remove_entry_secure`, `remove_file`, `rmdir`, `safe_unlink` (a path or a list), `Dir.rmdir`, `delete`, `unlink`, a `Pathname`'s `delete`, `unlink`, `rmtree`, `rmdir` |
| Writes (`Write`) | `File.write`, `binwrite`, `IO.write`, `binwrite`, `File.open` and `File.new` and `Kernel#open` with a mode that writes (`w`, `a`, `+`, `mode:`, or one only known when it runs, `File::WRONLY`), `File.truncate`, `mkfifo`, `FileUtils.touch`, `mkdir`, `mkdir_p`, `makedirs`, `mkpath`, `Dir.mkdir`, the destination of `FileUtils.cp`, `copy`, `cp_r`, `copy_file`, `copy_entry`, `install`, `cp_lr` and `IO.copy_stream`, a `Pathname`'s `write`, `mkdir`, `mkpath`; a file a program's output is redirected to (`system(…, out: 'f')`) |
| Moves, links, permissions | `File.rename`, `FileUtils.mv`, `move`; `File.symlink`, `link`, `FileUtils.ln`, `ln_s`, `ln_sf`, `ln_sr`, `symlink`, `link`; `File.chmod`, `lchmod`, `FileUtils.chmod`, `chmod_R`; `File.chown`, `lchown`, `FileUtils.chown`, `chown_R`; a `Pathname`'s `rename`, `make_symlink`, `chmod`, `chown` |
| Runs (`Script`, `Program`) | `system`, `exec`, `spawn` (also of `Kernel` and `Process`), `` `…` `` and `%x(…)`, `IO.popen`, `Open3.capture2`, `capture2e`, `capture3`, `popen2`, `popen2e`, `popen3` and each command of `Open3.pipeline`, `pipeline_r`, `pipeline_w`, `pipeline_rw`, `pipeline_start`, `PTY.spawn`; `Kernel#open`, `URI.open` and `IO.read`, `readlines`, `foreach`, `write` of a path that starts with `\|` |
| Kills | `Process.kill(SIGNAL, PID…)`, each process id |
| Reads (`Read`, `ReadTree`) | `File.read`, `binread`, `readlines`, `foreach`, `IO.read` and the same, `File.open` and `File.new` and `Kernel#open` with a mode that reads, the source of the copies (`cp_r`, `copy_entry` and `cp_lr` a `ReadTree`), a `Pathname`'s `read`, `binread`, `readlines`, `each_line`; a file a program's input is redirected from (`in: 'f'`) |

One string to `system`, `exec`, `spawn`, `IO.popen` and `Open3` is a
`Script`, a line a shell reads; more, or an array, are a `Program` and its
arguments (the first of them `[program, argv0]`), and an environment hash
first makes it a program `Started` with one; `chdir:` wraps it in an `In`,
and a redirect (`out:`, `err:`, `in:`, `2 =>`, `[:out, :err] =>`) is a
write or a read of its file. `IO.popen('-')` forks the interpreter itself,
and runs nothing else. A write to `ENV` (`ENV['X'] =`, `ENV.store`,
`update`, `delete`, `clear` and the rest of its writing methods) is an
`Environment`. `eval`, `instance_eval`, `class_eval` and `module_eval` of a
literal string are a `Code` of Ruby, read again as Python's `exec` is; of
anything the code fetches from the network (`Net::HTTP`, `URI`, `OpenURI`,
the HTTP clients, a URL of `http:`, `https:` or `ftp:`, or a name set to
one) a `Downloaded`, the guards' `run_downloaded`; of anything else an
`Unread`. `require`, `require_relative`, `load` and `autoload` of anything
are an `Unread`, as are the calls that call or define a method by a name or
reach into an object (`send`, `__send__`, `public_send`, `method`,
`instance_method`, `define_method`, `const_get`, `instance_variable_get`,
`alias_method`, `remove_method`, …), any call of `ObjectSpace`, `Fiddle`,
`TracePoint`, `RubyVM` or anything under it
(`RubyVM::InstructionSequence.compile`), `YAML.unsafe_load`,
`Psych.unsafe_load_file`, `Marshal.load`, `alias` and `undef`, a write to
`$LOAD_PATH` (`$:`, `$-I`: an assignment, `<<`, and any call of it,
`unshift`, `push`, `concat`), `trap` with a string that is not one of its words (`IGNORE`, `DEFAULT`,
`EXIT`, …), and a call of a value (`x.()`). A path given to a call it has no
row for is an `Opaque` (`YAML.load_file('/home/me/.ssh/id_rsa')`), but for
the calls that only print and stop (`puts`, `p`, `warn`, `raise`, …) and
those of `File`, `Dir` and `Pathname` that only work a path out or ask what
is there (`join`, `basename`, `exist?`, `directory?`, `size`, …). A
`flags:` that is not only `RDONLY` (`File.open(p, flags: File::TRUNC)`)
makes an open a write. tree-sitter-ruby ends the code at any `__END__` that
starts a line's words; Ruby only at one alone on its line, at its start:
past any other (`__END__ x`, `  __END__`, `__END__\r`) the code after it is a
`Code` of Ruby, read again.

A Ruby path is a literal string (`'…'`, `"…"`, `%q(…)`, with the escapes
Ruby reads; a code escape, `\x41`, `\u{…}`, is the end of what is known),
`Dir.home`, `Dir.pwd`, `Dir.tmpdir`, `ENV['HOME']`, `ENV.fetch('HOME')`,
`File.join`, `File.expand_path` and `absolute_path` (with a folder),
`Pathname.new`, `Pathname()` and a `Pathname` joined (`/`, `+`, `join`, to
16 links), `+`, `#{…}` and `.to_s` made only of those, the elements of an
array or a `%w[…]`; anything else, a name the code sets among them, is a
path only known when it runs, and a read of one that starts as the code
says a `Below` of its folder.

**A known limit of the grammar: Ruby's locals.** tree-sitter-ruby does not
know which names are locals, and reads a `/`, a `%` or a `<<WORD` after a
name as a call's argument where Ruby, for a local, reads an operator: `x =
1; x /2; system("…") #/` is a regular expression to the grammar, and
`arr<<A`, followed by lines and then `A`, a heredoc. What the grammar reads
as a literal there Ruby runs, and the reader does not find it: such code is
not understood either (a regular expression and a heredoc are outside the
strict subset), so a caller says `unknown`, never safe.

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
   - Ruby: `puts`, `print`, `p`, `format`, `sprintf`, `Integer`, `Float`,
     `String`; `Math.sqrt`, `cbrt`, `sin`, `cos`, `tan`, `atan`, `atan2`,
     `exp`, `log`, `log2`, `log10`, `hypot`, and `Math::PI` and `Math::E`;
     and a method of a value the code made (a string, a number, an array, a
     hash) of the list `to_s`, `to_i`, `to_f`, `to_a`, `inspect`, `length`,
     `size`, `upcase`, `downcase`, `capitalize`, `swapcase`, `strip`,
     `lstrip`, `rstrip`, `chomp`, `chop`, `chars`, `bytes`, `lines`, `split`,
     `join`, `reverse`, `include?`, `start_with?`, `end_with?`, `index`,
     `rindex`, `count`, `sub`, `gsub`, `tr`, `center`, `ljust`, `rjust`,
     `first`, `last`, `min`, `max`, `sum`, `sort`, `uniq`, `zero?`, `even?`,
     `odd?`, `abs`, `round`, `floor`, `ceil`, `push`, `pop`, `shift`,
     `unshift`, `empty?`, `nil?`, `succ`, `pred`, `ord`, `chr`, `keys`,
     `values`, `key?`, `freeze`, `frozen?`, `between?`, `divmod`, `pow`,
     `concat`, `squeeze`, `flatten`, `compact`, `hex`. Its statements are
     those above with Ruby's `if`, `unless`, `elsif`, `else` and their
     modifiers (`x if y`), and the conditional (`a ? b : c`); no block (`{
     … }`, `do … end`), lambda, `def`, `class`, `module`, loop, `begin`,
     `case`, `return`, `BEGIN`, `alias`, splat, `defined?` or `::` call.
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
5. **Ruby is held to more.** No `require`, `load` or `eval`, and no
   constant but `Math` and `File` (no `ENV`, `ARGV`, `Kernel`, `Object`),
   and `File` only to `read`, `readlines`, `write`, `exist?` and `file?` the
   one file it is given, named by a string written whole that does not start
   with `|` (Ruby 2.5 and before, and JRuby, run `File.read('|cmd')`), and for
   a read with no option but `chomp`, `encoding`, `external_encoding` and
   `binmode` (`mode: 'w'`, `flags:` and `open_args:` open the file for
   writing, which the reader reports as a write; the reader's acts say which
   file), no
   global, instance or class variable, no `self` or `__FILE__`. A name is a
   local only past where the code first sets it, as Ruby's own parser reads
   one: before it, and anywhere the code never sets it, a name alone is a
   call of a method of that name (`exit`, `fork`, `gets`), and not
   understood. No name on the list is set (`puts = 1`). The code is ASCII,
   so no encoding Ruby may read it in (a magic comment, the locale `ruby
   -e` reads code in) reads it otherwise, and it holds no literal the
   grammar may read otherwise than Ruby does or that runs: a heredoc, a `%`
   literal (`%q(…)`, `%w[…]`), a regular expression, a command string
   (`` `…` ``, `%x(…)`), a character (`?a`), a symbol with `#{…}`, and no
   `__END__`. An escape in a string is one of `\n \t \s \r \e \a \b \f \v \\
   \" \' \#`, an escaped line end, one to three octal digits, `\x` and one or
   two hex digits, and `\u` and four: any other (`\c`, `\C-`, `\M-`, `\u{…}`,
   `\z`) is not understood. A first line `#!` is read by Ruby when it runs the code as a
   file, its switches too (`-r`, `-I`, `-C`, `-x`), and a line without
   `ruby` in it is run as the program it names: code that has one with a word
   that starts with `-`, or none with `ruby`, is not understood, and `read`
   gives an `Unread` act for it. Strings between quotes (with `#{…}` of what
   is understood), numbers, symbols, arrays and hashes of them are.

`print(1+1)`, `console.log(1)`, `puts 'a-b'.split('-').join`, `import
sys; print(sys.version)` and `open('out.txt','w')` are understood. `import
json; print(json.dumps(1))`, `import re`, `import os; print(os.getcwd())`,
`process.env`, `require 'json'`, `puts ENV['HOME']` and `def f(): return 1`
are not, and `read` still finds a
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

### The length limit

The reader reads code of at most `MAX_LEN` bytes, 3 KiB, and no longer: a
deliberate limit of 0.2.0. Longer code is not read, before it is scanned or
parsed: `read` gives an `Unread` act, `understand` says `NotUnderstood`,
`parses` says no, and `gives_input` and `gives_shell_a_list` say it may; the
script guard calls it `unreadable`, `is too long to read`, and the shell
guard calls the inline code of a line (`python3 -c`, `node -e`, an
interpreter's input, a here-document) that long `unknown`, `runs code the
guard does not read`, as it calls any code the reader does not read; its
own limit on a line stays 64 KiB.

The reader's own tests of its budget (`tests/parse_budget.rs`) lift the
limit, through its `testing` feature, to the 64 KiB the budget was measured
to, so the budget stays held to every shape it stops at every length it was
measured at: within the limit it is what bounds a line of many pieces of
code, and past it should the limit rise.

The scan and the budget below hold every shape of costly code found, as the
grammars' lexers read the text. What they would not hold costs what the
grammar's own reading of it costs, and some readings grow faster than the
code: in time and memory with its square, or in stack with its depth. The
length limit bounds that cost whatever the scan makes of the code. It was
set by measurement: every costly shape measured (1,233 files of Python, of
JavaScript and of shell lines that hand them to an interpreter), brought to
each size with its repeated units (the runs of a short unit scaled, the
blocks of a long one scaled, and its first bytes alone) and with its head
kept, was read by `read` and `understand`, judged by the script guard, and
given to `python3 -c` or `node -e` and in a here-document to the shell
guard, each call on a thread of 1 MiB in a release build (the least time of
three runs, and the most memory allocated, by Rust and by tree-sitter):

| Length | Slowest call | Most memory | Aborted on a thread of 1 MiB |
| --- | --- | --- | --- |
| 1 KiB | 34 ms | 31 MB | none |
| 2 KiB | 67 ms | 108 MB | none |
| 3 KiB | 151 ms | 221 MB | none |
| 3,200 B | 163 ms | 235 MB | none |
| 3,328 B | 176 ms | 266 MB | none |
| 4 KiB | 257 ms | 469 MB | none |

The costliest at every length from 2 KiB on is Python the grammar reads two
ways at once; its memory grows with the square of the code. 3 KiB is the
longest length, in whole KiB, at which every costly shape measured stays
within a quarter of a second and 256 MB and fits a thread of 1 MiB.
JavaScript whose stack grows with its depth fits it far past the limit.

Ruby is held to the same length, and was measured at it the same way (an
optimized build, a thread of 1 MiB, each call's least of five): the 19,757
windows of 3 KiB of 11,181 real files, each unit of one or two tokens of a
vocabulary of 60 repeated to 3 KiB (7,260 of them), 60,000 units of three
tokens, 30,000 repeated units after a prefix of four tokens, 80,000 strings
of random tokens and of valid code with random tokens before or after it,
and the 188 shapes at the scan's bounds with an error before, after or in
them. The slowest call took 0.1 s (`+:s-%q(\}\}\}…`, a `%q` literal never
closed, in `understand`: 0.096 s) and no process held more than 19 MB:
Ruby's grammar has no shape found whose memory grows with the square of the
code as Python's does, and the budget holds the work of the code a limit
that rose would let through, as `tests/parse_budget.rs` holds it at every
size to 64 KB.

The price is code that is not read: of the 28,299 files of Python and
JavaScript below (up to 64 KB), 2,164 of the 3,590 of Python (60 %) and
6,761 of the 24,709 of JavaScript (27 %) are longer than 3 KiB; of the
72,817 files of both corpora, 24,224 of 38,039 of Python (64 %) and 11,788
of 34,778 of JavaScript (34 %). The script guard calls each of them
`unreadable`, where it found the acts in them; inline code that long on a
shell line is as rare as such lines are (none of the everyday answers, the
longest of which is 174 bytes, nor any case line holds one). A later release
may raise the limit once the cost of a reading is bounded some other way.

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
| the code's length | 3 KiB (`MAX_LEN`): past it, not read | code longer than the reader reads (see [The length limit](#the-length-limit)) |
| the openers left open at once: brackets; in Python each string in a format string's field, and each field; in JavaScript each template and `${…}` field, and each JSX element and `{…}` in one | 400 (`MAX_TREE_DEPTH`): past it, not read | the parser's recursion back through its stack, as deep as what is left open, as it merges the ways it reads the code |
| on the bytes alone, the brackets (`(`, `[`, `{`) left open at once, strings and comments too, each closer closing one opener and the count never below none | 400 (`MAX_TREE_DEPTH`): past it, not read | the same, where the reading of the text was misled |
| in JavaScript, on the bytes alone, the word `await` (wherever it stands, after a `.` or `...` too) followed, past anything that is not part of a name, by a `/`, in strings and comments too | 4 (`MAX_AWAITED_SLASHES`): past it, not read | an `await` read both as a name and as the keyword, which the grammar merges at a cost that grows with what is left open |
| in Python, a star (`*`, not `**`) after an operator (but an assignment, plain or augmented) or after `not`, `and`, `or`, `is`, `if`, `elif`, `else`, `while`, `with`, `assert`, `del` or `await`, in code and in format strings' fields | 4 (`MAX_STARS_AFTER_OPERATORS`): past it, code that does not parse | Python read two ways at once that never part; Python itself refuses such code |
| in Python, on the bytes alone, a star or `**` after an operator (`==`, `!=`, `<=`, `>=` and `:=` among them, but not an assignment) or one of those keywords, past anything between them that is not part of a name, an operator or a bracket, in strings and comments too | 256 (`MAX_RAW_STARS`): past it, not read | the same, where the reading of the text was misled |
| a space a grammar passes over that is not an ASCII space, tab, line end or form feed (Unicode's white space, the vertical tab, U+200B, U+2060 and U+FEFF but a byte-order mark at the start), outside the strings and comments | 4 (`MAX_ODD_SPACES`): past it, not read | a scan that reads such a space otherwise than the grammar does |
| in Python, a backtick outside the strings and comments | any: code that does not parse (Python 3 reads none) | tree-sitter-python takes one for a string's quote |
| in Ruby, the openers left open at once: brackets, the blocks a keyword opens to its `end` (`begin`, `do`, `def`, `class`, `module`, `case`, and `if`, `unless`, `while`, `until`, `for` where they start an expression, not where they end a statement: `x if y`, `return if y`; a loop's `do` is its own), each literal (a string, a symbol, a regular expression, a command string, a `%` literal), each `#{…}` field and the body of a heredoc, one at a time | 400 (`MAX_TREE_DEPTH`): past it, not read | the parser's recursion back through its stack, the reader's walk and the strings it works out |
| in Ruby, the literals open at once, one inside the other's `#{…}` | 64 (`MAX_RUBY_LITERALS`): past it, not read | tree-sitter-ruby's scanner keeps them in a state of 1 KB, five bytes each, and past some 200 keeps none and reads what follows as code |
| in Ruby, how deep a `%` literal nests its own delimiter (`%q(((…)))`) | 200 (`MAX_RUBY_NESTING`): past it, not read | the scanner keeps the count in a byte, which comes back to nothing past 255 |
| in Ruby, a heredoc's word (`<<~WORD`, `<<"WORD"`): its length, and whether it is ASCII; a quoted word a line's end cuts, an empty one | 64 bytes of ASCII (`MAX_HEREDOC_WORD`): past it, not read | the scanner keeps the length in a byte: a word longer than it holds fails an assertion that aborts the process, and a long one fills its state; it reads a word not in ASCII by its bytes and compares it by its characters, so it never finds the end (`x = <<"É"`), and the rest of the code is the heredoc's text, where Ruby runs it |
| in Ruby, the heredocs a line starts, open at once | 8 (`MAX_HEREDOCS`): past it, not read | their words share the scanner's state with the literals |

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

The Ruby scan reads literals, comments (`#`, `=begin` to `=end`), `__END__`,
character literals (`?(`) and globals (`$"`, `$'`) as tree-sitter-ruby
reads them, and a heredoc's body to its word as the grammar's scanner ends
it: at a line of the word and spaces, past spaces for `<<-` and `<<~`, and
also right after a `#{…}` field or an escape of its text, where that scanner
looks for the word again. After a name, spaced or not, `<<WORD` is a
heredoc, and after a name and a space a `/` or a `%` with no space after it
is a literal's start, and a `:` before an operator a symbol (`wont_be :<,
1`, as after another symbol: `alias :a :<<`), as the grammar reads them
(see the known limit of Ruby's locals above); a name's `?` before a `:` is
a key's (`success?: true`), and an escape is as long as the grammar's
`escape_sequence` reads it. Where the scan cannot tell what the text is (a
`?` after a name and a space with no space after it, a character literal
with a code escape, a `%` with a space for its delimiter, a heredoc started
in another's body, a body line that starts with its word and goes on, a
line's end inside a literal before the heredocs it started), it only counts
more: to the end of the line every opener (and every keyword that opens a
block) counts and no closer closes, and to the end of the code if the rest
of that line may start a literal or a heredoc's body is to come; there,
each `#{` counts as a literal, each bracket and `<` as a nesting of a `%`
literal's delimiter (past 200 the code is not read), and each `<<WORD` of a
line as a heredoc, its word held to the bounds above.

**Before the scan, the raw text.** The scan reads the context the grammar's
scanner is in, and a context it misreads (a `%` literal it does not see, a
character Ruby or the grammar reads as a space and the scan does not, an
`__END__` inside brackets, an `=end` followed by something) once let a
heredoc's word longer than the scanner holds reach it, which aborts the process. So
the limits of the scanner's state that the raw text alone can bound are
held to it first, with no context at all, and the code is not read past
them, whatever the scan would say:

- every `<<`, `<<-` or `<<~` anywhere in the text (a comment, a string,
  past `__END__`) followed by an unquoted word longer than 64 bytes or not
  in ASCII, or by a quoted word longer, not in ASCII, or that a line's end
  or the code's end cuts. Wherever it stands, after a quote, a `#` or a
  method's `.` too (`"#<<"`, `x.<<"a"`), where Ruby starts no heredoc: the
  grammar, once it has met an error, takes any token for valid and the
  scanner reads one (a quote, `<<`, a backslash and a word the next backtick
  ends, a long way on, took the scanner to the abort in a random noise of
  3 KiB, which an exception for the place after a quote let through). This
  alone keeps the abort unreachable: a word longer than the scanner holds is
  the only way to it.
- more than 150 `#{` in all (`MAX_RUBY_INTERPOLATIONS`): a literal opens
  inside another only in a `#{…}` of it, so the scanner never keeps more
  than one more literal than that, five bytes each of the 1,024 its state
  is written in.
- more than 256 bytes (`MAX_RUBY_HEREDOC_BYTES`) of heredocs: each `<<`
  with a word or a quoted word after it, anywhere, counts four bytes and
  its word, as the scanner writes it; and, where the text has one, more
  than 1,021 bytes (`MAX_RUBY_STATE`) of those and five for each byte that
  may start a literal (`"`, `'`, a backtick, `/`, `%`, anywhere). The
  scanner writes its state in 1,024 bytes (a count, five bytes for each
  literal, a count, four and the word for each heredoc); past what its
  check allows it writes nothing, or a byte past its buffer
  (`size + 2 + word >= 1024`, written `4 + word`). At an error the parser
  takes every token for valid and the scanner never reads a literal's
  content, so every such byte may start a literal, none closed, and the
  nesting of `#{…}` bounds nothing. With heredocs `2 + 5L + H <= 1,021`, `L`
  at most the bytes that start a literal and `H` the heredocs' bytes, the
  state is written whole and within 1,021 bytes whatever the order; with
  none, 205 literals or more are not written at all and fewer fit.
- a `\c`, `\C-` or `\M-` followed by anything but a letter or a digit,
  where no backslash escapes the backslash. Ruby reads these escapes with
  the character after them, a quote too (`"\c"; y = "; …; z = "`), where the
  grammar reads two characters and ends the string at the next quote: what
  Ruby runs between the two quotes is a string to the grammar. After `#$`
  a backslash is the global `$\` interpolated, to Ruby and to the scanner,
  so the backslashes of a run after it may pair up from the first or from
  the second: both readings are followed. The script guard says why it
  refused such code (`refusal`), not that it takes too long.
- an embedded document (`=begin` at a line's start) the grammar ends
  elsewhere than Ruby. The grammar's comment is `=begin`, the rest of the
  line, and everything up to the first `=end` anywhere (`=endx`, `=end=`,
  `  =end`, `*=end`, `x=end`), the rest of that line; Ruby's document
  ends at a line that starts with `=end` and then white space or the end, so
  the code between the two is a string or a comment to the grammar and
  what Ruby runs (`=begin` `=endx` `y = "` `=end` `system('rm -rf ~') #"`
  reads as a string holding the call). The raw text is refused where the
  two ends differ, or `=begin` is followed by anything but white space; and
  `understand` takes no document whose last line is not Ruby's `=end` or
  that holds another.
- a `%` literal with a paired delimiter whose openers, counted from it to
  where the delimiters close it (a backslash and the byte after it passed
  over, as the scanner reads no delimiter in an escape), are more than 200;
  and for one that reads `#{…}`, whose code may hold a closer the scanner
  does not count, every opener of its kind to the end of the code.

Of 7,820 distinct real Ruby files (CRuby's standard library, Homebrew and
the gems it vendors, up to 64 KB each), 2,876 (37 %) are longer than 3 KiB,
which the reader does not read (63 of them the raw text refuses besides);
of the 4,944 within it, the raw text refuses 6, each for a heredoc's word:
a `<<` and a quote the raw text cannot tell from a heredoc's start (`" +-<<"`
in a string of minitest's, `'<<'` in rubocop's, and `describe "#<<"` in four
of Homebrew's own specs). The scan before a parse
refuses none of the others and stops none: 6 do not parse as the grammar
reads them (newer syntax). The slowest took 3 ms.

tree-sitter-ruby's parser itself needs little stack: valid Ruby nested 4,000
deep by any opener, and 64 KB of each shape it reads two ways (`p /a/`, `a
*b`, `a [b]`, `a ?b :c`, `a <<b`, command calls in command calls) inside 399
levels of every opener, each parse in a few tens of milliseconds, fit a
thread of 64 KB; what the scan bounds is the grammar's scanner and the
reader's own walk. tree-sitter-ruby 0.23.1's scanner (`src/scanner.c`) was
read for its loops: each reads on through the text or returns, and ends at
the end of the code; the state it keeps (`serialize`) is what the bounds
above hold.

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
(0.26.13, tree-sitter-python 0.25.0, tree-sitter-javascript 0.25.0,
tree-sitter-ruby 0.23.1): another
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

Ruby's scanner is the one thing here that aborts: tree-sitter-ruby's keeps
its state in a buffer of 1,024 bytes and a heredoc's word in 255, and fails
an assertion, which ends the process, past them. A random noise of 3 KiB
(`''<<` and a backtick, and the word the next backtick ends) reached it once
the scan trusted where a heredoc starts; the bounds on the raw text, which
trust nothing, are held by `tests/stack.rs` and `tests/parse_budget.rs` of
each crate to every shape of the abort found, and over a million more
noisy inputs, of the vocabulary above and of openers (`<<`, quotes, `#{`,
`%w(`), ran without one.

## Tests

`crates/code/tests/` holds the crate's own cases, in case files
(`tests/cases`, the format is in
[CONTRIBUTING.md](../../CONTRIBUTING.md#case-files)), each checked by the test
file of its name. `acts.cases` has code and the acts it must give, for each
language. `understand.cases` has a case for every way out of the strict
subset, and the code that stays inside it, for Python, JavaScript,
Ruby and Python 2. `parses.cases` holds the code that parses and the code that
does not, `input.cases` the code that may give a program input, and
`shell_list.cases` the code that hands a shell a list. `modules.cases` holds the module specifiers and coding
declarations; `modules.rs` keeps the shape of an argument and the limits.
`cases.rs` tests the runner and dumps every case. `stack.rs` reads code at the
bounds of the scan before a parse on a thread of a small stack (1 MiB in an
optimized build), so a reading that would overflow it aborts the test and
not a caller, and holds valid code that one bound of the scan alone stops to
not being read, so that a bound taken away fails it. `robust.rs` runs seeded noise
through each grammar (no panic, the same answer twice, understood code only
ever opens a file), the code of every case changed at random and punctuation
joined at random, each held to the budget above, and checks that very deep,
very long and growing code ends. `parse_budget.rs` holds the shapes of
error to the rule that stops them, and the shapes the budget stops to it, at
each size up to the length limit, with their answers pinned (not read, not
understood); the valid literals the grammar reads two ways, dense and nested
real code, and comment runs up to the measured limit to being read whole;
and each question asked once its walk runs out to the cautious answer; and
Ruby past what tree-sitter-ruby's scanner holds to not being read, and at it
to being read whole. It
reads the counts through the crate's `testing` feature, which only its own
tests turn on and which is not for callers. The shell guard's own cases
(`crates/shell/tests/cases/inline.cases`, the `inline_*.cases` files beside
it and the rest) judge whole lines through the reader and hold the verdicts:
the reader moved out of the shell guard with none of them changing, and the
one whose code has a syntax error beside a line's other code (a nested
`eval` of the endless recovery) now reads as code that does not parse.
