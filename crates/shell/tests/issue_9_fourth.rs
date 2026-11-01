//! Inline code, the fourth pass: an interpreter that goes on to read code from
//! its input (`-i`, `repl`, `breakpoint()`), names that literal `exec` and
//! `eval` code binds or uses, a JavaScript hashbang that ends at a line
//! terminator other than `\n`, the members of `child_process` that run what
//! the reader does not read, `NODE_OPTIONS` that loads a `data:` URL, and a
//! `.open()` whose argument is not a mode.

mod common;

use common::{check, posix};
use milo_guards_shell::{Rule, Shell};

#[test]
fn an_interactive_interpreter_reads_the_code_it_is_handed_on_its_input() {
    check(
        Shell::Posix,
        &posix(),
        &[
            // `-I` is isolated mode, which does not read the input.
            "python3 -I -c 'print(1)'",
            "python3 -Ic 'print(1)'",
            // After the code, an `-i` is an argument of the code.
            "python3 -c 'print(1)' -i",
            "python3 -c 'print(1)' -i x",
            // Bun's `-i` installs packages.
            "bun -i -e 1",
            // A flag that only looks like it.
            "node -e 'console.log(1)' script-arg -i",
            "python3 -W i -c 'print(1)'",
        ],
        &[
            // CPython's `-i`, alone, bundled and attached to the code.
            (
                "python3 -ic \"print(1)\" <<'PY'\nimport shutil; shutil.rmtree('/home/me')\nPY",
                Rule::Unknown,
            ),
            (
                "echo \"import shutil; shutil.rmtree('/home/me')\" | python3 -i -c \"print(1)\"",
                Rule::Unknown,
            ),
            ("python3 -i -c 1 < /tmp/evil.py", Rule::Unknown),
            ("python3 -i -c 1", Rule::Unknown),
            ("python3 -bic 1", Rule::Unknown),
            ("python3 -ibc 1", Rule::Unknown),
            ("python3 -i -c1", Rule::Unknown),
            ("python3 -W i -ic 1", Rule::Unknown),
            ("python3 -b -i -c 1 <<'PY'\nprint(1)\nPY", Rule::Unknown),
            // What is in the code is read all the same.
            (
                "python3 -i -c \"import shutil; shutil.rmtree('/home/me')\"",
                Rule::Delete,
            ),
            // Node's `-i` and `--interactive`, before or after the code.
            (
                "node -i -e 1 <<'JS'\nrequire('fs').rmSync('/home/me',{recursive:true})\nJS",
                Rule::Unknown,
            ),
            ("node --interactive -e 1", Rule::Unknown),
            ("node --interactive -p 1", Rule::Unknown),
            ("node -i -e 1", Rule::Unknown),
            ("node -e 1 -i", Rule::Unknown),
            ("node -e 1 --interactive", Rule::Unknown),
            ("node -p 1 -i", Rule::Unknown),
            (
                "node -i -e \"require('fs').rmSync('/home/me',{recursive:true})\"",
                Rule::Delete,
            ),
            // `repl` reads the code it is given from the input.
            (
                "node -e \"require('repl').start()\" <<'JS'\nrequire('fs').rmSync('/home/me',{recursive:true})\nJS",
                Rule::Unknown,
            ),
            ("node -e \"require('node:repl').start()\"", Rule::Unknown),
            ("node -e \"const r = require('repl'); r.start()\"", Rule::Unknown),
            (
                "node -e \"const { start } = require('repl'); start()\"",
                Rule::Unknown,
            ),
            ("node -e \"new (require('repl').REPLServer)()\"", Rule::Unknown),
            (
                "node --input-type=module -e \"import repl from 'repl'; repl.start()\"",
                Rule::Unknown,
            ),
            // A debugger reads its commands, and runs statements, from the input.
            (
                "python3 -c \"breakpoint()\" <<'PY'\nimport shutil; shutil.rmtree('/home/me')\nPY",
                Rule::Unknown,
            ),
            (
                "python3 -c \"import pdb; pdb.set_trace()\" <<'PY'\nimport os; os.remove('/home/me/f')\nPY",
                Rule::Unknown,
            ),
            (
                "python3 -c \"from pdb import set_trace as t; t()\"",
                Rule::Unknown,
            ),
            ("python3 -c \"import code; code.interact()\"", Rule::Unknown),
        ],
    );
}

#[test]
fn names_literal_exec_and_eval_code_binds_or_uses_are_not_read_apart() {
    check(
        Shell::Posix,
        &posix(),
        &[
            // Names bound to what the reader does not follow.
            "python3 -c \"exec('x = 1'); print(x)\"",
            "python3 -c \"exec('print(1)')\"",
            "python3 -c \"exec('def f(): return 1'); print(f())\"",
            "python3 -c \"exec('a = [1, 2]'); print(a)\"",
            "python3 -c \"x = 1; exec('print(x)')\"",
            "python3 -c \"import json; exec('print(json.dumps(1))')\"",
            "node -e \"eval('var x = 1'); console.log(x)\"",
            "node -e \"eval('console.log(1)')\"",
            "node -e \"var x = 1; eval('console.log(x)')\"",
            "node -e \"eval('function f() { return 1 }'); console.log(f())\"",
        ],
        &[
            // What a name is bound to in nested code, followed outside it.
            (
                "python3 -c \"exec('import shutil as json'); json.rmtree('/home/me')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"exec('from shutil import rmtree as f'); f('/home/me')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"exec('import os as j'); j.system('rm -rf ~')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"exec('global j\\nimport shutil as j'); j.rmtree('/home/me')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"exec(\\\"exec('import shutil as j')\\\"); j.rmtree('/home/me')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"exec('j = __import__(\\\"shutil\\\")'); j.rmtree('/home/me')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"exec('r = shutil.rmtree'); r('/home/me')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"exec('(j := __import__(\\\"os\\\"))'); j.system('rm -rf ~')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"import os as o; exec('p = o.remove'); p('/home/me/f')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"exec('import distutils.dir_util as d'); d.remove_tree('/home/me')\"",
                Rule::Unknown,
            ),
            // A profiler's string runs in the namespace of the code.
            (
                "python3 -c \"import cProfile; cProfile.run('import shutil as j'); j.rmtree('/home/me')\"",
                Rule::Unknown,
            ),
            // A name this code bound, used in nested code.
            (
                "python3 -c \"import shutil as s; exec('s.rmtree(\\\"/home/me\\\")')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"from os import remove as r; exec('r(\\\"/home/me/f\\\")')\"",
                Rule::Unknown,
            ),
            // What the nested code does is read all the same.
            (
                "python3 -c \"exec('import shutil'); shutil.rmtree('/home/me')\"",
                Rule::Delete,
            ),
            (
                "python3 -c \"import os; exec('os.remove(\\\"/home/me/f\\\")')\"",
                Rule::Delete,
            ),
            // JavaScript: `var`, destructuring, an outer name assigned.
            (
                "node -e \"eval(\\\"var m = require('fs')\\\"); m.rm('/home/me',{recursive:true},()=>{})\"",
                Rule::Unknown,
            ),
            (
                "node -e \"eval(\\\"var {rm} = require('fs')\\\"); rm('/home/me',{recursive:true},()=>{})\"",
                Rule::Unknown,
            ),
            (
                "node -e \"eval(\\\"var cp = require('child_process')\\\"); cp.exec('rm -rf ~')\"",
                Rule::Unknown,
            ),
            (
                "node -e \"var m; eval('m = require(\\\"fs\\\")'); m.rm('/home/me',{recursive:true},()=>{})\"",
                Rule::Unknown,
            ),
            (
                "node -e \"eval('var m = require(\\\"fs\\\").promises'); m.rm('/home/me',{recursive:true})\"",
                Rule::Unknown,
            ),
            (
                "node -e \"eval('let { rm } = require(\\\"fs/promises\\\")'); rm('/home/me',{recursive:true})\"",
                Rule::Unknown,
            ),
            (
                "node -e \"eval('function f(p) { return require(\\\"fs\\\").rm(p, {recursive:true}, () => {}) }'); f('/home/me')\"",
                Rule::Delete,
            ),
            // A name this code bound, used in nested code.
            (
                "node -e \"const f = require('fs'); eval('f.rm(\\\"/home/me\\\",{recursive:true},()=>{})')\"",
                Rule::Unknown,
            ),
            (
                "node -e \"const { rm } = require('fs'); eval('rm(\\\"/home/me\\\",{recursive:true},()=>{})')\"",
                Rule::Unknown,
            ),
            // Nested in nested code.
            (
                "node -e \"eval(\\\"eval('var m = require(\\\\\\\"fs\\\\\\\")')\\\"); m.rm('/home/me',{recursive:true},()=>{})\"",
                Rule::Unknown,
            ),
            // What the nested code does is read all the same.
            (
                "node -e \"eval('require(\\\"fs\\\").rmSync(\\\"/home/me\\\",{recursive:true})')\"",
                Rule::Delete,
            ),
        ],
    );
}

#[test]
fn a_hashbang_line_ends_at_any_javascript_line_terminator() {
    check(
        Shell::Posix,
        &posix(),
        &[
            // The whole line is the comment.
            "node -e \"#!x require('fs').rmSync('/home/me',{recursive:true})\"",
            "node -e \"#!x\nconsole.log(1)\"",
            "node -e \"#!x\rconsole.log(1)\"",
            "node -e \"#!x\r\nconsole.log(1)\"",
            "node -e \"#!x\u{2028}console.log(1)\"",
            "node -e \"#!x\u{2029}console.log(1)\"",
            "node <<'JS'\n#!/usr/bin/env node\nconsole.log(1)\nJS",
            // Not at the start of the code, it is a syntax error, not a comment.
            "node -e \"console.log(1)\"",
        ],
        &[
            (
                "node -e \"#!x\rrequire('fs').rmSync('/home/me',{recursive:true})\"",
                Rule::Delete,
            ),
            (
                "node -e \"#!x\u{2028}require('fs').rmSync('/home/me',{recursive:true})\"",
                Rule::Delete,
            ),
            (
                "node -e \"#!x\u{2029}require('fs').rmSync('/home/me',{recursive:true})\"",
                Rule::Delete,
            ),
            (
                "node -e \"#!x\r\nrequire('fs').rmSync('/home/me',{recursive:true})\"",
                Rule::Delete,
            ),
            (
                "node -e \"#!x\nrequire('fs').rmSync('/home/me',{recursive:true})\"",
                Rule::Delete,
            ),
            (
                "node <<'JS'\n#!x\rrequire('fs').rmSync('/home/me',{recursive:true})\nJS",
                Rule::Delete,
            ),
            (
                "node <<'JS'\n#!x\u{2028}require('fs').rmSync('/home/me',{recursive:true})\nJS",
                Rule::Delete,
            ),
            (
                "node --input-type=module <<'JS'\n#!x\u{2029}require('fs').rmSync('/home/me',{recursive:true})\nJS",
                Rule::Delete,
            ),
            (
                "bun -e \"#!x\rrequire('fs').rmSync('/home/me',{recursive:true})\"",
                Rule::Delete,
            ),
            (
                "node -e \"eval('#!x\\u2028require(\\\"fs\\\").rmSync(\\\"/home/me\\\",{recursive:true})')\"",
                Rule::Delete,
            ),
        ],
    );
}

#[test]
fn child_process_calls_that_run_what_the_reader_does_not_read_are_unknown() {
    check(
        Shell::Posix,
        &posix(),
        &[
            // A module of the workspace's own, as `node worker.js` is.
            "node -e \"require('child_process').fork('worker.js')\"",
            "node -e \"require('child_process').fork('worker.js', ['a', 'b'])\"",
            "node -e \"require('child_process').fork('worker.js', { silent: true })\"",
            "node -e \"require('child_process').fork('worker.js', ['a'], { cwd: 'sub', silent: true, stdio: 'inherit' })\"",
            "node -e \"const { fork } = require('child_process'); fork('worker.js')\"",
            "node -e \"require('child_process').fork('worker.js', [], {})\"",
            // The calls that are read.
            "node -e \"require('child_process').execSync('echo 1')\"",
            "node -e \"require('child_process').spawn('echo', ['1'])\"",
        ],
        &[
            // `execArgv` is node's own options: `-e` is code.
            (
                "node -e \"require('child_process').fork('x.js', {execArgv:['-e', \\\"require('fs').rmSync('/home/me',{recursive:true})\\\"]})\"",
                Rule::Unknown,
            ),
            (
                "node -e \"require('child_process').fork('x.js', ['a'], {execArgv: []})\"",
                Rule::Unknown,
            ),
            (
                "node -e \"require('child_process').fork('x.js', {'execArgv': ['--import=data:text/javascript,1']})\"",
                Rule::Unknown,
            ),
            (
                "node -e \"const execArgv = ['-e', '1']; require('child_process').fork('x.js', {execArgv})\"",
                Rule::Unknown,
            ),
            // `execPath` is the program that runs.
            (
                "node -e \"require('child_process').fork('/home/me', ['-rf'], {execPath:'/bin/rm'})\"",
                Rule::Unknown,
            ),
            (
                "node -e \"require('child_process').fork('x.js', {execPath})\"",
                Rule::Unknown,
            ),
            // Options that are not an object literal may hold either.
            (
                "node -e \"require('child_process').fork('x.js', opts)\"",
                Rule::Unknown,
            ),
            (
                "node -e \"require('child_process').fork('x.js', ['a'], process.env.OPTS)\"",
                Rule::Unknown,
            ),
            (
                "node -e \"require('child_process').fork('x.js', {...opts})\"",
                Rule::Unknown,
            ),
            (
                "node -e \"require('child_process').fork('x.js', {[key]: 1})\"",
                Rule::Unknown,
            ),
            (
                "node -e \"require('child_process').fork('x.js', {get execPath() { return '/bin/rm' }})\"",
                Rule::Unknown,
            ),
            (
                "node -e \"require('child_process').fork('x.js', ...args)\"",
                Rule::Unknown,
            ),
            // A module that starts with `-` is an option of node.
            (
                "node -e \"require('child_process').fork('-e', ['require(\\\"fs\\\").rmSync(\\\"/home/me\\\",{recursive:true})'])\"",
                Rule::Unknown,
            ),
            (
                "node -e \"require('child_process').fork('--import=data:text/javascript,1')\"",
                Rule::Unknown,
            ),
            (
                "node -e \"require('child_process').fork(process.argv[1])\"",
                Rule::Unknown,
            ),
            // `fork` handed on as a value.
            (
                "node -e \"[require('child_process').fork].forEach(f => f('x.js', {execPath: '/bin/rm'}))\"",
                Rule::Unknown,
            ),
            // Members of `child_process` the reader does not read.
            (
                "node -e \"new (require('child_process').ChildProcess)().spawn({file:'rm',args:['rm','-rf','/home/me']})\"",
                Rule::Unknown,
            ),
            (
                "node -e \"const { ChildProcess } = require('child_process'); new ChildProcess().spawn({file:'rm',args:['rm','-rf','/home/me']})\"",
                Rule::Unknown,
            ),
            (
                "node -e \"require('child_process')._forkChild(3, 'json')\"",
                Rule::Unknown,
            ),
            // A worker the cluster starts takes its options from the settings.
            (
                "node -e \"const c = require('cluster'); c.setupPrimary({execArgv: ['-e', '1']}); c.fork()\"",
                Rule::Unknown,
            ),
            // A session of the inspector evaluates what it is sent.
            (
                "node -e \"const i = require('inspector'); const s = new i.Session(); s.connect(); s.post('Runtime.evaluate', {expression: 'process.exit()'})\"",
                Rule::Unknown,
            ),
        ],
    );
}

#[test]
fn node_options_that_load_a_data_url_make_inline_code_unknown() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "NODE_OPTIONS=--max-old-space-size=4096 node -e 'console.log(1)'",
            "NODE_OPTIONS='--max-old-space-size=4096 --no-warnings' node -e 'console.log(1)'",
            "NODE_OPTIONS='--require ./setup.js' node -e 'console.log(1)'",
            "NODE_OPTIONS='--import ./setup.mjs' node -e 'console.log(1)'",
            "NODE_OPTIONS= node -e 'console.log(1)'",
            "env NODE_OPTIONS=--max-old-space-size=4096 node -e 'console.log(1)'",
            "export NODE_OPTIONS=--max-old-space-size=4096; node -e 'console.log(1)'",
            "NODE_OPTIONS=--import=data:text/javascript,1 echo 1",
            // Not read by bun.
            "NODE_OPTIONS=--import=data:text/javascript,1 bun -e 1",
        ],
        &[
            // A prefix assignment.
            (
                "NODE_OPTIONS=\"--import=data:text/javascript,import('fs').then(f=>f.rmSync('/home/me',{recursive:true}))\" node -e \"console.log(1)\"",
                Rule::Unknown,
            ),
            (
                "NODE_OPTIONS='--import data:text/javascript,1' node -e 1",
                Rule::Unknown,
            ),
            (
                "NODE_OPTIONS='--max-old-space-size=4096 --import=data:text/javascript,1' node -e 1",
                Rule::Unknown,
            ),
            (
                "NODE_OPTIONS='--require ./a.js --import=data:text/javascript,1' node -e 1",
                Rule::Unknown,
            ),
            (
                "NODE_OPTIONS='--loader=data:text/javascript,1' node -e 1",
                Rule::Unknown,
            ),
            (
                "NODE_OPTIONS='--experimental-loader data:text/javascript,1' node -e 1",
                Rule::Unknown,
            ),
            (
                "NODE_OPTIONS='--import \"data:text/javascript,1\"' node -e 1",
                Rule::Unknown,
            ),
            (
                "NODE_OPTIONS='--import=DATA:text/javascript,1' nodejs -p 1",
                Rule::Unknown,
            ),
            (
                "NODE_OPTIONS='--import=data:text/javascript,1' node <<'JS'\nconsole.log(1)\nJS",
                Rule::Unknown,
            ),
            // `env`, also with a wrapper in front.
            (
                "env NODE_OPTIONS=\"--import=data:text/javascript,import('fs').then(f=>f.rmSync('/home/me',{recursive:true}))\" node -e 1",
                Rule::Unknown,
            ),
            (
                "env -i NODE_OPTIONS=--import=data:text/javascript,1 node -e 1",
                Rule::Unknown,
            ),
            (
                "env FOO=1 NODE_OPTIONS=--import=data:text/javascript,1 node -e 1",
                Rule::Unknown,
            ),
            // Set earlier in the line.
            (
                "export NODE_OPTIONS=--import=data:text/javascript,1; node -e 1",
                Rule::Unknown,
            ),
            (
                "export NODE_OPTIONS=--import=data:text/javascript,1 && node -e 1",
                Rule::Unknown,
            ),
            (
                "export \"NODE_OPTIONS=--import=data:text/javascript,1\"; node -e 1",
                Rule::Unknown,
            ),
            (
                "NODE_OPTIONS=--import=data:text/javascript,1; export NODE_OPTIONS; node -e 1",
                Rule::Unknown,
            ),
            (
                "read -r NODE_OPTIONS <<< '--import=data:text/javascript,1'; export NODE_OPTIONS; node -e 1",
                Rule::Unknown,
            ),
            ("export NODE_OPTIONS=\"--import=$URL\"; node -e 1", Rule::Unknown),
            // In front of a shell that starts node.
            (
                "NODE_OPTIONS='--import=data:text/javascript,1' bash -c \"node -e 1\"",
                Rule::Unknown,
            ),
            (
                "env NODE_OPTIONS=--import=data:text/javascript,1 sh -c 'node -p 1'",
                Rule::Unknown,
            ),
            // A value only known when it runs.
            ("NODE_OPTIONS=\"$OPTS\" node -e 1", Rule::Unknown),
            ("NODE_OPTIONS=\"--import=$URL\" node -e 1", Rule::Unknown),
            ("NODE_OPTIONS=$(cat opts) node -e 1", Rule::Unknown),
            // An underscore in an option's name is a hyphen to node.
            (
                "node --experimental_loader=data:text/javascript,1 -e 1",
                Rule::Unknown,
            ),
            // The code is read all the same when it does not load one.
            (
                "NODE_OPTIONS=--max-old-space-size=4096 node -e \"require('fs').rmSync('/home/me',{recursive:true})\"",
                Rule::Delete,
            ),
        ],
    );
}

#[test]
fn an_open_call_is_a_write_only_when_its_argument_can_be_a_mode() {
    check(
        Shell::Posix,
        &posix(),
        &[
            // A file name, a URL, a name with an `a` in it.
            "python3 -c \"from PIL import Image; print(Image.open('a.png').size)\"",
            "python3 -c \"import wave; print(wave.open('a.wav').getnframes())\"",
            "python3 -c \"import fitz; fitz.open('a.pdf')\"",
            "python3 -c \"import webbrowser; webbrowser.open('http://localhost:8000')\"",
            "python3 -c \"import webbrowser; webbrowser.open('https://example.com/x', new=2)\"",
            "python3 -c \"import wave; wave.open('data.wav', 'rb')\"",
            "python3 -c \"from PIL import Image; Image.open('x.png', 'r')\"",
            "python3 -c \"import shelve; shelve.open('data.db', 'r')\"",
            // Reads.
            "python3 -c \"from pathlib import Path; Path('a.txt').open().read()\"",
            "python3 -c \"from pathlib import Path; Path('a.txt').open('r')\"",
            "python3 -c \"from pathlib import Path; Path('a.txt').open('rb')\"",
            "python3 -c \"from pathlib import Path; Path('a.txt').open(mode='rt')\"",
            // A string that is not one mode, or one that `open` refuses.
            "python3 -c \"from pathlib import Path; Path('a.txt').open('rr')\"",
            "python3 -c \"from pathlib import Path; Path('a.txt').open('rw')\"",
            "python3 -c \"from pathlib import Path; Path('a.txt').open('bt')\"",
            "python3 -c \"from pathlib import Path; Path('a.txt').open('+')\"",
        ],
        &[
            (
                "python3 -c \"from pathlib import Path; Path('/home/me/f').open('w')\"",
                Rule::Overwrite,
            ),
            (
                "python3 -c \"from pathlib import Path; Path('/home/me/f').open('a')\"",
                Rule::Overwrite,
            ),
            (
                "python3 -c \"from pathlib import Path; Path('/home/me/f').open('wb')\"",
                Rule::Overwrite,
            ),
            (
                "python3 -c \"from pathlib import Path; Path('/home/me/f').open('r+')\"",
                Rule::Overwrite,
            ),
            (
                "python3 -c \"from pathlib import Path; Path('/home/me/f').open('x')\"",
                Rule::Overwrite,
            ),
            (
                "python3 -c \"from pathlib import Path; Path('/home/me/f').open(mode='w')\"",
                Rule::Overwrite,
            ),
            (
                "python3 -c \"from pathlib import Path; Path('/home/me/f').open(mode='ab')\"",
                Rule::Overwrite,
            ),
            ("python3 -c \"open('/home/me/f', 'a')\"", Rule::Overwrite),
            (
                "python3 -c \"open('/home/me/f', mode='w')\"",
                Rule::Overwrite,
            ),
            // The mode is the second argument of these.
            (
                "python3 -c \"import wave; wave.open('/home/me/out.wav', 'wb')\"",
                Rule::Overwrite,
            ),
            (
                "python3 -c \"import tarfile; tarfile.TarFile.open('/home/me/a.tar', 'w:gz')\"",
                Rule::Overwrite,
            ),
            (
                "python3 -c \"import shelve; shelve.open('/home/me/data', 'n')\"",
                Rule::Overwrite,
            ),
            (
                "python3 -c \"import shelve; shelve.open('/home/me/data', flag='c')\"",
                Rule::Overwrite,
            ),
            // The calls that open a file by name keep their own modes.
            (
                "python3 -c \"import tarfile; tarfile.open('/home/me/a.tar', 'w:gz')\"",
                Rule::Overwrite,
            ),
            (
                "python3 -c \"import gzip; gzip.open('/home/me/a.gz', 'wt')\"",
                Rule::Overwrite,
            ),
        ],
    );
}
