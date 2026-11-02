//! Inline code that starts a program: the options of the call (`cwd`,
//! `executable`, `shell`), Python library calls that run code, every call of
//! `execa` and `cross-spawn`, a spread in the call, members of a function that
//! starts a program, `os.kill` and `process.kill` of a literal id, the
//! members of `child_process` that run what the reader does not read,
//! `asyncio.subprocess`, a string handed to a timer, the words a program is
//! started with in either quoting, and an environment given to a started
//! program.

mod common;

use common::inline::{assert_risky_as, js, lines, py, UNKNOWN_OR_SECRET};
use common::{check, posix};
use milo_guards_shell::{Rule, Shell};

#[test]
fn inline_code_that_starts_a_program_is_judged_like_the_program() {
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[
            // The options of a call that starts a program are read.
            (
                "python3 -c \"import subprocess; subprocess.run(['rm','-rf','x'], cwd='/home/me')\"",
                Rule::Delete,
            ),
            (
                "python3 -c \"import subprocess; subprocess.run('rm -rf .ssh', shell=True, cwd='/home/me')\"",
                Rule::Delete,
            ),
            (
                "python3 -c \"import os, subprocess; subprocess.run(['rm','-rf','.ssh'], cwd=os.path.expanduser('~'))\"",
                Rule::Delete,
            ),
            (
                "python3 -c \"import subprocess; subprocess.Popen('rm -rf .ssh', shell=True, cwd='/home/me')\"",
                Rule::Delete,
            ),
            (
                "python3 -c \"import subprocess; subprocess.run(['x','-rf','/home/me'], executable='/bin/rm')\"",
                Rule::Delete,
            ),
            // A directory or a program only known when it runs.
            (
                "python3 -c \"import subprocess; subprocess.run(['rm','-rf','x'], cwd=d)\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"import subprocess; subprocess.run(['ls'], cwd=d)\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"import subprocess; subprocess.run(['x'], executable=e)\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"import subprocess; subprocess.run('x', shell=True, executable='/usr/bin/python3')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"import subprocess; subprocess.run(['ls'], **options)\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"import subprocess; subprocess.run(['x'], -1, '/bin/rm')\"",
                Rule::Unknown,
            ),
            (
                "node -e \"require('child_process').execSync('rm -rf .ssh', {cwd: '/home/me'})\"",
                Rule::Delete,
            ),
            (
                "node -e \"require('child_process').spawnSync('rm', ['-rf','.ssh'], {cwd: process.env.HOME})\"",
                Rule::Delete,
            ),
            (
                "node -e \"const {spawnSync} = require('child_process'); spawnSync('rm', ['-rf','.ssh'], {cwd: process.env.HOME})\"",
                Rule::Delete,
            ),
            (
                "node -e \"require('child_process').execFileSync('rm', ['-rf','.ssh'], {cwd: '/home/me'})\"",
                Rule::Delete,
            ),
            (
                "node -e \"require('child_process').spawn('rm -rf .ssh', {shell: true, cwd: '/home/me'})\"",
                Rule::Delete,
            ),
            (
                "bun -e 'Bun.spawnSync([\"rm\", \"-rf\", \".ssh\"], {cwd: \"/home/me\"})'",
                Rule::Delete,
            ),
            (
                "bun -e 'Bun.spawn({cmd: [\"rm\", \"-rf\", \".ssh\"], cwd: \"/home/me\"})'",
                Rule::Delete,
            ),
            (
                "deno eval 'Deno.run({cmd: [\"rm\", \"-rf\", \".ssh\"], cwd: \"/home/me\"})'",
                Rule::Delete,
            ),
            (
                "deno eval 'new Deno.Command(\"rm\", {args: [\"-rf\", \".ssh\"], cwd: \"/home/me\"}).outputSync()'",
                Rule::Delete,
            ),
            (
                "bun -e 'Bun.$`rm -rf .ssh`.cwd(\"/home/me\")'",
                Rule::Delete,
            ),
            (
                "bun -e 'await Bun.$`rm -rf .ssh`.quiet().cwd(\"/home/me\")'",
                Rule::Delete,
            ),
            // A directory, options or a shell only known when it runs.
            (
                "node -e \"require('child_process').execSync('rm -rf .ssh', {cwd: dir})\"",
                Rule::Unknown,
            ),
            (
                "node -e \"require('child_process').execSync('ls', {cwd})\"",
                Rule::Unknown,
            ),
            (
                "node -e \"require('child_process').execSync('ls', {...options})\"",
                Rule::Unknown,
            ),
            (
                "node -e \"require('child_process').execSync('ls', {[key]: '/home/me'})\"",
                Rule::Unknown,
            ),
            (
                "node -e \"require('child_process').execSync('ls', options)\"",
                Rule::Unknown,
            ),
            (
                "node -e \"require('child_process').spawnSync('git', ['status'], options)\"",
                Rule::Unknown,
            ),
            (
                "node -e \"require('child_process').spawnSync('git', options)\"",
                Rule::Unknown,
            ),
            (
                "node -e \"require('child_process').execSync(\\\"import os; os.remove('/home/me/.zshrc')\\\", {shell: 'python3'})\"",
                Rule::Unknown,
            ),
            (
                "node -e \"require('child_process').execSync('x', {shell: sh})\"",
                Rule::Unknown,
            ),
            (
                "bun -e 'Bun.$.cwd(\"/home/me\"); Bun.$`rm -rf .ssh`'",
                Rule::Unknown,
            ),
            // Not read whole by the strict gate: unknown.
            ("python3 -c \"import subprocess; subprocess.run(['ls'], cwd='/home/me')\"", Rule::Unknown),
            ("python3 -c \"import subprocess; subprocess.run(['cargo', 'build'], cwd='sub')\"", Rule::Unknown),
            ("python3 -c \"import subprocess; subprocess.run(['rm', '-rf', 'build'], cwd='/home/me/work/repo')\"", Rule::Unknown),
            ("python3 -c \"import subprocess; subprocess.run(['rm', '-rf', 'build'], cwd=None)\"", Rule::Unknown),
            ("python3 -c \"import subprocess; subprocess.run('cargo test', shell=True, cwd='sub')\"", Rule::Unknown),
            ("python3 -c \"import subprocess; subprocess.run(['x', '/tmp'], executable='/bin/ls')\"", Rule::Unknown),
            ("python3 -c \"import os, subprocess; subprocess.run(['ls'], cwd=os.getcwd())\"", Rule::Unknown),
            ("node -e \"require('child_process').execSync('ls', {cwd: '/home/me'})\"", Rule::Unknown),
            ("node -e \"require('child_process').execSync('npm test', {cwd: 'sub'})\"", Rule::Unknown),
            ("node -e \"require('child_process').execSync('npm test', {cwd: undefined})\"", Rule::Unknown),
            ("node -e \"require('child_process').execSync('echo hi', {shell: '/bin/bash'})\"", Rule::Unknown),
            ("node -e \"require('child_process').execSync('echo hi', {shell: true})\"", Rule::Unknown),
            ("node -e \"require('child_process').spawnSync('git', ['status'], {cwd: 'sub'})\"", Rule::Unknown),
            ("node -e \"require('child_process').execFile('ls', ['a'], (e) => {})\"", Rule::Unknown),
            ("node -e \"require('child_process').exec('ls', (e) => {})\"", Rule::Unknown),
            ("bun -e 'Bun.spawnSync([\"ls\"], {cwd: \"/home/me\"})'", Rule::Unknown),
            // An environment written out whole, with nothing the shell side
            // judges: not read whole by the strict gate, unknown.
            (
                r#"python3 -c "import subprocess; subprocess.run(['ls'], env={'LANG': 'C'})""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "require('child_process').spawnSync('ls', [], {env: {LANG: 'C'}})""#,
                Rule::Unknown,
            ),
            (
                r#"python3 -c "import subprocess; subprocess.run(['ls'])""#,
                Rule::Unknown,
            ),
            // Python library calls that run code are read or unknown. A
            // callable is walked where it is written, a literal is read.
            // (`json` is a file looked up in the folder first: unknown.)
            (
                r#"python3 -c 'import json; json.loads("{}")'"#,
                Rule::Unknown,
            ),
            (
                r#"python3 -c 'import timeit; timeit.timeit("import shutil; shutil.rmtree(\"/home/me\")", number=1)'"#,
                Rule::Delete,
            ),
            (
                r#"python3 -c 'import timeit; timeit.timeit(stmt="import shutil; shutil.rmtree(\"/home/me\")")'"#,
                Rule::Delete,
            ),
            (
                r#"python3 -c 'import timeit; timeit.timeit("pass", setup="import shutil; shutil.rmtree(\"/home/me\")")'"#,
                Rule::Delete,
            ),
            (
                r#"python3 -c 'import timeit; timeit.repeat("import shutil; shutil.rmtree(\"/home/me\")")'"#,
                Rule::Delete,
            ),
            (
                r#"python3 -c 'import timeit; timeit.Timer("import shutil; shutil.rmtree(\"/home/me\")").timeit()'"#,
                Rule::Delete,
            ),
            (
                r#"python3 -c 'from timeit import timeit as t; t("import shutil; shutil.rmtree(\"/home/me\")")'"#,
                Rule::Delete,
            ),
            (
                r#"python3 -c 'import cProfile; cProfile.run("import shutil; shutil.rmtree(\"/home/me\")")'"#,
                Rule::Delete,
            ),
            (
                r#"python3 -c 'import cProfile; cProfile.runctx("import shutil; shutil.rmtree(\"/home/me\")", {}, {})'"#,
                Rule::Delete,
            ),
            (
                r#"python3 -c 'import profile; profile.run("import shutil; shutil.rmtree(\"/home/me\")")'"#,
                Rule::Delete,
            ),
            (
                r#"python3 -c 'import pdb; pdb.run("import shutil; shutil.rmtree(\"/home/me\")")'"#,
                Rule::Unknown,
            ),
            (
                r#"python3 -c 'import pdb; pdb.runeval("__import__(\"shutil\").rmtree(\"/home/me\")")'"#,
                Rule::Unknown,
            ),
            // Code only known when it runs, a profiler's or a debugger's own
            // object, and a call handed on.
            ("python3 -c 'import timeit; timeit.timeit(s)'", Rule::Unknown),
            ("python3 -c 'import timeit; timeit.timeit(stmt=s)'", Rule::Unknown),
            ("python3 -c 'import timeit; timeit.timeit(\"x\", setup=s)'", Rule::Unknown),
            ("python3 -c 'import timeit; timeit.timeit(*a)'", Rule::Unknown),
            ("python3 -c 'import cProfile; cProfile.run(s)'", Rule::Unknown),
            ("python3 -c 'import profile; profile.runctx(s, g, l)'", Rule::Unknown),
            ("python3 -c 'import pdb; pdb.run(s)'", Rule::Unknown),
            ("python3 -c 'import pdb; pdb.runcall(f)'", Rule::Unknown),
            (
                r#"python3 -c 'import cProfile; cProfile.Profile().run("import shutil; shutil.rmtree(\"/home/me\")")'"#,
                Rule::Unknown,
            ),
            (
                r"python3 -c 'import cProfile; p = cProfile.Profile(); p.runctx(s, g, l)'",
                Rule::Unknown,
            ),
            ("python3 -c 'import timeit; f = timeit.timeit; f(s)'", Rule::Unknown),
            // Loading code that runs.
            (
                r#"python3 -c 'import pickle; pickle.loads(b"cposix\nsystem\n(S\"rm -rf ~\"\ntR.")'"#,
                Rule::Unknown,
            ),
            ("python3 -c 'import pickle; pickle.load(f)'", Rule::Unknown),
            ("python3 -c 'from pickle import loads; loads(data)'", Rule::Unknown),
            ("python3 -c 'import marshal; marshal.loads(data)'", Rule::Unknown),
            ("python3 -c 'import marshal; marshal.load(f)'", Rule::Unknown),
            (
                r#"python3 -c 'import pkgutil; pkgutil.resolve_name("shutil:rmtree")("/home/me")'"#,
                Rule::Unknown,
            ),
            (
                "python3 -c 'import importlib.util as u; s = u.spec_from_file_location(\"m\", \"m.py\"); m = u.module_from_spec(s); s.loader.exec_module(m); m.rmtree(\"/home/me\")'",
                Rule::Unknown,
            ),
            (
                "python3 -c 'import importlib.util; m = importlib.util.module_from_spec(spec)'",
                Rule::Unknown,
            ),
            ("python3 -c 'spec.loader.exec_module(m)'", Rule::Unknown),
            ("python3 -c 'loader.load_module(\"m\")'", Rule::Unknown),
            // Not read whole by the strict gate: unknown.
            (r"python3 -c 'import timeit; timeit.timeit(lambda: sum(range(10)), number=1)'", Rule::Unknown),
            (r#"python3 -c 'import timeit; timeit.timeit("sum(range(10))", number=1)'"#, Rule::Unknown),
            (r#"python3 -c 'import timeit; timeit.timeit("x = 1", setup="import os")'"#, Rule::Unknown),
            (r#"python3 -c 'import timeit; timeit.repeat("x = 1", repeat=2)'"#, Rule::Unknown),
            (r#"python3 -c 'import timeit; timeit.Timer("x = 1")'"#, Rule::Unknown),
            (r#"python3 -c 'import cProfile; cProfile.run("sum(range(10))")'"#, Rule::Unknown),
            (r#"python3 -c 'import profile; profile.run("sum(range(10))")'"#, Rule::Unknown),
            // `asyncio.subprocess` starts programs.
            (
                "python3 -c \"import asyncio.subprocess as s; s.create_subprocess_shell('rm -rf ~')\"",
                Rule::Delete,
            ),
            (
                "python3 -c \"from asyncio.subprocess import create_subprocess_shell as c; c('rm -rf ~')\"",
                Rule::Delete,
            ),
            (
                "python3 -c \"from asyncio import subprocess as sp; sp.create_subprocess_shell('rm -rf ~')\"",
                Rule::Delete,
            ),
            (
                "python3 -c \"import asyncio; asyncio.subprocess.create_subprocess_exec('rm','-rf','/home/me')\"",
                Rule::Delete,
            ),
            // Every call of execa that runs a command is read.
            (
                "node -e \"require('execa').execaCommand('rm -rf ~')\"",
                Rule::Delete,
            ),
            (
                "node -e \"require('execa').command('rm -rf ~')\"",
                Rule::Delete,
            ),
            (
                "node -e \"require('execa').commandSync('rm -rf ~')\"",
                Rule::Delete,
            ),
            (
                "node -e \"const {command} = require('execa'); command('rm -rf ~')\"",
                Rule::Delete,
            ),
            (
                "node --input-type=module -e \"import execa from 'execa'; execa.command('rm -rf ~')\"",
                Rule::Delete,
            ),
            // `$`, as a call and as a tagged template, and its `.sync`.
            (
                r#"node --input-type=module -e 'import {$} from "execa"; await $`rm -rf /home/me`'"#,
                Rule::Delete,
            ),
            (
                "node --input-type=module -e 'import {$} from \"execa\"; await $(\"rm -rf /home/me\")'",
                Rule::Delete,
            ),
            (
                r#"node --input-type=module -e 'import {$} from "execa"; $.sync`rm -rf /home/me`'"#,
                Rule::Delete,
            ),
            (
                r#"node -e 'const {$} = require("execa"); $.sync`rm -rf /home/me`'"#,
                Rule::Delete,
            ),
            (
                r#"node -e 'require("execa").$`rm -rf /home/me`'"#,
                Rule::Delete,
            ),
            // A command only known when it runs.
            (
                r#"node --input-type=module -e 'import {$} from "execa"; await $`ls ${x}`'"#,
                Rule::Unknown,
            ),
            // cross-spawn: `spawn` and `sync` are `child_process`'s.
            (
                "node -e \"require('cross-spawn').sync('rm', ['-rf', '/home/me'])\"",
                Rule::Delete,
            ),
            (
                "node -e \"require('cross-spawn').spawn('rm', ['-rf', '/home/me'])\"",
                Rule::Delete,
            ),
            (
                "node -e \"const spawn = require('cross-spawn'); spawn.sync('rm', ['-rf', '/home/me'])\"",
                Rule::Delete,
            ),
            (
                "node --input-type=module -e \"import spawn from 'cross-spawn'; spawn.sync('rm', ['-rf', '/home/me'])\"",
                Rule::Delete,
            ),
            // The module itself is the spawn: bare, through a name (any
            // declaration, or a later assignment), as a default import, and
            // as the namespace's `default`.
            (
                "node -e \"require('cross-spawn')('rm', ['-rf', '/home/me'])\"",
                Rule::Delete,
            ),
            (
                "node -e \"const spawn = require('cross-spawn'); spawn('rm', ['-rf', '/home/me'])\"",
                Rule::Delete,
            ),
            (
                "node -e \"var spawn = require('cross-spawn'); spawn('rm', ['-rf', '/home/me'])\"",
                Rule::Delete,
            ),
            (
                "node -e \"let spawn = require('cross-spawn'); spawn('rm', ['-rf', '/home/me'])\"",
                Rule::Delete,
            ),
            (
                "node -e \"let spawn; spawn = require('cross-spawn'); spawn('rm', ['-rf', '/home/me'])\"",
                Rule::Delete,
            ),
            (
                "node --input-type=module -e \"import spawn from 'cross-spawn'; spawn('rm', ['-rf', '/home/me'])\"",
                Rule::Delete,
            ),
            (
                "node --input-type=module -e \"import {default as spawn} from 'cross-spawn'; spawn('rm', ['-rf', '/home/me'])\"",
                Rule::Delete,
            ),
            (
                "node --input-type=module -e \"import * as cs from 'cross-spawn'; cs.default('rm', ['-rf', '/home/me'])\"",
                Rule::Delete,
            ),
            (
                "node -e \"require('execa')('rm', ['-rf', '/home/me'])\"",
                Rule::Delete,
            ),
            // The module handed on as a value stays unknown.
            (
                "node -e \"run(require('cross-spawn'))\"",
                Rule::Unknown,
            ),
            (
                "node -e \"const spawn = require('cross-spawn'); run(spawn)\"",
                Rule::Unknown,
            ),
            // Not read whole by the strict gate: unknown.
            ("node -e \"require('execa').command('ls -l')\"", Rule::Unknown),
            ("node -e \"require('execa').commandSync('ls')\"", Rule::Unknown),
            (r#"node --input-type=module -e 'import {$} from "execa"; await $`ls`'"#, Rule::Unknown),
            (r#"node --input-type=module -e 'import {$} from "execa"; $.sync`git status`'"#, Rule::Unknown),
            ("node -e \"require('cross-spawn').sync('ls', ['-l'])\"", Rule::Unknown),
            ("node -e \"require('cross-spawn').spawn('ls')\"", Rule::Unknown),
            ("node -e \"const spawn = require('cross-spawn'); spawn.sync('ls')\"", Rule::Unknown),
            ("node -e \"require('cross-spawn')('ls')\"", Rule::Unknown),
            ("node -e \"const spawn = require('cross-spawn'); spawn('ls', ['-l'])\"", Rule::Unknown),
            ("node --input-type=module -e \"import spawn from 'cross-spawn'; spawn('ls')\"", Rule::Unknown),
            // A spread in a call that starts a program is not read: it may
            // hold the program, its arguments or its options, and may come
            // before any of them, so the call is code the guard does not
            // read, as `fork` with one already was. Without a spread the
            // same calls are read.
            (
                r#"node -e "const {spawn} = require('child_process'); spawn('rm', ['-rf', '/home/me'])""#,
                Rule::Delete,
            ),
            (
                r#"node -e "const {spawn} = require('child_process'); spawn(...['rm', ['-rf', '/home/me']])""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "const {spawnSync} = require('child_process'); const a = ['rm', ['-rf', '/home/me']]; spawnSync(...a)""#,
                Rule::Unknown,
            ),
            // The spread after the program is read as a bare `rm`.
            (
                r#"node -e "const {execFileSync} = require('child_process'); execFileSync('rm', ...[['-rf', '/home/me']])""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "const {execa} = require('execa'); execa(...['rm', ['-rf', '/home/me']])""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "const {execa} = require('execa'); execa('rm', ...[['-rf', '/home/me']])""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "const spawn = require('cross-spawn'); spawn(...['rm', ['-rf', '/home/me']])""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "const spawn = require('cross-spawn'); [['rm', ['-rf', '/home/me']]].forEach(a => spawn(...a))""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "new Deno.Command(...['rm', {args: ['-rf', '/home/me']}])""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "const a = ['rm', {args: ['-rf', '/home/me']}]; new Deno.Command(...a)""#,
                Rule::Unknown,
            ),
            // Not read whole by the strict gate: unknown. A spread inside the
            // list of arguments is a word of the list.
            (
                r#"node -e "const {spawn} = require('child_process'); spawn('ls', ['-l'])""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "const {execa} = require('execa'); execa('ls', ['-l'])""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "new Deno.Command('ls', {args: ['-l']})""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "const {spawn} = require('child_process'); spawn('ls', ['-l', ...[]])""#,
                Rule::Unknown,
            ),
            // The members of `child_process` that run what the reader does
            // not read are unknown. `execArgv` is node's own options: `-e` is
            // code.
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
            // Not read whole by the strict gate: unknown.
            ("node -e \"require('child_process').fork('worker.js', ['a', 'b'])\"", Rule::Unknown),
            ("node -e \"require('child_process').fork('worker.js', { silent: true })\"", Rule::Unknown),
            ("node -e \"require('child_process').fork('worker.js', ['a'], { cwd: 'sub', silent: true, stdio: 'inherit' })\"", Rule::Unknown),
            ("node -e \"const { fork } = require('child_process'); fork('worker.js')\"", Rule::Unknown),
            ("node -e \"require('child_process').fork('worker.js', [], {})\"", Rule::Unknown),
            ("node -e \"require('child_process').execSync('echo 1')\"", Rule::Unknown),
            ("node -e \"require('child_process').spawn('echo', ['1'])\"", Rule::Unknown),
            // A string handed to a timer is code the reader does not read.
            (
                r#"deno eval "setTimeout('Deno.removeSync(\"/home/me\",{recursive:true})')""#,
                Rule::Unknown,
            ),
            (
                r#"deno eval "setInterval('Deno.removeSync(\"/home/me\")', 10)""#,
                Rule::Unknown,
            ),
            (
                r#"deno eval "setTimeout(`Deno.removeSync(\"/home/me\")`)""#,
                Rule::Unknown,
            ),
            (r#"deno eval "globalThis.setTimeout('x')""#, Rule::Unknown),
            (r#"deno eval "setTimeout(...['x'])""#, Rule::Unknown),
            (r#"deno eval "setTimeout.call(null, 'x')""#, Rule::Unknown),
            (r#"node -e "setTimeout('x' + y, 5)""#, Rule::Unknown),
            (r#"bun -e "setTimeout('x', 5)""#, Rule::Unknown),
            // A function is read where it is written.
            (
                r#"node -e "setTimeout(() => require('fs').rmSync('/home/me', {recursive:true}), 100)""#,
                Rule::Delete,
            ),
            // Not read whole by the strict gate: unknown.
            (
                "node -e 'setTimeout(() => console.log(1), 100)'",
                Rule::Unknown,
            ),
            (
                "node -e 'function f() {}; setTimeout(f, 100); setInterval(f, 1, \"a\")'",
                Rule::Unknown,
            ),
            ("node -e 'setTimeout(console.log, 1, \"x\")'", Rule::Unknown),
            (
                "deno eval 'setTimeout(() => console.log(1), 100)'",
                Rule::Unknown,
            ),
            ("bun -e 'setInterval(function () {}, 1000)'", Rule::Unknown),
            // Killing a process by a literal id is the `kill` command.
            (r"python3 -c 'import os; os.kill(-1, 9)'", Rule::StopSystem),
            (r"python3 -c 'import os; os.kill(-1, 15)'", Rule::StopSystem),
            (
                r"python3 -c 'import os, signal; os.kill(-1, signal.SIGKILL)'",
                Rule::StopSystem,
            ),
            (
                r"python3 -c 'import os; os.kill(pid=-1, sig=9)'",
                Rule::StopSystem,
            ),
            (
                r"python3 -c 'from os import kill; kill(-1, 9)'",
                Rule::StopSystem,
            ),
            (r"python3 -c 'import os; os.kill(- 1, 9)'", Rule::StopSystem),
            (
                r"python3 -c 'import os; os.kill(-0x1, 9)'",
                Rule::StopSystem,
            ),
            (r"python3 -c 'import os; os.kill(1, 9)'", Rule::StopSystem),
            (r"python3 -c 'import os; os.killpg(1, 9)'", Rule::StopSystem),
            (
                r"python3 -c 'import os; os.killpg(-1, 9)'",
                Rule::StopSystem,
            ),
            // A process id only known when it runs may be any of them.
            (r"python3 -c 'import os; os.kill(pid, 9)'", Rule::Unknown),
            (
                r"python3 -c 'import os; os.kill(-1 if a else 2, 9)'",
                Rule::Unknown,
            ),
            (r"python3 -c 'import os; os.kill(*a)'", Rule::Unknown),
            (r"python3 -c 'import os; os.kill(-01, 9)'", Rule::Unknown),
            ("node -e \"process.kill(-1, 'SIGKILL')\"", Rule::StopSystem),
            ("node -e \"process.kill(-1)\"", Rule::StopSystem),
            ("node -e \"process.kill(1, 'SIGTERM')\"", Rule::StopSystem),
            (
                "node -e \"const {kill} = process; kill(-1, 'SIGKILL')\"",
                Rule::StopSystem,
            ),
            ("deno eval 'Deno.kill(-1, \"SIGKILL\")'", Rule::StopSystem),
            ("node -e \"process.kill(pid, 'SIGKILL')\"", Rule::Unknown),
            ("node -e \"process.kill(...a)\"", Rule::Unknown),
            ("node -e \"process.kill(-1.5)\"", Rule::Unknown),
            // Process 0 is the caller's own group; another id is not read
            // whole: unknown.
            (r"python3 -c 'import os; os.kill(0, 9)'", Rule::StopSystem),
            (r"python3 -c 'import os; os.killpg(0, 9)'", Rule::StopSystem),
            (
                r"python3 -c 'import os, signal; os.kill(4242, signal.SIGTERM)'",
                Rule::Unknown,
            ),
            ("node -e \"process.kill(0, 'SIGKILL')\"", Rule::StopSystem),
            ("node -e \"process.kill(4242)\"", Rule::Unknown),
            ("deno eval 'Deno.kill(4242, \"SIGTERM\")'", Rule::Unknown),
        ],
    );
    // A member of a function that starts a program is not the call:
    // `cross-spawn` and `execa` are functions that start a program, with
    // `spawn`, `sync` and the like for members, and `call`, `apply` and
    // `bind` hand the program on to a call the guard does not see, as they
    // do through `child_process`. The members that are read are still read,
    // but code with a `require` is not read whole by the strict gate: each
    // is unknown.
    let unknown = [
        r#"node -e "const spawn = require('cross-spawn'); spawn.sync('ls', ['-l'])""#,
        r#"node -e "const spawn = require('cross-spawn'); spawn.spawn('ls', ['-l'])""#,
        r#"node -e "require('cross-spawn')('ls', ['-l'])""#,
        r#"node -e "require('cross-spawn').spawn('ls', ['-l'])""#,
        r#"node -e "require('cross-spawn').default('ls', ['-l'])""#,
        r#"node -e "require('execa').execa('ls', ['-l'])""#,
        r#"node -e "require('execa').execaSync('ls', ['-l'])""#,
        r#"node -e "import spawn from 'cross-spawn'; spawn('ls', ['-l'])""#,
        r#"node -e "const spawn = require('cross-spawn'); spawn.call(null, 'rm', ['-rf', '/home/me'])""#,
        r#"node -e "const spawn = require('cross-spawn'); spawn.apply(null, ['rm', ['-rf', '/home/me']])""#,
        r#"node -e "const spawn = require('cross-spawn'); spawn.bind(null, 'rm')(['-rf', '/home/me'])""#,
        r#"node -e "const spawn = require('cross-spawn'); const f = spawn.bind(null); f('rm', ['-rf', '/home/me'])""#,
        r#"node -e "const spawn = require('cross-spawn'); ['/home/me'].map(spawn.bind(null, 'rm'))""#,
        r#"node -e "const spawn = require('cross-spawn'); spawn.foo('rm', ['-rf', '/home/me'])""#,
        r#"node -e "require('cross-spawn').call(null, 'rm', ['-rf', '/home/me'])""#,
        r#"node -e "require('cross-spawn').apply(null, ['rm', ['-rf', '/home/me']])""#,
        r#"node -e "require('cross-spawn').bind(null, 'rm')(['-rf', '/home/me'])""#,
        r#"node -e "require('cross-spawn').default.call(null, 'rm', ['-rf', '/home/me'])""#,
        r#"node -e "import * as cs from 'cross-spawn'; cs.default.call(null, 'rm', ['-rf', '/home/me'])""#,
        r#"node -e "import spawn from 'cross-spawn'; spawn.call(null, 'rm', ['-rf', '/home/me'])""#,
        r#"node -e "let s; s = require('cross-spawn'); s.call(null, 'rm', ['-rf', '/home/me'])""#,
        r#"node -e "const {$} = require('execa'); $.call(null, 'rm', ['-rf', '/home/me'])""#,
        r#"node -e "const {$} = require('execa'); $.apply(null, [['rm -rf ~']])""#,
        r#"node -e "const {$} = require('execa'); $.bind(null)('rm -rf ~')""#,
        r#"node -e "require('execa').call(null, 'rm', ['-rf', '/home/me'])""#,
        r#"node -e "require('execa').apply(null, ['rm', ['-rf', '/home/me']])""#,
        r#"node -e "require('execa').bind(null, 'rm')(['-rf', '/home/me'])""#,
        r#"node -e "require('execa').execaNode('script.js')""#,
    ];
    let unknown: Vec<(&str, Rule)> = unknown.iter().map(|line| (*line, Rule::Unknown)).collect();
    check(Shell::Posix, &posix(), &[], &unknown);
}

#[test]
fn a_program_argument_the_code_writes_out_is_read_in_either_quoting() {
    // Programs started with words the code writes out are still read as
    // before, but code with an import, a `require` or a loop is not read
    // whole by the strict gate: unknown. A word only known when the code
    // runs is one the guard cannot judge, as `cat "$F"` is not one it can.
    let unknown = vec![
        py(r#"import subprocess\nsubprocess.run(["ls", "-l"])"#),
        py(r#"import subprocess\nsubprocess.run(["git", "status", "--short"], check=True)"#),
        py(r#"import subprocess\nsubprocess.run(["cat", "README.md"])"#),
        py(r#"import subprocess\nf = "README.md"\nsubprocess.run(["cat", f])"#),
        py(r#"import subprocess\nfor f in ["a.txt", "b.txt"]: subprocess.run(["cat", f])"#),
        py(r#"import subprocess\nsubprocess.run(["cat", "notes/" + "a.txt"])"#),
        js(
            "node",
            r#"require("child_process").execFileSync("ls", ["-l"])"#,
        ),
        js(
            "node",
            r#"const f = "README.md"; require("child_process").execFileSync("cat", [f])"#,
        ),
        js("bun", r#"Bun.spawnSync(["ls", "-l"])"#),
        py(r#"import subprocess, sys\nsubprocess.run(["echo", sys.argv[1]])"#),
        js(
            "node",
            r#"require("child_process").spawnSync("echo", [process.argv[1]])"#,
        ),
    ];
    assert_risky_as(&unknown, &[Rule::Unknown]);
    // A program argument is read the same when the code is in double quotes
    // (single-quoted strings in the code): a key named whole is a read of it.
    let rows = lines(&[
        "python3 -c \"import subprocess\nf = '/home/me/.ssh/id_rsa'\nsubprocess.run(['cat', f])\"",
        "python3 -c \"import subprocess\nf = 'id_rsa'\nsubprocess.run(['cat', '/home/me/.ssh/' + f])\"",
        "python3 -c \"import subprocess\nfor f in ['id_rsa']: subprocess.run(['cat', '/home/me/.ssh/' + f])\"",
        "node -e \"const cp = require('child_process'); const f = '/home/me/.ssh/id_rsa'; cp.execFileSync('cat', [f])\"",
        "node -e \"const f = 'id_rsa'; require('child_process').execFileSync('cat', ['/home/me/.ssh/' + f])\"",
        "bun -e \"const f = 'id_rsa'; Bun.spawnSync(['cat', '/home/me/.ssh/' + f])\"",
    ]);
    assert_risky_as(&rows, &[Rule::ReadSecret]);
    // And an argument the reader does not fold, or one from a listing, the
    // arguments or the environment, is not safe.
    let rows = lines(&[
        "python3 -c \"import subprocess\nsubprocess.run(['cat', '/home/me/.ssh/%s' % 'id_rsa'])\"",
        "python3 -c \"import subprocess\nsubprocess.run(['cat', '/home/me/.ssh/{}'.format('id_rsa')])\"",
        "python3 -c \"import subprocess, sys\nsubprocess.run(['cat', f'/home/me/.ssh/{sys.argv[1]}'])\"",
        "python3 -c \"import subprocess, os\nfor f in os.listdir(os.path.expanduser('~/.ssh')): subprocess.run(['cat', f], cwd=os.path.expanduser('~/.ssh'))\"",
        "python3 -c \"import subprocess, os\nfor f in os.listdir('.'): subprocess.run(['cat', f])\"",
        "python3 -c \"import subprocess, sys\nsubprocess.run(['cat', sys.argv[1]])\" ~/.ssh/id_rsa",
        "python3 -c \"import subprocess, sys\nsubprocess.run(['cat', sys.argv[1]], cwd='/home/me/.ssh')\"",
        "python3 -c \"import subprocess, sys\nsubprocess.run(['python3', sys.argv[1]])\"",
        "node -e \"require('child_process').execFileSync('cat', [process.argv[1]])\" ~/.ssh/id_rsa",
        "node -e \"require('child_process').execFileSync('cat', [process.argv[1]], {cwd: '/home/me/.ssh'})\"",
        "node -e \"require('child_process').execFileSync('cat', ['/home/me/.ssh/id_rsa'.slice(0)])\"",
        "node -e \"require('child_process').execFileSync('cat', [['/home/me/.ssh/id_rsa'][0]])\"",
        "bun -e \"Bun.spawnSync(['cat', Bun.argv[1]])\"",
    ]);
    assert_risky_as(&rows, &UNKNOWN_OR_SECRET);
}

#[test]
fn inline_code_that_gives_a_started_program_an_environment_is_unknown() {
    let rows = lines(&[
        r#"python3 -c "import subprocess; subprocess.run(['python3', '-c', '1'], env={'PYTHONPATH': '/tmp'})""#,
        r#"python3 -c "import subprocess, os; subprocess.run(['python3', '-c', '1'], env={**os.environ, 'PYTHONPATH': '/tmp'})""#,
        r#"python3 -c "import subprocess, os; subprocess.run(['python3', '-c', '1'], env=dict(os.environ, PYTHONPATH='/tmp'))""#,
        r#"python3 -c "import subprocess, os; e = os.environ.copy(); e['PYTHONPATH'] = '/tmp'; subprocess.run(['python3', '-c', '1'], env=e)""#,
        r#"python3 -c "import subprocess, sys; subprocess.run(['python3', '-c', '1'], env={'PYTHONPATH': sys.argv[1]})" /tmp"#,
        r#"python3 -c "import os; os.environ['PYTHONPATH'] = '/tmp'; os.system('python3 -c 1')""#,
        r#"python3 -c "import os; os.putenv('PYTHONPATH', '/tmp'); os.system('python3 -c 1')""#,
        r#"python3 -c "import os; os.environ.update(PYTHONPATH='/tmp'); os.system('python3 -c 1')""#,
        r#"python3 -c "import os, subprocess; os.environ['PYTHONPATH'] = '/tmp'; subprocess.run(['python3', '-c', '1'])""#,
        r#"python3 -c "import subprocess; subprocess.run(['python3', '-c', '1'], env={'LD_PRELOAD': '/tmp/x.so'})""#,
        r#"python3 -c "import subprocess; subprocess.run(['ls'], env={'PATH': '/tmp'})""#,
        r#"node -e "require('child_process').spawnSync('node', ['-e', '1'], {env: {NODE_OPTIONS: '--require /tmp/x.js'}})""#,
        r#"node -e "require('child_process').spawnSync('node', ['-e', '1'], {env: {...process.env, NODE_OPTIONS: '--require /tmp/x.js'}})""#,
        r#"node -e "process.env.NODE_OPTIONS = '--require /tmp/x.js'; require('child_process').execSync('node -e 1')""#,
        r#"node -e "require('child_process').execSync('node -e 1', {env: {NODE_OPTIONS: '--require /tmp/x.js'}})""#,
        r#"node -e "const e = process.env; require('child_process').spawnSync('ls', [], {env: e})""#,
        r#"node -e "const {execa} = require('execa'); execa('node', ['-e', '1'], {env: {NODE_OPTIONS: '--require /tmp/x.js'}})""#,
        r#"node -e "process.env.NODE_OPTIONS = '--require /tmp/x.js'; require('execa').execa('node', ['-e', '1'])""#,
        r#"bun -e "Bun.spawn(['bun', '-e', '1'], {env: {NODE_OPTIONS: '--require /tmp/x.js'}})""#,
        r#"bun -e "Bun.spawn(['bun', '-e', '1'], {env: {...process.env, NODE_OPTIONS: '--require /tmp/x.js'}})""#,
        r#"bun -e "process.env.NODE_OPTIONS = '--require /tmp/x.js'; Bun.spawn(['bun', '-e', '1'])""#,
        r#"deno eval "new Deno.Command('deno', {args: ['eval', '1'], env: {NODE_OPTIONS: '--require /tmp/x.js'}}).outputSync()""#,
        r#"deno eval "Deno.env.set('NODE_OPTIONS', '--require /tmp/x.js'); new Deno.Command('deno', {args: ['eval', '1']}).outputSync()""#,
    ]);
    assert_risky_as(&rows, &[Rule::Unknown]);
    // A key it reads still wins.
    let rows = lines(&[
        r#"python3 -c "import subprocess; subprocess.run(['cat', '/home/me/.ssh/id_rsa'], env={'PYTHONPATH': '/tmp'})""#,
    ]);
    assert_risky_as(&rows, &[Rule::ReadSecret]);
}
