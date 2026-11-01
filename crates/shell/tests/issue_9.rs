//! Inline code, the second pass: more than one code flag, `deno eval`'s
//! operands, names the reader does not follow (a default value, a module
//! handed on as a value), the options of a call that starts a program,
//! `bun --cwd`, Python 2's `exec`, `Path.rename(target=...)`, and `bun` and
//! `deno` reading code from their input.

mod common;

use common::{check, check_effect, posix, windows};
use milo_guards_shell::{Effect, Rule, Shell};

#[test]
fn every_code_flag_of_node_and_bun_is_read() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "node -e 'console.log(1)' -e 'console.log(2)'",
            "node -p -e 'console.log(1)'",
            "node -p 1 -e 'console.log(2)'",
            "node --eval 1 --eval 2",
            "node --print=1 --eval=2",
            "node -pe 1 -e 2",
            "bun -e 1 -e 2",
            "bun -p 1 -e 2",
            "node -e 'console.log(process.argv)' script-arg",
        ],
        &[
            // The last one runs, and an earlier one is read all the same.
            (
                r#"node -e "console.log(1)" -e "require('fs').rmSync('/home/me',{recursive:true})""#,
                Rule::Delete,
            ),
            (
                r#"node -e "require('fs').rmSync('/home/me',{recursive:true})" -e "console.log(1)""#,
                Rule::Delete,
            ),
            (
                r#"node -p -e "require('fs').rmSync('/home/me',{recursive:true})""#,
                Rule::Delete,
            ),
            (
                r#"node --eval 1 --eval "require('fs').rmSync('/home/me',{recursive:true})""#,
                Rule::Delete,
            ),
            (
                r#"node -p 1 -e "require('fs').rmSync('/home/me',{recursive:true})""#,
                Rule::Delete,
            ),
            (
                r#"node -pe 1 -e "require('fs').rmSync('/home/me',{recursive:true})""#,
                Rule::Delete,
            ),
            (
                r#"node --print=1 --eval="require('fs').rmSync('/home/me',{recursive:true})""#,
                Rule::Delete,
            ),
            (
                r#"node -r ts-node/register -e 1 -e "require('fs').rmSync('/home/me',{recursive:true})""#,
                Rule::Delete,
            ),
            (
                r#"bun -e 1 -e "require('fs').rmSync('/home/me',{recursive:true})""#,
                Rule::Delete,
            ),
            (
                r#"bun --print 1 --eval "require('fs').rmSync('/home/me',{recursive:true})""#,
                Rule::Delete,
            ),
            // A piece only known when it runs, or an option that could be one.
            ("node -e 1 -e \"$CODE\"", Rule::Unknown),
            ("node -e 1 $OPTION -e 2", Rule::Unknown),
        ],
    );
}

#[test]
fn every_operand_of_deno_eval_is_read() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "deno eval --reload 'console.log(1)'",
            "deno eval -L info 'console.log(1)'",
            "deno eval --log-level debug 'console.log(1)'",
            "deno eval --ext ts 'console.log(1)'",
            "deno eval -c deno.json 'console.log(1)'",
            "deno eval 'console.log(Deno.args)' a b",
            "deno eval -- 'console.log(1)'",
            "deno eval --v8-flags=--max-old-space-size=100 'console.log(1)'",
        ],
        &[
            (
                r#"deno eval --reload "Deno.removeSync('/home/me',{recursive:true})" "console.log(1)""#,
                Rule::Delete,
            ),
            (
                r#"deno eval -L info "Deno.removeSync('/home/me',{recursive:true})""#,
                Rule::Delete,
            ),
            (
                r#"deno eval --log-level info "Deno.removeSync('/home/me',{recursive:true})""#,
                Rule::Delete,
            ),
            (
                r#"deno eval --v8-flags "Deno.removeSync('/home/me',{recursive:true})" 1"#,
                Rule::Delete,
            ),
            (
                r#"deno eval --env-file "Deno.removeSync('/home/me',{recursive:true})""#,
                Rule::Delete,
            ),
            (
                r#"deno eval "console.log(1)" "Deno.removeSync('/home/me',{recursive:true})""#,
                Rule::Delete,
            ),
            (
                r#"deno eval -- "Deno.removeSync('/home/me',{recursive:true})""#,
                Rule::Delete,
            ),
            (
                r#"deno eval --ext ts "Deno.removeSync('/home/me',{recursive:true})""#,
                Rule::Delete,
            ),
            // An operand that is a path and not code does not parse: unread.
            (
                "deno eval --config ./deno.json 'console.log(1)'",
                Rule::Unknown,
            ),
            ("deno eval 'console.log(1)' \"$ARG\"", Rule::Unknown),
        ],
    );
}

#[test]
fn a_default_value_is_read() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "python3 -c 'def f(p, r=print): r(p)'",
            "python3 -c 'f = lambda x, y=1: x'",
            "python3 -c 'def f(a, *args, k: int = 1, **kw): pass'",
            "python3 -c 'def f(open): pass'",
        ],
        &[
            (
                "python3 -c \"import os\ndef f(p, r=os.remove): r(p)\nf('/home/me/.zshrc')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"import os\ndef f(p, *, r=os.remove): r(p)\nf('/home/me/.zshrc')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"import os\ndef f(p, r: object = os.remove): r(p)\nf('/home/me/.zshrc')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"import shutil; f = lambda p, r=shutil.rmtree: r(p)\"",
                Rule::Unknown,
            ),
            (
                r#"python3 -c "(lambda p, r=__import__('shutil').rmtree: r(p))('/home/me')""#,
                Rule::Unknown,
            ),
        ],
    );
}

#[test]
fn a_module_handed_on_as_a_value_is_unread() {
    check(
        Shell::Posix,
        &posix(),
        &[
            // Used for its attributes, or kept under a name the reader follows.
            "python3 -c 'import os; print(os.path.join(\"a\", \"b\"))'",
            "python3 -c 'import sys; print(sys.argv)'",
            "python3 -c 'import glob; print(glob.glob(\"*.py\"))'",
            "python3 -c 'import os; o = os; print(o.getcwd())'",
            "python3 -c 'import os; p = os.path; print(p.join(\"a\"))'",
            "python3 -c 'import os; a = b = os; print(a.getcwd(), b.getcwd())'",
            "python3 -c 'import os; print(getattr(os, \"getcwd\")())'",
            "python3 -c 'import os; print((os).getcwd())'",
            "python3 -c 'try:\n import os\nexcept ImportError:\n os = None'",
            "node -e 'const fs = require(\"fs\"); console.log(fs.readFileSync(\"a\"))'",
            "node -e 'const { readFileSync } = require(\"fs\"); readFileSync(\"a\")'",
            "node -e 'const { readFileSync: r = null } = require(\"fs\"); r(\"a\")'",
            "node -e 'const { a, ...rest } = { a: 1, b: 2 }; console.log(rest)'",
            "node -e 'let fs; fs = require(\"fs\"); fs.readFileSync(\"a\")'",
            "node -e 'console.log(typeof process, typeof require)'",
            "node -e 'process.exit(0)'",
            "node -e 'console.log(require(\"fs\").readdirSync(\".\"))'",
            "node -e 'const p = require(\"fs\").promises; p.readFile(\"a\")'",
            "node -e 'require(\"fs\"); require(\"os\")'",
            "node -e 'const r = require; console.log(r(\"os\").homedir())'",
            "deno eval 'console.log(Deno.cwd(), typeof Deno)'",
        ],
        &[
            (
                "python3 -c \"import os\ndef f(o): o.remove('/home/me/.zshrc')\nf(os)\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"import glob\ndef f(g): g.os.remove('/home/me/.zshrc')\nf(glob)\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"import os\ndef f(o): o.remove('/home/me/.zshrc')\nf(os.path)\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"import sys\n(lambda s: s.modules['os'].remove('/home/me/.zshrc'))(sys)\"",
                Rule::Unknown,
            ),
            (
                r#"python3 -c "(lambda o: o.remove('/home/me/.zshrc'))(__import__('os'))""#,
                Rule::Unknown,
            ),
            (
                "python3 -c \"import operator, shutil; operator.methodcaller('rmtree','/home/me')(shutil)\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"import shutil\nfor m in [shutil]: m.rmtree('/home/me')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"import shutil; [shutil][0].rmtree('/home/me')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"import shutil; d = {'m': shutil}; d['m'].rmtree('/home/me')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"import shutil; t = shutil, 1; t[0].rmtree('/home/me')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"import shutil; m = shutil if x else None; m.rmtree('/home/me')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"import shutil; list(map(getattr(shutil, 'rmtree'), ['/home/me']))\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"import sys; sys.modules.get('os').remove('/home/me/.zshrc')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"import os\ndef f(s): s.modules['os'].remove('/home/me/.zshrc')\nf(os.sys)\"",
                Rule::Unknown,
            ),
            // A module another one imported, under the name it imported it by.
            (
                "python3 -c \"import tempfile; tempfile._os.remove('/home/me/.zshrc')\"",
                Rule::Delete,
            ),
            (
                "python3 -c \"import glob; glob.os.remove('/home/me/.zshrc')\"",
                Rule::Delete,
            ),
            // A chain of names is followed to the end.
            (
                "python3 -c \"import os; a = b = os; a.remove('/home/me/.zshrc')\"",
                Rule::Delete,
            ),
            (
                r#"node -e "(f => f.rmSync('/home/me',{recursive:true}))(require('fs'))""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "Reflect.get(require('fs'),'rmSync')('/home/me',{recursive:true})""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "Object.values(require('child_process'))[0]('rm -rf ~')""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "Object.assign(globalThis, require('fs')); rmSync('/home/me',{recursive:true})""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "const d = {f: require('fs')}; d.f.rmSync('/home/me',{recursive:true})""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "const fs = require('fs'); const o = {fs}; o.fs.rmSync('/home/me',{recursive:true})""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "[require('fs')].forEach(f => f.rmSync('/home/me',{recursive:true}))""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "for (const f of [require('fs')]) f.rmSync('/home/me',{recursive:true})""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "(r => r('fs').rmSync('/home/me',{recursive:true}))(require)""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "(f => f.rmSync('/home/me',{recursive:true}))(process.mainModule)""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "(m => m.require('fs').rmSync('/home/me'))(module)""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "const f = x => x.rmSync('/home/me',{recursive:true}); f(require('fs'))""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "module.exports = require('fs')""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "require('module')._load('fs').rmSync('/home/me',{recursive:true})""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "const fs = (0, require)('fs'); fs.rmSync('/home/me')""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "(async () => (f => f.rmSync('/home/me'))(await import('fs')))()""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "const a = b = require('fs'); a.rmSync('/home/me',{recursive:true})""#,
                Rule::Delete,
            ),
            (
                r#"node -e "const r = require; r('fs').rmSync('/home/me',{recursive:true})""#,
                Rule::Delete,
            ),
        ],
    );
}

#[test]
fn a_with_statement_and_a_destructuring_with_a_rest_are_unread() {
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[
            (
                r#"node -e "with (require('fs')) rmSync('/home/me',{recursive:true})""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "const fs = require('fs'); with (fs) { rmSync('/home/me') }""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "const {...f} = require('fs'); f.rmSync('/home/me',{recursive:true})""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "const {rmSync, ...f} = require('fs'); f.unlinkSync('/home/me')""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "const {promises: {...p}} = require('fs'); p.rm('/home/me')""#,
                Rule::Unknown,
            ),
            // A default for a member that is not there still names the member.
            (
                r#"node -e "const {rmSync = null} = require('fs'); rmSync('/home/me',{recursive:true})""#,
                Rule::Delete,
            ),
            (
                r#"node -e "const {rmSync: r = null} = require('fs'); r('/home/me',{recursive:true})""#,
                Rule::Delete,
            ),
            (
                r#"node -e "const {promises: {rm = null}} = require('fs'); rm('/home/me')""#,
                Rule::Delete,
            ),
        ],
    );
}

#[test]
fn the_options_of_a_call_that_starts_a_program_are_read() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "python3 -c \"import subprocess; subprocess.run(['ls'], cwd='/home/me')\"",
            "python3 -c \"import subprocess; subprocess.run(['cargo', 'build'], cwd='sub')\"",
            "python3 -c \"import subprocess; subprocess.run(['rm', '-rf', 'build'], cwd='/home/me/work/repo')\"",
            "python3 -c \"import subprocess; subprocess.run(['rm', '-rf', 'build'], cwd=None)\"",
            "python3 -c \"import subprocess; subprocess.run('cargo test', shell=True, cwd='sub')\"",
            "python3 -c \"import subprocess; subprocess.run(['x', '/tmp'], executable='/bin/ls')\"",
            "python3 -c \"import os, subprocess; subprocess.run(['ls'], cwd=os.getcwd())\"",
            "node -e \"require('child_process').execSync('ls', {cwd: '/home/me'})\"",
            "node -e \"require('child_process').execSync('npm test', {cwd: 'sub'})\"",
            "node -e \"require('child_process').execSync('npm test', {cwd: undefined})\"",
            "node -e \"require('child_process').execSync('echo hi', {shell: '/bin/bash'})\"",
            "node -e \"require('child_process').execSync('echo hi', {shell: true})\"",
            "node -e \"require('child_process').spawnSync('git', ['status'], {cwd: 'sub'})\"",
            "node -e \"require('child_process').execFile('ls', ['a'], (e) => {})\"",
            "node -e \"require('child_process').exec('ls', (e) => {})\"",
            "bun -e 'Bun.spawnSync([\"ls\"], {cwd: \"/home/me\"})'",
        ],
        &[
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
        ],
    );
}

#[test]
fn bun_cwd_moves_the_code_first() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "bun --cwd=sub -e 'require(\"fs\").rmSync(\"x\")'",
            "bun --cwd sub -e 'require(\"fs\").rmSync(\"x\")'",
            "bun --cwd=/home/me/work/repo -e 'require(\"fs\").rmSync(\"x\")'",
        ],
        &[
            (
                r#"bun --cwd=/home/me -e "require('fs').rmSync('x',{recursive:true})""#,
                Rule::Delete,
            ),
            (
                r#"bun --cwd /home/me -e "require('fs').rmSync('x',{recursive:true})""#,
                Rule::Delete,
            ),
            (
                r#"bun -e "require('fs').rmSync('x',{recursive:true})" --cwd=/home/me"#,
                Rule::Delete,
            ),
            (
                "bun --cwd \"$DIR\" -e 'require(\"fs\").rmSync(\"x\")'",
                Rule::Unknown,
            ),
        ],
    );
}

#[test]
fn the_exec_statement_of_python_2_is_read() {
    check(
        Shell::Posix,
        &posix(),
        &["python2 -c 'exec \"print 1\"'"],
        &[
            (
                r#"python2 -c 'exec "import os; os.remove(\"/home/me/.zshrc\")"'"#,
                Rule::Delete,
            ),
            (
                r#"python2 -c "exec \"import os; os.remove('/home/me/.zshrc')\" in {}""#,
                Rule::Delete,
            ),
            (
                r#"python2 -c "exec 'import os; os.remove(\"/home/me/.zshrc\")'""#,
                Rule::Delete,
            ),
            ("python2 -c 'exec x'", Rule::Unknown),
            ("python2 -c 'exec x in {}'", Rule::Unknown),
        ],
    );
}

#[test]
fn path_rename_and_replace_take_a_target_keyword() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "python3 -c \"from pathlib import Path; Path('a').rename(target='b')\"",
            "python3 -c \"from pathlib import Path; Path('a').replace(target='b')\"",
            "python3 -c \"print('abc'.replace('a', 'b'))\"",
            "python3 -c \"print('abc'.replace(*args))\"",
            "python3 -c \"print(s.replace('a', 'b'))\"",
        ],
        &[
            (
                "python3 -c \"from pathlib import Path; Path('/tmp/x').replace(target='/home/me/.zshrc')\"",
                Rule::Overwrite,
            ),
            (
                "python3 -c \"from pathlib import Path; Path('/tmp/x').rename(target='/home/me/.zshrc')\"",
                Rule::Overwrite,
            ),
            (
                "python3 -c \"from pathlib import Path; Path('/tmp/x').replace('/home/me/.zshrc')\"",
                Rule::Overwrite,
            ),
            (
                "python3 -c \"from pathlib import Path; Path('/tmp/x').replace(*args)\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"from pathlib import Path; Path('/tmp/x').rename(**kw)\"",
                Rule::Unknown,
            ),
        ],
    );
}

#[test]
fn bun_and_deno_reading_code_from_their_input_are_read_or_unknown() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "deno run main.ts",
            "deno run --allow-read main.ts",
            "deno test",
            "bun run build.ts",
            "bun install",
            "bun main.ts",
            "bun - <<'JS'\nconsole.log(1)\nJS",
            "bun run - <<'JS'\nconsole.log(1)\nJS",
            "deno run - <<'JS'\nconsole.log(1)\nJS",
            "bun - <<JS\nconsole.log(1)\nJS",
        ],
        &[
            (
                "deno run - <<'JS'\nDeno.removeSync('/home/me', {recursive: true})\nJS",
                Rule::Delete,
            ),
            (
                "bun - <<'JS'\nrequire('fs').rmSync('/home/me', {recursive: true})\nJS",
                Rule::Delete,
            ),
            (
                "bun run - <<'JS'\nrequire('fs').rmSync('/home/me', {recursive: true})\nJS",
                Rule::Delete,
            ),
            (
                "deno run --allow-all - <<'JS'\nDeno.removeSync('/home/me', {recursive: true})\nJS",
                Rule::Delete,
            ),
            (
                "echo \"Deno.removeSync('/home/me', {recursive: true})\" | deno run -",
                Rule::Unknown,
            ),
            (
                "echo \"require('fs').rmSync('/home/me')\" | bun -",
                Rule::Unknown,
            ),
            ("echo 'x' | bun run -", Rule::Unknown),
            ("deno run - < script.js", Rule::Unknown),
            ("bun - < script.js", Rule::Unknown),
            ("deno repl", Rule::Unknown),
            ("echo 'x' | deno", Rule::Unknown),
            ("echo 'x' | bun repl", Rule::Unknown),
            ("deno run - <<'JS'\nDeno.removeSync(\nJS", Rule::Unknown),
            ("deno run - <<JS\nDeno.removeSync('$X')\nJS", Rule::Unknown),
        ],
    );
}

#[test]
fn inline_code_is_never_reads_only() {
    // Inline code is read to judge what it does to files, and `effect` does
    // not call it reads-only: the interpreter is not one of its readers, and
    // what the code does is a unit of its own that changes things.
    check_effect(
        Shell::Posix,
        &posix(),
        Effect::Unknown,
        &[
            "python3 -c 'print(1)'",
            "node -e 'console.log(1)'",
            "node -e 1 -e 2",
            "deno eval 'console.log(1)'",
            "python3 -c \"import subprocess; subprocess.run(['ls'], cwd='sub')\"",
        ],
    );
    check_effect(
        Shell::Posix,
        &posix(),
        Effect::Changes,
        &[
            "python3 -c \"import os; os.remove('x')\"",
            "node -e \"require('fs').rmSync('x')\"",
            "node -e 1 -e \"require('fs').rmSync('x')\"",
            "python3 -c \"import subprocess; subprocess.run(['rm', 'x'], cwd='sub')\"",
            "bun --cwd=sub -e \"require('fs').rmSync('x')\"",
            // `bun` is a package manager, which changes things.
            "bun - <<'JS'\nconsole.log(1)\nJS",
        ],
    );
}

// The review of the second pass: each line below was `unknown` before the
// second pass's reader and read as safe after it.

#[test]
fn javascript_follows_every_way_to_a_module() {
    check(
        Shell::Posix,
        &posix(),
        &[
            // The same ways, for modules that do nothing harmful.
            r#"node -e 'this.require("path").join("a", "b")'"#,
            r#"node -e 'require.call(null, "path").join("a", "b")'"#,
            r#"node -e 'process.getBuiltinModule("fs").readFileSync("x")'"#,
            r#"node -e 'import * as ns from "fs"; ns.default.readFileSync("x")'"#,
            r#"node -e 'globalThis["require"]("fs").readFileSync("x")'"#,
            r#"node -e 'this.require("fs").rmSync("dist", {recursive: true})'"#,
            r#"node -e 'require.call(null, "fs").rmSync("dist")'"#,
            r#"node -e 'process.getBuiltinModule("fs").rmSync("dist")'"#,
            r#"bun -e 'import.meta.require("fs").rmSync("dist")'"#,
            r#"node -e 'import * as ns from "fs"; ns.default.rmSync("dist")'"#,
            // `this` of a class and the names of a program are not the global
            // object's lookups.
            r"node -e 'class A { set(k, v) { this[k] = v; return this.x; } }'",
            r"node -e 'console.log(typeof window, this.x)'",
        ],
        &[
            // `this` is the global object in `node -e`.
            (
                r#"node -e 'this.require("fs").rmSync("/home/me", {recursive: true})'"#,
                Rule::Delete,
            ),
            (
                r#"node -e 'this.eval("require(\"fs\").rmSync(\"/home/me\",{recursive:true})")'"#,
                Rule::Delete,
            ),
            (
                r#"node -e 'this["eval"]("require(\"fs\").rmSync(\"/home/me\",{recursive:true})")'"#,
                Rule::Delete,
            ),
            (
                r#"node -e 'globalThis["require"]("fs").rmSync("/home/me", {recursive: true})'"#,
                Rule::Delete,
            ),
            (
                r#"node -e 'globalThis["eval"]("require(\"fs\").rmSync(\"/home/me\",{recursive:true})")'"#,
                Rule::Delete,
            ),
            (
                r#"node -e 'global.global.require("fs").rmSync("/home/me", {recursive: true})'"#,
                Rule::Delete,
            ),
            (
                r#"node -e 'globalThis.globalThis.require("fs").rmSync("/home/me", {recursive: true})'"#,
                Rule::Delete,
            ),
            (
                r#"node -e 'const g = globalThis; g.require("fs").rmSync("/home/me")'"#,
                Rule::Delete,
            ),
            // `require` through `call`, `apply` and `bind`.
            (
                r#"node -e 'require.call(null, "fs").rmSync("/home/me", {recursive: true})'"#,
                Rule::Delete,
            ),
            (
                r#"node -e 'require.apply(null, ["fs"]).rmSync("/home/me", {recursive: true})'"#,
                Rule::Delete,
            ),
            (
                r#"node -e 'require.bind(null)("fs").rmSync("/home/me", {recursive: true})'"#,
                Rule::Delete,
            ),
            (
                r#"node -e 'const r = require.bind(null); r("fs").rmSync("/home/me")'"#,
                Rule::Delete,
            ),
            (
                r#"node -e 'require.call(null, "child_process").execSync("rm -rf ~")'"#,
                Rule::Delete,
            ),
            ("node -e 'require.call(null, name)'", Rule::Unknown),
            ("node -e 'require.apply(null, args)'", Rule::Unknown),
            ("node -e 'require.call(null, ...args)'", Rule::Unknown),
            // `process.getBuiltinModule`.
            (
                r#"node -e 'process.getBuiltinModule("fs").rmSync("/home/me", {recursive: true})'"#,
                Rule::Delete,
            ),
            (
                r#"node -e 'require("process").getBuiltinModule("fs").rmSync("/home/me")'"#,
                Rule::Delete,
            ),
            (
                r#"node -e 'const { getBuiltinModule } = process; getBuiltinModule("fs").rmSync("/home/me")'"#,
                Rule::Delete,
            ),
            (
                r#"node -e 'const { rmSync } = process.getBuiltinModule("fs"); rmSync("/home/me")'"#,
                Rule::Delete,
            ),
            (
                r#"node -e 'const get = process.getBuiltinModule; get("child_process").execSync("rm -rf ~")'"#,
                Rule::Delete,
            ),
            ("node -e 'process.getBuiltinModule(name)'", Rule::Unknown),
            ("node -e 'f(process.getBuiltinModule)'", Rule::Unknown),
            // Bun's `import.meta.require`.
            (
                r#"bun -e 'import.meta.require("fs").rmSync("/home/me", {recursive: true})'"#,
                Rule::Delete,
            ),
            ("bun -e 'import.meta.require(name)'", Rule::Unknown),
            ("bun -e 'f(import.meta.require)'", Rule::Unknown),
            // The default export of a namespace is the module.
            (
                r#"node -e 'import * as ns from "fs"; ns.default.rmSync("/home/me", {recursive: true})'"#,
                Rule::Delete,
            ),
            (
                r#"node -e 'import { default as f } from "node:fs"; f.rmSync("/home/me")'"#,
                Rule::Delete,
            ),
            (
                r#"node -e 'import * as ns from "fs"; const { default: f } = ns; f.rmSync("/home/me")'"#,
                Rule::Delete,
            ),
            (
                r#"node -e 'import * as ns from "child_process"; ns.default.execSync("rm -rf ~")'"#,
                Rule::Delete,
            ),
            // A method only the file system has, on an object the reader cannot
            // name, is a call it cannot follow.
            ("node -e 'make().rmSync(\"/home/me\")'", Rule::Unknown),
            ("node -e 'x.rmdirSync(\"/home/me\")'", Rule::Unknown),
            ("node -e 'x.unlinkSync(\"/home/me/.zshrc\")'", Rule::Unknown),
            (
                "node -e 'x.writeFileSync(\"/home/me/.zshrc\", \"\")'",
                Rule::Unknown,
            ),
            (
                "node -e 'x.appendFileSync(\"/home/me/.zshrc\", \"\")'",
                Rule::Unknown,
            ),
            ("node -e 'x.execSync(\"rm -rf ~\")'", Rule::Unknown),
            (
                "node -e 'x.execFileSync(\"rm\", [\"-rf\", \"~\"])'",
                Rule::Unknown,
            ),
            (
                "node -e 'x.spawnSync(\"rm\", [\"-rf\", \"~\"])'",
                Rule::Unknown,
            ),
            ("node -e 'x[\"rmSync\"](\"/home/me\")'", Rule::Unknown),
            ("node -e 'this.rmSync(\"/home/me\")'", Rule::Unknown),
            (
                "node -e 'const r = x.rmSync; r(\"/home/me\")'",
                Rule::Unknown,
            ),
            (
                "node -e 'const { rmSync } = x; rmSync(\"/home/me\")'",
                Rule::Unknown,
            ),
        ],
    );
}

#[test]
fn python_library_calls_that_run_code_are_read_or_unknown() {
    check(
        Shell::Posix,
        &posix(),
        &[
            // A callable is walked where it is written, a literal is read.
            r"python3 -c 'import timeit; timeit.timeit(lambda: sum(range(10)), number=1)'",
            r#"python3 -c 'import timeit; timeit.timeit("sum(range(10))", number=1)'"#,
            r#"python3 -c 'import timeit; timeit.timeit("x = 1", setup="import os")'"#,
            r#"python3 -c 'import timeit; timeit.repeat("x = 1", repeat=2)'"#,
            r#"python3 -c 'import timeit; timeit.Timer("x = 1")'"#,
            r#"python3 -c 'import cProfile; cProfile.run("sum(range(10))")'"#,
            r#"python3 -c 'import profile; profile.run("sum(range(10))")'"#,
            r#"python3 -c 'import json; json.loads("{}")'"#,
        ],
        &[
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
        ],
    );
}

#[test]
fn file_calls_that_were_not_listed() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "python3 -c \"import io; io.FileIO('/home/me/.zshrc')\"",
            "python3 -c \"import io; io.FileIO('/home/me/.zshrc', 'r')\"",
            "python3 -c \"import io; io.FileIO('out.txt', 'w')\"",
            "bun -e \"Bun.file('dist/x').unlink()\"",
            "bun -e \"Bun.file('/home/me/.zshrc').text()\"",
        ],
        &[
            (
                "python3 -c \"import io; io.FileIO('/home/me/.zshrc', 'w')\"",
                Rule::Overwrite,
            ),
            (
                "python3 -c \"import io; io.FileIO('/home/me/.zshrc', mode='a')\"",
                Rule::Overwrite,
            ),
            (
                "python3 -c \"from io import FileIO; FileIO('/home/me/.zshrc', 'w')\"",
                Rule::Overwrite,
            ),
            (
                "python3 -c \"import _io; _io.FileIO('/home/me/.zshrc', 'wb')\"",
                Rule::Overwrite,
            ),
            (
                "bun -e \"Bun.file('/home/me/.zshrc').unlink()\"",
                Rule::Delete,
            ),
            (
                "bun -e \"await Bun.file('/home/me/.zshrc').unlink()\"",
                Rule::Delete,
            ),
        ],
    );
}

#[test]
fn python_changes_directory_in_other_ways() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "python3 -c \"import os, shutil; os.chdir('/tmp'); shutil.rmtree('x')\"",
            "python3 -c \"import os; os.unlink('x.log')\"",
            "python3 -c \"import os; os.open('x.txt', os.O_RDONLY, dir_fd=3)\"",
            "python3 -c \"import os; os.scandir('.')\"",
        ],
        &[
            // `os.fchdir` goes to a directory only known when it runs.
            (
                "python3 -c \"import os, shutil; os.fchdir(os.open('/home/me', os.O_RDONLY)); shutil.rmtree('.ssh')\"",
                Rule::Delete,
            ),
            (
                "python3 -c \"import os, shutil; os.fchdir(fd); shutil.rmtree('.ssh')\"",
                Rule::Delete,
            ),
            (
                "python3 -c \"import os; os.chdir(os.open('/home/me', os.O_RDONLY)); os.remove('.zshrc')\"",
                Rule::Delete,
            ),
            // `contextlib.chdir(D)` is a `chdir` to `D`.
            (
                "python3 -c \"import contextlib, os, shutil\nwith contextlib.chdir(os.path.expanduser('~')): shutil.rmtree('.ssh')\"",
                Rule::Delete,
            ),
            (
                "python3 -c \"import contextlib, shutil\nwith contextlib.chdir('/home/me'): shutil.rmtree('.ssh')\"",
                Rule::Delete,
            ),
            (
                "python3 -c \"from contextlib import chdir; import os\nwith chdir('/home/me'):\n    os.remove('.zshrc')\"",
                Rule::Delete,
            ),
            // A path counted from a directory handle is only known when it runs.
            (
                "python3 -c \"import os; os.unlink('.zshrc', dir_fd=os.open('/home/me', os.O_RDONLY))\"",
                Rule::Delete,
            ),
            (
                "python3 -c \"import os; os.remove('.zshrc', dir_fd=fd)\"",
                Rule::Delete,
            ),
            (
                "python3 -c \"import os; os.rmdir('.ssh', dir_fd=os.open('/home/me', os.O_RDONLY))\"",
                Rule::Delete,
            ),
            (
                "python3 -c \"import os; os.open('.zshrc', os.O_WRONLY | os.O_TRUNC, dir_fd=os.open('/home/me', os.O_RDONLY))\"",
                Rule::Overwrite,
            ),
            (
                "python3 -c \"import shutil; shutil.rmtree('.ssh', dir_fd=fd)\"",
                Rule::Delete,
            ),
            (
                "python3 -c \"import os; os.rename('a', 'b', src_dir_fd=fd)\"",
                Rule::Delete,
            ),
            (
                "python3 -c \"import os; os.rename('a', 'b', dst_dir_fd=fd)\"",
                Rule::Delete,
            ),
            (
                "python3 -c \"import os; os.mkdir('.ssh', dir_fd=fd)\"",
                Rule::Overwrite,
            ),
        ],
    );
}

#[test]
fn a_chdir_is_not_where_the_code_sits() {
    check(
        Shell::Posix,
        &posix(),
        &[
            // An absolute folder that is no harm, a folder below the start, or
            // a path that is the same in both.
            "python3 -c \"import os, shutil; os.chdir('/tmp'); shutil.rmtree('x')\"",
            "python3 -c \"import os, shutil; os.chdir('sub'); shutil.rmtree('x')\"",
            "python3 -c \"import os, shutil; os.chdir('sub'); os.chdir('deeper'); shutil.rmtree('x')\"",
            "python3 -c \"import os, shutil\ndef g(): shutil.rmtree('x')\nos.chdir('/tmp')\ng()\"",
            "python3 -c \"import os, shutil; shutil.rmtree('/tmp/x'); os.chdir('/home/me')\"",
            "node -e \"process.chdir('/tmp'); require('fs').rmSync('x')\"",
            "node -e \"const fs = require('fs'); function g() { fs.rmSync('x'); } process.chdir('sub'); g()\"",
        ],
        &[
            // A function defined before the `chdir` and called after it.
            (
                "python3 -c \"import os, shutil\ndef g(): shutil.rmtree('.ssh')\nos.chdir('/home/me')\ng()\"",
                Rule::Delete,
            ),
            // A later pass of a loop, after the first pass's `chdir`.
            (
                "python3 -c \"import os, shutil\nfor i in range(2):\n    shutil.rmtree('.ssh')\n    os.chdir('/home/me')\"",
                Rule::Delete,
            ),
            // Something registered to run when the code ends.
            (
                "python3 -c \"import atexit, os, shutil; atexit.register(lambda: shutil.rmtree('.ssh')); os.chdir('/home/me')\"",
                Rule::Delete,
            ),
            // The `chdir` first, as before.
            (
                "python3 -c \"import os, shutil; os.chdir('/home/me'); shutil.rmtree('.ssh')\"",
                Rule::Delete,
            ),
            // Where it goes when it is `..`, mixed, or only known when it runs.
            (
                "python3 -c \"import os, shutil\ndef g(): shutil.rmtree('.ssh')\nos.chdir('..')\ng()\"",
                Rule::Delete,
            ),
            (
                "python3 -c \"import os, shutil\ndef g(): shutil.rmtree('.ssh')\nos.chdir('/home')\nos.chdir('me')\ng()\"",
                Rule::Delete,
            ),
            (
                "python3 -c \"import os, shutil\ndef g(): shutil.rmtree('.ssh')\nos.chdir(d)\ng()\"",
                Rule::Delete,
            ),
            // Code that is run from a string has its own `chdir`.
            (
                "python3 -c \"import os, shutil\nexec('import os; os.chdir(\\\"/home/me\\\")')\nshutil.rmtree('.ssh')\"",
                Rule::Delete,
            ),
            // The same for JavaScript.
            (
                "node -e \"const fs = require('fs'); function g() { fs.rmSync('.ssh', {recursive: true}); } process.chdir('/home/me'); g()\"",
                Rule::Delete,
            ),
            (
                "node -e \"const fs = require('fs'); setTimeout(() => fs.rmSync('.ssh', {recursive: true}), 0); process.chdir('/home/me')\"",
                Rule::Delete,
            ),
            (
                "node -e \"const fs = require('fs'); for (const i of [1, 2]) { fs.rmSync('.ssh', {recursive: true}); process.chdir('/home/me'); }\"",
                Rule::Delete,
            ),
            (
                "bun -e \"const fs = require('fs'); function g() { fs.rmSync('.ssh', {recursive: true}); } process.chdir('/home/me'); g()\"",
                Rule::Delete,
            ),
            (
                "deno eval \"function g() { Deno.removeSync('.ssh', {recursive: true}); } Deno.chdir('/home/me'); g()\"",
                Rule::Delete,
            ),
        ],
    );
}

#[test]
fn escapes_the_reader_does_not_decode_are_only_known_when_the_code_runs() {
    check(
        Shell::Posix,
        &posix(),
        &[
            // What is decoded is the character it stands for.
            "python3 -c \"import shutil; shutil.rmtree('dist\\x2fx')\"",
            "python3 -c \"print('\\N{BULLET}')\"",
            "node -e \"require('fs').rmSync('dist\\57x')\"",
            "node -e \"require('fs').rmSync('\\144ist')\"",
            "node -e \"require('fs').rmSync('\\400')\"",
            "node -e \"console.log('\\57', '\\0')\"",
            "node -e \"require('fs').rmSync('\\x64ist')\"",
        ],
        &[
            // Python's `\N{NAME}`.
            (
                "python3 -c \"import shutil; shutil.rmtree('\\N{SOLIDUS}home\\N{SOLIDUS}me')\"",
                Rule::Delete,
            ),
            (
                "python3 -c \"import os; os.system('rm -rf \\N{TILDE}')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"import shutil; shutil.rmtree('\\N{LATIN SMALL LETTER E}')\"",
                Rule::Delete,
            ),
            (
                "python3 -c \"import shutil; shutil.rmtree('\\x')\"",
                Rule::Delete,
            ),
            // JavaScript's legacy octal escapes, which `node -e` reads.
            (
                "node -e \"require('fs').rmSync('\\57home\\57me', {recursive: true})\"",
                Rule::Delete,
            ),
            (
                "node -e \"require('fs').rmSync('\\176', {recursive: true})\"",
                Rule::Delete,
            ),
            (
                "node -e \"require('fs').rmSync('\\176/.ssh', {recursive: true})\"",
                Rule::Delete,
            ),
            (
                "node -e \"require('child_process').execSync('rm -rf \\176')\"",
                Rule::Delete,
            ),
            (
                "node -e \"require('fs').rmSync('\\057home\\057me')\"",
                Rule::Delete,
            ),
            // One it does not decode.
            ("node -e \"require('fs').rmSync('\\ud83d')\"", Rule::Delete),
            (
                "node -e \"require('child_process').execSync('rm -rf \\u{110000}')\"",
                Rule::Unknown,
            ),
        ],
    );
}

#[test]
fn code_handed_to_an_interpreter_on_windows_is_unknown() {
    // Its paths and commands are not POSIX ones, so it is not read: under
    // cmd as under PowerShell.
    for shell in [Shell::Cmd, Shell::PowerShell] {
        check(
            shell,
            &windows(),
            &[
                "python build.py",
                "node build.js",
                "bun run build.ts",
                "deno test",
            ],
            &[
                (
                    r#"python -c "import shutil; shutil.rmtree('C:/Users/me')""#,
                    Rule::Unknown,
                ),
                (r#"python3 -c "print(1)""#, Rule::Unknown),
                (
                    r#"node -e "require('fs').rmSync('C:/Users/me', {recursive: true})""#,
                    Rule::Unknown,
                ),
                (r#"bun -e "console.log(1)""#, Rule::Unknown),
                (r#"deno eval "console.log(1)""#, Rule::Unknown),
            ],
        );
    }
}

#[test]
fn python_names_are_read_in_their_nfkc_form_so_a_name_that_is_not_ascii_is_unread() {
    // Python reads `ｒｅｍｏｖｅ` (full-width) as `remove`: each of these runs
    // the call it spells, and is not one the reader follows.
    check(
        Shell::Posix,
        &posix(),
        &[
            // A string or a comment that is not ASCII is only text.
            "python3 -c \"print('ｒｅｍｏｖｅ')\"",
            "python3 -c \"print('é')  # ｒｅｍｏｖｅ\"",
            "python3 -c \"import os; print(os.getcwd(), 'ｅｘｅｃ')\"",
        ],
        &[
            (
                "python3 -c \"import os; os.ｒｅｍｏｖｅ('/home/me/.zshrc')\"",
                Rule::Unknown,
            ),
            ("python3 -c \"ｅｘｅｃ(input())\"", Rule::Unknown),
            (
                "python3 -c \"import ｓｈｕｔｉｌ; ｓｈｕｔｉｌ.rmtree('/home/me')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"__ｉｍｐｏｒｔ__('os').remove('/home/me/.zshrc')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"ｏｐｅｎ('/home/me/.zshrc','w').write('x')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"import os; os.ｃｈｄｉｒ('/home/me'); import shutil; shutil.rmtree('.ssh')\"",
                Rule::Unknown,
            ),
            // Also a keyword argument's name, an alias and a method.
            (
                "python3 -c \"import os; os.remove('/home/me/.zshrc', ｄｉｒ_ｆｄ=1)\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"from os import remove as ｒ; ｒ('/home/me/.zshrc')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"from pathlib import Path; Path('/home/me/.zshrc').ｕｎｌｉｎｋ()\"",
                Rule::Unknown,
            ),
        ],
    );
}

#[test]
fn javascript_names_written_with_an_escape_are_unread() {
    // Node reads `\u0072mSync` as `rmSync`.
    check(
        Shell::Posix,
        &posix(),
        &[
            // An escape in a string is decoded, and reads as it always did.
            r#"node -e "console.log('\u0072mSync')""#,
            r#"node -e "console.log(require('fs').readFileSync('\u002fetc/hosts', 'utf8'))""#,
            r#"node -e "const o = {a: 1}; console.log(o.a)""#,
        ],
        &[
            (
                r#"node -e "require('fs').\u0072mSync('/home/me',{recursive:true})""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "const {\u0072mSync}=require('fs'); \u0072mSync('/home/me',{recursive:true})""#,
                Rule::Unknown,
            ),
            (r#"node -e "\u0065val(process.argv[1])""#, Rule::Unknown),
            (
                r#"node -e "require('child_process').e\u0078ecSync('rm -rf ~')""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "const cp=require('child_process'); cp.\u{65}xecSync('rm -rf ~')""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "process.\u0063hdir('/home/me'); require('fs').rmSync('.ssh',{recursive:true})""#,
                Rule::Unknown,
            ),
            // A shorthand property, a pattern with a rename and a local name.
            (
                r#"node -e "const {rmSync: \u0072}=require('fs'); r('/home/me',{recursive:true})""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "const \u0066s=require('fs'); fs.rmSync('/home/me',{recursive:true})""#,
                Rule::Unknown,
            ),
        ],
    );
}

#[test]
fn code_in_a_data_url_is_not_read() {
    check(
        Shell::Posix,
        &posix(),
        &[
            // Modules that are not a `data:` URL are as they were.
            r#"node -e "import fs from 'fs'; fs.readFileSync('package.json')""#,
            r#"node -e "import {a} from './a.js'""#,
            r#"node -e "export * from './a.js'""#,
            "node --import ./setup.js -e 1",
            "node --import=./setup.js -e 1",
            "node --loader ./hooks.js -e 1",
            "node --experimental-loader=./hooks.js -e 1",
            "node --import ./setup.js build.js",
        ],
        &[
            (
                r#"node -e "import 'data:text/javascript,import fs from \"fs\"; fs.rmSync(\"/home/me\",{recursive:true})'""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "import {a} from 'data:text/javascript,export const a=1'""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "export * from 'data:text/javascript,console.log(45)'""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "export {a} from 'data:text/javascript,export const a=1'""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "import 'data:text/javascript;base64,Y29uc29sZS5sb2coNDYp'""#,
                Rule::Unknown,
            ),
            // The URL parser drops leading spaces and reads the scheme in
            // any case.
            (
                r#"node -e "import ' DATA:text/javascript,1'""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "import('data:text/javascript,1')""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "(async () => { await import('data:text/javascript,1') })()""#,
                Rule::Unknown,
            ),
            ("node --import data:text/javascript,1 -e 1", Rule::Unknown),
            ("node --import=data:text/javascript,1 -e 1", Rule::Unknown),
            ("node --loader data:text/javascript,1 -e 1", Rule::Unknown),
            ("node --loader=data:text/javascript,1 -e 1", Rule::Unknown),
            (
                "node --experimental-loader data:text/javascript,1 -e 1",
                Rule::Unknown,
            ),
            (
                "node --experimental-loader=data:text/javascript,1 -e 1",
                Rule::Unknown,
            ),
            ("node -e 1 --import data:text/javascript,1", Rule::Unknown),
            (
                "node --import data:text/javascript,1 build.js",
                Rule::Unknown,
            ),
            // A module only known when it runs may be one.
            ("node --import $LOADER -e 1", Rule::Unknown),
        ],
    );
}

#[test]
fn a_chdir_in_nested_code_is_read_not_searched_for() {
    check(
        Shell::Posix,
        &posix(),
        &[
            // Nested code that never changes directory moves nothing.
            "python3 -c \"exec('print(1)')\"",
            "python3 -c \"import shutil; exec('import os; os.getcwd()'); print(shutil.which('ls'))\"",
            "node -e \"eval('1+1'); console.log(process.cwd())\"",
            // The word in a string is not a call.
            "python3 -c \"exec('print(\\\"chdir\\\")')\"",
        ],
        &[
            (
                r#"python3 -c "import shutil; exec(\"import os; getattr(os,'ch'+'dir')('/home/me')\"); shutil.rmtree('.ssh')""#,
                Rule::Delete,
            ),
            (
                r#"node -e "eval(\"process[\`ch\${'dir'}\`]('/home/me')\"); require('fs').rmSync('.ssh',{recursive:true})""#,
                Rule::Delete,
            ),
            // At any depth.
            (
                r#"python3 -c "import shutil; exec(\"exec(\\\"import os; getattr(os,'ch'+'dir')('/home/me')\\\")\"); shutil.rmtree('.ssh')""#,
                Rule::Delete,
            ),
            // Nested code the reader cannot read may change directory.
            (
                r#"python3 -c "import shutil; exec(\"import os; f = getattr(os, input()); f('/home/me')\"); shutil.rmtree('.ssh')""#,
                Rule::Unknown,
            ),
            // The nested code is in the other language's own terms.
            (
                r#"node -e "eval(\"process.chdir('/home/me')\"); require('fs').rmSync('.ssh',{recursive:true})""#,
                Rule::Delete,
            ),
        ],
    );
}

#[test]
fn a_module_bound_in_a_class_body_is_unread() {
    check(
        Shell::Posix,
        &posix(),
        &[
            // A class that binds nothing the reader looks for.
            "python3 -c \"class C:\n    x = 1\n    def f(self):\n        return self.x\nprint(C().f())\"",
            "python3 -c \"import os\nclass C:\n    def f(self):\n        return os.getcwd()\nprint(C().f())\"",
            "python3 -c \"class C:\n    name = 'os'\nprint(C.name)\"",
            // A name bound in a method is the method's own.
            "python3 -c \"class C:\n    def f(self):\n        o = 1\n        return o\nprint(C().f())\"",
        ],
        &[
            (
                "python3 -c \"import os\nclass C: o = os\nC.o.remove('/home/me/.zshrc')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"import os\nclass C: o = os\nC().o.system('rm -rf ~')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"class C:\n    from os import system\nC.system('rm -rf ~')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"class C:\n    import shutil as s\nC().s.rmtree('/home/me')\"",
                Rule::Unknown,
            ),
            // A call the reader knows, bound the same way.
            (
                "python3 -c \"import os\nclass C:\n    r = os.remove\nC.r('/home/me/.zshrc')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"import os\nclass C:\n    r = getattr(os, 'remove')\nC.r('/home/me/.zshrc')\"",
                Rule::Unknown,
            ),
            // A class in a class.
            (
                "python3 -c \"import os\nclass A:\n    class B:\n        o = os\nA.B.o.remove('/home/me/.zshrc')\"",
                Rule::Unknown,
            ),
        ],
    );
}

#[test]
fn reading_a_file_with_a_flag_that_writes_writes_it() {
    // `{flag: 'w'}` opens the file for writing, which truncates it.
    check(
        Shell::Posix,
        &posix(),
        &[
            "node -e \"require('fs').readFileSync('/home/me/.zshrc')\"",
            "node -e \"require('fs').readFileSync('/home/me/.zshrc', 'utf8')\"",
            "node -e \"require('fs').readFileSync('/home/me/.zshrc', {encoding: 'utf8'})\"",
            "node -e \"require('fs').readFileSync('/home/me/.zshrc', {encoding: 'utf8', flag: 'r'})\"",
            "node -e \"require('fs').readFileSync('/home/me/.zshrc', {flag: 'rs'})\"",
            "node -e \"require('fs').readFile('/home/me/.zshrc', 'utf8', (e, d) => console.log(d))\"",
            "node -e \"require('fs').readFile('/home/me/.zshrc', (e, d) => console.log(d))\"",
            "node -e \"require('fs').promises.readFile('/home/me/.zshrc', {flag: 'r'})\"",
            "node -e \"require('fs').createReadStream('/home/me/.zshrc').pipe(process.stdout)\"",
            "node -e \"require('fs').createReadStream('/home/me/.zshrc', {flags: 'r', encoding: 'utf8'})\"",
            "node -e \"require('fs').createReadStream('/home/me/.zshrc', 'utf8')\"",
        ],
        &[
            (
                "node -e \"require('fs').readFileSync('/home/me/.zshrc', {flag:'w'})\"",
                Rule::Overwrite,
            ),
            (
                "node -e \"require('fs').createReadStream('/home/me/.zshrc', {flags:'w'})\"",
                Rule::Overwrite,
            ),
            (
                "node -e \"require('fs').readFile('/home/me/.zshrc', {flag:'w'}, () => 0)\"",
                Rule::Overwrite,
            ),
            (
                "node -e \"require('fs').promises.readFile('/home/me/.zshrc', {flag:'w+'})\"",
                Rule::Overwrite,
            ),
            (
                "node -e \"require('fs').readFileSync('/home/me/.zshrc', {encoding: 'utf8', flag: 'a'})\"",
                Rule::Overwrite,
            ),
            // A flag only known when it runs, a spread, a computed name.
            (
                "node -e \"require('fs').readFileSync('/home/me/.zshrc', {flag: process.argv[1]})\"",
                Rule::Overwrite,
            ),
            (
                "node -e \"require('fs').readFileSync('/home/me/.zshrc', {flag: require('fs').constants.O_WRONLY})\"",
                Rule::Overwrite,
            ),
            (
                "node -e \"require('fs').readFileSync('/home/me/.zshrc', {...process.env})\"",
                Rule::Overwrite,
            ),
            (
                "node -e \"require('fs').readFileSync('/home/me/.zshrc', {['fl'+'ag']: 'w'})\"",
                Rule::Overwrite,
            ),
            (
                "node -e \"const flag = 'w'; require('fs').readFileSync('/home/me/.zshrc', {flag})\"",
                Rule::Overwrite,
            ),
            (
                "node -e \"require('fs').readFileSync('/home/me/.zshrc', process.argv[1])\"",
                Rule::Overwrite,
            ),
            (
                "node -e \"const {readFileSync: r} = require('fs'); r('/home/me/.zshrc', {flag: 'w'})\"",
                Rule::Overwrite,
            ),
        ],
    );
}

#[test]
fn deno_options_that_print_do_not_read_the_input() {
    check(
        Shell::Posix,
        &posix(),
        &["deno --version", "deno -V", "deno --help", "deno -h"],
        &[
            // No subcommand and no such option reads its input.
            ("deno", Rule::Unknown),
            ("deno --unstable", Rule::Unknown),
            ("deno repl", Rule::Unknown),
        ],
    );
}

#[test]
fn fileinput_in_place_rewrites_each_file_as_sed_i_does() {
    check(
        Shell::Posix,
        &posix(),
        &[
            // Only read, or a file of the workspace.
            r#"python3 -c 'import fileinput; [print(l) for l in fileinput.input("/home/me/.zshrc")]'"#,
            r#"python3 -c 'import fileinput; fileinput.input(["/home/me/.zshrc"], False)'"#,
            r#"python3 -c 'import fileinput; fileinput.input("/home/me/.zshrc", inplace=False)'"#,
            r#"python3 -c 'import fileinput; fileinput.FileInput("/home/me/.zshrc", inplace=0)'"#,
            r#"python3 -c 'import fileinput; fileinput.input("notes.txt", inplace=True)'"#,
            r#"python3 -c 'import fileinput; fileinput.input(files=["a.txt", "b.txt"], inplace=1)'"#,
        ],
        &[
            (
                r#"python3 -c 'import fileinput; [print("x") for l in fileinput.input("/home/me/.zshrc", inplace=True)]'"#,
                Rule::Overwrite,
            ),
            (
                r#"python3 -c 'import fileinput; fileinput.FileInput("/home/me/.zshrc", inplace=True)'"#,
                Rule::Overwrite,
            ),
            (
                r#"python3 -c 'import fileinput; fileinput.input(files=["/home/me/.zshrc"], inplace=1)'"#,
                Rule::Overwrite,
            ),
            // The files in a tuple, the second argument, any one of them.
            (
                r#"python3 -c 'import fileinput; fileinput.input(("a.txt", "/home/me/.zshrc"), True)'"#,
                Rule::Overwrite,
            ),
            (
                r#"python3 -c 'import fileinput; fileinput.input(files="/home/me/.zshrc", inplace=True, backup=".bak")'"#,
                Rule::Overwrite,
            ),
            // Under another name.
            (
                r#"python3 -c 'import fileinput as f; f.input("/home/me/.zshrc", inplace=True)'"#,
                Rule::Overwrite,
            ),
            (
                r#"python3 -c 'from fileinput import FileInput as F; F("/home/me/.zshrc", inplace=True)'"#,
                Rule::Overwrite,
            ),
            (
                r#"python3 -c 'from fileinput import *; input("/home/me/.zshrc", inplace=True)'"#,
                Rule::Overwrite,
            ),
            // `inplace` only known when it runs may be on.
            (
                r#"python3 -c 'import fileinput; fileinput.input("/home/me/.zshrc", inplace=flag)'"#,
                Rule::Overwrite,
            ),
            // Files only known when it runs, or the script's own arguments.
            (
                r"python3 -c 'import fileinput; fileinput.input(inplace=True)'",
                Rule::Unknown,
            ),
            (
                r"python3 -c 'import fileinput, sys; fileinput.input(sys.argv[1:], inplace=True)'",
                Rule::Unknown,
            ),
            (
                r"python3 -c 'import fileinput; fileinput.input([], inplace=True)'",
                Rule::Unknown,
            ),
            (
                r"python3 -c 'import fileinput; fileinput.input(*a, inplace=True)'",
                Rule::Unknown,
            ),
            (
                r"python3 -c 'import fileinput; fileinput.input(*a)'",
                Rule::Unknown,
            ),
        ],
    );
}

#[test]
fn pathlibs_move_and_copy_methods_are_read_like_rename_and_shutil_copy() {
    check(
        Shell::Posix,
        &posix(),
        &[
            r#"python3 -c 'from pathlib import Path; Path("notes.txt").copy("out.txt")'"#,
            r#"python3 -c 'from pathlib import Path; Path("notes.txt").copy_into("out")'"#,
            r#"python3 -c 'from pathlib import Path; Path("notes.txt").move("out.txt")'"#,
            r#"python3 -c 'from pathlib import Path; Path("a").move_into("out")'"#,
            r#"python3 -c 'from pathlib import Path; Path("/tmp/x").move("/tmp/y")'"#,
            r#"python3 -c 'from pathlib import Path; Path("/home/me/a").copy("/tmp/y", follow_symlinks=False)'"#,
            // A call with no target, and the functions of a module.
            r"python3 -c 'd = {}; print(d.copy())'",
            r"python3 -c 'import copy; x = copy.copy(y)'",
            r"python3 -c 'import numpy as np; a = np.copy(b)'",
            r"python3 -c 'import turtle; turtle.move(5)'",
        ],
        &[
            (
                r#"python3 -c 'from pathlib import Path; Path("/home/me/.ssh").move("/tmp/x")'"#,
                Rule::Delete,
            ),
            (
                r#"python3 -c 'from pathlib import Path; Path("/home/me/.ssh").move_into("/tmp")'"#,
                Rule::Delete,
            ),
            (
                r#"python3 -c 'from pathlib import Path; Path("/home/me/.ssh").move(target="/tmp/x")'"#,
                Rule::Delete,
            ),
            (
                r#"python3 -c 'from pathlib import Path; Path("/tmp/x").copy("/home/me/.zshrc")'"#,
                Rule::Overwrite,
            ),
            (
                r#"python3 -c 'from pathlib import Path; Path("/tmp/x").copy(target="/home/me/.zshrc")'"#,
                Rule::Overwrite,
            ),
            (
                r#"python3 -c 'from pathlib import Path; Path("/tmp/x").copy_into("/home/me/.ssh")'"#,
                Rule::Overwrite,
            ),
            (
                r#"python3 -c 'from pathlib import Path; Path("/tmp/x").copy_into(target_dir="/home/me/.ssh")'"#,
                Rule::Overwrite,
            ),
            (
                r#"python3 -c 'from pathlib import Path; p = Path("/tmp/x"); p.copy("/home/me/.zshrc", preserve_metadata=True)'"#,
                Rule::Overwrite,
            ),
            // The path or its target only known when it runs.
            (
                r#"python3 -c 'from pathlib import Path; Path("/tmp/x").copy(*a)'"#,
                Rule::Unknown,
            ),
            (
                r#"python3 -c 'from pathlib import Path; Path("/home/me/.ssh").move(*a)'"#,
                Rule::Unknown,
            ),
        ],
    );
}

#[test]
fn killing_a_process_by_a_literal_id_is_the_kill_command() {
    check(
        Shell::Posix,
        &posix(),
        &[
            // The process itself and its group, and an ordinary process.
            r"python3 -c 'import os; os.kill(0, 9)'",
            r"python3 -c 'import os; os.killpg(0, 9)'",
            r"python3 -c 'import os, signal; os.kill(4242, signal.SIGTERM)'",
            "node -e \"process.kill(0, 'SIGKILL')\"",
            "node -e \"process.kill(4242)\"",
            "deno eval 'Deno.kill(4242, \"SIGTERM\")'",
        ],
        &[
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
        ],
    );
}

#[test]
fn copying_permission_bits_is_a_chmod_of_the_destination() {
    check(
        Shell::Posix,
        &posix(),
        &[
            r#"python3 -c 'import shutil; shutil.copymode("a.txt", "b.txt")'"#,
            r#"python3 -c 'import shutil; shutil.copystat("/home/me/.ssh/id_rsa", "b.txt")'"#,
            r#"python3 -c 'import shutil; shutil.copystat("a", "/tmp/y", follow_symlinks=False)'"#,
        ],
        &[
            (
                r#"python3 -c 'import shutil; shutil.copymode("/tmp/x", "/home/me/.ssh/id_rsa")'"#,
                Rule::Permissions,
            ),
            (
                r#"python3 -c 'import shutil; shutil.copystat("/tmp/x", "/home/me/.ssh/id_rsa")'"#,
                Rule::Permissions,
            ),
            (
                r#"python3 -c 'import shutil; shutil.copymode("/tmp/x", dst="/home/me/.ssh/id_rsa")'"#,
                Rule::Permissions,
            ),
            (
                r#"python3 -c 'from shutil import copystat as c; c("/tmp/x", "/home/me/.ssh/id_rsa")'"#,
                Rule::Permissions,
            ),
            (
                r#"python3 -c 'import shutil; shutil.copymode("/tmp/x", d)'"#,
                Rule::Permissions,
            ),
        ],
    );
    // What the shell reads the same way.
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[(
            "chmod --reference=/tmp/x /home/me/.ssh/id_rsa",
            Rule::Permissions,
        )],
    );
}

#[test]
fn every_call_of_execa_that_runs_a_command_is_read() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "node -e \"require('execa').command('ls -l')\"",
            "node -e \"require('execa').commandSync('ls')\"",
            r#"node --input-type=module -e 'import {$} from "execa"; await $`ls`'"#,
            r#"node --input-type=module -e 'import {$} from "execa"; $.sync`git status`'"#,
            "node -e \"require('cross-spawn').sync('ls', ['-l'])\"",
            "node -e \"require('cross-spawn').spawn('ls')\"",
            "node -e \"const spawn = require('cross-spawn'); spawn.sync('ls')\"",
            "node -e \"require('cross-spawn')('ls')\"",
            "node -e \"const spawn = require('cross-spawn'); spawn('ls', ['-l'])\"",
            "node --input-type=module -e \"import spawn from 'cross-spawn'; spawn('ls')\"",
        ],
        &[
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
        ],
    );
}

#[test]
fn an_interpreter_asked_to_print_its_version_or_help_reads_no_input() {
    let printing = [
        "python --version",
        "python -V",
        "python -VV",
        "python3 --version",
        "python3.12 --version",
        "python3 -h",
        "python3 --help",
        "node --version",
        "node -v",
        "node --help",
        "nodejs --version",
        "bun -v",
        "perl --version",
        "ruby --version",
        "php -h",
        "lua --help",
    ];
    // Under any shell: PowerShell and cmd as POSIX.
    check(Shell::Posix, &posix(), &printing, &[]);
    check(Shell::PowerShell, &windows(), &printing, &[]);
    check(Shell::Cmd, &windows(), &printing, &[]);
    // A flag that is not a print-and-exit one, or is another option's value,
    // or comes where the script's name does, reads the input; so does
    // anything that does more than print.
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[
            ("python3 -v", Rule::Unknown),
            ("python3 -W --version", Rule::Unknown),
            ("python3 -X --version", Rule::Unknown),
            ("python3 -- --version", Rule::Unknown),
            ("node -r --version", Rule::Unknown),
            ("node --import --version", Rule::Unknown),
            ("python3 -V -", Rule::Unknown),
            ("python3 -i", Rule::Unknown),
            ("python3", Rule::Unknown),
            ("node", Rule::Unknown),
            // The input is read as code, and is.
            (
                "python3 -W --version <<'PY'\nimport shutil\nshutil.rmtree('/home/me')\nPY",
                Rule::Delete,
            ),
            // A print flag that is the value of perl's, ruby's or php's
            // option before it: the program comes from the input.
            (
                "perl -I --version <<'PL'\nsystem(\"rm -rf /home/me\");\nPL",
                Rule::Unknown,
            ),
            (
                "ruby -I --version <<'RB'\nsystem(\"rm -rf /home/me\")\nRB",
                Rule::Unknown,
            ),
            (
                "ruby -E --version <<'RB'\nsystem(\"rm -rf /home/me\")\nRB",
                Rule::Unknown,
            ),
            (
                "php -d --version <<'PH'\n<?php system(\"rm -rf /home/me\");\nPH",
                Rule::Unknown,
            ),
            (
                "php -c --version <<'PH'\n<?php system(\"rm -rf /home/me\");\nPH",
                Rule::Unknown,
            ),
            ("php -z --help", Rule::Unknown),
        ],
    );
}

#[test]
fn under_cmd_a_python_or_node_with_nothing_to_run_is_as_it_was() {
    // A line with only a print flag, and a bare program or a script file:
    // nothing is handed to it to run.
    check(
        Shell::Cmd,
        &windows(),
        &[
            "python",
            "python3",
            "node",
            "deno",
            "bun",
            "python --version",
            "node -v",
            "node --help",
            "deno --version",
            "python build.py",
            "deno test",
            "python -v",
        ],
        &[
            // Inline code, the input, and what is piped into it.
            (r#"python -c "print(1)""#, Rule::Unknown),
            (r#"node -e "console.log(1)""#, Rule::Unknown),
            ("python -", Rule::Unknown),
            ("node -", Rule::Unknown),
            ("type run.py | python", Rule::Unknown),
            ("type run.js | node", Rule::Unknown),
            ("echo print(1) | deno", Rule::Unknown),
        ],
    );
    // PowerShell reads the input of a bare interpreter as the POSIX shell
    // does; `deno` and `bun` only when something is piped into them.
    check(
        Shell::PowerShell,
        &windows(),
        &["deno", "bun", "python --version", "deno --version"],
        &[
            ("python", Rule::Unknown),
            ("node", Rule::Unknown),
            ("python -", Rule::Unknown),
            ("'print(1)' | python", Rule::Unknown),
            ("'1' | deno", Rule::Unknown),
        ],
    );
}
