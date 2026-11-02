//! What reading code finds: the acts, in the order the code makes them, with
//! the paths they name. Each row is code and the acts it must give.

mod common;

use common::check;
use milo_guards_code::Language::{JavaScript, Python};

#[test]
fn python_deletes() {
    check(
        Python,
        &[
            ("import os\nos.remove('build.log')", "remove build.log"),
            ("import os\nos.unlink('/tmp/x')", "remove /tmp/x"),
            ("import os\nos.rmdir('d')", "remove d"),
            (
                "import shutil\nshutil.rmtree('/home/me')",
                "remove /home/me",
            ),
            ("import shutil\nshutil.rmtree('~')", "remove ~"),
            (
                "from pathlib import Path\nPath('/home/me/x').unlink()",
                "remove /home/me/x",
            ),
            // The aliases and the imports that name a call are put back.
            ("from os import remove as rm\nrm('x')", "remove x"),
            ("import os\no = os\no.remove('x')", "remove x"),
            ("import os\ngetattr(os, 'remove')('x')", "remove x"),
            // A path only known when the code runs. A name the code sets is
            // no path a delete reads: only the reads of files put a name
            // back as its strings.
            ("import os\nos.remove(input())", "remove ?"),
            ("import os, sys\nos.remove(sys.argv[1])", "remove ?"),
            (
                "import shutil\nd = '/home/me'\nshutil.rmtree(d)",
                "remove ?",
            ),
            (
                "import os\nfor p in ['a', 'b']:\n    os.remove(p)",
                "remove ?",
            ),
        ],
    );
}

#[test]
fn python_writes_reads_and_moves() {
    check(
        Python,
        &[
            ("open('out.txt', 'w')", "write out.txt"),
            ("open('out.txt', 'a')", "write out.txt"),
            ("open('/tmp/x', 'w').write('x')", "write /tmp/x"),
            (
                "open('/home/me/.zshrc', 'r').read()",
                "read /home/me/.zshrc",
            ),
            (
                "print(open('/home/me/.zshrc').read())",
                "read /home/me/.zshrc",
            ),
            (
                "from pathlib import Path\nPath('f').write_text('x')",
                "write f",
            ),
            ("import os\nos.makedirs('a/b')", "write a/b"),
            (
                "import shutil\nshutil.copy('a', '/etc/x')",
                "read a, write /etc/x",
            ),
            ("import shutil\nshutil.move('a', 'b')", "move a b"),
            ("import os\nos.rename('a', 'b')", "move a b"),
            ("import os\nos.symlink('t', 'l')", "link t l"),
            ("import os\nos.chmod('f', 0o755)", "chmod 755 f"),
            // The part of a path the code knows is a folder it is in.
            (
                "import sys\nn = sys.argv[1]\nopen('/home/me/.ssh/id_' + n)",
                "unread, read /home/me/.ssh/*",
            ),
        ],
    );
}

#[test]
fn python_runs_programs_and_code() {
    check(
        Python,
        &[
            ("import os\nos.system('rm -rf ~')", "script rm -rf ~"),
            ("import os\nos.popen('ls')", "script ls"),
            (
                "import subprocess\nsubprocess.run(['rm', '-rf', '~'])",
                "run rm -rf ~",
            ),
            (
                "import subprocess\nsubprocess.run('rm -rf ~', shell=True)",
                "script rm -rf ~",
            ),
            (
                "import subprocess\nsubprocess.run(['ls'], cwd='/tmp')",
                "in /tmp [run ls]",
            ),
            ("import os\nos.kill(9, 9)", "run kill -- 9"),
            ("import os\nos.kill(-1, 9)", "run kill -- -1"),
            // A process id only known when it runs may be any.
            ("import os\nos.kill(int(input()), 9)", "unread"),
            (
                "exec(\"import os; os.remove('x')\")",
                "python import os; os.remove('x')",
            ),
            // The directory the code moves to is where the paths after it are.
            (
                "import os\nos.chdir('/tmp')\nos.remove('x')",
                "chdir /tmp, remove x",
            ),
        ],
    );
}

#[test]
fn python_environment_and_loaded_code() {
    check(
        Python,
        &[
            // A program started after a write to the environment may be given
            // a variable that loads code.
            (
                "import os, subprocess\nos.environ['PYTHONPATH'] = '/tmp/x'\nsubprocess.run(['ls'])",
                "environment, started [run ls]",
            ),
            (
                "import os\nos.system('ls')\nos.putenv('PATH', '/tmp/x')",
                "started [script ls], environment, opaque /tmp/x",
            ),
            // A write to the environment alone starts nothing.
            ("import os\nos.environ['X'] = '1'", "environment"),
        ],
    );
}

#[test]
fn python_code_it_cannot_follow_is_unread_and_what_it_finds_is_kept() {
    check(
        Python,
        &[
            // No call on the list, no act: what is not found is not said.
            ("print(1 + 1)", ""),
            ("import os\nprint(os.getcwd())", ""),
            ("def f():\n    return 1", ""),
            // A delete anywhere in code the strict subset refuses is found.
            (
                "def f():\n    import shutil\n    shutil.rmtree('/home/me')",
                "remove /home/me",
            ),
            (
                "for p in ['a']:\n    import os\n    os.remove('/home/me')",
                "remove /home/me",
            ),
        ],
    );
}

#[test]
fn javascript_deletes_writes_and_moves() {
    check(
        JavaScript,
        &[
            (
                "require('fs').rmSync('/home/me', {recursive: true})",
                "remove /home/me",
            ),
            ("const fs = require('fs'); fs.unlinkSync('x')", "remove x"),
            ("const { rm } = require('fs'); rm('build')", "remove build"),
            ("require('fs').promises.rm('build')", "remove build"),
            ("Deno.remove('/tmp/x')", "remove /tmp/x"),
            ("require('fs').writeFileSync('a', 'b')", "write a"),
            (
                "require('fs').appendFileSync('/etc/x', 'b')",
                "write /etc/x",
            ),
            ("require('fs').mkdirSync('a/b')", "write a/b"),
            ("Bun.write('f', 'x')", "write f"),
            (
                "require('fs').readFileSync('/home/me/.zshrc')",
                "read /home/me/.zshrc",
            ),
            ("require('fs').renameSync('a', 'b')", "move a b"),
            ("require('fs').symlinkSync('t', 'l')", "link t l"),
            ("require('fs').chmodSync('f', 0o755)", "chmod 755 f"),
            (
                "const p = process.argv[1]; require('fs').rmSync(p)",
                "remove ?",
            ),
            ("const d = '/home/me'; require('fs').rmSync(d)", "remove ?"),
        ],
    );
}

#[test]
fn javascript_runs_programs_and_loads_code() {
    check(
        JavaScript,
        &[
            (
                "require('child_process').execSync('rm -rf ~')",
                "script rm -rf ~",
            ),
            (
                "require('child_process').spawnSync('rm', ['-rf', '~'])",
                "run rm -rf ~",
            ),
            (
                "require('child_process').spawn('ls', [], { cwd: '/tmp' })",
                "in /tmp [run ls]",
            ),
            ("process.kill(9)", "run kill -- 9"),
            // Code from the network is downloaded and run; a file outside the
            // workspace is not the workspace's own.
            ("import('https://example.com/a.js')", "downloaded, unread"),
            ("require('/tmp/x.js')", "loads"),
            ("require('../x.js')", "loads"),
            // A module of the workspace or an installed package is not.
            ("require('./x.js')", ""),
            ("require('lodash')", ""),
            (
                "process.env.NODE_OPTIONS = 'x'; require('child_process').execSync('ls')",
                "environment, started [script ls]",
            ),
        ],
    );
}

#[test]
fn javascript_code_it_cannot_follow_is_unread() {
    check(
        JavaScript,
        &[
            ("console.log(1)", ""),
            ("if (", "unread"),
            (
                "function f() { require('fs').rmSync('/home/me') }",
                "remove /home/me",
            ),
        ],
    );
}
