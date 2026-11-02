//! Inline code: the members of `child_process` that run what the reader does
//! not read, and a `.open()` whose argument is not a mode.

mod common;

use common::{check, posix};
use milo_guards_shell::{Rule, Shell};

#[test]
fn child_process_calls_that_run_what_the_reader_does_not_read_are_unknown() {
    check(
        Shell::Posix,
        &posix(),
        &[
            // A module of the workspace's own, as `node worker.js` is.
            // The calls that are read.
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
            // Not read whole by the strict gate: unknown.
            ("node -e \"require('child_process').fork('worker.js')\"", Rule::Unknown),
            ("node -e \"require('child_process').fork('worker.js', ['a', 'b'])\"", Rule::Unknown),
            ("node -e \"require('child_process').fork('worker.js', { silent: true })\"", Rule::Unknown),
            ("node -e \"require('child_process').fork('worker.js', ['a'], { cwd: 'sub', silent: true, stdio: 'inherit' })\"", Rule::Unknown),
            ("node -e \"const { fork } = require('child_process'); fork('worker.js')\"", Rule::Unknown),
            ("node -e \"require('child_process').fork('worker.js', [], {})\"", Rule::Unknown),
            ("node -e \"require('child_process').execSync('echo 1')\"", Rule::Unknown),
            ("node -e \"require('child_process').spawn('echo', ['1'])\"", Rule::Unknown),
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
            // Reads.
            // A string that is not one mode, or one that `open` refuses.
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
            // Not read whole by the strict gate: unknown.
            (
                "python3 -c \"from pathlib import Path; Path('a.txt').open().read()\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"from pathlib import Path; Path('a.txt').open('r')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"from pathlib import Path; Path('a.txt').open('rb')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"from pathlib import Path; Path('a.txt').open(mode='rt')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"from pathlib import Path; Path('a.txt').open('rr')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"from pathlib import Path; Path('a.txt').open('rw')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"from pathlib import Path; Path('a.txt').open('bt')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"from pathlib import Path; Path('a.txt').open('+')\"",
                Rule::Unknown,
            ),
        ],
    );
    // A file name, a URL, a name with an `a` in it is no mode, so it is no
    // write; but the `open` of a module the reader has no row for is a call
    // it has no row for, so each is `unknown` and none is an overwrite.
    for line in [
        "python3 -c \"from PIL import Image; print(Image.open('a.png').size)\"",
        "python3 -c \"import wave; print(wave.open('a.wav').getnframes())\"",
        "python3 -c \"import fitz; fitz.open('a.pdf')\"",
        "python3 -c \"import webbrowser; webbrowser.open('http://localhost:8000')\"",
        "python3 -c \"import webbrowser; webbrowser.open('https://example.com/x', new=2)\"",
        "python3 -c \"import wave; wave.open('data.wav', 'rb')\"",
        "python3 -c \"from PIL import Image; Image.open('x.png', 'r')\"",
        "python3 -c \"import shelve; shelve.open('data.db', 'r')\"",
    ] {
        let rules = common::rules(line, Shell::Posix, &posix());
        assert!(rules.contains(&Rule::Unknown), "{line}: {rules:?}");
        assert!(!rules.contains(&Rule::Overwrite), "{line}: {rules:?}");
    }
}
