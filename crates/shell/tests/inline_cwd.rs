//! Where the relative paths of inline code land: `bun --cwd` moves the code
//! first, `os.chdir` and the other ways Python changes directory (`fchdir`,
//! `contextlib.chdir`, a directory handle) move what comes after, a `chdir`
//! is not where the code sits (a function, a loop, a handler), a `chdir` in
//! nested code is read rather than searched for, and a relative read after a
//! `chdir` the reader cannot place is unknown.

mod common;

use common::inline::{assert_risky_as, lines, UNKNOWN_OR_SECRET};
use common::{check, posix};
use milo_guards_shell::{Rule, Shell};

#[test]
fn a_relative_path_of_inline_code_is_counted_from_where_the_code_has_moved() {
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[
            // `bun --cwd` moves the code first.
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
            // Not read whole by the strict gate: unknown.
            (
                "bun --cwd=sub -e 'require(\"fs\").rmSync(\"x\")'",
                Rule::Unknown,
            ),
            (
                "bun --cwd sub -e 'require(\"fs\").rmSync(\"x\")'",
                Rule::Unknown,
            ),
            (
                "bun --cwd=/home/me/work/repo -e 'require(\"fs\").rmSync(\"x\")'",
                Rule::Unknown,
            ),
            // Python changes directory in other ways. A file opened from a
            // directory handle is a file the guard cannot name: its path is
            // counted from a place only known when the code runs, and a read
            // of one is `unknown`.
            (
                "python3 -c \"import os; os.open('x.txt', os.O_RDONLY, dir_fd=3)\"",
                Rule::Unknown,
            ),
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
            // Not read whole by the strict gate: unknown.
            ("python3 -c \"import os; os.unlink('x.log')\"", Rule::Unknown),
            ("python3 -c \"import os; os.scandir('.')\"", Rule::Unknown),
            // A `chdir` is not where the code sits. A function defined before
            // the `chdir` and called after it.
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
            // Not read whole by the strict gate: unknown.
            ("python3 -c \"import os, shutil; os.chdir('/tmp'); shutil.rmtree('x')\"", Rule::Unknown),
            ("python3 -c \"import os, shutil; os.chdir('sub'); shutil.rmtree('x')\"", Rule::Unknown),
            ("python3 -c \"import os, shutil; os.chdir('sub'); os.chdir('deeper'); shutil.rmtree('x')\"", Rule::Unknown),
            ("python3 -c \"import os, shutil\ndef g(): shutil.rmtree('x')\nos.chdir('/tmp')\ng()\"", Rule::Unknown),
            ("python3 -c \"import os, shutil; shutil.rmtree('/tmp/x'); os.chdir('/home/me')\"", Rule::Unknown),
            ("node -e \"const fs = require('fs'); function g() { fs.rmSync('x'); } process.chdir('sub'); g()\"", Rule::Unknown),
            // A `chdir` in nested code is read, not searched for.
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
            // Not read whole by the strict gate: unknown.
            ("python3 -c \"import shutil; exec('import os; os.getcwd()'); print(shutil.which('ls'))\"", Rule::Unknown),
            ("node -e \"eval('1+1'); console.log(process.cwd())\"", Rule::Unknown),
            ("python3 -c \"exec('print(\\\"chdir\\\")')\"", Rule::Unknown),
            // A read after a `chdir` the reader can place stays as it was: a
            // key by its absolute path is a key from anywhere.
            (
                "python3 -c 'import os, sys; os.chdir(sys.argv[1]); print(open(\"/home/me/.ssh/id_rsa\").read())'",
                Rule::ReadSecret,
            ),
            (
                "python3 -c 'import os, sys; os.chdir(sys.argv[1]); print(open(os.path.expanduser(\"~/.ssh/id_rsa\")).read())'",
                Rule::ReadSecret,
            ),
            // Not read whole by the strict gate: unknown.
            ("python3 -c 'import os; os.chdir(\"a\"); os.chdir(\"b\"); print(open(\"notes.txt\").read())'", Rule::Unknown),
            ("python3 -c 'import os; os.chdir(\"/tmp\"); print(open(\"notes.txt\").read())'", Rule::Unknown),
            ("node -e \"process.chdir('/tmp'); console.log(require('fs').readFileSync('notes.txt', 'utf8'))\"", Rule::Unknown),
            ("python3 -c 'import os, sys; os.chdir(sys.argv[1]); print(open(\"/home/me/work/repo/notes.txt\").read())'", Rule::Unknown),
            ("python3 -c 'import os, sys; os.chdir(sys.argv[1]); print(1)'", Rule::Unknown),
        ],
    );
}

#[test]
fn a_relative_read_after_a_chdir_the_reader_cannot_place_is_unknown() {
    let rows = lines(&[
        // Two steps up: `cd .. && cd .. && cat .ssh/id_rsa` is the same read.
        "python3 -c 'import os; os.chdir(\"..\"); os.chdir(\"..\"); print(open(\".ssh/id_rsa\").read())'",
        "python3 -c 'import os; os.chdir(\"../..\"); print(open(\".ssh/id_rsa\").read())'",
        // An absolute target and a relative one mix.
        "python3 -c 'import os; os.chdir(\"/home\"); os.chdir(\"me\"); print(open(\".ssh/id_rsa\").read())'",
        "python3 -c 'import os\nos.chdir(\"/home/me/work\")\nos.chdir(\"..\")\nprint(open(\".ssh/id_rsa\").read())'",
        "python3 -c 'import os\nfor _ in range(2): os.chdir(\"..\")\nprint(open(\".ssh/id_rsa\").read())'",
        // A directory handle, and a target from the arguments.
        "python3 -c 'import os\nos.fchdir(os.open(\"/home/me\", os.O_RDONLY))\nprint(open(\".ssh/id_rsa\").read())'",
        "python3 -c 'import os, sys; os.chdir(sys.argv[1]); print(open(\"id_rsa\").read())'",
        // A program or a script run from there reads the same file.
        "python3 -c 'import os; os.chdir(\"..\"); os.chdir(\"..\"); os.system(\"cat .ssh/id_rsa\")'",
        "python3 -c 'import os, subprocess; os.chdir(\"..\"); os.chdir(\"..\"); subprocess.run([\"cat\", \".ssh/id_rsa\"])'",
        // The same in JavaScript.
        "node -e \"process.chdir('..'); process.chdir('..'); console.log(require('fs').readFileSync('.ssh/id_rsa', 'utf8'))\"",
        "deno eval \"Deno.chdir('..'); Deno.chdir('..'); console.log(Deno.readTextFileSync('.ssh/id_rsa'))\"",
        "bun -e \"process.chdir('..'); process.chdir('..'); console.log(await Bun.file('.ssh/id_rsa').text())\"",
        // A read of a whole folder, and nested code run from there.
        "python3 -c 'import os, shutil; os.chdir(\"..\"); os.chdir(\"..\"); shutil.make_archive(\"x\", \"tar\", \".ssh\")'",
        "python3 -c 'import os; os.chdir(\"..\"); os.chdir(\"..\"); exec(\"print(open(\\\".ssh/id_rsa\\\").read())\")'",
        "node -e \"process.chdir('..'); process.chdir('..'); require('child_process').execSync('cat .ssh/id_rsa')\"",
    ]);
    assert_risky_as(&rows, &UNKNOWN_OR_SECRET);
}
