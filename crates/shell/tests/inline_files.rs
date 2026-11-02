//! What the file calls of inline code do to their paths: the target of
//! `rename` and `replace`, file calls that were not listed (`io.FileIO`,
//! `Bun.file().unlink()`), a read with a flag that writes, the `fs` stream
//! classes, `fileinput` in place, pathlib's move and copy methods, an `open`
//! whose argument can be a mode, copying permission bits, and
//! `argparse.FileType`.

mod common;

use common::inline::{assert_risky_as, lines};
use common::{check, posix};
use milo_guards_shell::{Rule, Shell};

#[test]
fn a_file_call_of_inline_code_is_judged_by_what_it_does_to_the_path() {
    check(
        Shell::Posix,
        &posix(),
        &[
            // `replace` of a string, and `copy` of a dict.
            "python3 -c \"print('abc'.replace('a', 'b'))\"",
            "python3 -c \"s = 'abc'; print(s.replace('a', 'b'))\"",
            r"python3 -c 'd = {}; print(d.copy())'",
        ],
        &[
            // Path's `rename` and `replace` take a `target` keyword. A name
            // nothing bound is not a string the code made: it is read as a
            // module, which the reader has no row for.
            ("python3 -c \"print(s.replace('a', 'b'))\"", Rule::Unknown),
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
            // Not read whole by the strict gate: unknown.
            ("python3 -c \"from pathlib import Path; Path('a').rename(target='b')\"", Rule::Unknown),
            ("python3 -c \"from pathlib import Path; Path('a').replace(target='b')\"", Rule::Unknown),
            ("python3 -c \"print('abc'.replace(*args))\"", Rule::Unknown),
            // File calls that were not listed.
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
            // Not read whole by the strict gate: unknown.
            (
                "python3 -c \"import io; io.FileIO('/home/me/.zshrc')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"import io; io.FileIO('/home/me/.zshrc', 'r')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"import io; io.FileIO('out.txt', 'w')\"",
                Rule::Unknown,
            ),
            ("bun -e \"Bun.file('dist/x').unlink()\"", Rule::Unknown),
            (
                "bun -e \"Bun.file('/home/me/.zshrc').text()\"",
                Rule::Unknown,
            ),
            // Reading a file with a flag that writes writes it: `{flag: 'w'}`
            // opens the file for writing, which truncates it.
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
            // Not read whole by the strict gate: unknown.
            ("node -e \"require('fs').readFileSync('/home/me/.zshrc')\"", Rule::Unknown),
            ("node -e \"require('fs').readFileSync('/home/me/.zshrc', 'utf8')\"", Rule::Unknown),
            ("node -e \"require('fs').readFileSync('/home/me/.zshrc', {encoding: 'utf8'})\"", Rule::Unknown),
            ("node -e \"require('fs').readFileSync('/home/me/.zshrc', {encoding: 'utf8', flag: 'r'})\"", Rule::Unknown),
            ("node -e \"require('fs').readFileSync('/home/me/.zshrc', {flag: 'rs'})\"", Rule::Unknown),
            ("node -e \"require('fs').readFile('/home/me/.zshrc', 'utf8', (e, d) => console.log(d))\"", Rule::Unknown),
            ("node -e \"require('fs').readFile('/home/me/.zshrc', (e, d) => console.log(d))\"", Rule::Unknown),
            ("node -e \"require('fs').promises.readFile('/home/me/.zshrc', {flag: 'r'})\"", Rule::Unknown),
            ("node -e \"require('fs').createReadStream('/home/me/.zshrc').pipe(process.stdout)\"", Rule::Unknown),
            ("node -e \"require('fs').createReadStream('/home/me/.zshrc', {flags: 'r', encoding: 'utf8'})\"", Rule::Unknown),
            ("node -e \"require('fs').createReadStream('/home/me/.zshrc', 'utf8')\"", Rule::Unknown),
            // The stream classes of `fs` write as the functions that make
            // them do.
            (
                r#"node -e 'const fs = require("fs"); fs.WriteStream("/home/me/a")'"#,
                Rule::Overwrite,
            ),
            (
                r#"node -e 'const fs = require("fs"); new fs.WriteStream("/home/me/a")'"#,
                Rule::Overwrite,
            ),
            (
                r#"node -e 'const {WriteStream} = require("fs"); new WriteStream("/home/me/a")'"#,
                Rule::Overwrite,
            ),
            (
                r#"node -e 'const fs = require("fs"); fs.ReadStream("/home/me/a", {flags: "w"})'"#,
                Rule::Overwrite,
            ),
            (
                r#"node -e 'const fs = require("fs"); new fs.ReadStream("/home/me/a", {flags: "w"})'"#,
                Rule::Overwrite,
            ),
            (
                r#"node -e 'const {ReadStream} = require("fs"); new ReadStream("/home/me/a", {flags: "w"})'"#,
                Rule::Overwrite,
            ),
            (
                r#"node -e 'make().WriteStream("/home/me/a")'"#,
                Rule::Unknown,
            ),
            // Not read whole by the strict gate: unknown.
            (
                r#"node -e 'const fs = require("fs"); new fs.ReadStream("/home/me/a")'"#,
                Rule::Unknown,
            ),
            (
                r#"node -e 'const fs = require("fs"); new fs.ReadStream("/home/me/a", {flags: "r"})'"#,
                Rule::Unknown,
            ),
            (
                r#"node -e 'const {ReadStream} = require("fs"); ReadStream("/home/me/a", {encoding: "utf8"})'"#,
                Rule::Unknown,
            ),
            // `fileinput` in place rewrites each file as `sed -i` does.
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
            // Not read whole by the strict gate: unknown.
            (
                r#"python3 -c 'import fileinput; [print(l) for l in fileinput.input("/home/me/.zshrc")]'"#,
                Rule::Unknown,
            ),
            (
                r#"python3 -c 'import fileinput; fileinput.input(["/home/me/.zshrc"], False)'"#,
                Rule::Unknown,
            ),
            (
                r#"python3 -c 'import fileinput; fileinput.input("/home/me/.zshrc", inplace=False)'"#,
                Rule::Unknown,
            ),
            (
                r#"python3 -c 'import fileinput; fileinput.FileInput("/home/me/.zshrc", inplace=0)'"#,
                Rule::Unknown,
            ),
            (
                r#"python3 -c 'import fileinput; fileinput.input("notes.txt", inplace=True)'"#,
                Rule::Unknown,
            ),
            (
                r#"python3 -c 'import fileinput; fileinput.input(files=["a.txt", "b.txt"], inplace=1)'"#,
                Rule::Unknown,
            ),
            // Pathlib's move and copy methods are read like `rename` and
            // `shutil.copy`. The functions of a module the reader has no row
            // for are not safe: `copy` and `move` may be anything there.
            (
                r"python3 -c 'import numpy as np; a = np.copy(b)'",
                Rule::Unknown,
            ),
            (r"python3 -c 'import turtle; turtle.move(5)'", Rule::Unknown),
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
            // Not read whole by the strict gate: unknown.
            (
                r#"python3 -c 'from pathlib import Path; Path("notes.txt").copy("out.txt")'"#,
                Rule::Unknown,
            ),
            (
                r#"python3 -c 'from pathlib import Path; Path("notes.txt").copy_into("out")'"#,
                Rule::Unknown,
            ),
            (
                r#"python3 -c 'from pathlib import Path; Path("notes.txt").move("out.txt")'"#,
                Rule::Unknown,
            ),
            (
                r#"python3 -c 'from pathlib import Path; Path("a").move_into("out")'"#,
                Rule::Unknown,
            ),
            (
                r#"python3 -c 'from pathlib import Path; Path("/tmp/x").move("/tmp/y")'"#,
                Rule::Unknown,
            ),
            (
                r#"python3 -c 'from pathlib import Path; Path("/home/me/a").copy("/tmp/y", follow_symlinks=False)'"#,
                Rule::Unknown,
            ),
            (r"python3 -c 'import copy; x = copy.copy(y)'", Rule::Unknown),
            // An `open` call is a write only when its argument can be a mode.
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
            // A literal reading mode reads.
            (
                "python3 -c \"from pathlib import Path; Path('/home/me/.ssh/id_rsa').open(mode='rb')\"",
                Rule::ReadSecret,
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
            ("python3 -c \"from pathlib import Path; Path('notes.txt').open()\"", Rule::Unknown),
            ("python3 -c \"from pathlib import Path; Path('notes.txt').open('r')\"", Rule::Unknown),
            ("python3 -c \"from pathlib import Path; Path('notes.txt').open(mode='rb')\"", Rule::Unknown),
            ("python3 -c \"from pathlib import Path; Path('notes.txt').open('r', encoding='utf-8')\"", Rule::Unknown),
            // Copying permission bits is a `chmod` of the destination.
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
            // What the shell reads the same way.
            (
                "chmod --reference=/tmp/x /home/me/.ssh/id_rsa",
                Rule::Permissions,
            ),
            // Not read whole by the strict gate: unknown.
            (
                r#"python3 -c 'import shutil; shutil.copymode("a.txt", "b.txt")'"#,
                Rule::Unknown,
            ),
            (
                r#"python3 -c 'import shutil; shutil.copystat("/home/me/.ssh/id_rsa", "b.txt")'"#,
                Rule::Unknown,
            ),
            (
                r#"python3 -c 'import shutil; shutil.copystat("a", "/tmp/y", follow_symlinks=False)'"#,
                Rule::Unknown,
            ),
            // `argparse.FileType`: not read whole by the strict gate, unknown.
            ("python3 -c \"import argparse; p = argparse.ArgumentParser(); p.add_argument('-n', type=int); print(p.parse_args(['-n', '1']))\"", Rule::Unknown),
        ],
    );
}

#[test]
fn a_pathlib_open_with_a_mode_that_is_not_a_literal_reading_mode_writes_the_path() {
    let rows = lines(&[
        "python3 -c \"from pathlib import Path; import sys; Path('/home/me/.zshrc').open(sys.argv[1])\"",
        "python3 -c \"from pathlib import Path; import sys; Path('/home/me/.zshrc').open(mode=sys.argv[1])\"",
        "python3 -c \"from pathlib import Path; import sys; Path('/home/me/.zshrc').open(*sys.argv[1:])\"",
        "python3 -c \"from pathlib import Path; Path('/home/me/.zshrc').open(**{'mode': 'w'})\"",
        "python3 -c \"from pathlib import Path; m = 'r'; m = 'w'; Path('/home/me/.zshrc').open(m)\"",
        "python3 -c \"from pathlib import Path; Path('/home/me/.zshrc').open('r' + '+')\"",
    ]);
    assert_risky_as(&rows, &[Rule::Overwrite]);
}

#[test]
fn argparse_file_type_opens_what_it_is_given() {
    let rows = lines(&[
        "python3 -c \"import argparse; p = argparse.ArgumentParser(); p.add_argument('f', type=argparse.FileType('w')); p.parse_args(['/home/me/.zshrc'])\"",
        "python3 -c \"from argparse import FileType; import argparse; p = argparse.ArgumentParser(); p.add_argument('f', type=FileType('w'))\"",
        "python3 -c \"import argparse; f = argparse.FileType('w'); f('/home/me/.zshrc')\"",
    ]);
    assert_risky_as(&rows, &[Rule::Unknown]);
}

#[test]
fn an_open_of_a_module_the_reader_has_no_row_for_is_unknown_and_no_overwrite() {
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
