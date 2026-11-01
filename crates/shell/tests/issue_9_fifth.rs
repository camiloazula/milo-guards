//! Inline code, the fifth pass: `asyncio.subprocess`, a dotted `__import__`
//! (which returns the top package), the value of `eval` used as an object,
//! the `pdb` calls that start a debugger, and the members of node's `module`
//! that load or run code.

mod common;

use common::{check, posix};
use milo_guards_shell::{Rule, Shell};

#[test]
fn asyncio_subprocess_starts_programs() {
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[
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
        ],
    );
}

#[test]
fn a_dotted_import_is_the_top_package_unless_a_fromlist_is_given() {
    check(
        Shell::Posix,
        &posix(),
        &[
            // With a `fromlist` the submodule is what comes back, and it has no
            // `system`.
            "python3 -c \"__import__('os.path', fromlist=['join']).join('a', 'b')\"",
            "python3 -c \"import importlib; importlib.import_module('os.path').join('a', 'b')\"",
        ],
        &[
            (
                "python3 -c \"__import__('os.path').system('rm -rf ~')\"",
                Rule::Delete,
            ),
            (
                "python3 -c \"__import__('os.path').remove('/home/me/.zshrc')\"",
                Rule::Delete,
            ),
            (
                "python3 -c \"__import__('distutils.dir_util').dir_util.remove_tree('/home/me')\"",
                Rule::Delete,
            ),
            (
                "python3 -c \"import builtins; builtins.__import__('os.path').system('rm -rf ~')\"",
                Rule::Delete,
            ),
            (
                "python3 -c \"import importlib; importlib.__import__('os.path').system('rm -rf ~')\"",
                Rule::Delete,
            ),
            // An empty `fromlist` is none.
            (
                "python3 -c \"__import__('os.path', fromlist=[]).system('rm -rf ~')\"",
                Rule::Delete,
            ),
            (
                "python3 -c \"__import__('os.path', None, None, ()).system('rm -rf ~')\"",
                Rule::Delete,
            ),
            // A `fromlist` only known when it runs is not read.
            (
                "python3 -c \"__import__('os.path', fromlist=x).system('rm -rf ~')\"",
                Rule::Unknown,
            ),
        ],
    );
}

#[test]
fn the_value_of_eval_comes_back_under_no_name() {
    check(
        Shell::Posix,
        &posix(),
        &[
            // A statement of its own, or a value that is only printed.
            "node -e \"eval('1+1')\"",
            "python3 -c \"eval('1+1')\"",
            "python3 -c \"print(eval('1+2'))\"",
        ],
        &[
            (
                "node -e \"eval('require(\\\"fs\\\")').rm('/home/me',{recursive:true},()=>{})\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"eval('__import__(\\\"shutil\\\")').rmtree('/home/me')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"import os; eval('os').system('rm -rf ~')\"",
                Rule::Unknown,
            ),
            (
                "node -e \"eval('require')('child_process').exec('rm -rf ~')\"",
                Rule::Unknown,
            ),
            (
                "node -e \"const fs=require('fs'); eval('fs').rm('/home/me',{recursive:true},()=>{})\"",
                Rule::Unknown,
            ),
            (
                "node -e \"const r = eval('1; require(\\\"fs\\\")'); r.rm('/home/me',{recursive:true},()=>{})\"",
                Rule::Unknown,
            ),
            (
                "node -e \"eval('globalThis').require('fs').rm('/home/me',{recursive:true},()=>{})\"",
                Rule::Unknown,
            ),
            (
                "deno eval \"eval('Deno').remove('/home/me',{recursive:true})\"",
                Rule::Unknown,
            ),
            (
                "node -e \"eval('process').binding('fs')\"",
                Rule::Unknown,
            ),
            (
                "node -e \"globalThis.eval('require')('fs').rmSync('/home/me')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"import builtins; builtins.eval('__import__')('os').system('rm -rf ~')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"r = eval('__import__'); r('os').system('rm -rf ~')\"",
                Rule::Unknown,
            ),
        ],
    );
}

#[test]
fn every_pdb_call_starts_a_debugger_that_reads_the_input() {
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[
            (
                "python3 -c \"import pdb; pdb.run('1')\" <<'X'\n!__import__('shutil').rmtree('/home/me')\nc\nX",
                Rule::Unknown,
            ),
            ("python3 -c \"import pdb; pdb.runeval('1')\"", Rule::Unknown),
            (
                "python3 -c \"import pdb; pdb.runeval('__import__(\\\"os\\\")').system('rm -rf ~')\"",
                Rule::Unknown,
            ),
            ("python3 -c \"import pdb; pdb.main()\"", Rule::Unknown),
            ("python3 -c \"import pdb; pdb.runcall(print, 1)\"", Rule::Unknown),
            ("python3 -c \"import pdb; pdb.Pdb().set_trace()\"", Rule::Unknown),
            ("python3 -c \"import pdb; pdb.set_trace()\"", Rule::Unknown),
            ("python3 -c \"from pdb import run; run('1')\"", Rule::Unknown),
        ],
    );
}

#[test]
fn the_members_of_module_that_load_or_run_code_are_not_read() {
    check(
        Shell::Posix,
        &posix(),
        &[
            // Plain data.
            "node -e \"console.log(module.paths, module.id, module.filename)\"",
            "node -e \"module.exports = 1\"",
        ],
        &[
            (
                "node -e \"module._compile('require(\\\"fs\\\").rmSync(\\\"/home/me\\\",{recursive:true})', 'x.js')\"",
                Rule::Unknown,
            ),
            (
                "node -e \"require('module').register('data:text/javascript,1')\"",
                Rule::Unknown,
            ),
            ("node -e \"module.runMain()\"", Rule::Unknown),
            (
                "node -e \"module.prototype._compile('1', 'x.js')\"",
                Rule::Unknown,
            ),
            (
                "node -e \"require('module').createRequire('/x')('fs')\"",
                Rule::Unknown,
            ),
            ("node -e \"module.require('fs')\"", Rule::Unknown),
        ],
    );
}
