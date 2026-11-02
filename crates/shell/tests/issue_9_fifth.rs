//! Inline code: `asyncio.subprocess` starts programs.

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
