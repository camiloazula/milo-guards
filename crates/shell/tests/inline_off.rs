//! The shell guard without the reader of inline code: the `inline` feature
//! off. The line is still found (`python3 -c CODE`, `node -e CODE`, a
//! here-document fed to an interpreter), but none of the code is read, so
//! every such line is `unknown`, whatever the code is, and neither grammar is
//! built.
//!
//! This test is only compiled without the feature, which `--all-features`
//! never is; `just no-inline` runs it:
//!
//! ```text
//! cargo test -p milo-guards-shell --no-default-features --test inline_off
//! ```

#![cfg(not(feature = "inline"))]

mod common;

use common::{macos, posix, rules, windows};
use milo_guards_shell::{effect, Effect, Rule, Shell};

/// Lines whose code the guard reads when the feature is on, and finds
/// nothing in, a delete in or a key in: with it off, `unknown` for all.
const INLINE: [&str; 24] = [
    "python3 -c 'print(1+1)'",
    "python -c 'print(\"hi\")'",
    "python3.12 -c 'print(1)'",
    "python3 -c \"import json,sys; json.load(sys.stdin)\"",
    "node -e 'console.log(1)'",
    "node --eval 'console.log(1)'",
    "node -p 'process.version'",
    "bun -e 'console.log(1)'",
    "bun --print '1+1'",
    "deno eval 'console.log(1)'",
    // Code that deletes, writes and reads a key is not read either: the line
    // says only that it runs code the guard does not read.
    "python3 -c \"import shutil; shutil.rmtree('/home/me')\"",
    "python3 -c \"open('/home/me/.ssh/id_rsa').read()\"",
    "python3 -c \"import os; os.system('rm -rf ~')\"",
    "node -e \"require('fs').rmSync('/home/me', {recursive: true})\"",
    "node -e \"require('child_process').execSync('rm -rf ~')\"",
    // Code from the input.
    "python3 - <<'PY'\nprint(1)\nPY",
    "python3 <<< 'print(1)'",
    "node <<< 'console.log(1)'",
    "echo 'print(1)' | python3",
    // Around the interpreter.
    "FOO=1 python3 -c 'print(1)'",
    "python3 -W ignore -c 'print(1)'",
    "node -r ts-node/register -e 'console.log(1)'",
    "bash -c \"python3 -c 'print(1)'\"",
    "cd /tmp && python3 -c 'print(1)'",
];

#[test]
fn every_inline_line_is_unknown() {
    let wrong: Vec<String> = INLINE
        .iter()
        .filter_map(|line| {
            let found = rules(line, Shell::Posix, &posix());
            (found != [Rule::Unknown]).then(|| format!("{line:?}: {found:?}"))
        })
        .collect();
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn an_inline_line_is_never_reads_only() {
    for line in INLINE {
        // The interpreter is not one of `effect`'s readers: it is unknown, or
        // (`bun`) a program that changes things.
        let answer = effect(line, Shell::Posix, &posix());
        assert!(
            matches!(answer, Effect::Unknown | Effect::Changes),
            "{line:?}: {answer:?}"
        );
    }
}

/// Lines for every shell, with the quotes each of them reads as one word, and
/// with a module or loader option in front of bun's code flag.
const EVERY_SHELL: [&str; 14] = [
    "python3 -c \"print(1)\"",
    "python -c \"import shutil; shutil.rmtree('/home/me')\"",
    "node -e \"console.log(1)\"",
    "node -p \"process.version\"",
    "node -e \"require('fs').rmSync('/home/me', {recursive: true})\"",
    "bun -e \"console.log(1)\"",
    "bun --print \"1+1\"",
    "deno eval \"console.log(1)\"",
    "bun --import r.js -e \"require('fs').rmSync('/home/me',{recursive:true})\"",
    "bun --import r.js -e \"$X\"",
    "bun --require r.js -e \"$X\"",
    "bun --loader .js:jsx -p \"$X\"",
    "bun -r ./x.js -e 'console.log(1)'",
    "bun --import data:text/javascript -e \"console.log(1)\"",
];

#[test]
fn every_inline_line_is_unknown_in_every_shell() {
    // cmd and PowerShell lines are not read with the feature on either, and
    // a line that runs code is unknown there as it is under a POSIX shell,
    // whichever path setup the caller has.
    let wrong: Vec<String> = [Shell::Posix, Shell::PowerShell, Shell::Cmd]
        .into_iter()
        .flat_map(|shell| {
            [posix(), macos(), windows()]
                .into_iter()
                .flat_map(move |paths| {
                    EVERY_SHELL.iter().filter_map(move |line| {
                        let found = rules(line, shell, &paths);
                        (found != [Rule::Unknown]).then(|| format!("{shell:?} {line:?}: {found:?}"))
                    })
                })
        })
        .collect();
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn an_inline_line_is_never_reads_only_in_any_shell() {
    for shell in [Shell::Posix, Shell::PowerShell, Shell::Cmd] {
        for line in EVERY_SHELL {
            let answer = effect(line, shell, &posix());
            assert!(
                matches!(answer, Effect::Unknown | Effect::Changes),
                "{shell:?} {line:?}: {answer:?}"
            );
        }
    }
}

#[test]
fn a_script_file_is_the_workspaces_own_code_as_before() {
    for line in ["python3 scripts/gen.py", "node app.js", "python3 --version"] {
        assert!(
            rules(line, Shell::Posix, &posix()).is_empty(),
            "{line:?}: not inline code"
        );
    }
}

#[test]
fn a_module_an_option_loads_is_not_told_from_the_workspaces_own() {
    // With the reader there, `./setup.js` is a file of the workspace and a
    // `data:` URL or a module outside it is not. Without it nothing tells
    // them apart, so each is code the guard does not read.
    for line in [
        "node --import data:text/javascript,x script.js",
        "node --import ./setup.js script.js",
        "node -r ./setup.js script.js",
        "PYTHONPATH=/tmp/x python3 <<< 'print(1)'",
    ] {
        assert_eq!(
            rules(line, Shell::Posix, &posix()),
            [Rule::Unknown],
            "{line:?}"
        );
    }
}
