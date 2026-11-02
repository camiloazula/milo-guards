//! Which code is understood: the strict, fail-closed subset. Anything outside
//! it is not understood, and the table of each language holds a row for every
//! way out of it.

use milo_guards_code::Language::{self, JavaScript, Python};
use milo_guards_code::{understand, Understanding};

const YES: Understanding = Understanding::Understood { imports: false };
const YES_IMPORTING: Understanding = Understanding::Understood { imports: true };
const NO: Understanding = Understanding::NotUnderstood;

/// Every row whose answer is not the one it expects, named together.
fn check(language: Language, rows: &[(&str, Understanding)]) {
    let wrong: Vec<String> = rows
        .iter()
        .filter_map(|(code, expected)| {
            let found = understand(language, code);
            (found != *expected)
                .then(|| format!("{code:?}: expected {expected:?}, found {found:?}"))
        })
        .collect();
    assert!(wrong.is_empty(), "\n{}", wrong.join("\n"));
}

#[test]
fn python_that_computes_is_understood() {
    check(
        Python,
        &[
            ("print(1+1)", YES_IMPORTING),
            ("print('hi')", YES_IMPORTING),
            ("x = 1\nx += 2\nprint(x)", YES_IMPORTING),
            ("a, b = 1, 2\nprint(a + b)", YES_IMPORTING),
            (
                "x = 1\nif x:\n    print(x)\nelse:\n    print(0)",
                YES_IMPORTING,
            ),
            (
                "print(len('abc'), max(1, 2), sorted([3, 1]))",
                YES_IMPORTING,
            ),
            // The modules built into the interpreter binary.
            ("import sys\nprint(sys.argv)", YES_IMPORTING),
            ("import sys; print(sys.version)", YES_IMPORTING),
            ("import sys\nprint(sys.stdin.read())", YES_IMPORTING),
            ("import time\nprint(time.time())", YES_IMPORTING),
            ("import errno\nprint(errno.ENOENT)", YES_IMPORTING),
            ("import itertools, builtins", YES_IMPORTING),
            (
                "import sys, time, errno\nprint(sys.argv, time.monotonic())",
                YES_IMPORTING,
            ),
            ("open('out.txt', 'w')", YES_IMPORTING),
            ("print(open('x').read())", YES_IMPORTING),
            ("print('x'.upper(), [1, 2].count(1))", YES_IMPORTING),
        ],
    );
}

#[test]
fn python_outside_the_subset_is_not_understood() {
    check(
        Python,
        &[
            // It does not parse, or holds no statement.
            ("if 1:", NO),
            ("", NO),
            ("# a comment", NO),
            ("pass if", NO),
            // It does not run straight through.
            ("def f(): return 1", NO),
            ("class A: pass", NO),
            ("f = lambda: 1", NO),
            ("for i in range(3): print(i)", NO),
            ("while False: pass", NO),
            ("print([i for i in range(3)])", NO),
            ("print(i for i in range(3))", NO),
            ("try:\n    print(1)\nexcept Exception:\n    pass", NO),
            ("with open('x') as f:\n    print(1)", NO),
            ("match 1:\n    case 1:\n        print(1)", NO),
            ("@dec\ndef f(): pass", NO),
            ("print(*[1, 2])", NO),
            // A call or an import that is not on the list.
            ("import os\nprint(os.getcwd())", NO),
            ("import os\nos.remove('x')", NO),
            ("import os.path", NO),
            ("import json as j\nj.dumps(1)", NO),
            // A module that is a file looked up in the folder the code runs
            // in first, however little the code does with it.
            ("import json", NO),
            ("import json, sys\njson.load(sys.stdin)", NO),
            ("import re\nprint(re.sub('a', 'b', 'abc'))", NO),
            ("import math\nprint(math.pi)", NO),
            ("import sys, json", NO),
            ("import enum", NO),
            // The built-in modules, used beyond the few members on the list.
            ("import builtins\nbuiltins.exec('1')", NO),
            ("import builtins\nprint(builtins.len('a'))", NO),
            ("import time\ntime.sleep(0)", NO),
            ("import itertools\nprint(itertools.count())", NO),
            ("import errno\nprint(errno.strerror(2))", NO),
            ("import sys\nprint(sys.modules)", NO),
            ("import sys\nsys.stdout.write('x')", NO),
            ("from json import dumps\ndumps(1)", NO),
            ("import sys\nsys.exit(0)", NO),
            ("import sys\nprint(sys.path)", NO),
            ("input()", NO),
            ("exit()", NO),
            ("getattr(print, '__call__')(1)", NO),
            ("x = print\nx(1)", NO),
            ("print(list(map(open, ['a'])))", NO),
            ("f()()", NO),
            // Run-time code, and a name nothing bound.
            ("eval('1')", NO),
            ("exec('x = 1')", NO),
            ("__import__('os')", NO),
            ("print(os.getcwd())", NO),
            ("print(math.pi)", NO),
            ("json.dumps(1)", NO),
            // Reaching into an object, and a name that is not plain.
            ("print(().__class__)", NO),
            ("_x = 1", NO),
            ("print = 1", NO),
            ("import os\nos.environ['X'] = '1'", NO),
            ("print(\u{ff3f}\u{ff3f}class\u{ff3f}\u{ff3f})", NO),
            // A control character, a line separator.
            ("print(1)\u{0}", NO),
            ("print(1)\u{2028}print(2)", NO),
        ],
    );
}

#[test]
fn javascript_that_computes_is_understood() {
    check(
        JavaScript,
        &[
            ("console.log(1)", YES),
            ("console.log('hi')", YES),
            ("let x = 1; x += 2; console.log(x)", YES),
            ("const a = [1, 2]; console.log(a.length)", YES),
            ("if (1) { console.log(1) } else { console.log(0) }", YES),
            ("console.log(Math.max(1, 2), parseInt('3'))", YES),
            ("console.log(JSON.stringify({a: 1}))", YES),
            ("console.log('x'.toUpperCase().trim())", YES),
            ("1 + 1", YES),
        ],
    );
}

#[test]
fn javascript_outside_the_subset_is_not_understood() {
    check(
        JavaScript,
        &[
            // It does not parse, or holds no statement.
            ("if (", NO),
            ("", NO),
            ("// a comment", NO),
            ("{}", NO),
            ("if (1) {}", NO),
            // It does not run straight through.
            ("function f() { return 1 }", NO),
            ("const f = () => 1", NO),
            ("class A {}", NO),
            ("for (let i = 0; i < 3; i++) console.log(i)", NO),
            ("while (false) {}", NO),
            ("try { console.log(1) } catch (e) {}", NO),
            ("switch (1) { case 1: console.log(1) }", NO),
            ("(async () => { await 1 })()", NO),
            ("console.log(...[1, 2])", NO),
            ("new Date()", NO),
            // A call, a member or a module that is not on the list.
            ("process.exit(0)", NO),
            ("process.env", NO),
            ("console.log(process.version)", NO),
            ("require('fs')", NO),
            ("import('fs')", NO),
            ("require('fs').readFileSync('x')", NO),
            ("setTimeout(() => 1, 1)", NO),
            ("Date.now()", NO),
            ("Buffer.from('x')", NO),
            ("Object.keys({})", NO),
            ("Bun.write('f', 'x')", NO),
            ("Deno.readTextFileSync('x')", NO),
            ("const p = console.log; p(1)", NO),
            ("eval('1')", NO),
            ("Function('return 1')()", NO),
            // Writing to what is not a plain name.
            ("console.log = 1", NO),
            ("process.env.X = '1'", NO),
            ("({}).__proto__", NO),
            ("console.log(\u{ff43}onsole)", NO),
            // A control character, a line separator.
            ("console.log(1)\u{0}", NO),
            ("console.log(1)\u{2028}console.log(2)", NO),
        ],
    );
}

#[test]
fn what_is_understood_does_nothing_to_a_file_but_open_in_python() {
    // The point of understanding: no act found in understood code is no act.
    for (language, code) in [
        (Python, "print(1+1)"),
        (Python, "import sys\nprint(sys.stdin.read())"),
        (JavaScript, "console.log(1)"),
        (JavaScript, "console.log(JSON.stringify({a: 1}))"),
    ] {
        assert_ne!(understand(language, code), NO, "{code:?}");
        assert!(
            milo_guards_code::read(language, code).acts.is_empty(),
            "{code:?}"
        );
    }
    // `open` is on the list because the reader judges it by its path and mode.
    let reading = milo_guards_code::read(Python, "open('out.txt', 'w')");
    assert_eq!(reading.acts.len(), 1);
}
