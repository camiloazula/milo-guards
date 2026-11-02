//! Inline code, the third pass: Python's coding declaration and line endings,
//! a Python name bound more than once, JavaScript destructuring and import
//! keys that are not plain identifiers, the `fs` stream classes, `--import`
//! of a `data:` URL with a here-document, and a string handed to `setTimeout`.

mod common;

use common::{check, posix};
use milo_guards_shell::{Rule, Shell};

#[test]
fn a_python_coding_declaration_that_decodes_the_input_to_other_text_is_not_read() {
    check(
        Shell::Posix,
        &posix(),
        &[
            // UTF-8 is what the reader reads, in any spelling.
            // An ASCII-compatible encoding reads an ASCII text the same.
            // A coding line in code that is not bytes is ignored by Python.
            "python3 -c '# coding: utf-7\nprint(1)'",
            // Only the first two lines are a declaration.
        ],
        &[
            (
                "python3 <<'PY'\n# coding: utf-7\nprint(1)\nPY",
                Rule::Unknown,
            ),
            (
                "python3 - <<'PY'\n# -*- coding: utf-7 -*-\nprint(1)\nPY",
                Rule::Unknown,
            ),
            (
                "python3 - <<'PY'\n# coding: utf-7\nimport shutil\nshutil.rmtree(\"/home/me\")\nPY",
                Rule::Delete,
            ),
            ("python3 <<<'# coding: utf-7\nprint(1)'", Rule::Unknown),
            (
                "python3 <<'PY'\n#!/usr/bin/python3\n# coding: utf-16\nprint(1)\nPY",
                Rule::Unknown,
            ),
            (
                "python3 <<'PY'\n# coding: cp037\nprint(1)\nPY",
                Rule::Unknown,
            ),
            ("python3 <<'PY'\n# coding: hz\nprint(1)\nPY", Rule::Unknown),
            // A latin-1 text with more than ASCII in it is not the same text.
            (
                "python3 <<'PY'\n# coding: latin-1\nprint('é')\nPY",
                Rule::Unknown,
            ),
            // A bytes literal given to exec, eval or compile is decoded by it.
            (
                "python3 -c 'exec(b\"# coding: utf-7\\nprint(1)\")'",
                Rule::Unknown,
            ),
            (
                "python3 -c 'eval(rb\"# coding: utf-7\\nprint(1)\")'",
                Rule::Unknown,
            ),
            (
                "python3 -c 'compile(b\"# coding: utf-7\\nprint(1)\", \"x\", \"exec\")'",
                Rule::Unknown,
            ),
            (
                "python3 -c 'exec(b\"\\n# coding: utf-7\\nprint(1)\")'",
                Rule::Unknown,
            ),
            // Not read whole by the strict gate: unknown.
            (
                "python3 <<'PY'\n# coding: utf-8\nprint(1)\nPY",
                Rule::Unknown,
            ),
            (
                "python3 <<'PY'\n# -*- coding: utf-8 -*-\nprint(1)\nPY",
                Rule::Unknown,
            ),
            (
                "python3 <<'PY'\n# vim: set fileencoding=utf_8 :\nprint(1)\nPY",
                Rule::Unknown,
            ),
            (
                "python3 <<'PY'\n#!/usr/bin/python3\n# coding: utf8\nprint(1)\nPY",
                Rule::Unknown,
            ),
            (
                "python3 <<'PY'\n# coding: latin-1\nprint(1)\nPY",
                Rule::Unknown,
            ),
            (
                "python3 <<'PY'\n# coding: ascii\nprint(1)\nPY",
                Rule::Unknown,
            ),
            (
                "python3 -c 'exec(\"# coding: utf-7\\nprint(1)\")'",
                Rule::Unknown,
            ),
            (
                "python3 -c 'exec(b\"# coding: utf-8\\nprint(1)\")'",
                Rule::Unknown,
            ),
            (
                "python3 <<'PY'\nprint(1)\nprint(2)\n# coding: utf-7\nPY",
                Rule::Unknown,
            ),
        ],
    );
}

#[test]
fn python_reads_a_carriage_return_as_a_newline() {
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[
            (
                "python3 -c '# x\rimport shutil;shutil.rmtree(\"/home/me\")'",
                Rule::Delete,
            ),
            (
                "python3 <<'PY'\n# x\rimport shutil;shutil.rmtree(\"/home/me\")\nPY",
                Rule::Delete,
            ),
            (
                "python3 <<'PY'\n# x\r\nimport shutil;shutil.rmtree(\"/home/me\")\nPY",
                Rule::Delete,
            ),
            (
                "python3 -c 'exec(\"# x\\rimport shutil;shutil.rmtree(\\\"/home/me\\\")\")'",
                Rule::Delete,
            ),
            // Not read whole by the strict gate: unknown.
            ("python3 -c 'print(1)\r\nprint(2)\r'", Rule::Unknown),
            ("python3 -c '# a comment\rprint(1)'", Rule::Unknown),
            ("python3 <<'PY'\r\nprint(1)\r\nPY", Rule::Unknown),
        ],
    );
}

#[test]
fn a_python_name_bound_more_than_once_to_different_things_is_not_followed() {
    check(
        Shell::Posix,
        &posix(),
        &[
            // The same thing twice, or things the reader has no use for.
        ],
        &[
            (
                "python3 -c 'import os\nif 0: import pathlib as os\nos.remove(\"/home/me/.zshrc\")'",
                Rule::Unknown,
            ),
            (
                "python3 -c 'import os\ndef g():\n  import json as os\nos.remove(\"/home/me/.zshrc\")'",
                Rule::Unknown,
            ),
            (
                "python3 -c 'from os import remove\nif 0: remove = print\nremove(\"/home/me/.zshrc\")'",
                Rule::Unknown,
            ),
            (
                "python3 -c 'import os, json; o = os\nif 0: o = json\no.remove(\"/home/me/.zshrc\")'",
                Rule::Unknown,
            ),
            (
                "python3 -c 'import subprocess as s\ntry:\n  import json as s\nexcept: pass\ns.run([\"rm\", \"-rf\", \"/home/me\"])'",
                Rule::Unknown,
            ),
            (
                "python3 -c 'from shutil import rmtree as r\ndef g(): r = print\nr(\"/home/me\")'",
                Rule::Unknown,
            ),
            (
                "python3 -c 'import os\n(os := __import__(\"json\"))\nos.remove(\"/home/me/.zshrc\")'",
                Rule::Unknown,
            ),
            // The order does not matter: the last may be the one that deletes.
            (
                "python3 -c 'import json as o\nimport os as o\no.remove(\"/home/me/.zshrc\")'",
                Rule::Delete,
            ),
            // Not read whole by the strict gate: unknown.
            ("python3 -c 'import os\nimport os\nfrom os import path\nimport os.path\nprint(os.getcwd())'", Rule::Unknown),
            ("python3 -c 'import os\nx = os\nx = os\nprint(x.getcwd())'", Rule::Unknown),
            ("python3 -c 'a = b\na = c\nprint(a)'", Rule::Unknown),
            ("python3 -c 'import json as j\nk = 1\nk = 2\nprint(j.dumps(k))'", Rule::Unknown),
            ("python3 -c 'from os import path\nimport os.path as path\nprint(path.sep)'", Rule::Unknown),
        ],
    );
}

#[test]
fn a_javascript_key_that_is_not_a_plain_name_names_its_member() {
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[
            // A member of a module that is no call the reader has a row for
            // (`fs.1`), and a key looked up on an object that is not a
            // module, are functions it does not know when they are called.
            (
                r#"node -e 'const {1: r} = require("fs"); r(1)'"#,
                Rule::Unknown,
            ),
            (r"node -e 'const {[k]: r} = obj; r(1)'", Rule::Unknown),
            (
                r#"node -e 'const {"rmSync": r} = require("fs"); r("/home/me",{recursive:true})'"#,
                Rule::Delete,
            ),
            (
                r#"node -e 'const {["rmSync"]: r} = require("fs"); r("/home/me",{recursive:true})'"#,
                Rule::Delete,
            ),
            (
                r#"node -e 'const {[`rm${"Sync"}`]: r} = require("fs"); r("/home/me",{recursive:true})'"#,
                Rule::Delete,
            ),
            (
                r#"node -e '({["rmSync"]: r} = require("fs")); r("/home/me",{recursive:true})'"#,
                Rule::Delete,
            ),
            (
                r#"node -e 'const {"promises": {rm}} = require("fs"); rm("/home/me",{recursive:true})'"#,
                Rule::Delete,
            ),
            (
                r#"node -e 'const {[`exec${"Sync"}`]: x} = require("child_process"); x("rm -rf ~")'"#,
                Rule::Delete,
            ),
            // A key only known when it runs, taken from a module.
            (
                r#"node -e 'const fs = require("fs"); const {[k]: r} = fs; r("/home/me",{recursive:true})'"#,
                Rule::Unknown,
            ),
            (
                r#"node -e 'const {[k]: r} = require("fs"); r("/home/me",{recursive:true})'"#,
                Rule::Unknown,
            ),
            (
                r#"node -e 'const {"\uD800": r} = require("fs"); r("/home/me",{recursive:true})'"#,
                Rule::Unknown,
            ),
            (
                r#"node --input-type=module -e 'import {"rmSync" as r} from "fs"; r("/home/me",{recursive:true})'"#,
                Rule::Delete,
            ),
            (
                r#"bun -e 'import {"rmSync" as r} from "fs"; r("/home/me",{recursive:true})'"#,
                Rule::Delete,
            ),
            (
                r#"node --input-type=module -e 'import {"promises" as p} from "fs"; p.rm("/home/me",{recursive:true})'"#,
                Rule::Delete,
            ),
            // Not read whole by the strict gate: unknown.
            (
                r#"node -e 'const {"readFileSync": r} = require("fs"); r("/etc/hosts")'"#,
                Rule::Unknown,
            ),
            (
                r#"node -e 'const {["readFileSync"]: r} = require("fs"); r("/etc/hosts")'"#,
                Rule::Unknown,
            ),
            (
                r#"node --input-type=module -e 'import {"readFileSync" as r} from "fs"; r("/etc/hosts")'"#,
                Rule::Unknown,
            ),
            (
                r#"node --input-type=module -e 'import {readFileSync as r} from "fs"; r("/etc/hosts")'"#,
                Rule::Unknown,
            ),
        ],
    );
}

#[test]
fn the_stream_classes_of_fs_write_as_the_functions_that_make_them_do() {
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[
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
        ],
    );
}

#[test]
fn a_data_url_import_keeps_the_line_unknown_whatever_the_input_holds() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "node --import ./setup.js <<'JS'\nconsole.log(1)\nJS",
        ],
        &[
            (
                "node '--import=data:text/javascript,import(\"fs\").then(f=>f.rmSync(\"/home/me\",{recursive:true}))' <<'JS'\nconsole.log(1)\nJS",
                Rule::Unknown,
            ),
            (
                "node '--import=data:text/javascript,1' - <<'JS'\nconsole.log(1)\nJS",
                Rule::Unknown,
            ),
            (
                "node --import 'data:text/javascript,1' <<'JS'\nconsole.log(1)\nJS",
                Rule::Unknown,
            ),
            (
                "node --import 'data:text/javascript,1' - <<'JS'\nconsole.log(1)\nJS",
                Rule::Unknown,
            ),
            (
                "node --loader=data:text/javascript,1 <<<'console.log(1)'",
                Rule::Unknown,
            ),
            (
                "env node '--import=data:text/javascript,1' <<'JS'\nconsole.log(1)\nJS",
                Rule::Unknown,
            ),
            // Not read whole by the strict gate: unknown.
            ("node <<'JS'\nconsole.log(1)\nJS", Rule::Unknown),
            ("node - <<'JS'\nconsole.log(1)\nJS", Rule::Unknown),
            ("node --import=./setup.js - <<'JS'\nconsole.log(1)\nJS", Rule::Unknown),
        ],
    );
}

#[test]
fn a_string_handed_to_a_timer_is_code_the_reader_does_not_read() {
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[
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
        ],
    );
}
