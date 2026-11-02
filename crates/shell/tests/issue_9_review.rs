//! Inline code: the `fs` stream classes, and a string handed to `setTimeout`.

mod common;

use common::{check, posix};
use milo_guards_shell::{Rule, Shell};

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
