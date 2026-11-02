//! The names and modules the inline reader follows, and those it does not:
//! a module under another name, default values, a module handed on as a
//! value, `with` and destructuring with a rest, every way JavaScript reaches a
//! module, names read in their NFKC form or written with an escape, names
//! bound in a class body or more than once, keys that are not plain names,
//! names literal `exec` and `eval` code binds or uses, a dotted `__import__`,
//! the value of `eval`, node's `module`, awaited imports of a computed value,
//! assignments to a module or a builtin prototype, escapes the reader does not
//! decode, and chains of names held to a bound.

mod common;

use common::inline::{assert_risky_as, lines};
use common::{check, posix, took};
use milo_guards_shell::{classify, Rule, Shell};

#[test]
fn a_name_is_followed_only_to_what_it_is_certain_to_hold() {
    check(
        Shell::Posix,
        &posix(),
        &[
            // What is decoded is the character it stands for.
            "python3 -c \"print('\\N{BULLET}')\"",
            "node -e \"console.log('\\57', '\\0')\"",
            // A string or a comment that is not ASCII is only text.
            "python3 -c \"print('ｒｅｍｏｖｅ')\"",
            "python3 -c \"print('é')  # ｒｅｍｏｖｅ\"",
            // An escape in a string is decoded, and reads as it always did.
            r#"node -e "console.log('\u0072mSync')""#,
        ],
        &[
            // A module under another name is followed.
            (
                "python3 -c 'import os; o = os; o.remove(\"/etc/passwd\")'",
                Rule::Delete,
            ),
            (
                "python3 -c 'o = __import__(\"os\"); o.remove(\"/etc/passwd\")'",
                Rule::Delete,
            ),
            (
                "python3 -c 'import shutil; shutil.os.remove(\"/etc/passwd\")'",
                Rule::Delete,
            ),
            (
                "python3 -c 'import posix; posix.remove(\"/etc/passwd\")'",
                Rule::Delete,
            ),
            (
                "python3 -c '__builtins__.__import__(\"os\").remove(\"/etc/passwd\")'",
                Rule::Unknown,
            ),
            (
                "python3 -c 'import builtins; builtins.open(\"/etc/x\", \"w\")'",
                Rule::Overwrite,
            ),
            (
                "python3 -c 'from builtins import exec as e; e(x)'",
                Rule::Unknown,
            ),
            (
                "python3 -c '().__class__.__bases__[0].__subclasses__()'",
                Rule::Unknown,
            ),
            (
                "python3 -c 'import subprocess; subprocess.os.system(\"rm -rf ~\")'",
                Rule::Delete,
            ),
            (
                "python3 -c 'from distutils import dir_util; dir_util.remove_tree(\"/home/me\")'",
                Rule::Delete,
            ),
            (
                "python3 -c 'import urllib.request; urllib.request.urlretrieve(\"http://x\", \"/etc/x\")'",
                Rule::Overwrite,
            ),
            (
                "python3 -c 'import os; os.remove(\"/home/me/x\")\nimport subprocess; subprocess.run(\"ls\")'",
                Rule::Delete,
            ),
            (
                "node -e 'const fs=require(\"fs\"); const g = fs; g.rmSync(\"/home/me\")'",
                Rule::Delete,
            ),
            (
                "node -e 'const {rmSync}=require(\"fs\"); (0, rmSync)(\"/home/me\")'",
                Rule::Unknown,
            ),
            (
                "node -e '(function(){}).constructor(\"return process\")()'",
                Rule::Unknown,
            ),
            (
                "node -e 'const cp=require(\"child_process\"); const x = cp.exec; x(\"rm -rf ~\")'",
                Rule::Unknown,
            ),
            (
                "node -e 'const x = require; x(\"fs\").rmSync(\"/home/me\")'",
                Rule::Delete,
            ),
            (
                "node -e 'require(\"fs\").rmSync?.(\"/home/me\")'",
                Rule::Delete,
            ),
            (
                "node -e 'module.require(\"fs\").rmSync(\"/home/me\")'",
                Rule::Unknown,
            ),
            (
                "bun -e 'import {$} from \"bun\"; await $`rm -rf ~`'",
                Rule::Delete,
            ),
            (
                "bun -e 'import {write} from \"bun\"; await write(\"/home/me/.zshrc\", \"x\")'",
                Rule::Overwrite,
            ),
            ("node -e 'require(\"shelljs\").rm(\"-rf\", \"~\")'", Rule::Delete),
            (
                "node -e 'const sh = require(\"shelljs\"); sh.exec(\"rm -rf ~\")'",
                Rule::Delete,
            ),
            (
                "node -e 'require(\"execa\").execaSync(\"rm\", [\"-rf\", \"~\"])'",
                Rule::Delete,
            ),
            (
                "node --input-type=module -e 'import {execSync as e} from \"node:child_process\"; e(\"rm -rf ~\")'",
                Rule::Delete,
            ),
            (
                "deno eval 'const {remove} = Deno; await remove(\"/home/me\")'",
                Rule::Delete,
            ),
            (
                "deno eval 'Deno.run({cmd: [\"sh\", \"-c\", \"rm -rf ~\"]})'",
                Rule::Delete,
            ),
            ("deno eval 'Deno.run(opts)'", Rule::Unknown),
            ("bun -e 'Bun.spawn(argv)'", Rule::Unknown),
            ("node -e 'require(\"fs\").rmSync(...paths)'", Rule::Delete),
            ("node -e 'require(\"fs\").writeFileSync(...a)'", Rule::Overwrite),
            ("node -e 'require(\"fs\").openSync(...a)'", Rule::Overwrite),
            ("deno eval 'Deno.openSync(...a)'", Rule::Overwrite),
            ("python3 -c 'import os; os.open(*a)'", Rule::Overwrite),
            ("python3 -c 'open(*a)'", Rule::Overwrite),
            (
                "node -e 'eval(\"require(\\\"fs\\\").rmSync(\\\"/home/me\\\")\")'",
                Rule::Delete,
            ),
            (
                "python3 -c 'eval(\"__import__(\\\"os\\\").remove(\\\"/home/me\\\")\")'",
                Rule::Delete,
            ),
            (
                "python3 -c 'exec(\"import os\\nos.remove(\\\"/home/me\\\")\")'",
                Rule::Delete,
            ),
            // Not read whole by the strict gate: unknown.
            ("python3 -c 'import os; p = os.path; print(p.join(\"a\"))'", Rule::Unknown),
            ("python3 -c 'import os, sys; print(sys.argv, os.getcwd())'", Rule::Unknown),
            ("python3 -c 'import pathlib; print(list(pathlib.Path(\".\").glob(\"*.py\")))'", Rule::Unknown),
            ("python3 -c 'import os; print([f for f in os.listdir(\".\") if f.endswith(\".pyc\")])'", Rule::Unknown),
            ("node -e 'console.log(process.argv, require(\"os\").homedir())'", Rule::Unknown),
            ("node -e 'JSON.parse(require(\"fs\").readFileSync(\"package.json\"))'", Rule::Unknown),
            ("node --input-type=module -e 'import {execSync as e} from \"node:child_process\"; e(\"echo\")'", Rule::Unknown),
            ("node -e 'require(\"shelljs\").rm(\"-rf\", \"build\")'", Rule::Unknown),
            ("node -e 'require(\"shelljs\").mkdir(\"-p\", \"build\")'", Rule::Unknown),
            ("node -e 'require(\"child_process\").execSync(\"echo hi\", {stdio: \"inherit\"})'", Rule::Unknown),
            ("node -e 'require(\"fs\").openSync(\"in.txt\")'", Rule::Unknown),
            ("node -e 'require(\"fs\").openSync(\"/etc/hosts\", \"r\")'", Rule::Unknown),
            ("deno eval 'Deno.openSync(\"/etc/hosts\", {read: true})'", Rule::Unknown),
            ("deno eval 'Deno.openSync(\"/etc/hosts\", {write: false})'", Rule::Unknown),
            ("deno eval 'Deno.openSync(\"/etc/hosts\")'", Rule::Unknown),
            ("python3 -c \"import os; os.open('/etc/hosts', os.O_RDONLY)\"", Rule::Unknown),
            ("python3 -c \"import os; os.open('/etc/hosts', 0)\"", Rule::Unknown),
            // A default value: a parameter that is called is a function the
            // code is handed, and whatever it is, the reader has no row for it.
            ("python3 -c 'def f(p, r=print): r(p)'", Rule::Unknown),
            (
                "python3 -c \"import os\ndef f(p, r=os.remove): r(p)\nf('/home/me/.zshrc')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"import os\ndef f(p, *, r=os.remove): r(p)\nf('/home/me/.zshrc')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"import os\ndef f(p, r: object = os.remove): r(p)\nf('/home/me/.zshrc')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"import shutil; f = lambda p, r=shutil.rmtree: r(p)\"",
                Rule::Unknown,
            ),
            (
                r#"python3 -c "(lambda p, r=__import__('shutil').rmtree: r(p))('/home/me')""#,
                Rule::Unknown,
            ),
            // Not read whole by the strict gate: unknown.
            ("python3 -c 'def f(p, r=print): pass'", Rule::Unknown),
            ("python3 -c 'f = lambda x, y=1: x'", Rule::Unknown),
            ("python3 -c 'def f(a, *args, k: int = 1, **kw): pass'", Rule::Unknown),
            ("python3 -c 'def f(open): pass'", Rule::Unknown),
            // A module handed on as a value is unread.
            (
                "python3 -c \"import os\ndef f(o): o.remove('/home/me/.zshrc')\nf(os)\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"import glob\ndef f(g): g.os.remove('/home/me/.zshrc')\nf(glob)\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"import os\ndef f(o): o.remove('/home/me/.zshrc')\nf(os.path)\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"import sys\n(lambda s: s.modules['os'].remove('/home/me/.zshrc'))(sys)\"",
                Rule::Unknown,
            ),
            (
                r#"python3 -c "(lambda o: o.remove('/home/me/.zshrc'))(__import__('os'))""#,
                Rule::Unknown,
            ),
            (
                "python3 -c \"import operator, shutil; operator.methodcaller('rmtree','/home/me')(shutil)\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"import shutil\nfor m in [shutil]: m.rmtree('/home/me')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"import shutil; [shutil][0].rmtree('/home/me')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"import shutil; d = {'m': shutil}; d['m'].rmtree('/home/me')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"import shutil; t = shutil, 1; t[0].rmtree('/home/me')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"import shutil; m = shutil if x else None; m.rmtree('/home/me')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"import shutil; list(map(getattr(shutil, 'rmtree'), ['/home/me']))\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"import sys; sys.modules.get('os').remove('/home/me/.zshrc')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"import os\ndef f(s): s.modules['os'].remove('/home/me/.zshrc')\nf(os.sys)\"",
                Rule::Unknown,
            ),
            // A module another one imported, under the name it imported it by.
            (
                "python3 -c \"import tempfile; tempfile._os.remove('/home/me/.zshrc')\"",
                Rule::Delete,
            ),
            (
                "python3 -c \"import glob; glob.os.remove('/home/me/.zshrc')\"",
                Rule::Delete,
            ),
            // A chain of names is followed to the end.
            (
                "python3 -c \"import os; a = b = os; a.remove('/home/me/.zshrc')\"",
                Rule::Delete,
            ),
            (
                r#"node -e "(f => f.rmSync('/home/me',{recursive:true}))(require('fs'))""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "Reflect.get(require('fs'),'rmSync')('/home/me',{recursive:true})""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "Object.values(require('child_process'))[0]('rm -rf ~')""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "Object.assign(globalThis, require('fs')); rmSync('/home/me',{recursive:true})""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "const d = {f: require('fs')}; d.f.rmSync('/home/me',{recursive:true})""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "const fs = require('fs'); const o = {fs}; o.fs.rmSync('/home/me',{recursive:true})""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "[require('fs')].forEach(f => f.rmSync('/home/me',{recursive:true}))""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "for (const f of [require('fs')]) f.rmSync('/home/me',{recursive:true})""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "(r => r('fs').rmSync('/home/me',{recursive:true}))(require)""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "(f => f.rmSync('/home/me',{recursive:true}))(process.mainModule)""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "(m => m.require('fs').rmSync('/home/me'))(module)""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "const f = x => x.rmSync('/home/me',{recursive:true}); f(require('fs'))""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "module.exports = require('fs')""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "require('module')._load('fs').rmSync('/home/me',{recursive:true})""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "const fs = (0, require)('fs'); fs.rmSync('/home/me')""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "(async () => (f => f.rmSync('/home/me'))(await import('fs')))()""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "const a = b = require('fs'); a.rmSync('/home/me',{recursive:true})""#,
                Rule::Delete,
            ),
            (
                r#"node -e "const r = require; r('fs').rmSync('/home/me',{recursive:true})""#,
                Rule::Delete,
            ),
            // Not read whole by the strict gate: unknown.
            ("python3 -c 'import os; print(os.path.join(\"a\", \"b\"))'", Rule::Unknown),
            ("python3 -c 'import glob; print(glob.glob(\"*.py\"))'", Rule::Unknown),
            ("python3 -c 'import os; o = os; print(o.getcwd())'", Rule::Unknown),
            ("python3 -c 'import os; a = b = os; print(a.getcwd(), b.getcwd())'", Rule::Unknown),
            ("python3 -c 'import os; print(getattr(os, \"getcwd\")())'", Rule::Unknown),
            ("python3 -c 'import os; print((os).getcwd())'", Rule::Unknown),
            ("python3 -c 'try:\n import os\nexcept ImportError:\n os = None'", Rule::Unknown),
            ("node -e 'const fs = require(\"fs\"); console.log(fs.readFileSync(\"a\"))'", Rule::Unknown),
            ("node -e 'const { readFileSync } = require(\"fs\"); readFileSync(\"a\")'", Rule::Unknown),
            ("node -e 'const { readFileSync: r = null } = require(\"fs\"); r(\"a\")'", Rule::Unknown),
            ("node -e 'const { a, ...rest } = { a: 1, b: 2 }; console.log(rest)'", Rule::Unknown),
            ("node -e 'let fs; fs = require(\"fs\"); fs.readFileSync(\"a\")'", Rule::Unknown),
            ("node -e 'console.log(typeof process, typeof require)'", Rule::Unknown),
            ("node -e 'process.exit(0)'", Rule::Unknown),
            ("node -e 'console.log(require(\"fs\").readdirSync(\".\"))'", Rule::Unknown),
            ("node -e 'const p = require(\"fs\").promises; p.readFile(\"a\")'", Rule::Unknown),
            ("node -e 'require(\"fs\"); require(\"os\")'", Rule::Unknown),
            ("node -e 'const r = require; console.log(r(\"os\").homedir())'", Rule::Unknown),
            ("deno eval 'console.log(Deno.cwd(), typeof Deno)'", Rule::Unknown),
            // A `with` statement and a destructuring with a rest are unread.
            (
                r#"node -e "with (require('fs')) rmSync('/home/me',{recursive:true})""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "const fs = require('fs'); with (fs) { rmSync('/home/me') }""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "const {...f} = require('fs'); f.rmSync('/home/me',{recursive:true})""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "const {rmSync, ...f} = require('fs'); f.unlinkSync('/home/me')""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "const {promises: {...p}} = require('fs'); p.rm('/home/me')""#,
                Rule::Unknown,
            ),
            // A default for a member that is not there still names the member.
            (
                r#"node -e "const {rmSync = null} = require('fs'); rmSync('/home/me',{recursive:true})""#,
                Rule::Delete,
            ),
            (
                r#"node -e "const {rmSync: r = null} = require('fs'); r('/home/me',{recursive:true})""#,
                Rule::Delete,
            ),
            (
                r#"node -e "const {promises: {rm = null}} = require('fs'); rm('/home/me')""#,
                Rule::Delete,
            ),
            // Every way JavaScript reaches a module: `this` is the global
            // object in `node -e`.
            (
                r#"node -e 'this.require("fs").rmSync("/home/me", {recursive: true})'"#,
                Rule::Delete,
            ),
            (
                r#"node -e 'this.eval("require(\"fs\").rmSync(\"/home/me\",{recursive:true})")'"#,
                Rule::Delete,
            ),
            (
                r#"node -e 'this["eval"]("require(\"fs\").rmSync(\"/home/me\",{recursive:true})")'"#,
                Rule::Delete,
            ),
            (
                r#"node -e 'globalThis["require"]("fs").rmSync("/home/me", {recursive: true})'"#,
                Rule::Delete,
            ),
            (
                r#"node -e 'globalThis["eval"]("require(\"fs\").rmSync(\"/home/me\",{recursive:true})")'"#,
                Rule::Delete,
            ),
            (
                r#"node -e 'global.global.require("fs").rmSync("/home/me", {recursive: true})'"#,
                Rule::Delete,
            ),
            (
                r#"node -e 'globalThis.globalThis.require("fs").rmSync("/home/me", {recursive: true})'"#,
                Rule::Delete,
            ),
            (
                r#"node -e 'const g = globalThis; g.require("fs").rmSync("/home/me")'"#,
                Rule::Delete,
            ),
            // `require` through `call`, `apply` and `bind`.
            (
                r#"node -e 'require.call(null, "fs").rmSync("/home/me", {recursive: true})'"#,
                Rule::Delete,
            ),
            (
                r#"node -e 'require.apply(null, ["fs"]).rmSync("/home/me", {recursive: true})'"#,
                Rule::Delete,
            ),
            (
                r#"node -e 'require.bind(null)("fs").rmSync("/home/me", {recursive: true})'"#,
                Rule::Delete,
            ),
            (
                r#"node -e 'const r = require.bind(null); r("fs").rmSync("/home/me")'"#,
                Rule::Delete,
            ),
            (
                r#"node -e 'require.call(null, "child_process").execSync("rm -rf ~")'"#,
                Rule::Delete,
            ),
            ("node -e 'require.call(null, name)'", Rule::Unknown),
            ("node -e 'require.apply(null, args)'", Rule::Unknown),
            ("node -e 'require.call(null, ...args)'", Rule::Unknown),
            // `process.getBuiltinModule`.
            (
                r#"node -e 'process.getBuiltinModule("fs").rmSync("/home/me", {recursive: true})'"#,
                Rule::Delete,
            ),
            (
                r#"node -e 'require("process").getBuiltinModule("fs").rmSync("/home/me")'"#,
                Rule::Delete,
            ),
            (
                r#"node -e 'const { getBuiltinModule } = process; getBuiltinModule("fs").rmSync("/home/me")'"#,
                Rule::Delete,
            ),
            (
                r#"node -e 'const { rmSync } = process.getBuiltinModule("fs"); rmSync("/home/me")'"#,
                Rule::Delete,
            ),
            (
                r#"node -e 'const get = process.getBuiltinModule; get("child_process").execSync("rm -rf ~")'"#,
                Rule::Delete,
            ),
            ("node -e 'process.getBuiltinModule(name)'", Rule::Unknown),
            ("node -e 'f(process.getBuiltinModule)'", Rule::Unknown),
            // Bun's `import.meta.require`.
            (
                r#"bun -e 'import.meta.require("fs").rmSync("/home/me", {recursive: true})'"#,
                Rule::Delete,
            ),
            ("bun -e 'import.meta.require(name)'", Rule::Unknown),
            ("bun -e 'f(import.meta.require)'", Rule::Unknown),
            // The default export of a namespace is the module.
            (
                r#"node -e 'import * as ns from "fs"; ns.default.rmSync("/home/me", {recursive: true})'"#,
                Rule::Delete,
            ),
            (
                r#"node -e 'import { default as f } from "node:fs"; f.rmSync("/home/me")'"#,
                Rule::Delete,
            ),
            (
                r#"node -e 'import * as ns from "fs"; const { default: f } = ns; f.rmSync("/home/me")'"#,
                Rule::Delete,
            ),
            (
                r#"node -e 'import * as ns from "child_process"; ns.default.execSync("rm -rf ~")'"#,
                Rule::Delete,
            ),
            // A method only the file system has, on an object the reader cannot
            // name, is a call it cannot follow.
            ("node -e 'make().rmSync(\"/home/me\")'", Rule::Unknown),
            ("node -e 'x.rmdirSync(\"/home/me\")'", Rule::Unknown),
            ("node -e 'x.unlinkSync(\"/home/me/.zshrc\")'", Rule::Unknown),
            (
                "node -e 'x.writeFileSync(\"/home/me/.zshrc\", \"\")'",
                Rule::Unknown,
            ),
            (
                "node -e 'x.appendFileSync(\"/home/me/.zshrc\", \"\")'",
                Rule::Unknown,
            ),
            ("node -e 'x.execSync(\"rm -rf ~\")'", Rule::Unknown),
            (
                "node -e 'x.execFileSync(\"rm\", [\"-rf\", \"~\"])'",
                Rule::Unknown,
            ),
            (
                "node -e 'x.spawnSync(\"rm\", [\"-rf\", \"~\"])'",
                Rule::Unknown,
            ),
            ("node -e 'x[\"rmSync\"](\"/home/me\")'", Rule::Unknown),
            ("node -e 'this.rmSync(\"/home/me\")'", Rule::Unknown),
            (
                "node -e 'const r = x.rmSync; r(\"/home/me\")'",
                Rule::Unknown,
            ),
            (
                "node -e 'const { rmSync } = x; rmSync(\"/home/me\")'",
                Rule::Unknown,
            ),
            // Not read whole by the strict gate: unknown. (`this` of a class
            // and the names of a program are not the global object's lookups.)
            (
                r#"node -e 'this.require("path").join("a", "b")'"#,
                Rule::Unknown,
            ),
            (
                r#"node -e 'require.call(null, "path").join("a", "b")'"#,
                Rule::Unknown,
            ),
            (
                r#"node -e 'process.getBuiltinModule("fs").readFileSync("x")'"#,
                Rule::Unknown,
            ),
            (
                r#"node -e 'import * as ns from "fs"; ns.default.readFileSync("x")'"#,
                Rule::Unknown,
            ),
            (
                r#"node -e 'globalThis["require"]("fs").readFileSync("x")'"#,
                Rule::Unknown,
            ),
            (
                r#"node -e 'this.require("fs").rmSync("dist", {recursive: true})'"#,
                Rule::Unknown,
            ),
            (
                r#"node -e 'require.call(null, "fs").rmSync("dist")'"#,
                Rule::Unknown,
            ),
            (
                r#"node -e 'process.getBuiltinModule("fs").rmSync("dist")'"#,
                Rule::Unknown,
            ),
            (
                r#"bun -e 'import.meta.require("fs").rmSync("dist")'"#,
                Rule::Unknown,
            ),
            (
                r#"node -e 'import * as ns from "fs"; ns.default.rmSync("dist")'"#,
                Rule::Unknown,
            ),
            (
                r"node -e 'class A { set(k, v) { this[k] = v; return this.x; } }'",
                Rule::Unknown,
            ),
            (
                r"node -e 'console.log(typeof window, this.x)'",
                Rule::Unknown,
            ),
            // Escapes the reader does not decode are only known when the code
            // runs: Python's `\N{NAME}`.
            (
                "python3 -c \"import shutil; shutil.rmtree('\\N{SOLIDUS}home\\N{SOLIDUS}me')\"",
                Rule::Delete,
            ),
            (
                "python3 -c \"import os; os.system('rm -rf \\N{TILDE}')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"import shutil; shutil.rmtree('\\N{LATIN SMALL LETTER E}')\"",
                Rule::Delete,
            ),
            (
                "python3 -c \"import shutil; shutil.rmtree('\\x')\"",
                Rule::Delete,
            ),
            // JavaScript's legacy octal escapes, which `node -e` reads.
            (
                "node -e \"require('fs').rmSync('\\57home\\57me', {recursive: true})\"",
                Rule::Delete,
            ),
            (
                "node -e \"require('fs').rmSync('\\176', {recursive: true})\"",
                Rule::Delete,
            ),
            (
                "node -e \"require('fs').rmSync('\\176/.ssh', {recursive: true})\"",
                Rule::Delete,
            ),
            (
                "node -e \"require('child_process').execSync('rm -rf \\176')\"",
                Rule::Delete,
            ),
            (
                "node -e \"require('fs').rmSync('\\057home\\057me')\"",
                Rule::Delete,
            ),
            // One it does not decode.
            ("node -e \"require('fs').rmSync('\\ud83d')\"", Rule::Delete),
            (
                "node -e \"require('child_process').execSync('rm -rf \\u{110000}')\"",
                Rule::Unknown,
            ),
            // Not read whole by the strict gate: unknown.
            (
                "python3 -c \"import shutil; shutil.rmtree('dist\\x2fx')\"",
                Rule::Unknown,
            ),
            (
                "node -e \"require('fs').rmSync('dist\\57x')\"",
                Rule::Unknown,
            ),
            (
                "node -e \"require('fs').rmSync('\\144ist')\"",
                Rule::Unknown,
            ),
            ("node -e \"require('fs').rmSync('\\400')\"", Rule::Unknown),
            (
                "node -e \"require('fs').rmSync('\\x64ist')\"",
                Rule::Unknown,
            ),
            // Python reads `ｒｅｍｏｖｅ` (full-width) as `remove`: each of these
            // runs the call it spells, and is not one the reader follows.
            (
                "python3 -c \"import os; os.ｒｅｍｏｖｅ('/home/me/.zshrc')\"",
                Rule::Unknown,
            ),
            ("python3 -c \"ｅｘｅｃ(input())\"", Rule::Unknown),
            (
                "python3 -c \"import ｓｈｕｔｉｌ; ｓｈｕｔｉｌ.rmtree('/home/me')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"__ｉｍｐｏｒｔ__('os').remove('/home/me/.zshrc')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"ｏｐｅｎ('/home/me/.zshrc','w').write('x')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"import os; os.ｃｈｄｉｒ('/home/me'); import shutil; shutil.rmtree('.ssh')\"",
                Rule::Unknown,
            ),
            // Also a keyword argument's name, an alias and a method.
            (
                "python3 -c \"import os; os.remove('/home/me/.zshrc', ｄｉｒ_ｆｄ=1)\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"from os import remove as ｒ; ｒ('/home/me/.zshrc')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"from pathlib import Path; Path('/home/me/.zshrc').ｕｎｌｉｎｋ()\"",
                Rule::Unknown,
            ),
            // Not read whole by the strict gate: unknown.
            ("python3 -c \"import os; print(os.getcwd(), 'ｅｘｅｃ')\"", Rule::Unknown),
            // Node reads `\u0072mSync` as `rmSync`: JavaScript names written
            // with an escape are unread.
            (
                r#"node -e "require('fs').\u0072mSync('/home/me',{recursive:true})""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "const {\u0072mSync}=require('fs'); \u0072mSync('/home/me',{recursive:true})""#,
                Rule::Unknown,
            ),
            (r#"node -e "\u0065val(process.argv[1])""#, Rule::Unknown),
            (
                r#"node -e "require('child_process').e\u0078ecSync('rm -rf ~')""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "const cp=require('child_process'); cp.\u{65}xecSync('rm -rf ~')""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "process.\u0063hdir('/home/me'); require('fs').rmSync('.ssh',{recursive:true})""#,
                Rule::Unknown,
            ),
            // A shorthand property, a pattern with a rename and a local name.
            (
                r#"node -e "const {rmSync: \u0072}=require('fs'); r('/home/me',{recursive:true})""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "const \u0066s=require('fs'); fs.rmSync('/home/me',{recursive:true})""#,
                Rule::Unknown,
            ),
            // Not read whole by the strict gate: unknown.
            (
                r#"node -e "console.log(require('fs').readFileSync('\u002fetc/hosts', 'utf8'))""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "const o = {a: 1}; console.log(o.a)""#,
                Rule::Unknown,
            ),
            // A module bound in a class body is unread.
            (
                "python3 -c \"import os\nclass C: o = os\nC.o.remove('/home/me/.zshrc')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"import os\nclass C: o = os\nC().o.system('rm -rf ~')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"class C:\n    from os import system\nC.system('rm -rf ~')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"class C:\n    import shutil as s\nC().s.rmtree('/home/me')\"",
                Rule::Unknown,
            ),
            // A call the reader knows, bound the same way.
            (
                "python3 -c \"import os\nclass C:\n    r = os.remove\nC.r('/home/me/.zshrc')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"import os\nclass C:\n    r = getattr(os, 'remove')\nC.r('/home/me/.zshrc')\"",
                Rule::Unknown,
            ),
            // A class in a class.
            (
                "python3 -c \"import os\nclass A:\n    class B:\n        o = os\nA.B.o.remove('/home/me/.zshrc')\"",
                Rule::Unknown,
            ),
            // Not read whole by the strict gate: unknown. (A class that binds
            // nothing the reader looks for; a name bound in a method is the
            // method's own.)
            ("python3 -c \"class C:\n    x = 1\n    def f(self):\n        return self.x\nprint(C().f())\"", Rule::Unknown),
            ("python3 -c \"import os\nclass C:\n    def f(self):\n        return os.getcwd()\nprint(C().f())\"", Rule::Unknown),
            ("python3 -c \"class C:\n    name = 'os'\nprint(C.name)\"", Rule::Unknown),
            ("python3 -c \"class C:\n    def f(self):\n        o = 1\n        return o\nprint(C().f())\"", Rule::Unknown),
            // A Python name bound more than once to different things is not
            // followed.
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
            // Not read whole by the strict gate: unknown. (The same thing
            // twice, or things the reader has no use for.)
            ("python3 -c 'import os\nimport os\nfrom os import path\nimport os.path\nprint(os.getcwd())'", Rule::Unknown),
            ("python3 -c 'import os\nx = os\nx = os\nprint(x.getcwd())'", Rule::Unknown),
            ("python3 -c 'a = b\na = c\nprint(a)'", Rule::Unknown),
            ("python3 -c 'import json as j\nk = 1\nk = 2\nprint(j.dumps(k))'", Rule::Unknown),
            ("python3 -c 'from os import path\nimport os.path as path\nprint(path.sep)'", Rule::Unknown),
            // A JavaScript key that is not a plain name names its member. A
            // member of a module that is no call the reader has a row for
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
            // Names that literal `exec` and `eval` code binds or uses are not
            // read apart: what a name is bound to in nested code, followed
            // outside it.
            (
                "python3 -c \"exec('import shutil as json'); json.rmtree('/home/me')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"exec('from shutil import rmtree as f'); f('/home/me')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"exec('import os as j'); j.system('rm -rf ~')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"exec('global j\\nimport shutil as j'); j.rmtree('/home/me')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"exec(\\\"exec('import shutil as j')\\\"); j.rmtree('/home/me')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"exec('j = __import__(\\\"shutil\\\")'); j.rmtree('/home/me')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"exec('r = shutil.rmtree'); r('/home/me')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"exec('(j := __import__(\\\"os\\\"))'); j.system('rm -rf ~')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"import os as o; exec('p = o.remove'); p('/home/me/f')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"exec('import distutils.dir_util as d'); d.remove_tree('/home/me')\"",
                Rule::Unknown,
            ),
            // A profiler's string runs in the namespace of the code.
            (
                "python3 -c \"import cProfile; cProfile.run('import shutil as j'); j.rmtree('/home/me')\"",
                Rule::Unknown,
            ),
            // A name this code bound, used in nested code.
            (
                "python3 -c \"import shutil as s; exec('s.rmtree(\\\"/home/me\\\")')\"",
                Rule::Unknown,
            ),
            (
                "python3 -c \"from os import remove as r; exec('r(\\\"/home/me/f\\\")')\"",
                Rule::Unknown,
            ),
            // What the nested code does is read all the same.
            (
                "python3 -c \"exec('import shutil'); shutil.rmtree('/home/me')\"",
                Rule::Delete,
            ),
            (
                "python3 -c \"import os; exec('os.remove(\\\"/home/me/f\\\")')\"",
                Rule::Delete,
            ),
            // JavaScript: `var`, destructuring, an outer name assigned.
            (
                "node -e \"eval(\\\"var m = require('fs')\\\"); m.rm('/home/me',{recursive:true},()=>{})\"",
                Rule::Unknown,
            ),
            (
                "node -e \"eval(\\\"var {rm} = require('fs')\\\"); rm('/home/me',{recursive:true},()=>{})\"",
                Rule::Unknown,
            ),
            (
                "node -e \"eval(\\\"var cp = require('child_process')\\\"); cp.exec('rm -rf ~')\"",
                Rule::Unknown,
            ),
            (
                "node -e \"var m; eval('m = require(\\\"fs\\\")'); m.rm('/home/me',{recursive:true},()=>{})\"",
                Rule::Unknown,
            ),
            (
                "node -e \"eval('var m = require(\\\"fs\\\").promises'); m.rm('/home/me',{recursive:true})\"",
                Rule::Unknown,
            ),
            (
                "node -e \"eval('let { rm } = require(\\\"fs/promises\\\")'); rm('/home/me',{recursive:true})\"",
                Rule::Unknown,
            ),
            (
                "node -e \"eval('function f(p) { return require(\\\"fs\\\").rm(p, {recursive:true}, () => {}) }'); f('/home/me')\"",
                Rule::Delete,
            ),
            // A name this code bound, used in nested code.
            (
                "node -e \"const f = require('fs'); eval('f.rm(\\\"/home/me\\\",{recursive:true},()=>{})')\"",
                Rule::Unknown,
            ),
            (
                "node -e \"const { rm } = require('fs'); eval('rm(\\\"/home/me\\\",{recursive:true},()=>{})')\"",
                Rule::Unknown,
            ),
            // Nested in nested code.
            (
                "node -e \"eval(\\\"eval('var m = require(\\\\\\\"fs\\\\\\\")')\\\"); m.rm('/home/me',{recursive:true},()=>{})\"",
                Rule::Unknown,
            ),
            // What the nested code does is read all the same.
            (
                "node -e \"eval('require(\\\"fs\\\").rmSync(\\\"/home/me\\\",{recursive:true})')\"",
                Rule::Delete,
            ),
            // Not read whole by the strict gate: unknown.
            ("python3 -c \"exec('x = 1'); print(x)\"", Rule::Unknown),
            ("python3 -c \"exec('print(1)')\"", Rule::Unknown),
            ("python3 -c \"exec('def f(): return 1'); print(f())\"", Rule::Unknown),
            ("python3 -c \"exec('a = [1, 2]'); print(a)\"", Rule::Unknown),
            ("python3 -c \"x = 1; exec('print(x)')\"", Rule::Unknown),
            ("python3 -c \"import json; exec('print(json.dumps(1))')\"", Rule::Unknown),
            ("node -e \"eval('var x = 1'); console.log(x)\"", Rule::Unknown),
            ("node -e \"eval('console.log(1)')\"", Rule::Unknown),
            ("node -e \"var x = 1; eval('console.log(x)')\"", Rule::Unknown),
            ("node -e \"eval('function f() { return 1 }'); console.log(f())\"", Rule::Unknown),
            // A dotted import is the top package unless a `fromlist` is given.
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
            // Not read whole by the strict gate: unknown. (With a `fromlist`
            // the submodule is what comes back, and it has no `system`.)
            ("python3 -c \"__import__('os.path', fromlist=['join']).join('a', 'b')\"", Rule::Unknown),
            ("python3 -c \"import importlib; importlib.import_module('os.path').join('a', 'b')\"", Rule::Unknown),
            // The value of `eval` comes back under no name.
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
            // Not read whole by the strict gate: unknown. (A statement of its
            // own, or a value that is only printed.)
            ("node -e \"eval('1+1')\"", Rule::Unknown),
            ("python3 -c \"eval('1+1')\"", Rule::Unknown),
            ("python3 -c \"print(eval('1+2'))\"", Rule::Unknown),
            // The members of node's `module` that load or run code are not
            // read.
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
            // Not read whole by the strict gate: unknown. (Plain data.)
            ("node -e \"console.log(module.paths, module.id, module.filename)\"", Rule::Unknown),
            ("node -e \"module.exports = 1\"", Rule::Unknown),
            // The workspace's own module, awaited, is read as before: not read
            // whole by the strict gate, unknown.
            ("node --input-type=module -e \"await import('./x.js')\"", Rule::Unknown),
            ("node --input-type=module -e \"const fs = await import('node:fs'); fs.readFileSync('notes.txt')\"", Rule::Unknown),
            // Reading a member of a module, and assigning to the code's own
            // objects, is not an assignment to the module: not read whole by
            // the strict gate, unknown.
            ("python3 -c \"import os\nx = os.path.join('a', 'b')\nprint(x)\"", Rule::Unknown),
            ("python3 -c \"class A: pass\na = A()\na.x = 1\nprint(a.x)\"", Rule::Unknown),
            ("node -e \"const o = {}; o.x = 1; console.log(o.x)\"", Rule::Unknown),
            ("node -e \"const path = require('path'); const p = path.join('a', 'b'); console.log(p)\"", Rule::Unknown),
            ("node -e \"process.exitCode = 1; module.exports = 1; process.env.NODE_ENV = 'production'\"", Rule::Unknown),
            ("node -e \"function F() {} F.prototype.go = function () { return 1 }; console.log(1)\"", Rule::Unknown),
        ],
    );
    let unknown = lines(&[
        // An awaited import of a computed value is unknown.
        "node --input-type=module -e \"await import(process.argv[1])\"",
        "deno eval \"await import(Deno.args[0])\"",
        "bun -e \"await import(process.argv[1])\"",
        "deno eval \"const m = await import(Deno.args[0])\"",
        "deno eval \"await import(Deno.env.get('X'))\"",
        "node -e \"(async () => { await import(process.argv[1]) })()\"",
        "node -e \"async function f() { await import(process.argv[1]) } f()\"",
        "deno eval \"const u = 'https://x.example/a.ts'; await import(u)\"",
        // Not awaited, as before.
        "node -e \"import(process.argv[1])\"",
        // An assignment to a module or a builtin prototype makes the code
        // unknown.
        "python3 -c \"import os\nos.path.join = lambda *a: '/home/me/.zshrc'\nos.remove(os.path.join('a', 'b'))\"",
        "python3 -c \"import os\nos.path.expanduser = lambda p: '/home/me/.zshrc'\nos.remove(os.path.expanduser('~/x'))\"",
        "python3 -c \"import posixpath, os\nposixpath.join = lambda *a: '/home/me/.zshrc'\nos.remove(posixpath.join('a', 'b'))\"",
        "python3 -c \"from pathlib import Path\nimport os\nPath.__truediv__ = lambda s, o: Path('/home/me/.zshrc')\nos.remove(Path('a') / 'b')\"",
        "python3 -c \"import os\nsetattr(os.path, 'join', lambda *a: '/home/me/.zshrc')\nos.remove(os.path.join('a', 'b'))\"",
        "node -e \"const fs = require('fs'); const path = require('path'); path.resolve = () => '/home/me/.zshrc'; fs.rmSync(path.resolve('a'))\"",
        "node -e \"const fs = require('fs'); require('path').join = () => '/home/me/.zshrc'; fs.rmSync(require('path').join('a'))\"",
        "node -e \"const fs = require('fs'); process.cwd = () => '/home/me'; console.log(fs.readFileSync(require('path').join(process.cwd(), '.ssh/id_rsa')))\"",
        "node -e \"const fs = require('fs'); String.prototype.concat = () => '/home/me/.zshrc'; fs.rmSync('a'.concat('b'))\"",
        "node -e \"const fs = require('fs'); Array.prototype.join = () => '/home/me/.zshrc'; fs.rmSync(['a', 'b'].join('/'))\"",
        "node -e \"const fs = require('fs'); String.prototype.toString = () => '/home/me/.zshrc'; fs.rmSync('a'.toString())\"",
        "node -e \"const fs = require('fs'); Object.defineProperty(String.prototype, 'concat', { value: () => '/home/me/.zshrc' }); fs.rmSync('a'.concat('b'))\"",
        "node -e \"const fs = require('fs'); ''.__proto__.concat = () => '/home/me/.zshrc'; fs.rmSync('a'.concat('b'))\"",
        "node -e \"const fs = require('fs'); Object.getPrototypeOf('').concat = () => '/home/me/.zshrc'; fs.rmSync('a'.concat('b'))\"",
        "node -e \"const fs = require('fs'); const S = String; S.prototype.concat = () => '/home/me/.zshrc'; fs.rmSync('a'.concat('b'))\"",
        "deno eval \"Deno.cwd = () => '/home/me'; Deno.removeSync(Deno.cwd() + '/.zshrc')\"",
        "node -e \"process.env.HOME = '/tmp'; console.log(1)\"",
        "bun -e \"Bun.file = () => 1; console.log(1)\"",
    ]);
    assert_risky_as(&unknown, &[Rule::Unknown]);
    // The literal form of a network module is downloaded code.
    let downloaded = lines(&["deno eval \"await import('https://x.example/a.ts')\""]);
    assert_risky_as(&downloaded, &[Rule::RunDownloaded]);
}

/// A script that sets `levels` names, each by `line(at)` from the one before,
/// and then runs `last`.
fn chain(interpreter: &str, levels: usize, line: impl Fn(usize) -> String, last: &str) -> String {
    let (start, prelude, end) = if interpreter == "python3" {
        (
            "python3 - <<'PY'",
            "import os\nfrom pathlib import Path\n",
            "PY",
        )
    } else {
        ("node - <<'JS'", "const path = require('path');\n", "JS")
    };
    let mut text = format!("{start}\n{prelude}");
    for at in 0..levels {
        text.push_str(&line(at));
        text.push('\n');
    }
    text.push_str(last);
    text.push('\n');
    text.push_str(end);
    text
}

#[test]
fn names_each_set_to_twice_the_one_before_are_read_in_bounded_time() {
    // A name put back as its string, when the next name is set, doubled the
    // string at every line: 30 lines took seconds and 36 ran out of memory.
    // A string is cut at a length now, and the name that went over it is a
    // path the guard does not read.
    let base = "xy";
    let mut lines: Vec<(String, Rule)> = Vec::new();
    let python: Vec<Box<dyn Fn(usize) -> String>> = vec![
        Box::new(|at| match at {
            0 => format!("a0 = '{base}'"),
            _ => format!("a{at} = a{p} + a{p}", p = at - 1),
        }),
        Box::new(|at| match at {
            0 => format!("a0 = '{base}'"),
            _ => format!("a{at} = f'{{a{p}}}{{a{p}}}'", p = at - 1),
        }),
        Box::new(|at| match at {
            0 => format!("a0 = '{base}'"),
            _ => format!("a{at} = os.path.join(a{p}, a{p})", p = at - 1),
        }),
        Box::new(|at| match at {
            0 => format!("a0 = '{base}'"),
            _ => format!("a{at} = Path(a{p}) / a{p}", p = at - 1),
        }),
        Box::new(|at| match at {
            0 => format!("a0 = '{base}'"),
            _ => format!("a{at} = ''.join([a{p}, a{p}])", p = at - 1),
        }),
        Box::new(|at| match at {
            0 => format!("a0 = '{base}'"),
            _ => format!("a{at} = Path(a{p}).joinpath(a{p})", p = at - 1),
        }),
        Box::new(|at| match at {
            0 => "a0 = '/home/me/.ssh/id_rsa'".to_string(),
            _ => format!("a{at} = a{p} + a{p}", p = at - 1),
        }),
    ];
    for line in python {
        for levels in [30, 40, 100] {
            let read = format!("print(open(a{}).read())", levels - 1);
            lines.push((chain("python3", levels, &line, &read), Rule::Unknown));
        }
    }
    let javascript: Vec<Box<dyn Fn(usize) -> String>> = vec![
        Box::new(|at| match at {
            0 => format!("const a0 = '{base}';"),
            _ => format!("const a{at} = a{p} + a{p};", p = at - 1),
        }),
        Box::new(|at| match at {
            0 => format!("const a0 = '{base}';"),
            _ => format!("const a{at} = `${{a{p}}}${{a{p}}}`;", p = at - 1),
        }),
        Box::new(|at| match at {
            0 => format!("const a0 = '{base}';"),
            _ => format!("const a{at} = path.join(a{p}, a{p});", p = at - 1),
        }),
        Box::new(|at| match at {
            0 => "const a0 = '/home/me/.ssh/id_rsa';".to_string(),
            _ => format!("const a{at} = [a{p}, a{p}].join('');", p = at - 1),
        }),
    ];
    for line in javascript {
        for levels in [30, 40, 100] {
            let read = format!("require('fs').readFileSync(a{});", levels - 1);
            lines.push((chain("node", levels, &line, &read), Rule::Unknown));
        }
    }
    // One long string used thousands of times in one expression: built a
    // piece at a time, it is cut at the limit, not built.
    let long = "y".repeat(3000);
    let python_args = vec!["a"; 12_000].join(", ");
    let python_template = "{a}".repeat(12_000);
    let javascript_template = "${a}".repeat(10_000);
    for body in [
        format!("import os\na = '{long}'\nk = os.path.join({python_args})\nopen(k)"),
        format!("a = '{long}'\nk = f'{python_template}'\nopen(k)"),
        format!("a = '{long}'\nk = ''.join([{python_args}])\nopen(k)"),
        format!("a = '{long}'\nk = Path({python_args})\nopen(k)"),
    ] {
        lines.push((format!("python3 - <<'PY'\n{body}\nPY"), Rule::Unknown));
    }
    for body in [
        format!(
            "const path = require('path');\nconst a = '{long}';\nconst k = path.join({python_args});\nrequire('fs').readFileSync(k);"
        ),
        format!(
            "const a = '{long}';\nconst k = `{javascript_template}`;\nrequire('fs').readFileSync(k);"
        ),
        format!(
            "const a = '{long}';\nconst k = [{python_args}].join('');\nrequire('fs').readFileSync(k);"
        ),
    ] {
        lines.push((format!("node - <<'JS'\n{body}\nJS"), Rule::Unknown));
    }
    for (line, rule) in &lines {
        assert!(line.len() <= 64 * 1024, "{}", line.len());
        let took = took(line, Shell::Posix, &posix());
        assert!(
            took < std::time::Duration::from_secs(2),
            "{} bytes took {took:?}: {line}",
            line.len()
        );
        // Not read, so not safe: a name that went over the limit is no path
        // the guard knows.
        let rules: Vec<Rule> = classify(line, Shell::Posix, &posix())
            .findings()
            .iter()
            .map(|finding| finding.rule)
            .collect();
        assert!(rules.contains(rule), "{rules:?}: {line}");
    }
    // Under the limit the strings are still put back, so the key is found
    // at the end of a chain.
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[
            // A here-document is never read whole: unknown.
            (
                &chain(
                    "python3",
                    6,
                    |at| match at {
                        0 => "a0 = 'a'".to_string(),
                        _ => format!("a{at} = a{p} + 'b'", p = at - 1),
                    },
                    "print(open(a5).read())",
                ),
                Rule::Unknown,
            ),
            (
                &chain(
                    "python3",
                    6,
                    |at| match at {
                        0 => "a0 = '/home/me/.ssh/'".to_string(),
                        _ => format!("a{at} = a{p}", p = at - 1),
                    },
                    "print(open(a5 + 'id_rsa').read())",
                ),
                Rule::ReadSecret,
            ),
            (
                &chain(
                    "node",
                    6,
                    |at| match at {
                        0 => "const a0 = '/home/me/.ssh/';".to_string(),
                        _ => format!("const a{at} = a{p};", p = at - 1),
                    },
                    "require('fs').readFileSync(a5 + 'id_rsa');",
                ),
                Rule::ReadSecret,
            ),
        ],
    );
}

#[test]
fn a_name_that_holds_more_than_the_reader_keeps_is_not_read_as_any_string() {
    // 65 strings written out, the key last: every one is read, as `cat` of
    // each is.
    let paths: Vec<String> = (0..65).map(|at| format!("'a{at}.txt'")).collect();
    let many = format!("{}, '/home/me/.ssh/id_rsa'", paths.join(", "));
    let many_js = format!("{}, '/home/me/.ssh/id_rsa'", paths.join(", "));
    // A thousand, in a line well under the length limit.
    let thousands: Vec<String> = (0..1000).map(|at| format!("'a{at}'")).collect();
    let thousands = format!("{}, '/home/me/.ssh/id_rsa'", thousands.join(","));
    let safe_thousands: Vec<String> = (0..1000).map(|at| format!("'a{at}'")).collect();
    let safe_thousands = safe_thousands.join(",");
    // A name set to more strings, in all, than the reader holds is a path it
    // does not read: not safe, as the key may be any of them. Strings made
    // of one long string each pile up past the budget.
    let long = "d".repeat(1000);
    let derived: Vec<String> = (0..400)
        .map(|at| format!("p{at} = base + '{at}'"))
        .collect();
    let derived = derived.join("\n");
    let script = format!("base = '/home/me/work/repo/{long}'\n{derived}\n");
    // Read again and again, a name with a thousand strings is not read in
    // full each time: past a count of reads the code is not followed.
    let strings: Vec<String> = (0..1000).map(|at| format!("'b{at}'")).collect();
    let reads = "print(open(k).read())\n".repeat(200);
    let nine_names = format!(
        "python3 - <<'PY'\n{}\nprint(open({}).read())\nPY",
        (0..9)
            .map(|at| format!("for n{at} in ['x{at}', 'y{at}']: pass"))
            .collect::<Vec<_>>()
            .join("\n"),
        (0..9)
            .map(|at| format!("n{at}"))
            .collect::<Vec<_>>()
            .join(" + ")
    );
    check(
        Shell::Posix,
        &posix(),
        &[
            // A name grown in place is a string the reader does not work out;
            // one set to a string is.
            r#"python3 -c "k = 'a.txt'; print(open(k).read())""#,
            r#"python3 -c "k = j = 'a.txt'; print(open(k).read())""#,
            // A name that holds more than one string, in a longer path, is
            // read once for each of them.
            r#"python3 -c "d = 'a'; d = 'b'; print(open(d + '/x').read())""#,
        ],
        &[
            // Loops, here-documents and a `require` are not read whole by the
            // strict gate: unknown.
            (
                &format!("python3 -c \"for k in [{}]: print(open(k).read())\"", paths.join(", ")),
                Rule::Unknown,
            ),
            (
                &format!("python3 - <<'PY'\nfor k in [{safe_thousands}]:\n    print(open(k).read())\nPY"),
                Rule::Unknown,
            ),
            (
                &format!(
                    "node - <<'JS'\nfor (const k of [{safe_thousands}]) require('fs').readFileSync(k);\nJS"
                ),
                Rule::Unknown,
            ),
            (
                &format!("python3 -c \"for k in [{many}]: print(open(k).read())\""),
                Rule::ReadSecret,
            ),
            (
                &format!("python3 - <<'PY'\nfor k in [{thousands}]:\n    print(open(k).read())\nPY"),
                Rule::ReadSecret,
            ),
            (
                &format!(
                    "node - <<'JS'\nfor (const k of [{many_js}]) require('fs').readFileSync(k);\nJS"
                ),
                Rule::ReadSecret,
            ),
            (
                &format!(
                    "node - <<'JS'\nfor (const k of [{thousands}]) require('fs').readFileSync(k);\nJS"
                ),
                Rule::ReadSecret,
            ),
            // More strings than the reader holds (a here-document is never
            // read whole: unknown).
            (
                &format!("python3 - <<'PY'\n{script}print(open(p0).read())\nPY"),
                Rule::Unknown,
            ),
            (
                &format!("python3 - <<'PY'\n{script}print(open(p399).read())\nPY"),
                Rule::Unknown,
            ),
            (
                &format!(
                    "python3 - <<'PY'\nfor k in [{}]:\n    pass\n{reads}PY",
                    strings.join(",")
                ),
                Rule::Unknown,
            ),
            // A name grown in place.
            (
                r#"python3 -c "k = '/home/me/'; k += '.ssh/id_rsa'; print(open(k).read())""#,
                Rule::Unknown,
            ),
            (
                r#"python3 -c "k = j = '/home/me/.ssh/id_rsa'; print(open(k).read())""#,
                Rule::ReadSecret,
            ),
            (
                r#"python3 -c "k = j = '/home/me/.ssh/id_rsa'; print(open(j).read())""#,
                Rule::ReadSecret,
            ),
            (
                "node -e 'let k = \"/home/me/\"; k += \".ssh/id_rsa\"; require(\"fs\").readFileSync(k)'",
                Rule::Unknown,
            ),
            (
                "node -e 'let k, j; k = j = \"/home/me/.ssh/id_rsa\"; require(\"fs\").readFileSync(k)'",
                Rule::ReadSecret,
            ),
            // A name that holds more than one string, in a longer path, is
            // read once for each of them, as the shell reads `for d in a
            // /home/me/.ssh; do cat $d/id_rsa; done`.
            (
                r#"python3 -c "for d in ['a', '/home/me/.ssh']: print(open(d + '/id_rsa').read())""#,
                Rule::ReadSecret,
            ),
            (
                "python3 -c \"import os\nfor d in ['a', '/home/me/.ssh']: print(open(os.path.join(d, 'id_rsa')).read())\"",
                Rule::ReadSecret,
            ),
            (
                "python3 -c \"for d in ['a', '/home/me/']:\n    for n in ['x', '.ssh/id_rsa']: print(open(d + n).read())\"",
                Rule::ReadSecret,
            ),
            (
                // A name built from one that holds two.
                "python3 -c \"for d in ['a', '/home/me/.ssh']: pass\nk = d + '/id_rsa'\nprint(open(k).read())\"",
                Rule::ReadSecret,
            ),
            (
                "node -e 'for (const d of [\"a\", \"/home/me/.ssh\"]) require(\"fs\").readFileSync(d + \"/id_rsa\")'",
                Rule::ReadSecret,
            ),
            (
                "node -e 'for (const d of [\"a\", \"/home/me/.ssh\"]) require(\"fs\").readFileSync(`${d}/id_rsa`)'",
                Rule::ReadSecret,
            ),
            // More choices than the reader goes through (9 names of 2
            // strings are 512) are a path it does not read.
            (&nine_names, Rule::Unknown),
            // Not read whole by the strict gate: unknown.
            ("python3 -c \"import os\nfor n in ['a.txt', 'b.txt']: print(open(os.path.join('src', n)).read())\"", Rule::Unknown),
            ("python3 -c \"for n in ['a', 'b']: print(open(f'src/{n}.txt').read())\"", Rule::Unknown),
            ("node -e 'for (const n of [\"a\", \"b\"]) require(\"fs\").readFileSync(\"src/\" + n + \".txt\")'", Rule::Unknown),
        ],
    );
}
