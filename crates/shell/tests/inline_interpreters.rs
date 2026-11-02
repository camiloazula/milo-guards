//! How code reaches an interpreter: every code flag of node and bun, the
//! operands of `deno eval`, Python 2's `exec`, code an interpreter reads from
//! its input (a here-document, `-i`, `repl`, a debugger), flags that only
//! print a version or help, perl, ruby, php and lua options that take the
//! print flag as their value, runners and bun options in front of the code,
//! hashbang lines, Python coding declarations and carriage returns, `data:`
//! URLs and `NODE_OPTIONS`, and code handed to an interpreter under cmd and
//! PowerShell.

mod common;

use common::{check, posix, rules, windows};
use milo_guards_shell::{Rule, Shell};

#[test]
fn code_is_read_however_it_reaches_the_interpreter() {
    check(
        Shell::Posix,
        &posix(),
        &[
            // A program or a script file, and nothing read from the input.
            "deno run main.ts",
            "deno run --allow-read main.ts",
            "deno test",
            "bun run build.ts",
            "bun install",
            "bun main.ts",
            // Deno's options that print do not read the input.
            "deno --version",
            "deno -V",
            "deno --help",
            "deno -h",
            "php --version",
            "ruby --help",
            "php --help",
            // A value joined to its option takes no word.
            "ruby --enable=gems --version",
            // Modules that are not a `data:` URL are as they were.
            "node --import ./setup.js build.js",
            "node --import ./setup.js <<'JS'\nconsole.log(1)\nJS",
            "NODE_OPTIONS=--import=data:text/javascript,1 echo 1",
            // A hashbang not at the start of the code is a syntax error, not a
            // comment.
            "node -e \"console.log(1)\"",
            // A coding line in code that is not bytes is ignored by Python.
            "python3 -c '# coding: utf-7\nprint(1)'",
        ],
        &[
            // Every code flag of node and bun: the last one runs, and an
            // earlier one is read all the same.
            (
                r#"node -e "console.log(1)" -e "require('fs').rmSync('/home/me',{recursive:true})""#,
                Rule::Delete,
            ),
            (
                r#"node -e "require('fs').rmSync('/home/me',{recursive:true})" -e "console.log(1)""#,
                Rule::Delete,
            ),
            (
                r#"node -p -e "require('fs').rmSync('/home/me',{recursive:true})""#,
                Rule::Delete,
            ),
            (
                r#"node --eval 1 --eval "require('fs').rmSync('/home/me',{recursive:true})""#,
                Rule::Delete,
            ),
            (
                r#"node -p 1 -e "require('fs').rmSync('/home/me',{recursive:true})""#,
                Rule::Delete,
            ),
            (
                r#"node -pe 1 -e "require('fs').rmSync('/home/me',{recursive:true})""#,
                Rule::Delete,
            ),
            (
                r#"node --print=1 --eval="require('fs').rmSync('/home/me',{recursive:true})""#,
                Rule::Delete,
            ),
            (
                r#"node -r ts-node/register -e 1 -e "require('fs').rmSync('/home/me',{recursive:true})""#,
                Rule::Delete,
            ),
            (
                r#"bun -e 1 -e "require('fs').rmSync('/home/me',{recursive:true})""#,
                Rule::Delete,
            ),
            (
                r#"bun --print 1 --eval "require('fs').rmSync('/home/me',{recursive:true})""#,
                Rule::Delete,
            ),
            // A piece only known when it runs, or an option that could be one.
            ("node -e 1 -e \"$CODE\"", Rule::Unknown),
            ("node -e 1 $OPTION -e 2", Rule::Unknown),
            // Not read whole by the strict gate: unknown.
            (
                "node -e 'console.log(1)' -e 'console.log(2)'",
                Rule::Unknown,
            ),
            ("node -p -e 'console.log(1)'", Rule::Unknown),
            ("node -p 1 -e 'console.log(2)'", Rule::Unknown),
            ("node --eval 1 --eval 2", Rule::Unknown),
            ("node --print=1 --eval=2", Rule::Unknown),
            ("node -pe 1 -e 2", Rule::Unknown),
            ("bun -e 1 -e 2", Rule::Unknown),
            ("bun -p 1 -e 2", Rule::Unknown),
            (
                "node -e 'console.log(process.argv)' script-arg",
                Rule::Unknown,
            ),
            // Every operand of `deno eval` is read.
            (
                r#"deno eval --reload "Deno.removeSync('/home/me',{recursive:true})" "console.log(1)""#,
                Rule::Delete,
            ),
            (
                r#"deno eval -L info "Deno.removeSync('/home/me',{recursive:true})""#,
                Rule::Delete,
            ),
            (
                r#"deno eval --log-level info "Deno.removeSync('/home/me',{recursive:true})""#,
                Rule::Delete,
            ),
            (
                r#"deno eval --v8-flags "Deno.removeSync('/home/me',{recursive:true})" 1"#,
                Rule::Delete,
            ),
            (
                r#"deno eval --env-file "Deno.removeSync('/home/me',{recursive:true})""#,
                Rule::Delete,
            ),
            (
                r#"deno eval "console.log(1)" "Deno.removeSync('/home/me',{recursive:true})""#,
                Rule::Delete,
            ),
            (
                r#"deno eval -- "Deno.removeSync('/home/me',{recursive:true})""#,
                Rule::Delete,
            ),
            (
                r#"deno eval --ext ts "Deno.removeSync('/home/me',{recursive:true})""#,
                Rule::Delete,
            ),
            // An operand that is a path and not code does not parse: unread.
            (
                "deno eval --config ./deno.json 'console.log(1)'",
                Rule::Unknown,
            ),
            ("deno eval 'console.log(1)' \"$ARG\"", Rule::Unknown),
            // Not read whole by the strict gate: unknown.
            ("deno eval --reload 'console.log(1)'", Rule::Unknown),
            ("deno eval -L info 'console.log(1)'", Rule::Unknown),
            (
                "deno eval --log-level debug 'console.log(1)'",
                Rule::Unknown,
            ),
            ("deno eval --ext ts 'console.log(1)'", Rule::Unknown),
            ("deno eval -c deno.json 'console.log(1)'", Rule::Unknown),
            ("deno eval 'console.log(Deno.args)' a b", Rule::Unknown),
            ("deno eval -- 'console.log(1)'", Rule::Unknown),
            (
                "deno eval --v8-flags=--max-old-space-size=100 'console.log(1)'",
                Rule::Unknown,
            ),
            // The `exec` statement of Python 2.
            (
                r#"python2 -c 'exec "import os; os.remove(\"/home/me/.zshrc\")"'"#,
                Rule::Delete,
            ),
            (
                r#"python2 -c "exec \"import os; os.remove('/home/me/.zshrc')\" in {}""#,
                Rule::Delete,
            ),
            (
                r#"python2 -c "exec 'import os; os.remove(\"/home/me/.zshrc\")'""#,
                Rule::Delete,
            ),
            ("python2 -c 'exec x'", Rule::Unknown),
            ("python2 -c 'exec x in {}'", Rule::Unknown),
            // Not read whole by the strict gate: unknown.
            ("python2 -c 'exec \"print 1\"'", Rule::Unknown),
            // Bun and deno reading code from their input.
            (
                "deno run - <<'JS'\nDeno.removeSync('/home/me', {recursive: true})\nJS",
                Rule::Delete,
            ),
            (
                "bun - <<'JS'\nrequire('fs').rmSync('/home/me', {recursive: true})\nJS",
                Rule::Delete,
            ),
            (
                "bun run - <<'JS'\nrequire('fs').rmSync('/home/me', {recursive: true})\nJS",
                Rule::Delete,
            ),
            (
                "deno run --allow-all - <<'JS'\nDeno.removeSync('/home/me', {recursive: true})\nJS",
                Rule::Delete,
            ),
            (
                "echo \"Deno.removeSync('/home/me', {recursive: true})\" | deno run -",
                Rule::Unknown,
            ),
            (
                "echo \"require('fs').rmSync('/home/me')\" | bun -",
                Rule::Unknown,
            ),
            ("echo 'x' | bun run -", Rule::Unknown),
            ("deno run - < script.js", Rule::Unknown),
            ("bun - < script.js", Rule::Unknown),
            // The REPL reads its input under a POSIX shell.
            ("deno repl", Rule::Unknown),
            ("bun repl", Rule::Unknown),
            ("echo 'x' | deno", Rule::Unknown),
            ("echo 'x' | bun repl", Rule::Unknown),
            ("deno run - <<'JS'\nDeno.removeSync(\nJS", Rule::Unknown),
            ("deno run - <<JS\nDeno.removeSync('$X')\nJS", Rule::Unknown),
            // No subcommand and no option that prints reads its input.
            ("deno", Rule::Unknown),
            ("deno --unstable", Rule::Unknown),
            // Not read whole by the strict gate: unknown.
            ("bun - <<'JS'\nconsole.log(1)\nJS", Rule::Unknown),
            ("bun run - <<'JS'\nconsole.log(1)\nJS", Rule::Unknown),
            ("deno run - <<'JS'\nconsole.log(1)\nJS", Rule::Unknown),
            ("bun - <<JS\nconsole.log(1)\nJS", Rule::Unknown),
            // An interactive interpreter reads the code it is handed on its
            // input: CPython's `-i`, alone, bundled and attached to the code.
            (
                "python3 -ic \"print(1)\" <<'PY'\nimport shutil; shutil.rmtree('/home/me')\nPY",
                Rule::Unknown,
            ),
            (
                "echo \"import shutil; shutil.rmtree('/home/me')\" | python3 -i -c \"print(1)\"",
                Rule::Unknown,
            ),
            ("python3 -i -c 1 < /tmp/evil.py", Rule::Unknown),
            ("python3 -i -c 1", Rule::Unknown),
            ("python3 -bic 1", Rule::Unknown),
            ("python3 -ibc 1", Rule::Unknown),
            ("python3 -i -c1", Rule::Unknown),
            ("python3 -W i -ic 1", Rule::Unknown),
            ("python3 -b -i -c 1 <<'PY'\nprint(1)\nPY", Rule::Unknown),
            // What is in the code is read all the same.
            (
                "python3 -i -c \"import shutil; shutil.rmtree('/home/me')\"",
                Rule::Delete,
            ),
            // Node's `-i` and `--interactive`, before or after the code.
            (
                "node -i -e 1 <<'JS'\nrequire('fs').rmSync('/home/me',{recursive:true})\nJS",
                Rule::Unknown,
            ),
            ("node --interactive -e 1", Rule::Unknown),
            ("node --interactive -p 1", Rule::Unknown),
            ("node -i -e 1", Rule::Unknown),
            ("node -e 1 -i", Rule::Unknown),
            ("node -e 1 --interactive", Rule::Unknown),
            ("node -p 1 -i", Rule::Unknown),
            (
                "node -i -e \"require('fs').rmSync('/home/me',{recursive:true})\"",
                Rule::Delete,
            ),
            // `repl` reads the code it is given from the input.
            (
                "node -e \"require('repl').start()\" <<'JS'\nrequire('fs').rmSync('/home/me',{recursive:true})\nJS",
                Rule::Unknown,
            ),
            ("node -e \"require('node:repl').start()\"", Rule::Unknown),
            ("node -e \"const r = require('repl'); r.start()\"", Rule::Unknown),
            (
                "node -e \"const { start } = require('repl'); start()\"",
                Rule::Unknown,
            ),
            ("node -e \"new (require('repl').REPLServer)()\"", Rule::Unknown),
            (
                "node --input-type=module -e \"import repl from 'repl'; repl.start()\"",
                Rule::Unknown,
            ),
            // A debugger reads its commands, and runs statements, from the
            // input: every `pdb` call that starts one.
            (
                "python3 -c \"breakpoint()\" <<'PY'\nimport shutil; shutil.rmtree('/home/me')\nPY",
                Rule::Unknown,
            ),
            (
                "python3 -c \"import pdb; pdb.set_trace()\" <<'PY'\nimport os; os.remove('/home/me/f')\nPY",
                Rule::Unknown,
            ),
            (
                "python3 -c \"from pdb import set_trace as t; t()\"",
                Rule::Unknown,
            ),
            ("python3 -c \"import code; code.interact()\"", Rule::Unknown),
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
            // Not read whole by the strict gate: unknown. (`-I` is isolated
            // mode, which does not read the input; after the code, an `-i` is
            // an argument of the code; bun's `-i` installs packages.)
            ("python3 -I -c 'print(1)'", Rule::Unknown),
            ("python3 -Ic 'print(1)'", Rule::Unknown),
            ("python3 -c 'print(1)' -i", Rule::Unknown),
            ("python3 -c 'print(1)' -i x", Rule::Unknown),
            ("bun -i -e 1", Rule::Unknown),
            ("node -e 'console.log(1)' script-arg -i", Rule::Unknown),
            ("python3 -W i -c 'print(1)'", Rule::Unknown),
            // A flag that is not a print-and-exit one, or is another option's
            // value, or comes where the script's name does, reads the input;
            // so does anything that does more than print.
            ("python3 -v", Rule::Unknown),
            ("python3 -W --version", Rule::Unknown),
            ("python3 -X --version", Rule::Unknown),
            ("python3 -- --version", Rule::Unknown),
            ("node -r --version", Rule::Unknown),
            ("node --import --version", Rule::Unknown),
            ("python3 -V -", Rule::Unknown),
            ("python3 -i", Rule::Unknown),
            // The input is read as code, and is.
            (
                "python3 -W --version <<'PY'\nimport shutil\nshutil.rmtree('/home/me')\nPY",
                Rule::Delete,
            ),
            // A print flag that is the value of perl's, ruby's or php's
            // option before it: the program comes from the input.
            (
                "perl -I --version <<'PL'\nsystem(\"rm -rf /home/me\");\nPL",
                Rule::Unknown,
            ),
            (
                "ruby -I --version <<'RB'\nsystem(\"rm -rf /home/me\")\nRB",
                Rule::Unknown,
            ),
            (
                "ruby -E --version <<'RB'\nsystem(\"rm -rf /home/me\")\nRB",
                Rule::Unknown,
            ),
            (
                "php -d --version <<'PH'\n<?php system(\"rm -rf /home/me\");\nPH",
                Rule::Unknown,
            ),
            (
                "php -c --version <<'PH'\n<?php system(\"rm -rf /home/me\");\nPH",
                Rule::Unknown,
            ),
            ("php -z --help", Rule::Unknown),
            // Ruby's `--enable`, `--disable`, `--dump` and `--crash-report`,
            // and php's `--define`, `--php-ini` and `--zend-extension` take
            // the next word as their value, whatever it starts with, as `-d`,
            // `-c` and `-z` do: the program comes from the input.
            (
                "ruby --enable --version <<'RB'\nsystem(\"rm -rf /home/me\")\nRB",
                Rule::Unknown,
            ),
            (
                "ruby --disable --version <<'RB'\nsystem(\"rm -rf /home/me\")\nRB",
                Rule::Unknown,
            ),
            (
                "ruby --dump --version <<'RB'\nsystem(\"rm -rf /home/me\")\nRB",
                Rule::Unknown,
            ),
            (
                "ruby --crash-report --version <<'RB'\nsystem(\"rm -rf /home/me\")\nRB",
                Rule::Unknown,
            ),
            (
                "ruby --encoding --version <<'RB'\nsystem(\"rm -rf /home/me\")\nRB",
                Rule::Unknown,
            ),
            (
                "php --define --version <<'PH'\n<?php system(\"rm -rf /home/me\");\nPH",
                Rule::Unknown,
            ),
            (
                "php --php-ini --version <<'PH'\n<?php system(\"rm -rf /home/me\");\nPH",
                Rule::Unknown,
            ),
            (
                "php --zend-extension --version <<'PH'\n<?php system(\"rm -rf /home/me\");\nPH",
                Rule::Unknown,
            ),
            (
                "perl --unknown --version <<'PL'\nsystem(\"rm -rf /home/me\");\nPL",
                Rule::Unknown,
            ),
            // Code a runner or a bun option hands on is read too.
            (
                r#"npx node -e "require('fs').rmSync('/home/me',{recursive:true})""#,
                Rule::Delete,
            ),
            (
                r#"bun x node -e "require('fs').rmSync('/home/me',{recursive:true})""#,
                Rule::Delete,
            ),
            (
                r#"bun --import r.js -e "require('fs').rmSync('/home/me',{recursive:true})""#,
                Rule::Delete,
            ),
            (
                r#"uvx python -c "import shutil; shutil.rmtree('/home/me')""#,
                Rule::Delete,
            ),
            (
                r#"sudo deno eval "Deno.removeSync('/home/me',{recursive:true})""#,
                Rule::Delete,
            ),
            (
                "python3 - <<'PY'\nimport shutil; shutil.rmtree('/home/me')\nPY",
                Rule::Delete,
            ),
            // Not read whole by the strict gate: unknown.
            ("bun --cwd app -e 'console.log(1)'", Rule::Unknown),
            // A JavaScript hashbang line ends at any line terminator.
            (
                "node -e \"#!x\rrequire('fs').rmSync('/home/me',{recursive:true})\"",
                Rule::Delete,
            ),
            (
                "node -e \"#!x\u{2028}require('fs').rmSync('/home/me',{recursive:true})\"",
                Rule::Delete,
            ),
            (
                "node -e \"#!x\u{2029}require('fs').rmSync('/home/me',{recursive:true})\"",
                Rule::Delete,
            ),
            (
                "node -e \"#!x\r\nrequire('fs').rmSync('/home/me',{recursive:true})\"",
                Rule::Delete,
            ),
            (
                "node -e \"#!x\nrequire('fs').rmSync('/home/me',{recursive:true})\"",
                Rule::Delete,
            ),
            (
                "node <<'JS'\n#!x\rrequire('fs').rmSync('/home/me',{recursive:true})\nJS",
                Rule::Delete,
            ),
            (
                "node <<'JS'\n#!x\u{2028}require('fs').rmSync('/home/me',{recursive:true})\nJS",
                Rule::Delete,
            ),
            (
                "node --input-type=module <<'JS'\n#!x\u{2029}require('fs').rmSync('/home/me',{recursive:true})\nJS",
                Rule::Delete,
            ),
            (
                "bun -e \"#!x\rrequire('fs').rmSync('/home/me',{recursive:true})\"",
                Rule::Delete,
            ),
            (
                "node -e \"eval('#!x\\u2028require(\\\"fs\\\").rmSync(\\\"/home/me\\\",{recursive:true})')\"",
                Rule::Delete,
            ),
            // Not read whole by the strict gate: unknown. (The whole line is
            // the comment.)
            ("node -e \"#!x require('fs').rmSync('/home/me',{recursive:true})\"", Rule::Unknown),
            ("node -e \"#!x\nconsole.log(1)\"", Rule::Unknown),
            ("node -e \"#!x\rconsole.log(1)\"", Rule::Unknown),
            ("node -e \"#!x\r\nconsole.log(1)\"", Rule::Unknown),
            ("node -e \"#!x\u{2028}console.log(1)\"", Rule::Unknown),
            ("node -e \"#!x\u{2029}console.log(1)\"", Rule::Unknown),
            ("node <<'JS'\n#!/usr/bin/env node\nconsole.log(1)\nJS", Rule::Unknown),
            // A Python coding declaration that decodes the input to other
            // text is not read. (UTF-8 is what the reader reads, in any
            // spelling; an ASCII-compatible encoding reads an ASCII text the
            // same; only the first two lines are a declaration.)
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
            // Python reads a carriage return as a newline.
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
            // Code in a `data:` URL is not read.
            (
                r#"node -e "import 'data:text/javascript,import fs from \"fs\"; fs.rmSync(\"/home/me\",{recursive:true})'""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "import {a} from 'data:text/javascript,export const a=1'""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "export * from 'data:text/javascript,console.log(45)'""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "export {a} from 'data:text/javascript,export const a=1'""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "import 'data:text/javascript;base64,Y29uc29sZS5sb2coNDYp'""#,
                Rule::Unknown,
            ),
            // The URL parser drops leading spaces and reads the scheme in
            // any case.
            (
                r#"node -e "import ' DATA:text/javascript,1'""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "import('data:text/javascript,1')""#,
                Rule::Unknown,
            ),
            (
                r#"node -e "(async () => { await import('data:text/javascript,1') })()""#,
                Rule::Unknown,
            ),
            ("node --import data:text/javascript,1 -e 1", Rule::Unknown),
            ("node --import=data:text/javascript,1 -e 1", Rule::Unknown),
            ("node --loader data:text/javascript,1 -e 1", Rule::Unknown),
            ("node --loader=data:text/javascript,1 -e 1", Rule::Unknown),
            (
                "node --experimental-loader data:text/javascript,1 -e 1",
                Rule::Unknown,
            ),
            (
                "node --experimental-loader=data:text/javascript,1 -e 1",
                Rule::Unknown,
            ),
            ("node -e 1 --import data:text/javascript,1", Rule::Unknown),
            (
                "node --import data:text/javascript,1 build.js",
                Rule::Unknown,
            ),
            // A module only known when it runs may be one.
            ("node --import $LOADER -e 1", Rule::Unknown),
            // Not read whole by the strict gate: unknown.
            (
                r#"node -e "import fs from 'fs'; fs.readFileSync('package.json')""#,
                Rule::Unknown,
            ),
            (r#"node -e "import {a} from './a.js'""#, Rule::Unknown),
            (r#"node -e "export * from './a.js'""#, Rule::Unknown),
            ("node --import ./setup.js -e 1", Rule::Unknown),
            ("node --import=./setup.js -e 1", Rule::Unknown),
            ("node --loader ./hooks.js -e 1", Rule::Unknown),
            ("node --experimental-loader=./hooks.js -e 1", Rule::Unknown),
            // A `data:` URL import keeps the line unknown whatever the input
            // holds.
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
            ("node --import=./setup.js - <<'JS'\nconsole.log(1)\nJS", Rule::Unknown),
            // `NODE_OPTIONS` that load a `data:` URL make inline code unknown:
            // a prefix assignment.
            (
                "NODE_OPTIONS=\"--import=data:text/javascript,import('fs').then(f=>f.rmSync('/home/me',{recursive:true}))\" node -e \"console.log(1)\"",
                Rule::Unknown,
            ),
            (
                "NODE_OPTIONS='--import data:text/javascript,1' node -e 1",
                Rule::Unknown,
            ),
            (
                "NODE_OPTIONS='--max-old-space-size=4096 --import=data:text/javascript,1' node -e 1",
                Rule::Unknown,
            ),
            (
                "NODE_OPTIONS='--require ./a.js --import=data:text/javascript,1' node -e 1",
                Rule::Unknown,
            ),
            (
                "NODE_OPTIONS='--loader=data:text/javascript,1' node -e 1",
                Rule::Unknown,
            ),
            (
                "NODE_OPTIONS='--experimental-loader data:text/javascript,1' node -e 1",
                Rule::Unknown,
            ),
            (
                "NODE_OPTIONS='--import \"data:text/javascript,1\"' node -e 1",
                Rule::Unknown,
            ),
            (
                "NODE_OPTIONS='--import=DATA:text/javascript,1' nodejs -p 1",
                Rule::Unknown,
            ),
            (
                "NODE_OPTIONS='--import=data:text/javascript,1' node <<'JS'\nconsole.log(1)\nJS",
                Rule::Unknown,
            ),
            // `env`, also with a wrapper in front.
            (
                "env NODE_OPTIONS=\"--import=data:text/javascript,import('fs').then(f=>f.rmSync('/home/me',{recursive:true}))\" node -e 1",
                Rule::Unknown,
            ),
            (
                "env -i NODE_OPTIONS=--import=data:text/javascript,1 node -e 1",
                Rule::Unknown,
            ),
            (
                "env FOO=1 NODE_OPTIONS=--import=data:text/javascript,1 node -e 1",
                Rule::Unknown,
            ),
            // Set earlier in the line.
            (
                "export NODE_OPTIONS=--import=data:text/javascript,1; node -e 1",
                Rule::Unknown,
            ),
            (
                "export NODE_OPTIONS=--import=data:text/javascript,1 && node -e 1",
                Rule::Unknown,
            ),
            (
                "export \"NODE_OPTIONS=--import=data:text/javascript,1\"; node -e 1",
                Rule::Unknown,
            ),
            (
                "NODE_OPTIONS=--import=data:text/javascript,1; export NODE_OPTIONS; node -e 1",
                Rule::Unknown,
            ),
            (
                "read -r NODE_OPTIONS <<< '--import=data:text/javascript,1'; export NODE_OPTIONS; node -e 1",
                Rule::Unknown,
            ),
            ("export NODE_OPTIONS=\"--import=$URL\"; node -e 1", Rule::Unknown),
            // In front of a shell that starts node.
            (
                "NODE_OPTIONS='--import=data:text/javascript,1' bash -c \"node -e 1\"",
                Rule::Unknown,
            ),
            (
                "env NODE_OPTIONS=--import=data:text/javascript,1 sh -c 'node -p 1'",
                Rule::Unknown,
            ),
            // A value only known when it runs.
            ("NODE_OPTIONS=\"$OPTS\" node -e 1", Rule::Unknown),
            ("NODE_OPTIONS=\"--import=$URL\" node -e 1", Rule::Unknown),
            ("NODE_OPTIONS=$(cat opts) node -e 1", Rule::Unknown),
            // An underscore in an option's name is a hyphen to node.
            (
                "node --experimental_loader=data:text/javascript,1 -e 1",
                Rule::Unknown,
            ),
            // The code is read all the same when it does not load one.
            (
                "NODE_OPTIONS=--max-old-space-size=4096 node -e \"require('fs').rmSync('/home/me',{recursive:true})\"",
                Rule::Delete,
            ),
            // Not read whole by the strict gate: unknown. (Bun does not read
            // `NODE_OPTIONS`.)
            ("NODE_OPTIONS=--max-old-space-size=4096 node -e 'console.log(1)'", Rule::Unknown),
            ("NODE_OPTIONS='--max-old-space-size=4096 --no-warnings' node -e 'console.log(1)'", Rule::Unknown),
            ("NODE_OPTIONS='--require ./setup.js' node -e 'console.log(1)'", Rule::Unknown),
            ("NODE_OPTIONS='--import ./setup.mjs' node -e 'console.log(1)'", Rule::Unknown),
            ("NODE_OPTIONS= node -e 'console.log(1)'", Rule::Unknown),
            ("env NODE_OPTIONS=--max-old-space-size=4096 node -e 'console.log(1)'", Rule::Unknown),
            ("export NODE_OPTIONS=--max-old-space-size=4096; node -e 'console.log(1)'", Rule::Unknown),
            ("NODE_OPTIONS=--import=data:text/javascript,1 bun -e 1", Rule::Unknown),
        ],
    );
}

#[test]
fn an_interpreter_asked_to_print_its_version_or_help_reads_no_input_in_any_shell() {
    let printing = [
        "python --version",
        "python -V",
        "python -VV",
        "python3 --version",
        "python3.12 --version",
        "python3 -h",
        "python3 --help",
        "node --version",
        "node -v",
        "node --help",
        "nodejs --version",
        "bun -v",
        "perl --version",
        "ruby --version",
        "php -h",
        "lua --help",
    ];
    // Under any shell: PowerShell and cmd as POSIX.
    for (shell, paths) in [
        (Shell::Posix, posix()),
        (Shell::PowerShell, windows()),
        (Shell::Cmd, windows()),
    ] {
        check(shell, &paths, &printing, &[]);
    }
}

#[test]
fn code_handed_to_an_interpreter_under_cmd_or_powershell_is_unknown() {
    // Its paths and commands are not POSIX ones, so it is not read: under
    // cmd as under PowerShell.
    for shell in [Shell::Cmd, Shell::PowerShell] {
        check(
            shell,
            &windows(),
            &[
                "python build.py",
                "node build.js",
                "bun run build.ts",
                "deno test",
                "bun --version",
                "deno --version",
            ],
            &[
                (
                    r#"python -c "import shutil; shutil.rmtree('C:/Users/me')""#,
                    Rule::Unknown,
                ),
                (r#"python3 -c "print(1)""#, Rule::Unknown),
                (
                    r#"node -e "require('fs').rmSync('C:/Users/me', {recursive: true})""#,
                    Rule::Unknown,
                ),
                (r#"bun -e "console.log(1)""#, Rule::Unknown),
                (r#"deno eval "console.log(1)""#, Rule::Unknown),
            ],
        );
    }
    // Under cmd, a line with only a print flag, and a bare program or a
    // script file: nothing is handed to it to run.
    check(
        Shell::Cmd,
        &windows(),
        &["python", "python3", "node", "deno", "bun", "python -v"],
        &[
            // Inline code, the input, and what is piped into it.
            (r#"python -c "print(1)""#, Rule::Unknown),
            (r#"node -e "console.log(1)""#, Rule::Unknown),
            ("python -", Rule::Unknown),
            ("node -", Rule::Unknown),
            ("type run.py | python", Rule::Unknown),
            ("type run.js | node", Rule::Unknown),
            ("echo print(1) | deno", Rule::Unknown),
        ],
    );
    // PowerShell reads the input of a bare interpreter as the POSIX shell
    // does; `deno` and `bun` only when something is piped into them.
    check(
        Shell::PowerShell,
        &windows(),
        &["deno", "bun"],
        &[
            ("python", Rule::Unknown),
            ("node", Rule::Unknown),
            ("python -", Rule::Unknown),
            ("'print(1)' | python", Rule::Unknown),
            ("'1' | deno", Rule::Unknown),
            (
                "python -c \"import os; os.remove('C:\\Users\\me\\x')\"",
                Rule::Unknown,
            ),
            (
                "node -e \"require('fs').rmSync('C:\\Users\\me')\"",
                Rule::Unknown,
            ),
            (
                "deno eval \"Deno.removeSync('C:\\Users\\me')\"",
                Rule::Unknown,
            ),
        ],
    );
}

#[test]
fn a_loader_in_front_of_buns_code_flag_is_unknown_in_every_shell() {
    // The code of such a line may not be told (a module the options load runs
    // first, or the code is only known when it runs), so cmd says `unknown`
    // for it as the other shells do, not that bun is the whole story.
    for shell in [Shell::Posix, Shell::PowerShell, Shell::Cmd] {
        for paths in [posix(), common::macos(), windows()] {
            for line in [
                "bun --import r.js -e \"$X\"",
                "bun --require r.js -e \"$X\"",
                "bun --loader .js:jsx -p \"$X\"",
                "bun --import data:text/javascript -e \"console.log(1)\"",
                "bun -F x run -e \"console.log(1)\"",
            ] {
                assert_eq!(
                    rules(line, shell, &paths),
                    [Rule::Unknown],
                    "{shell:?} {line:?}"
                );
            }
        }
    }
}
