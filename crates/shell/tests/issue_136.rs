//! Inline Python looks in the folder it runs in first: `python3 -c` puts the
//! working folder at the front of its import path, so `import json` runs
//! `./json.py` if there is one, and so does every module `json` loads in turn.
//! An import in `-c` code is read whole only for the modules built into the
//! interpreter binary (`sys`, `errno`, `itertools`, `time`), which the import
//! system finds before it looks at the path; any other import makes the code
//! not read whole, whatever the folder is. `python2` (and `python`, which is
//! Python 2 on some systems) has only `sys` and `errno` built in, and no
//! `builtins` module at all: it is `__builtin__` there.

mod common;

use common::{check, posix};
use milo_guards_shell::{Rule, Shell};

#[test]
fn an_import_of_a_module_that_is_a_file_is_unknown() {
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[
            // The lines of the issue: a planted `json.py` in `sub` runs.
            ("cd sub && python3 -c 'import json'", Rule::Unknown),
            ("python3 -c 'import re'", Rule::Unknown),
            (
                "cd sub && python3 -c 'import json; print(json.dumps(1))'",
                Rule::Unknown,
            ),
            // The same in the workspace itself, not only after a `cd`.
            ("python3 -c 'import json'", Rule::Unknown),
            (
                "python3 -c 'import json; print(json.dumps(1))'",
                Rule::Unknown,
            ),
            (
                "python3 -c 'import json, sys; json.load(sys.stdin)'",
                Rule::Unknown,
            ),
            ("python3 -c 'import sys, json'", Rule::Unknown),
            ("python3 -c 'import math; print(math.pi)'", Rule::Unknown),
            (
                "python3 -c 'import re; print(re.escape(\"a\"))'",
                Rule::Unknown,
            ),
            // `import re` loads `enum`: a module the code never names.
            ("python3 -c 'import enum'", Rule::Unknown),
            ("python3 -c 'import functools'", Rule::Unknown),
            ("python3 -c 'import traceback'", Rule::Unknown),
            ("python3 -c 'import stringprep'", Rule::Unknown),
            ("python3 -c 'import unicodedata'", Rule::Unknown),
            ("python3 -c 'import datetime'", Rule::Unknown),
            ("python3 -c 'import random'", Rule::Unknown),
            ("python3 -c 'import collections'", Rule::Unknown),
            ("python3 -c 'import string'", Rule::Unknown),
            // A module of a package, an alias and a `from` are still imports.
            ("python3 -c 'import os.path'", Rule::Unknown),
            ("python3 -c 'import json.decoder'", Rule::Unknown),
            ("python3 -c 'import sys.x'", Rule::Unknown),
            ("python3 -c 'import json as j'", Rule::Unknown),
            ("python3 -c 'import sys as s'", Rule::Unknown),
            (
                "python3 -c 'from json import dumps; print(dumps(1))'",
                Rule::Unknown,
            ),
            ("python3 -c 'from sys import argv'", Rule::Unknown),
            ("python3 -c 'from time import time'", Rule::Unknown),
            // An import where the code does not run straight through.
            ("python3 -c 'if 1:\n    import json'", Rule::Unknown),
            (
                "python3 -c 'if 0:\n    pass\nelse:\n    import json'",
                Rule::Unknown,
            ),
            // A builtin module beside a file: the file decides.
            (
                "python3 -c 'import time, json; print(time.time())'",
                Rule::Unknown,
            ),
            // Other spellings of the interpreter and of the option.
            ("python -c 'import json'", Rule::Unknown),
            ("python3.12 -c 'import json'", Rule::Unknown),
            ("python3 -c\"import json\"", Rule::Unknown),
            ("python3 -c $'import json'", Rule::Unknown),
            ("python3 -c 'import\\tjson'", Rule::Unknown),
            ("python3 -c 'import json;print(1)'", Rule::Unknown),
            ("python3 -c 'print(1)\nimport json'", Rule::Unknown),
            ("python3 -c 'import  json'", Rule::Unknown),
            ("python3 -c 'import json # sys'", Rule::Unknown),
            ("python3 -c 'import \\\njson'", Rule::Unknown),
            // Around the interpreter.
            (
                "cd sub && python3 -c 'import json' && echo ok",
                Rule::Unknown,
            ),
            ("echo go; python3 -c 'import json'", Rule::Unknown),
            ("(cd sub; python3 -c 'import json')", Rule::Unknown),
            ("f() { python3 -c 'import json'; }; f", Rule::Unknown),
            ("env python3 -c 'import json'", Rule::Unknown),
            ("exec python3 -c 'import json'", Rule::Unknown),
            ("time python3 -c 'import json'", Rule::Unknown),
            ("python3 -c 'import json' | cat", Rule::Unknown),
            (
                "python3 -c 'print(1)' && python3 -c 'import json'",
                Rule::Unknown,
            ),
            // A name that was once an import is still not a name to set.
            ("python3 -c 'json = 1'", Rule::Unknown),
            ("python3 -c 'math = 1'", Rule::Unknown),
            ("python3 -c 're = 1'", Rule::Unknown),
        ],
    );
}

#[test]
fn a_module_built_into_the_interpreter_is_still_read_whole() {
    check(
        Shell::Posix,
        &posix(),
        &[
            // The lines of the issue that stay as they are.
            "python3 -c 'print(1)'",
            "python3 -c 'import sys; print(sys.version)'",
            // Nothing a planted file can stand in for.
            "python3 -c 'import sys'",
            "python3 -c 'import sys; print(sys.argv)'",
            "python3 -c 'import sys; print(sys.stdin.read())'",
            "python3 -c 'import time; print(time.time())'",
            "python3 -c 'import time; print(time.monotonic(), time.perf_counter())'",
            "python3 -c 'import errno; print(errno.ENOENT)'",
            "python3 -c 'import itertools'",
            "python3 -c 'import sys, time, errno, itertools'",
            "python3 -c 'import sys\nimport time\nprint(sys.argv, time.time())'",
            "cd sub && python3 -c 'import sys; print(sys.version)'",
            "cd sub && python3 -c 'import time'",
            "python -c 'import sys; print(sys.version)'",
            "python3.12 -c 'import sys; print(sys.version)'",
        ],
        &[
            // `builtins` is no built-in module in Python 2 (it is
            // `__builtin__`), so a planted `./builtins.py` would run.
            ("python3 -c 'import builtins'", Rule::Unknown),
            ("python -c 'import builtins'", Rule::Unknown),
            (
                "python3 -c 'import sys, time, errno, builtins, itertools'",
                Rule::Unknown,
            ),
            // Using a built-in module beyond the few members on the list is
            // not read whole: `builtins.exec` is `exec`.
            (
                "python3 -c 'import builtins; builtins.exec(\"1\")'",
                Rule::Unknown,
            ),
            (
                "python3 -c 'import builtins; print(builtins.len(\"a\"))'",
                Rule::Unknown,
            ),
            (
                "python3 -c 'import itertools; print(itertools.count())'",
                Rule::Unknown,
            ),
            ("python3 -c 'import time; time.sleep(1)'", Rule::Unknown),
            (
                "python3 -c 'import time; print(time.strftime(\"%Y\"))'",
                Rule::Unknown,
            ),
            (
                "python3 -c 'import errno; print(errno.strerror(2))'",
                Rule::Unknown,
            ),
            ("python3 -c 'import sys; print(sys.modules)'", Rule::Unknown),
            ("python3 -c 'import sys; print(sys.path)'", Rule::Unknown),
            (
                "python3 -c 'import sys; sys.stdout.write(\"x\")'",
                Rule::Unknown,
            ),
            (
                "python3 -c 'import sys; print(sys._getframe())'",
                Rule::Unknown,
            ),
            // A built-in module that is not on the list is an import like any
            // other: no table of what each one loads.
            ("python3 -c 'import gc'", Rule::Unknown),
            ("python3 -c 'import posix'", Rule::Unknown),
            ("python3 -c 'import marshal'", Rule::Unknown),
            ("python3 -c 'import atexit'", Rule::Unknown),
            // A name set by the code is not the module.
            ("python3 -c 'sys = 1'", Rule::Unknown),
            ("python3 -c 'time = 1'", Rule::Unknown),
            ("python3 -c 'import sys; sys = 1'", Rule::Unknown),
            // Without the import the module is a name nothing bound.
            ("python3 -c 'print(time.time())'", Rule::Unknown),
            // What the code does is still found beside the import.
            (
                "python3 -c \"import sys; open('/home/me/.zshrc', 'w').write('x')\"",
                Rule::Overwrite,
            ),
            (
                "python3 -c \"import json; open('/home/me/.zshrc', 'w').write('x')\"",
                Rule::Overwrite,
            ),
        ],
    );
}

#[test]
fn python_2_reads_an_import_whole_only_for_sys_and_errno() {
    check(
        Shell::Posix,
        &posix(),
        &[
            // Nothing a planted file can stand in for, in Python 2 too.
            "python2 -c 'print(1)'",
            "python2 -c 'import sys; print(sys.version)'",
            "python2 -c 'import sys; print(sys.argv)'",
            "python2 -c 'import errno; print(errno.ENOENT)'",
            "python2 -c 'import sys, errno'",
            "python -c 'import sys, errno'",
        ],
        &[
            // Python 2 has no `builtins` module: `import builtins` searches
            // the path, the working folder first, and a planted
            // `./builtins.py` runs.
            ("python2 -c 'import builtins'", Rule::Unknown),
            ("python -c 'import builtins'", Rule::Unknown),
            ("cd sub && python2 -c 'import builtins'", Rule::Unknown),
            // `time` and `itertools` are shared files of `lib-dynload`, which
            // come after the working folder on the path.
            (
                "python2 -c 'import time; print(time.time())'",
                Rule::Unknown,
            ),
            ("python2 -c 'import time'", Rule::Unknown),
            ("python2 -c 'import itertools'", Rule::Unknown),
            ("python -c 'import time'", Rule::Unknown),
            ("python -c 'import time; print(time.time())'", Rule::Unknown),
            ("python -c 'import itertools'", Rule::Unknown),
            ("python2 -c 'import sys, time'", Rule::Unknown),
            ("python2 -c 'import json'", Rule::Unknown),
            // The names stay names the code may not use unbound.
            ("python2 -c 'print(time.time())'", Rule::Unknown),
            ("python2 -c 'time = 1'", Rule::Unknown),
            // What the code does is still found beside the import.
            (
                "python2 -c \"import time; open('/home/me/.zshrc', 'w').write('x')\"",
                Rule::Overwrite,
            ),
        ],
    );
}
