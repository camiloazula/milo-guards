//! Whether inline code is read whole, the strict gate: code is safe only when
//! it is written whole after its flag, runs straight through, calls only what
//! is on the list, and nothing around the interpreter (an option, an
//! environment, a runner, an assignment or a name the line redefines earlier,
//! the folder it runs in) can change what it does. What cannot be read is
//! unknown, and inline code is never reads-only.
//!
//! Inline Python looks in the folder it runs in first: `python3 -c` puts the
//! working folder at the front of its import path, so `import json` runs
//! `./json.py` if there is one, and so does every module `json` loads in turn.
//! An import in `-c` code is read whole only for the modules built into the
//! interpreter binary (`sys`, `errno`, `itertools`, `time`), which the import
//! system finds before it looks at the path; any other import makes the code
//! not read whole, whatever the folder is. `python2` (and `python`, which is
//! Python 2 on some systems) has only `sys` and `errno` built in, and no
//! `builtins` module at all: it is `__builtin__` there.
//!
//! The lines and their answers are in `tests/cases/inline_read_whole.cases`.

mod common;

#[test]
fn every_case_holds() {
    common::cases::check("inline_read_whole");
}
