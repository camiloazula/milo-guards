# milo-guards-script

Judges Python, JavaScript or Ruby code an agent runs directly (a Python
tool, a notebook, a JavaScript sandbox), with no shell line around it, and
says whether it is safe to run without asking, or risky and why. The script guard
of [milo-guards](https://github.com/camiloazula/milo-guards).

The code is read by the code reader (`milo-guards-code`), and each act it is
certain to do is judged as the shell guard judges the same act in the code a
line hands an interpreter (`python3 -c …`), with the same rule names and
reasons: a delete beyond the workspace is `delete`, a write there
`overwrite`, a read of a key `read_secret`. Code the reader does not read
whole is `unknown`, never safe.

A program the code starts is `run_program`. Whether the program is risky is
the shell guard's to say, so the finding's target is its command line, for
the machine's shell: `cmd` on Windows, POSIX elsewhere. Code that starts a
program is never read whole, so it is always `unknown` as well: the target
tells you which program to ask the shell guard about, and what that answer
finds adds to this one, but a safe answer for the program never makes the
code safe.

**Code longer than 3 KiB is not read.** In this release the code reader
reads at most 3 KiB of code (`MAX_LEN`), a deliberate limit that bounds the
work any reading takes. Longer code is `unreadable`, `is too long to read`,
whatever it does, so most real scripts and notebooks come back unreadable,
not judged act by act. Later releases will raise the limit.

## Install

Through the front door, where it is the `script` feature (on by default):

```toml
[dependencies]
milo-guards = "0.2"
```

Or on its own:

```toml
[dependencies]
milo-guards-script = "0.2"
```

## Example

```rust
use milo_guards_script::{judge, Language, Paths, Rule};

let paths = Paths::new("/home/me/work/repo", "/home/me", ["/home/me/work/repo"]);

assert!(judge(Language::Python, "print(1)", &paths).is_safe());

let assessment = judge(Language::Python, "import shutil; shutil.rmtree('/home/me')", &paths);
assert_eq!(assessment.findings()[0].rule, Rule::Delete);
assert_eq!(assessment.findings()[0].reason, "deletes your home directory");

let assessment = judge(Language::JavaScript, "require('fs').readFileSync('/home/me/.ssh/id_rsa')", &paths);
assert_eq!(assessment.findings()[0].rule, Rule::ReadSecret);
assert_eq!(assessment.findings()[0].reason, "reads your SSH keys");

// A program: its command line to ask the shell guard about, and the code is
// `unknown` whatever the program is.
let assessment = judge(Language::Python, "import subprocess; subprocess.run(['true'])", &paths);
assert_eq!(assessment.findings()[0].rule, Rule::RunProgram);
assert_eq!(assessment.findings()[0].target.as_deref(), Some("true"));
assert_eq!(assessment.findings()[1].rule, Rule::Unknown);
```

The design is in
[docs/design/script.md](https://github.com/camiloazula/milo-guards/blob/main/docs/design/script.md).

## License

MIT or Apache-2.0, at your option
([LICENSE-MIT](https://github.com/camiloazula/milo-guards/blob/main/LICENSE-MIT),
[LICENSE-APACHE](https://github.com/camiloazula/milo-guards/blob/main/LICENSE-APACHE)). Part of
[milo-guards](https://github.com/camiloazula/milo-guards); the API is on
[docs.rs](https://docs.rs/milo-guards-script).
