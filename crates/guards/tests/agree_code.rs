//! The script guard and the shell guard give one answer for the same code.
//!
//! An agent refused code on a code tool can hand it to an interpreter on a
//! shell line, so `script::judge(language, code)` and
//! `shell::classify("python3 -c '<code>'")` (`node -e` for JavaScript) must
//! agree, and neither guard knows of the other. The code is:
//!
//! - every `python`, `python2` and `javascript` case of the code reader's
//!   case files (`crates/code/tests/cases/*.cases`, Python 2's judged as
//!   Python), on a POSIX machine, a Mac and a Windows one;
//! - every POSIX line of the shell guard's inline case files
//!   (`crates/shell/tests/cases/inline*.cases`) that is `python3 -c WORD` or
//!   `node -e WORD` and nothing else, the word quoted whole: on the paths the
//!   case names, and when that is a sample machine, on the other two too;
//! - code made here: each act on files after one or two `chdir`s to places
//!   risky and harmless from the start, reads and writes of what the kernel
//!   serves, every act on paths the caller protects, names as a secret, or
//!   both, and every act on paths through the links the caller resolves and
//!   the drives it says WSL mounts, from a workspace on either side.
//!
//! For each, the whole answers are compared, every rule with its reason and
//! what it says to do instead (the targets are the guards' own: a path as
//! the code spells it, a word as the line spells it). The script guard's
//! answer is read as a caller combines it: its findings, with each
//! `run_program` replaced by what the shell guard finds in its target (read
//! as the machine's shell reads it: cmd on Windows, POSIX elsewhere), and
//! `runs code the guard does not read fully` said only when nothing else is,
//! as the shell guard says it. Both answers are safe, or both risky, and the
//! two sets of findings are the same.
//!
//! Where the two differ by design, [`BY_DESIGN`] says how and why, and a
//! case is held to differ only so; [`LEFT_OUT`] lists the cases that still
//! differ otherwise, each with both answers and the reason, and fails when
//! one of them comes to agree, so neither list goes stale.

#![cfg(all(feature = "shell", feature = "script", feature = "code"))]
#![allow(
    clippy::disallowed_methods,
    clippy::disallowed_macros,
    reason = "this test reads the repository's own files, which no guard may do"
)]

#[path = "../../core/tests/common/cases.rs"]
mod format;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use format::Word;
use milo_guards::code::declares_other_encoding;
use milo_guards::script::{self, Language};
use milo_guards::shell::{self, Shell};
use milo_guards::{Assessment, Finding, Link, Paths, Protected, RuleName, Secret};

/// A finding as the two answers are compared: its rule's wire name, its
/// reason and what it says to do instead.
type Said = (String, String, Option<String>);

/// The rules of both guards that are about a file act, by wire name.
const FILE_ACTS: [&str; 5] = [
    "delete",
    "wipe_disk",
    "overwrite",
    "permissions",
    "read_secret",
];

/// Why code the guard does not read whole is `unknown`: said by both guards
/// only where nothing else is found.
const UNREAD_FULLY: &str = "runs code the guard does not read fully";

/// What the script guard says that the shell guard does not, by design: the
/// finding, and why. A case may differ from the shell guard's answer by
/// these findings only, and then is counted as differing by design.
const BY_DESIGN: [(&str, &str, &str); 5] = [
    (
        "unknown",
        "runs code the guard does not read",
        "Python code that declares another encoding: Python honours the \
         declaration when it reads the code from a file or its input, which \
         the script guard holds for; `python3 -c` hands the code as text, where \
         it is not read",
    ),
    (
        "unknown",
        "gives a program input the guard does not show",
        "a program the code gives input to (`input=`, `stdin`): the reader \
         does not give the input with the program, so a target cannot show it; \
         the shell guard's inline reading drops it the same way",
    ),
    (
        "unknown",
        "starts a program the guard cannot write as a command line",
        "a program cmd cannot carry as a line, on a Windows machine: the shell \
         guard's inline reading runs it as a POSIX unit",
    ),
    (
        "unknown",
        "runs a program with an argument only known when the code runs",
        "a program with a word known only in part, which the shell guard finds \
         reads a key in the part that is known: its inline reading then drops \
         the `unknown` for the word (it knows the program reads the key), which \
         the script guard, which does not judge the program, keeps",
    ),
    (
        "unknown",
        "opens a file whose path is only known when the code runs",
        "a read of a path that cannot be placed (another user's home directory \
         that holds no key, a path on another drive's own working directory): \
         the shell guard's inline reading does not judge such a read, and the \
         script guard says it may be any file",
    ),
];

/// Why code on a Windows machine whose Windows paths the script guard finds
/// risky differs by design, when the shell guard finds nothing in them.
const WINDOWS_PATHS: &str = "a Windows path on a Windows machine (a drive, a stream, the NT \
     prefix): the shell guard's inline reading places it as a POSIX name, and finds nothing, \
     where the script guard reads it as Windows does";

/// Why a program the code starts on a Windows machine may differ by design
/// beyond its file acts: the script guard's target is read by cmd, which
/// runs it there, where the shell guard's inline reading judges it as a
/// POSIX unit, so what the two say of the program itself (`elevated` as
/// root or administrator, `stop_system`, an `unknown`'s reason) is not
/// compared. Every finding about a file act is (see [`windows_programs`]).
const WINDOWS_PROGRAM: &str = "a program on a Windows machine: what the two say of the \
     program beyond its file acts is not compared, the script guard's target being read by \
     cmd and the shell guard's inline reading judging a POSIX unit";

/// Where the shell guard's inline reading of a program on a Windows machine
/// finds a file act that cmd's reading of the script guard's target does
/// not, because the shell guard judges the program as a POSIX unit, which
/// is not what runs: `(rule, reason, a shape of the code, why)`.
const WINDOWS_MAPPED: &[(&str, &str, &str, &str)] = &[];

/// What the script guard says where the shell guard says another thing, as
/// `(script's rule, script's reason, shell's rule, shell's reason)`: code
/// that does not parse, and code the reader stops on past the work its
/// grammar may do, is `unreadable` to the script guard, as such a line is to
/// the shell guard, and `unknown` to the shell guard's inline reading.
const MAPPED: [(&str, &str, &str, &str); 2] = [
    (
        "unreadable",
        "does not parse",
        "unknown",
        "runs code the guard does not read",
    ),
    (
        "unreadable",
        "takes too long to read",
        "unknown",
        "runs code the guard does not read",
    ),
];

/// The code the two guards do not agree on, beyond [`BY_DESIGN`], as
/// `(machine, language, code, why)`.
const LEFT_OUT: &[(&str, &str, &str, &str)] = &[
    (
        "windows",
        "python",
        "import os; os.system('python3 -c \"import os; os.system(\\'python3 -c \\\\\"import os; os.system(\\\\\\\\\\'rm -rf /home/me\\\\\\\\\\')\\\\\"\\')\"')",
        "the target, the line as written, is the command cmd runs; the shell guard's cmd \\
         reading of it does not read the inline code that `python3 -c` is given there and \\
         says `unknown` (`runs code the guard does not read`), where its POSIX reading of the \\
         whole code finds the delete of `/home/me`",
    ),
    (
        "posix",
        "python",
        "open('x.sh','w').write('rm -rf ~'); import os; os.system('sh x.sh')",
        WRITTEN_THEN_RUN,
    ),
    (
        "macos",
        "python",
        "open('x.sh','w').write('rm -rf ~'); import os; os.system('sh x.sh')",
        WRITTEN_THEN_RUN,
    ),
    (
        "posix",
        "javascript",
        "require('fs').writeFileSync('x.sh','rm -rf ~'); require('child_process').execSync('sh x.sh')",
        WRITTEN_THEN_RUN,
    ),
    (
        "macos",
        "javascript",
        "require('fs').writeFileSync('x.sh','rm -rf ~'); require('child_process').execSync('sh x.sh')",
        WRITTEN_THEN_RUN,
    ),
];

/// Why code that writes a script and runs it is left out: both are
/// `unknown`, the script guard because the code is not read whole (the
/// target `sh x.sh` is safe to the shell guard, which is not told the code
/// wrote `x.sh`), the shell guard because it runs a script the same line
/// writes.
const WRITTEN_THEN_RUN: &str = "both unknown, for different reasons: the shell guard \
     says `runs a script the same line writes`, which the target `sh x.sh` alone cannot show";

/// One piece of code, where it came from, and the machine it is judged on.
struct Code {
    at: String,
    machine: String,
    language: Language,
    code: String,
    paths: Paths,
}

fn posix() -> Paths {
    Paths::new("/home/me/work/repo", "/home/me", ["/home/me/work/repo"])
}

fn macos() -> Paths {
    Paths::new("/Users/me/dev/repo", "/Users/me", ["/Users/me/dev/repo"])
}

fn windows() -> Paths {
    Paths::new(
        r"C:\Users\me\dev\repo",
        r"C:\Users\me",
        [r"C:\Users\me\dev\repo"],
    )
}

/// The sample machines, by name.
fn machines() -> [(&'static str, Paths); 3] {
    [
        ("posix", posix()),
        ("macos", macos()),
        ("windows", windows()),
    ]
}

/// `code` on each sample machine.
fn on_machines(at: &str, language: Language, code: &str) -> Vec<Code> {
    machines()
        .into_iter()
        .map(|(machine, paths)| Code {
            at: at.to_string(),
            machine: machine.to_string(),
            language,
            code: code.to_string(),
            paths,
        })
        .collect()
}

/// The case files of the crate `krate` whose names start with `prefix`.
fn case_files(krate: &str, prefix: &str) -> Result<Vec<(String, PathBuf)>, String> {
    let folder = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../{krate}/tests/cases"));
    let mut found: Vec<(String, PathBuf)> = fs::read_dir(&folder)
        .map_err(|e| format!("cannot read {}: {e}", folder.display()))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "cases"))
        .filter_map(|path| {
            let name = path.file_stem()?.to_str()?.to_string();
            name.starts_with(prefix)
                .then(|| (format!("crates/{krate}/tests/cases/{name}.cases"), path))
        })
        .collect();
    found.sort();
    Ok(found)
}

fn records(shown: &str, path: &Path) -> Result<Vec<format::Record>, String> {
    let source =
        fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    format::parse(shown, &source).map_err(|refused| refused.join("\n"))
}

/// Every piece of code of the code reader's case files, on each machine.
fn reader_cases() -> Result<Vec<Code>, String> {
    let mut found = Vec::new();
    for (shown, path) in case_files("code", "")? {
        for record in records(&shown, &path)? {
            let (Some((what, None)), Some(code)) = (format::head(&record.words), record.text)
            else {
                continue;
            };
            let language = match what {
                "python" | "python2" => Language::Python,
                "javascript" => Language::JavaScript,
                _ => continue,
            };
            // No shell line can carry a NUL, so such code has no line to
            // hand an interpreter.
            if code.contains('\0') {
                continue;
            }
            found.extend(on_machines(&record.at, language, &code));
        }
    }
    Ok(found)
}

/// The paths a `paths` line of a shell case file declares.
fn declared(words: &[Word], machines: &HashMap<String, Paths>) -> Result<(String, Paths), String> {
    let declared = format::declaration(words)?;
    let mut paths = match (&declared.base, declared.cwd, declared.home) {
        (Some(base), ..) => machines
            .get(base.as_str())
            .cloned()
            .ok_or_else(|| format!("no paths named `{base}`"))?,
        (None, Some(cwd), Some(home)) => Paths::new(cwd, home, Vec::<PathBuf>::new()),
        _ => return Err("a `paths` line takes `base`, or `cwd` and `home`".to_string()),
    };
    paths.workspaces.extend(declared.workspaces);
    for named in declared.named {
        paths = match (named.secret, named.folder) {
            (false, true) => paths.with_protected([Protected::folder(named.path, named.words)]),
            (false, false) => paths.with_protected([Protected::file(named.path, named.words)]),
            (true, true) => paths.with_secrets([Secret::folder(named.path, named.words)]),
            (true, false) => paths.with_secrets([Secret::file(named.path, named.words)]),
        };
    }
    paths = paths.with_drive_mounts(declared.drive_mounts).with_links(
        declared
            .links
            .into_iter()
            .map(|(path, to)| Link::new(path, to)),
    );
    if let Some(home) = declared.windows_home {
        paths = paths.with_windows_home(home);
    }
    Ok((declared.name, paths))
}

/// The code of a POSIX word quoted whole: `'…'` with no quote in it, or
/// `"…"` with nothing a shell expands in it (a backslash escapes `$`, a
/// backtick, `"`, a backslash and a line break, and is itself elsewhere).
fn unquoted(word: &str) -> Option<String> {
    if let Some(inner) = word.strip_prefix('\'').and_then(|w| w.strip_suffix('\'')) {
        return (!inner.contains('\'')).then(|| inner.to_string());
    }
    let inner = word.strip_prefix('"')?.strip_suffix('"')?;
    let mut code = String::new();
    let mut chars = inner.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next()? {
                next @ ('$' | '`' | '"' | '\\') => code.push(next),
                '\n' => {}
                next => {
                    code.push('\\');
                    code.push(next);
                }
            },
            '$' | '`' | '"' => return None,
            c => code.push(c),
        }
    }
    Some(code)
}

/// Every piece of code the shell guard's inline case files write whole on a
/// POSIX line of its own: on the paths the case names, and on every sample
/// machine when it names one of them.
fn shell_cases() -> Result<Vec<Code>, String> {
    let mut found = Vec::new();
    for (shown, path) in case_files("shell", "inline")? {
        let mut named: HashMap<String, Paths> = machines()
            .into_iter()
            .map(|(name, paths)| (name.to_string(), paths))
            .collect();
        for record in records(&shown, &path)? {
            let Some(line) = record.text else {
                if matches!(record.words.first(), Some(Word::Bare(word)) if word == "paths") {
                    let (name, paths) = declared(&record.words[1..], &named)?;
                    named.insert(name, paths);
                }
                continue;
            };
            let Some(("posix", machine)) = format::head(&record.words) else {
                continue;
            };
            let (language, word) = if let Some(word) = line.strip_prefix("python3 -c ") {
                (Language::Python, word)
            } else if let Some(word) = line.strip_prefix("node -e ") {
                (Language::JavaScript, word)
            } else {
                continue;
            };
            let Some(code) = unquoted(word) else {
                continue;
            };
            let machine = machine.unwrap_or("posix");
            if ["posix", "macos", "windows"].contains(&machine) {
                found.extend(on_machines(&record.at, language, &code));
                continue;
            }
            let paths = named
                .get(machine)
                .cloned()
                .ok_or_else(|| format!("{}: no paths named `{machine}`", record.at))?;
            found.push(Code {
                at: record.at,
                machine: machine.to_string(),
                language,
                code,
                paths,
            });
        }
    }
    Ok(found)
}

/// Code made here: acts on files after moves, what the kernel serves, and
/// the paths the caller protects and names as secrets.
fn made_cases() -> Vec<Code> {
    let mut found = Vec::new();
    // Each act on files, after one or two moves, so that a path that is
    // harmless from where the code moved to is risky from where it started,
    // and the other way.
    let targets = ["/home/me", "/tmp", "sub", "..", "/home/me/.ssh", "~"];
    let python_acts = [
        "import shutil\nshutil.rmtree('.')",
        "import os\nos.remove('x')",
        "print(open('id_rsa').read())",
        "open('.bashrc', 'a')",
        "print(open('.ssh/id_rsa').read())",
        "import os\nos.chmod('x', 0o777)",
        "import shutil\nshutil.move('x', '/tmp/y')",
    ];
    let javascript_acts = [
        "fs.rmSync('.', {recursive: true})",
        "fs.unlinkSync('x')",
        "console.log(fs.readFileSync('id_rsa'))",
        "fs.appendFileSync('.bashrc', 'x')",
        "console.log(fs.readFileSync('.ssh/id_rsa'))",
        "fs.chmodSync('x', 0o777)",
        "fs.renameSync('x', '/tmp/y')",
    ];
    let mut moves: Vec<Vec<&str>> = targets.iter().map(|target| vec![*target]).collect();
    for first in targets {
        for second in targets {
            moves.push(vec![first, second]);
        }
    }
    // Three to eight moves, past the places the code is judged from and the
    // folders a move that may have failed is kept as leaving it in.
    let many = [".github", "a", "b", "c", "workflows", "d", "e", "f"];
    for count in 3..=many.len() {
        moves.push(many[..count].to_vec());
        let mut mixed = many[..count].to_vec();
        mixed[0] = "/home/me";
        moves.push(mixed);
        let mut last = many[..count - 1].to_vec();
        last.push("workflows");
        moves.push(last);
    }
    for (at, moves) in moves.iter().enumerate() {
        for act in python_acts {
            let chdirs: String = moves
                .iter()
                .map(|target| format!("os.chdir('{target}')\n"))
                .collect::<Vec<_>>()
                .concat();
            let code = format!("import os\n{chdirs}{act}");
            found.extend(on_machines(&format!("chdir {at}"), Language::Python, &code));
        }
        for act in javascript_acts {
            let chdirs: String = moves
                .iter()
                .map(|target| format!("process.chdir('{target}'); "))
                .collect::<Vec<_>>()
                .concat();
            let code = format!("const fs = require('fs'); {chdirs}{act}");
            found.extend(on_machines(
                &format!("chdir {at}"),
                Language::JavaScript,
                &code,
            ));
        }
    }
    // What the kernel serves, and the files it shows.
    for path in [
        "/proc/self/environ",
        "/proc/1/cmdline",
        "/proc/cpuinfo",
        "/dev/sda",
        "/dev/fd/3",
        "/dev/null",
        "/dev/stdin",
        "/dev/urandom",
        "/etc/shadow",
        // Another user's home directory, and the Windows spellings a file API
        // reads for the file they name, and a path on another drive's own
        // working directory.
        "~root/.ssh/id_rsa",
        "~alice/.ssh/id_rsa",
        "~alice/notes.txt",
        r"C:\\Users\\me\\.ssh\\id_rsa::$DATA",
        r"\\??\\C:\\Users\\me\\.ssh\\id_rsa",
        "D:x",
    ] {
        for (language, code) in [
            (Language::Python, format!("print(open('{path}').read())")),
            (Language::Python, format!("open('{path}', 'w').write('x')")),
            (
                Language::JavaScript,
                format!("console.log(require('fs').readFileSync('{path}'))"),
            ),
            (
                Language::JavaScript,
                format!("require('fs').writeFileSync('{path}', 'x')"),
            ),
        ] {
            found.extend(on_machines("kernel", language, &code));
        }
    }
    // What the caller protects, names as a secret, or both.
    let named = posix()
        .with_protected([
            Protected::folder("/home/me/.agent", "the agent's settings"),
            Protected::file("/home/me/work/repo/rules.yaml", "the agent's rules"),
            Protected::file("/home/me/work/repo/both.env", "the agent's file"),
        ])
        .with_secrets([
            Secret::file("/home/me/work/repo/.env", "the project's environment file"),
            Secret::folder("/home/me/.vault", "your password vault"),
            Secret::file("/home/me/work/repo/both.env", "the shared secret"),
        ]);
    for path in [
        "/home/me/.agent/config.yaml",
        "rules.yaml",
        ".env",
        "/home/me/work/repo/.env",
        "/home/me/.vault/db",
        "both.env",
        "~/.agent",
        "src/main.rs",
    ] {
        for (language, code) in [
            (Language::Python, format!("print(open('{path}').read())")),
            (Language::Python, format!("open('{path}', 'w')")),
            (Language::Python, format!("import os\nos.remove('{path}')")),
            (
                Language::Python,
                format!("import os\nos.rename('{path}', 'x')"),
            ),
            (
                Language::Python,
                format!("import os\nos.chmod('{path}', 0o600)"),
            ),
            (
                Language::Python,
                format!("import os\nos.chdir('/home/me')\nprint(open('{path}').read())"),
            ),
            (
                Language::JavaScript,
                format!("console.log(require('fs').readFileSync('{path}'))"),
            ),
            (
                Language::JavaScript,
                format!("require('fs').writeFileSync('{path}', 'x')"),
            ),
            (
                Language::JavaScript,
                format!("require('fs').rmSync('{path}')"),
            ),
        ] {
            found.push(Code {
                at: "named".to_string(),
                machine: "named".to_string(),
                language,
                code,
                paths: named.clone(),
            });
        }
    }
    // How the caller says WSL spells the Windows drives: under `/mnt`, with
    // the Windows home, from a workspace on this machine's side and from one
    // on a mounted drive.
    let wsl = posix()
        .with_protected([Protected::file(
            "/mnt/c/Users/me/agent.yaml",
            "the agent's rules",
        )])
        .with_drive_mounts(["/mnt"])
        .with_windows_home(r"C:\Users\me");
    let mounted = Paths::new("/mnt/c/Users/me/repo", "/home/me", ["/mnt/c/Users/me/repo"])
        .with_drive_mounts(["/mnt"])
        .with_windows_home(r"C:\Users\me");
    for (machine, paths) in [("wsl", &wsl), ("mounted", &mounted)] {
        for path in [
            "src/main.rs",
            "../.ssh/id_rsa",
            "../agent.yaml",
            "/mnt/c/Users/me/.ssh/id_rsa",
            "/mnt/C/users/ME/.ssh/id_rsa",
            "/mnt/c/Users/me",
            "/mnt/c/Users/me/agent.yaml",
            "/mnt/c/Users/other/.aws/credentials",
            "/mnt/c/Windows/System32/config/SAM",
            "/mnt/c/Windows/Temp/x",
            "/mnt/c/../../etc/shadow",
            "/mnt/d/x",
        ] {
            for (language, code) in [
                (Language::Python, format!("print(open('{path}').read())")),
                (Language::Python, format!("open('{path}', 'w')")),
                (Language::Python, format!("import os\nos.remove('{path}')")),
                (
                    Language::Python,
                    format!("import shutil\nshutil.rmtree('{path}')"),
                ),
                (
                    Language::Python,
                    format!("import os\nos.chdir('/mnt/c/Users')\nprint(open('{path}').read())"),
                ),
                (
                    Language::JavaScript,
                    format!("console.log(require('fs').readFileSync('{path}'))"),
                ),
                (
                    Language::JavaScript,
                    format!("require('fs').writeFileSync('{path}', 'x')"),
                ),
            ] {
                found.push(Code {
                    at: machine.to_string(),
                    machine: machine.to_string(),
                    language,
                    code,
                    paths: paths.clone(),
                });
            }
        }
    }
    // The links the caller has resolved, on this machine's side and on a
    // mounted drive.
    let linked = posix()
        .with_protected([Protected::folder("/home/me/.agent", "the agent's settings")])
        .with_links([
            Link::new("/home/me/work/repo/keys", "/home/me/.ssh"),
            Link::new("/home/me/work/repo/data", "/data/x"),
            Link::new("/home/me/work/repo/agent", "/home/me/.agent"),
            Link::new("/home/me/work/repo/rc", "../../.bashrc"),
            Link::new("/home/me/work/repo/a", "b"),
            Link::new("/home/me/work/repo/b", "a"),
        ]);
    let linked_mount = Paths::new("/mnt/c/Users/me/repo", "/home/me", ["/mnt/c/Users/me/repo"])
        .with_drive_mounts(["/mnt"])
        .with_windows_home(r"C:\Users\me")
        .with_links([Link::new("/mnt/c/Users/me/repo/keys", "../.ssh")]);
    for (machine, paths) in [("linked", &linked), ("linked_mount", &linked_mount)] {
        for path in [
            "keys/id_rsa",
            "keys/../.ssh/id_rsa",
            "keys/../keys.txt",
            "data/y",
            "agent/config.json",
            "rc",
            "a/x",
            "src/main.rs",
            "../.ssh/id_rsa",
            "/mnt/c/Users/me/.ssh/id_rsa",
        ] {
            for (language, code) in [
                (Language::Python, format!("print(open('{path}').read())")),
                (Language::Python, format!("open('{path}', 'w')")),
                (Language::Python, format!("import os\nos.remove('{path}')")),
                (
                    Language::Python,
                    format!("import shutil\nshutil.rmtree('{path}')"),
                ),
                (
                    Language::Python,
                    format!("import os\nos.chdir('keys')\nprint(open('{path}').read())"),
                ),
                (
                    Language::JavaScript,
                    format!("console.log(require('fs').readFileSync('{path}'))"),
                ),
                (
                    Language::JavaScript,
                    format!("require('fs').writeFileSync('{path}', 'x')"),
                ),
            ] {
                found.push(Code {
                    at: machine.to_string(),
                    machine: machine.to_string(),
                    language,
                    code,
                    paths: paths.clone(),
                });
            }
        }
    }
    found
}

/// The shell guard's shell for the lines the script guard gives as targets
/// on the machine `paths` describe.
fn shell_of(paths: &Paths) -> Shell {
    match script::target_shell(paths) {
        script::TargetShell::Posix => Shell::Posix,
        script::TargetShell::Cmd => Shell::Cmd,
    }
}

/// The shell line that hands `code` to the interpreter of `language`.
fn line_of(language: Language, code: &str) -> String {
    let word = format!("'{}'", code.replace('\'', "'\\''"));
    match language {
        Language::Python => format!("python3 -c {word}"),
        Language::JavaScript => format!("node -e {word}"),
    }
}

fn language_name(language: Language) -> &'static str {
    match language {
        Language::Python => "python",
        Language::JavaScript => "javascript",
    }
}

fn said<R: RuleName>(findings: &[Finding<R>]) -> BTreeSet<Said> {
    findings
        .iter()
        .map(|finding| {
            (
                finding.rule.name().to_string(),
                finding.reason.clone(),
                finding.instead.clone(),
            )
        })
        .collect()
}

fn answer<R: RuleName>(assessment: &Assessment<R>) -> String {
    if assessment.is_safe() {
        return "safe".to_string();
    }
    assessment
        .findings()
        .iter()
        .map(|finding| {
            format!(
                "{} \"{}\" {:?}",
                finding.rule.name(),
                finding.reason,
                finding.target.as_deref().unwrap_or("")
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// `runs code the guard does not read fully` is said only where nothing
/// else is.
fn settled(mut found: BTreeSet<Said>) -> BTreeSet<Said> {
    if found.iter().any(|said| said.1 != UNREAD_FULLY) {
        found.retain(|said| said.1 != UNREAD_FULLY);
    }
    found
}

/// How two answers compare.
enum Compared {
    Agree,
    /// They differ by these findings of [`BY_DESIGN`] only.
    ByDesign(Vec<&'static str>),
    /// They differ otherwise: why, with both answers.
    Disagree(String),
}

/// The script guard's answer as a caller combines it with the shell guard's
/// answer for each program it starts, against the shell guard's answer for
/// the whole code.
fn compare(case: &Code) -> Compared {
    let Code {
        language,
        code,
        paths,
        machine,
        ..
    } = case;
    let script = script::judge(*language, code, paths);
    let shell = shell::classify(&line_of(*language, code), Shell::Posix, paths);
    let shell_of_targets = shell_of(paths);
    let windows = shell_of_targets == Shell::Cmd;
    let mut combined: BTreeSet<Said> = BTreeSet::new();
    let mut programs = Vec::new();
    for finding in script.findings() {
        if finding.rule == script::Rule::RunProgram {
            if let Some(target) = &finding.target {
                let found = shell::classify(target, shell_of_targets, paths);
                programs.push(format!("{target:?}: {}", answer(&found)));
                combined.extend(said(found.findings()));
            }
            continue;
        }
        let mut one = said(std::slice::from_ref(finding));
        for (rule, reason, shell_rule, shell_reason) in MAPPED {
            if finding.rule.name() == rule && finding.reason == reason {
                one = [(shell_rule.to_string(), shell_reason.to_string(), None)].into();
            }
        }
        combined.extend(one);
    }
    let starts_program = script
        .findings()
        .iter()
        .any(|finding| finding.rule == script::Rule::RunProgram);
    if windows && starts_program {
        return windows_programs(case, &script, &shell, &combined, &programs);
    }
    let reads_key = combined.iter().any(|said| said.0 == "read_secret");
    let mut designed = Vec::new();
    for (rule, reason, why) in BY_DESIGN {
        let applies = if reason == BY_DESIGN[0].1 {
            *language == Language::Python && declares_other_encoding(code)
        } else if reason == BY_DESIGN[3].1 {
            reads_key
        } else {
            true
        };
        let found = combined
            .iter()
            .find(|said| said.0 == rule && said.1 == reason)
            .cloned();
        if let Some(found) = found.filter(|_| applies) {
            if !said(shell.findings()).contains(&found) {
                combined.remove(&found);
                designed.push(why);
            }
        }
    }
    let ours = settled(combined);
    let theirs = settled(said(shell.findings()));
    // A difference by design is one where the script guard says more, never
    // less: without those findings, the two say the same, or the shell guard
    // says only that it does not read the code whole.
    let only_unread = theirs.iter().all(|said| said.1 == UNREAD_FULLY);
    if windows && ours != theirs && only_unread && !ours.is_empty() && !script.is_safe() {
        return Compared::ByDesign(vec![WINDOWS_PATHS]);
    }
    let same = ours == theirs || (!designed.is_empty() && ours.is_empty() && only_unread);
    let safe_alike =
        script.is_safe() == shell.is_safe() || (!designed.is_empty() && shell.is_safe());
    if same && safe_alike {
        return if designed.is_empty() {
            Compared::Agree
        } else {
            Compared::ByDesign(designed)
        };
    }
    let mut why = Vec::new();
    if !safe_alike {
        why.push("one is safe and the other risky".to_string());
    }
    for found in ours.difference(&theirs) {
        why.push(format!("{found:?} is not the shell guard's"));
    }
    for found in theirs.difference(&ours) {
        why.push(format!(
            "the shell guard's {found:?} is not the script guard's"
        ));
    }
    Compared::Disagree(format!(
        "{} on {machine}: {} {code:?}: {}\n    script: {}\n    shell:  {}{}",
        case.at,
        language_name(*language),
        why.join(", "),
        answer(&script),
        answer(&shell),
        programs
            .iter()
            .map(|program| format!("\n    target {program}"))
            .collect::<Vec<_>>()
            .concat()
    ))
}

/// The script guard's answer for code that starts a program on a Windows
/// machine, combined with cmd's reading of each target, against the shell
/// guard's for the whole code: both risky, and every finding of the shell
/// guard about a file act is one of the combined answer's, or is excused by
/// a program the script guard cannot write as a line (one finding for each
/// such program), or is one of [`WINDOWS_MAPPED`], where the shell guard's
/// inline reading, which judges the program as a POSIX unit, says what cmd
/// does not do.
fn windows_programs(
    case: &Code,
    script: &Assessment<script::Rule>,
    shell: &Assessment<shell::Rule>,
    combined: &BTreeSet<Said>,
    programs: &[String],
) -> Compared {
    // A program with no target is one whose file acts the combined answer
    // cannot hold, since no line of it is read. The shell guard's findings
    // are not tied to the program that made them (a reason names a place,
    // not a program), so they are held by count: each program with no target
    // excuses one finding about a file act of the shell guard's that the
    // combined answer lacks, and no more. The file acts of the programs that
    // have a target, and of the code's own acts, are compared one for one:
    // they are in the combined answer, or they use up an excuse.
    let mut excuses = script
        .findings()
        .iter()
        .filter(|finding| finding.rule == script::Rule::RunProgram && finding.target.is_none())
        .count();
    let mut why = Vec::new();
    if script.is_safe() != shell.is_safe() {
        why.push("one is safe and the other risky".to_string());
    }
    let mut mapped = Vec::new();
    for found in said(shell.findings()) {
        if !FILE_ACTS.contains(&found.0.as_str()) || combined.contains(&found) {
            continue;
        }
        if excuses > 0 {
            excuses -= 1;
            continue;
        }
        let shape = WINDOWS_MAPPED.iter().find(|(rule, reason, shape, _)| {
            *rule == found.0 && *reason == found.1 && case.code.contains(shape)
        });
        match shape {
            Some((_, _, _, because)) => mapped.push(*because),
            None => why.push(format!(
                "the shell guard's {found:?} is not the script guard's"
            )),
        }
    }
    if why.is_empty() {
        mapped.push(WINDOWS_PROGRAM);
        return Compared::ByDesign(mapped);
    }
    Compared::Disagree(format!(
        "{} on {}: {} {:?}: {}\n    script: {}\n    shell:  {}{}",
        case.at,
        case.machine,
        language_name(case.language),
        case.code,
        why.join(", "),
        answer(script),
        answer(shell),
        programs
            .iter()
            .map(|program| format!("\n    target {program}"))
            .collect::<Vec<_>>()
            .concat()
    ))
}

fn left_out(case: &Code) -> bool {
    LEFT_OUT.iter().any(|(machine, language, code, _)| {
        *machine == case.machine && *language == language_name(case.language) && *code == case.code
    })
}

#[test]
fn the_script_guard_and_the_shell_guard_agree_on_the_code_of_every_case() {
    let (reader, shell) = match (reader_cases(), shell_cases()) {
        (Ok(reader), Ok(shell)) => (reader, shell),
        (Err(why), _) | (_, Err(why)) => panic!("{why}"),
    };
    let made = made_cases();
    // Each source gives its cases, or the check is empty.
    assert!(
        reader.len() > 600,
        "only {} cases of the reader",
        reader.len()
    );
    assert!(
        shell.len() > 4_000,
        "only {} cases of the shell guard",
        shell.len()
    );
    assert!(made.len() > 1_500, "only {} cases made here", made.len());
    let cases: Vec<Code> = reader.into_iter().chain(shell).chain(made).collect();
    let mut wrong = Vec::new();
    let mut agreeing_left_out = Vec::new();
    let mut designed: BTreeMap<&str, usize> = BTreeMap::new();
    for case in &cases {
        match (compare(case), left_out(case)) {
            (Compared::Disagree(why), false) => wrong.push(why),
            (Compared::Disagree(_), true) => {}
            (Compared::ByDesign(whys), false) => {
                for why in whys {
                    *designed.entry(why).or_default() += 1;
                }
            }
            (_, true) => {
                agreeing_left_out.push(format!("{} on {}: {:?}", case.at, case.machine, case.code));
            }
            (Compared::Agree, false) => {}
        }
    }
    assert!(
        wrong.is_empty(),
        "{} of {} cases disagree:\n{}",
        wrong.len(),
        cases.len(),
        wrong.join("\n")
    );
    assert!(
        agreeing_left_out.is_empty(),
        "left out, but the guards agree: take them out of LEFT_OUT\n{}",
        agreeing_left_out.join("\n")
    );
    // Each difference by design is met, or it says nothing. (A program cmd
    // cannot carry, and input a program is given, are in none of the cases:
    // the script guard's own cases hold them.)
    for (_, _, why) in [BY_DESIGN[0], BY_DESIGN[3]] {
        assert!(
            designed.contains_key(why),
            "no case differs by design so: {why}"
        );
    }
    assert!(
        designed.contains_key(WINDOWS_PROGRAM),
        "no program on a Windows machine"
    );
    assert!(
        designed.contains_key(WINDOWS_PATHS),
        "no Windows path on a Windows machine"
    );
    assert!(
        designed.contains_key(BY_DESIGN[4].2),
        "no read of a path that cannot be placed"
    );
}

#[test]
fn a_left_out_case_says_why() {
    for (machine, language, code, why) in LEFT_OUT {
        assert!(!machine.is_empty(), "{code:?}");
        assert!(["python", "javascript"].contains(language), "{code:?}");
        assert!(!why.is_empty(), "{code:?}");
    }
}
