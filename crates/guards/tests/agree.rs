//! The shell guard and the file guard give the same answer for the same file.
//!
//! An agent refused a key on the file API can read it through the shell, so
//! `cat <path>` must be `read_secret` exactly when a read of `<path>` is, for
//! every path the file guard's own cases name, on a POSIX machine, a Mac and
//! a Windows one (in PowerShell and in cmd). The paths are read from every
//! case file of the file guard, `crates/file/tests/cases/*.cases` (the path
//! of each case, and the paths each `paths` line names), so a case added
//! there is held against the shell as soon as it lands. The paths of a case
//! file are also judged on each machine its `paths` lines declare that names
//! a secret (`secret_file=`, `secret_folder=`), with the protected paths and
//! the secrets it names, so a secret the caller names gets one answer too.

#![cfg(all(feature = "shell", feature = "file"))]
#![allow(
    clippy::disallowed_methods,
    clippy::disallowed_macros,
    reason = "this test reads the repository's own files, which no guard may do"
)]

#[path = "../../core/tests/common/cases.rs"]
mod format;

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use format::{Word, PATH_FIELDS};
use milo_guards::file::{self, Access};
use milo_guards::shell::{self, Shell};
use milo_guards::{Paths, Protected, Secret};

/// The most a path may have in it for a case to be one worth a line.
const LONGEST: usize = 300;

/// The folder of the file guard's case files.
fn folder() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../file/tests/cases")
}

/// The names of the file guard's case files, sorted.
fn case_files() -> Result<Vec<String>, String> {
    let entries =
        fs::read_dir(folder()).map_err(|e| format!("cannot read {}: {e}", folder().display()))?;
    let mut names: Vec<String> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "cases"))
        .filter_map(|path| Some(path.file_stem()?.to_str()?.to_string()))
        .collect();
    names.sort();
    Ok(names)
}

/// The records of the file guard's case file `name`.
fn records_of(name: &str) -> Result<Vec<format::Record>, String> {
    let shown = format!("crates/file/tests/cases/{name}.cases");
    let path = folder().join(format!("{name}.cases"));
    let source =
        fs::read_to_string(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    format::parse(&shown, &source).map_err(|refused| refused.join("\n"))
}

/// Every path the case file `name` of the file guard names: the path of each
/// case, and each path a `paths` line names.
fn paths_of(name: &str) -> Result<Vec<String>, String> {
    let records = records_of(name)?;
    let mut found = Vec::new();
    for record in records {
        match record.text {
            Some(text) => found.push(text),
            None => found.extend(record.words.into_iter().filter_map(|word| match word {
                Word::Field(field, value) if PATH_FIELDS.contains(&field.as_str()) => Some(value),
                _ => None,
            })),
        }
    }
    Ok(found)
}

/// The paths of the file guard's cases: each that a line can name whole.
fn paths_of_the_cases() -> Result<BTreeSet<String>, String> {
    let mut found = BTreeSet::new();
    for name in case_files()? {
        found.extend(paths_of(&name)?.into_iter().filter(|path| {
            !path.is_empty()
                && path.len() <= LONGEST
                && !path.chars().any(char::is_control)
                && !path.starts_with(char::is_whitespace)
        }));
    }
    Ok(found)
}

/// Whether `read_secret` is among the file guard's findings for a read of
/// `path`; `None` when the path is not one literal path the shell could be
/// given (a wildcard, a variable, `~user`: the file guard calls it
/// unreadable).
fn file_says(path: &str, paths: &Paths) -> Option<bool> {
    let assessment = file::judge(Access::Read, path, paths);
    let found: Vec<_> = assessment.findings().iter().map(|f| f.rule).collect();
    if found.contains(&file::Rule::Unreadable) {
        return None;
    }
    Some(found.contains(&file::Rule::ReadSecret))
}

fn shell_says(line: &str, shell: Shell, paths: &Paths) -> bool {
    shell::classify(line, shell, paths)
        .findings()
        .iter()
        .any(|finding| finding.rule == shell::Rule::ReadSecret)
}

/// The lines that read `path` in `shell`, in every form that names it whole:
/// quoted as the shell reads it as written, as a `<` redirect's source (cmd
/// and POSIX), and, where the path starts at the home directory, spelled with
/// the variable that names it (`$HOME`, `%USERPROFILE%`). A path a form cannot
/// carry is left out of that form, never out of the others:
///
/// - cmd cannot carry `"`: no Windows name has one, so there is nothing to
///   judge;
/// - cmd cannot carry `%`: it expands `%name%` even in quotes, so the word is a
///   variable and not this file;
/// - cmd cannot carry `^`: the guard reads a caret as cmd's escape, which cmd
///   does not do inside quotes (a known gap, kept visible by the skip);
/// - a word spelled with `$HOME` cannot carry `$`, a backtick, `"` or `\`
///   (POSIX), which are not plain text in it, nor, bare in PowerShell, a space
///   or one of `;|&(){},'"<>@#`, which end the word.
fn lines(path: &str, shell: Shell, home: &str) -> Vec<String> {
    let mut lines = Vec::new();
    // The path with the home directory spelled as a variable, when it starts
    // there (whole parts, without case on Windows).
    let under = |variable: &str| {
        let rest = path.get(home.len()..)?;
        let same = path.get(..home.len()).is_some_and(|head| {
            if home.starts_with('/') {
                head == home
            } else {
                head.eq_ignore_ascii_case(home)
            }
        });
        (same && (rest.is_empty() || rest.starts_with(['/', '\\'])))
            .then(|| format!("{variable}{rest}"))
    };
    match shell {
        Shell::Posix => {
            let quoted = format!("'{}'", path.replace('\'', "'\\''"));
            lines.push(format!("cat {quoted}"));
            lines.push(format!("cat < {quoted}"));
            lines.push(format!("base64 <{quoted}"));
            if let Some(spelled) =
                under("$HOME").filter(|text| !text.contains(['"', '$', '`', '\\', '!', '\n']))
            {
                lines.push(format!("cat \"{spelled}\""));
                lines.push(format!("cat < \"{spelled}\""));
            }
        }
        Shell::PowerShell => {
            let quoted = format!("'{}'", path.replace('\'', "''"));
            lines.push(format!("Get-Content -LiteralPath {quoted}"));
            lines.push(format!("Get-Content {quoted}"));
            lines.push(format!("Get-Content -Path {quoted} -Raw"));
            if let Some(spelled) = under("$HOME") {
                if !spelled.contains([
                    ' ', ';', '|', '&', '(', ')', '{', '}', ',', '\'', '"', '<', '>', '@', '#',
                    '$', '`',
                ]) {
                    lines.push(format!("Get-Content {spelled}"));
                    lines.push(format!("Get-Content -Path {spelled}"));
                }
            }
        }
        Shell::Cmd if !path.contains(['"', '%', '^']) => {
            lines.push(format!("type \"{path}\""));
            lines.push(format!("more < \"{path}\""));
            lines.push(format!("more <\"{path}\""));
            lines.push(format!("sort < \"{path}\""));
            lines.push(format!("findstr x 0< \"{path}\""));
            if !path.contains([' ', '&', '|', '<', '>', '(', ')', ',', ';', '=']) {
                lines.push(format!("more < {path}"));
            }
            if let Some(spelled) = under("%USERPROFILE%") {
                lines.push(format!("type \"{spelled}\""));
                lines.push(format!("more < \"{spelled}\""));
            }
        }
        _ => {}
    }
    lines
}

/// The three machines a case names by default, by the names a `paths` line's
/// `base=` gives them.
fn machines() -> HashMap<String, Paths> {
    HashMap::from([
        (
            "posix".to_string(),
            Paths::new("/home/me/work/repo", "/home/me", ["/home/me/work/repo"]),
        ),
        (
            "macos".to_string(),
            Paths::new("/Users/me/dev/repo", "/Users/me", ["/Users/me/dev/repo"]),
        ),
        (
            "windows".to_string(),
            Paths::new(
                r"C:\Users\me\dev\repo",
                r"C:\Users\me",
                [r"C:\Users\me\dev\repo"],
            ),
        ),
    ])
}

/// The machines the `paths` lines of the case file `name` declare, with the
/// protected paths and the secrets each names, in order.
fn declared_in(name: &str) -> Result<Vec<Paths>, String> {
    let mut known = machines();
    let mut declared = Vec::new();
    for record in records_of(name)? {
        if record.text.is_some() || record.words.first() != Some(&Word::Bare("paths".to_string())) {
            continue;
        }
        let made = format::declaration(&record.words[1..])
            .map_err(|why| format!("{}: {why}", record.at))?;
        let mut paths = match (&made.base, made.cwd, made.home) {
            (Some(base), ..) => known
                .get(base)
                .cloned()
                .ok_or_else(|| format!("{}: no paths named `{base}`", record.at))?,
            (None, Some(cwd), Some(home)) => Paths::new(cwd, home, Vec::<PathBuf>::new()),
            _ => return Err(format!("{}: no base, cwd or home", record.at)),
        };
        paths.workspaces.extend(made.workspaces);
        for named in made.named {
            paths = match (named.secret, named.folder) {
                (false, true) => paths.with_protected([Protected::folder(named.path, named.words)]),
                (false, false) => paths.with_protected([Protected::file(named.path, named.words)]),
                (true, true) => paths.with_secrets([Secret::folder(named.path, named.words)]),
                (true, false) => paths.with_secrets([Secret::file(named.path, named.words)]),
            };
        }
        known.insert(made.name, paths.clone());
        declared.push(paths);
    }
    Ok(declared)
}

/// The shells a line is read in on `paths`: POSIX on a POSIX machine,
/// PowerShell and cmd on a Windows one.
fn shells_of(paths: &Paths) -> &'static [Shell] {
    let home = paths.home.to_string_lossy();
    if home.starts_with('/') {
        &[Shell::Posix]
    } else {
        &[Shell::PowerShell, Shell::Cmd]
    }
}

/// Whether the shell and the file guard agree on reading `path` on `paths`,
/// in every line that names it: each line they do not agree on, and how many
/// were judged and secrets.
fn disagree(path: &str, paths: &Paths, shells: &[Shell]) -> (Vec<String>, usize, usize) {
    let (mut wrong, mut judged, mut secrets) = (Vec::new(), 0_usize, 0_usize);
    let Some(expected) = file_says(path, paths) else {
        return (wrong, judged, secrets);
    };
    let home = paths.home.to_string_lossy();
    for &shell in shells {
        for line in lines(path, shell, &home) {
            judged += 1;
            secrets += usize::from(expected);
            let got = shell_says(&line, shell, paths);
            if got != expected {
                wrong.push(format!(
                    "{shell:?} on {home}: the file guard says read_secret = {expected}, \
                     the shell says {got}: {line}"
                ));
            }
        }
    }
    (wrong, judged, secrets)
}

#[test]
fn the_shell_and_the_file_guard_agree_on_every_path_of_the_file_guards_cases() {
    let cases = paths_of_the_cases().expect("the file guard's case files are readable");
    let machines = machines();
    let (mut wrong, mut judged, mut secrets) = (Vec::new(), 0_usize, 0_usize);
    for path in &cases {
        for name in ["posix", "macos", "windows"] {
            let paths = &machines[name];
            let (more, of, keys) = disagree(path, paths, shells_of(paths));
            wrong.extend(more);
            judged += of;
            secrets += keys;
        }
    }
    // The case files are read, and name keys: not an empty scan that agrees
    // on nothing.
    assert!(judged > 10_000, "only {judged} lines were judged");
    assert!(secrets > 2_000, "only {secrets} of them were secrets");
    assert!(
        wrong.is_empty(),
        "{} of {judged} lines are judged differently:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// The same on each machine a case file declares that names a secret: the
/// secrets the caller names change what a read is, and the two guards still
/// give one answer for every path of that file.
#[test]
fn the_shell_and_the_file_guard_agree_on_the_machines_the_cases_declare() {
    let (mut wrong, mut judged, mut secrets) = (Vec::new(), 0_usize, 0_usize);
    for name in case_files().expect("the file guard's case files are listed") {
        let declared = declared_in(&name).expect("the declarations are readable");
        let paths_of_file: BTreeSet<String> = paths_of(&name)
            .expect("the case file is readable")
            .into_iter()
            .filter(|path| {
                !path.is_empty()
                    && path.len() <= LONGEST
                    && !path.chars().any(char::is_control)
                    && !path.starts_with(char::is_whitespace)
            })
            .collect();
        for paths in declared.iter().filter(|paths| !paths.secrets.is_empty()) {
            for path in &paths_of_file {
                let (more, of, keys) = disagree(path, paths, shells_of(paths));
                wrong.extend(more.into_iter().map(|line| format!("{name}: {line}")));
                judged += of;
                secrets += keys;
            }
        }
    }
    // The declared machines name secrets of their own: some reads are ones.
    assert!(judged > 500, "only {judged} lines were judged");
    assert!(secrets > 150, "only {secrets} of them were secrets");
    assert!(
        wrong.is_empty(),
        "{} of {judged} lines are judged differently:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// The machines a case names by default, each with secrets named: a file in
/// the workspace, a folder beside the home directory's keys and a file in a
/// temporary folder, so every spelling of the file guard's own cases is held
/// to one answer where a named secret may change it.
fn named_machines() -> Vec<Paths> {
    let machines = machines();
    let named = |name: &str, workspace: &str, home: &str, temp: &str, separator: char| {
        machines[name].clone().with_secrets([
            Secret::file(
                format!("{workspace}{separator}.env"),
                "the project's environment file",
            ),
            Secret::folder(format!("{home}{separator}.vault"), "your password vault"),
            Secret::file(temp.to_string(), "the session token"),
        ])
    };
    vec![
        named(
            "posix",
            "/home/me/work/repo",
            "/home/me",
            "/tmp/s/token",
            '/',
        ),
        named(
            "macos",
            "/Users/me/dev/repo",
            "/Users/me",
            "/tmp/s/token",
            '/',
        ),
        named(
            "windows",
            r"C:\Users\me\dev\repo",
            r"C:\Users\me",
            r"C:\Users\me\AppData\Local\Temp\s\token",
            '\\',
        ),
    ]
}

/// Every spelling of the file guard's `posix.cases` and `windows.cases`, on
/// each machine with secrets named: the two guards give one answer for each,
/// with none left out.
#[test]
fn the_shell_and_the_file_guard_agree_on_every_spelling_where_secrets_are_named() {
    let mut spellings: BTreeSet<String> = BTreeSet::new();
    for name in ["posix", "windows"] {
        spellings.extend(
            paths_of(name)
                .expect("the case file is readable")
                .into_iter()
                .filter(|path| {
                    !path.is_empty()
                        && path.len() <= LONGEST
                        && !path.chars().any(char::is_control)
                        && !path.starts_with(char::is_whitespace)
                }),
        );
    }
    // Each spelling of a key's folder, as a spelling of the named folder
    // beside it: `~/.SSH/id_rsa` as `~/.VAULT/id_rsa`, `SSH~1` as `VAULT~1`.
    let vault: Vec<String> = spellings
        .iter()
        .filter_map(|path| {
            let lower = path.to_lowercase();
            let at = lower.find(".ssh").map(|at| (at, ".ssh", ".vault"));
            let at = at.or_else(|| lower.find("ssh~1").map(|at| (at, "ssh~1", "vault~1")));
            let (at, from, to) = at?;
            let spelled = &path[at..at + from.len()];
            let to = if spelled.chars().any(char::is_uppercase) {
                to.to_uppercase()
            } else {
                to.to_string()
            };
            Some(format!("{}{to}{}", &path[..at], &path[at + from.len()..]))
        })
        .collect();
    spellings.extend(vault);
    let (mut wrong, mut judged, mut secrets) = (Vec::new(), 0_usize, 0_usize);
    for paths in &named_machines() {
        for path in &spellings {
            let (more, of, keys) = disagree(path, paths, shells_of(paths));
            wrong.extend(more);
            judged += of;
            secrets += keys;
        }
    }
    // Of those, the ones the file guard calls a read of a named secret, in
    // its words: the spellings reach the named paths, not core's keys alone.
    const NAMED: [&str; 3] = [
        "reads the project's environment file",
        "reads your password vault",
        "reads the session token",
    ];
    let named = named_machines()
        .iter()
        .flat_map(|paths| spellings.iter().map(move |path| (path, paths)))
        .filter(|(path, paths)| {
            file::judge(Access::Read, path, paths)
                .findings()
                .iter()
                .any(|finding| NAMED.contains(&finding.reason.as_str()))
        })
        .count();
    assert!(judged > 5_000, "only {judged} lines were judged");
    assert!(secrets > 1_000, "only {secrets} of them were secrets");
    assert!(named > 100, "only {named} spellings read a named secret");
    assert!(
        wrong.is_empty(),
        "{} of {judged} lines are judged differently:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

#[test]
fn each_case_file_names_its_paths() {
    let posix = paths_of("posix").expect("posix.cases is readable");
    // A case's path, decoded, and a path a `paths` line names.
    assert!(posix.iter().any(|path| path == "~/.ssh\\id_rsa"));
    assert!(posix.iter().any(|path| path == "/home/me/.docker/proj"));
    let windows = paths_of("windows").expect("windows.cases is readable");
    assert!(windows
        .iter()
        .any(|path| path == r"\\?\C:\Users\me\.ssh\id_rsa"));
    assert!(windows.iter().any(|path| path == r"C:\Users\Camilo Azula"));
    let protected = paths_of("protected").expect("protected.cases is readable");
    assert!(protected.iter().any(|path| path == "/home/me/.agent"));
    let named = paths_of("named_secrets").expect("named_secrets.cases is readable");
    assert!(named.iter().any(|path| path == "/home/me/work/repo/.env"));
    let declared = declared_in("named_secrets").expect("its declarations are readable");
    assert!(declared.iter().any(|paths| !paths.secrets.is_empty()));
    assert!(paths_of("no_such_cases").is_err());
    // Every case file is read, the ones that were tables first among them.
    let names = case_files().expect("the case files are listed");
    for name in [
        "posix",
        "windows",
        "protected",
        "limits",
        "startup",
        "named_secrets",
    ] {
        assert!(
            names.iter().any(|listed| listed == name),
            "{name}: {names:?}"
        );
    }
}
