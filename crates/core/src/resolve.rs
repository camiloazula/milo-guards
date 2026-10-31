//! Where a path argument resolves, by its spelling alone: POSIX paths
//! (`/home/me`) and Windows ones (`C:\Users\me`, `\\server\share`),
//! whatever the host. Windows paths compare without case, as Windows does.
//! Nothing reads the file system, so a symlink is judged by its own name.

use crate::spelling::glob::{self, Shape, WILDCARDS};
use crate::{Paths, Place};

/// How a path is spelled: what its separators are, and whether it can name
/// a drive or a share. It follows the system the path will be used on, not
/// the host the guard runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Flavour {
    /// `/` separates, a file name may hold `:` and `\`, and names compare
    /// with case.
    Posix,
    /// `/` and `\` separate, a path can start with a drive letter (`C:`) or
    /// a share (`\\server\share`), and names compare without case.
    Windows,
}

impl Flavour {
    /// The characters a path is split at.
    pub fn separators(self) -> &'static [char] {
        match self {
            Self::Posix => &['/'],
            Self::Windows => &['/', '\\'],
        }
    }
}

/// A path as the caller spells it out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Spelling<'a> {
    /// A path as written: absolute, or relative to the working directory.
    Plain(&'a str),
    /// The part of a path below the home directory (`.ssh/id_rsa` for
    /// `~/.ssh/id_rsa`). However it starts, it is read from the home
    /// directory.
    Home(&'a str),
}

impl<'a> Spelling<'a> {
    fn text(self) -> &'a str {
        match self {
            Self::Plain(text) | Self::Home(text) => text,
        }
    }

    fn with(self, text: &'a str) -> Self {
        match self {
            Self::Plain(_) => Self::Plain(text),
            Self::Home(_) => Self::Home(text),
        }
    }
}

/// A path as a root and its parts, `.` and `..` already applied.
#[derive(Debug, Clone)]
struct Loc {
    root: Root,
    parts: Vec<String>,
}

#[derive(Debug, Clone)]
enum Root {
    /// `/`.
    Unix,
    /// `C:`, upper case.
    Drive(char),
    /// `\\server\share`, lower case.
    Unc(String),
}

impl Root {
    fn same(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Unix, Self::Unix) => true,
            (Self::Drive(a), Self::Drive(b)) => a == b,
            (Self::Unc(a), Self::Unc(b)) => a == b,
            _ => false,
        }
    }
}

impl Loc {
    fn at(root: Root) -> Self {
        Self {
            root,
            parts: Vec::new(),
        }
    }

    fn windows(&self) -> bool {
        !matches!(self.root, Root::Unix)
    }

    /// Whether `self` is `other` or a folder holding it.
    fn holds(&self, other: &Self) -> bool {
        let windows = self.windows();
        self.root.same(&other.root)
            && self.parts.len() <= other.parts.len()
            && self.parts.iter().zip(&other.parts).all(|(a, b)| {
                if windows {
                    a.eq_ignore_ascii_case(b)
                } else {
                    a == b
                }
            })
    }

    fn is(&self, other: &Self) -> bool {
        self.parts.len() == other.parts.len() && self.holds(other)
    }

    /// A string that is the same for two paths that name the same file, for
    /// matching a script a line both writes and runs.
    fn key(&self) -> String {
        let root = match &self.root {
            Root::Unix => "/".to_string(),
            Root::Drive(letter) => format!("{letter}:"),
            Root::Unc(share) => format!("//{share}"),
        };
        let parts = if self.windows() {
            self.parts
                .iter()
                .map(|part| part.to_ascii_lowercase())
                .collect::<Vec<_>>()
                .join("/")
        } else {
            self.parts.join("/")
        };
        format!("{root}|{parts}")
    }

    fn join(&self, parts: &[&str]) -> Self {
        let mut joined = self.clone();
        joined
            .parts
            .extend(parts.iter().map(|part| (*part).to_string()));
        joined
    }

    /// Apply `rest`, split at the separators of `flavour`, to this location.
    fn walk(mut self, rest: &str, flavour: Flavour) -> Self {
        let names: Vec<&str> = rest.split(flavour.separators()).collect();
        for (at, part) in names.iter().enumerate() {
            let part = if flavour == Flavour::Windows {
                windows_name(part, at + 1 == names.len())
            } else {
                part
            };
            match part {
                "" | "." => {}
                ".." => {
                    self.parts.pop();
                }
                part => self.parts.push(part.to_string()),
            }
        }
        self
    }

    /// An absolute directory as the caller passed it.
    fn absolute(text: &str) -> Self {
        let windows = drive(text).is_some() || unc(text).is_some();
        let flavour = if windows {
            Flavour::Windows
        } else {
            Flavour::Posix
        };
        if let Some((letter, rest)) = drive(text) {
            return Self::at(Root::Drive(letter)).walk(rest, flavour);
        }
        if let Some((share, rest)) = unc(text) {
            return Self::at(Root::Unc(share)).walk(rest, flavour);
        }
        Self::at(Root::Unix).walk(text, flavour)
    }
}

/// A part of a Windows path as Windows names it. `.` and `..` are read
/// first. The last part then loses every trailing dot and space, so `.git.`
/// and `.git ` are `.git`. A part before it loses one trailing dot only, and
/// a run of dots is a name; a part that still ends in a dot or a space is
/// not one this reads, and [`unreadable_name`] says so.
fn windows_name(part: &str, last: bool) -> &str {
    if matches!(part, "" | "." | "..") {
        part
    } else if last {
        part.trim_end_matches(['.', ' '])
    } else if part.bytes().all(|b| b == b'.') {
        part
    } else {
        part.strip_suffix('.').unwrap_or(part)
    }
}

/// Whether a Windows part is one [`windows_name`] cannot say the name of: it
/// is nothing but dots and spaces (and not `.` or `..`), or a part before the
/// last still ends in a dot or a space once its one trailing dot is gone.
fn unreadable_name(part: &str, last: bool) -> bool {
    if matches!(part, "" | "." | "..") {
        return false;
    }
    part.bytes().all(|b| matches!(b, b'.' | b' '))
        || (!last && part.strip_suffix('.').unwrap_or(part).ends_with([' ', '.']))
}

/// Whether `part` could be the 8.3 short name of `name`, which drops its
/// dots and keeps its first six characters in capitals, then `~` and a number
/// (`AGENT~1` for `.agent`, `SETTIN~1.YAM` for `settings.yaml`), or two
/// characters, four hex digits and `~1` once names collide. Any other
/// `NAME~N` is a plain name.
fn short_name(part: &str, name: &str) -> bool {
    let Some((stem, ext)) = short_stem(name) else {
        return false;
    };
    let Some((head, rest)) = part.split_once('~') else {
        return false;
    };
    let (number, extension) = match rest.split_once('.') {
        Some((number, extension)) => (number, Some(extension)),
        None => (rest, None),
    };
    let hashed = head.len() == 6
        && head.is_char_boundary(2)
        && stem.is_char_boundary(2)
        && head[..2].eq_ignore_ascii_case(&stem[..2])
        && head[2..].bytes().all(|b| b.is_ascii_hexdigit());
    (head.eq_ignore_ascii_case(&stem) || hashed)
        && !number.is_empty()
        && number.bytes().all(|b| b.is_ascii_digit())
        && match (extension, &ext) {
            (None, None) => true,
            (Some(extension), Some(ext)) => extension.eq_ignore_ascii_case(ext),
            _ => false,
        }
}

/// The short name `name` would get, with the number `1`: what a pattern is
/// matched against as well as the name.
fn short_form(name: &str) -> Option<String> {
    let (stem, ext) = short_stem(name)?;
    Some(match ext {
        Some(ext) => format!(
            "{}~1.{}",
            stem.to_ascii_uppercase(),
            ext.to_ascii_uppercase()
        ),
        None => format!("{}~1", stem.to_ascii_uppercase()),
    })
}

/// The first six characters of a name's base without dots, spaces and what a
/// short name leaves out, and its extension cut to three; `None` when
/// nothing is left of the base.
fn short_stem(name: &str) -> Option<(String, Option<String>)> {
    let keep = |text: &str, most: usize| -> String {
        text.chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '$' | '!' | '#'))
            .take(most)
            .collect()
    };
    let (base, ext) = match name.trim_start_matches('.').rsplit_once('.') {
        Some((base, ext)) => (base, Some(keep(ext, 3)).filter(|ext| !ext.is_empty())),
        None => (name.trim_start_matches('.'), None),
    };
    let stem = keep(&base.replace('.', ""), 6);
    (!stem.is_empty()).then_some((stem, ext))
}

/// Whether `part` could be the 8.3 short name of `.git`.
fn short_git(part: &str) -> bool {
    short_name(part, ".git")
}

/// Whether a Windows path is known only when it runs, because the spelling
/// does not say which name it is: a stream (`x.txt:stream`,
/// `.git::$INDEX_ALLOCATION`, a `:` in a part below the drive or share), or a
/// part [`unreadable_name`] cannot read.
fn known_when_run(path: Spelling<'_>, flavour: Flavour) -> bool {
    if flavour != Flavour::Windows {
        return false;
    }
    let rest = match path {
        Spelling::Home(rest) => rest,
        Spelling::Plain(text) => match (unc(text), drive(text)) {
            (Some((_, rest)), _) | (None, Some((_, rest))) => rest,
            (None, None) => text,
        },
    };
    let names: Vec<&str> = rest.split(flavour.separators()).collect();
    names
        .iter()
        .enumerate()
        .any(|(at, part)| part.contains(':') || unreadable_name(part, at + 1 == names.len()))
}

/// `C:` and what follows it, for a path that starts with a drive letter.
fn drive(text: &str) -> Option<(char, &str)> {
    let mut chars = text.chars();
    let letter = chars.next().filter(char::is_ascii_alphabetic)?;
    (chars.next() == Some(':')).then(|| (letter.to_ascii_uppercase(), &text[2..]))
}

/// `\\server\share` (lower case) and what follows it.
fn unc(text: &str) -> Option<(String, &str)> {
    let rest = text
        .strip_prefix("\\\\")
        .or_else(|| text.strip_prefix("//"))?;
    let mut parts = rest.splitn(3, ['/', '\\']);
    let server = parts.next().filter(|server| !server.is_empty())?;
    let share = parts.next().unwrap_or_default();
    let tail = parts.next().unwrap_or_default();
    Some((format!("{server}/{share}").to_lowercase(), tail))
}

/// Devices that discard or echo, by their POSIX spelling.
const NULL_DEVICES: [&str; 7] = [
    "/dev/null",
    "/dev/stdout",
    "/dev/stderr",
    "/dev/tty",
    "/dev/zero",
    "/dev/random",
    "/dev/urandom",
];

/// Disk devices under `/dev`, by the start of their names.
const DISK_DEVICES: [&str; 11] = [
    "sd", "hd", "vd", "xvd", "nvme", "mmcblk", "disk", "rdisk", "md", "dm-", "mapper/",
];

/// Files and folders under the home directory whose loss or change hurts.
const SENSITIVE: [(&[&str], &str); 19] = [
    (&[".ssh"], "your SSH keys"),
    (&[".gnupg"], "your GPG keys"),
    (&[".aws"], "your AWS credentials"),
    (&[".azure"], "your Azure credentials"),
    (&[".kube"], "your Kubernetes credentials"),
    (&[".docker"], "your Docker credentials"),
    (&[".netrc"], "your saved logins"),
    (&[".git-credentials"], "your git credentials"),
    (&[".gitconfig"], "your git settings"),
    (&[".bashrc"], "a shell startup file"),
    (&[".bash_profile"], "a shell startup file"),
    (&[".zshrc"], "a shell startup file"),
    (&[".zprofile"], "a shell startup file"),
    (&[".zshenv"], "a shell startup file"),
    (&[".profile"], "a shell startup file"),
    (&["Library", "Keychains"], "your keychains"),
    (
        &[
            "AppData",
            "Roaming",
            "Microsoft",
            "Windows",
            "Start Menu",
            "Programs",
            "Startup",
        ],
        "the programs Windows starts at login",
    ),
    (&["Documents", "PowerShell"], "your PowerShell profile"),
    (
        &["Documents", "WindowsPowerShell"],
        "your PowerShell profile",
    ),
];

/// Top-level system folders on a POSIX system.
const POSIX_SYSTEM: [&str; 18] = [
    "etc",
    "usr",
    "bin",
    "sbin",
    "lib",
    "lib64",
    "boot",
    "System",
    "Library",
    "Applications",
    "opt",
    "var",
    "private",
    "dev",
    "proc",
    "sys",
    "root",
    "srv",
];

/// Top-level system folders on a Windows drive.
const WINDOWS_SYSTEM: [&str; 4] = [
    "Windows",
    "Program Files",
    "Program Files (x86)",
    "ProgramData",
];

/// Judges paths against the caller's directories.
#[derive(Debug, Clone)]
pub struct Resolver {
    cwd: Loc,
    home: Loc,
    workspaces: Vec<Loc>,
    temps: Vec<Loc>,
    sensitive: Vec<(Loc, &'static str)>,
    protected: Vec<(Loc, &'static str)>,
    system: Vec<Loc>,
}

impl Resolver {
    /// A resolver for the directories in `paths`. A Windows home directory
    /// makes it a Windows machine (its temporary and system folders are
    /// Windows ones); any other makes it a POSIX one.
    pub fn new(paths: &Paths) -> Self {
        let cwd = Loc::absolute(&paths.cwd.to_string_lossy());
        let home = Loc::absolute(&paths.home.to_string_lossy());
        let workspaces = paths
            .workspaces
            .iter()
            .map(|folder| Loc::absolute(&folder.to_string_lossy()))
            .collect();
        let (temps, system) = if home.windows() {
            let drive = Loc::at(home.root.clone());
            (
                vec![
                    home.join(&["AppData", "Local", "Temp"]),
                    drive.join(&["Windows", "Temp"]),
                ],
                WINDOWS_SYSTEM
                    .iter()
                    .map(|folder| drive.join(&[folder]))
                    .collect(),
            )
        } else {
            let root = Loc::at(Root::Unix);
            (
                [
                    &["tmp"][..],
                    &["private", "tmp"],
                    &["var", "tmp"],
                    &["private", "var", "tmp"],
                    &["var", "folders"],
                    &["private", "var", "folders"],
                ]
                .iter()
                .map(|parts| root.join(parts))
                .collect(),
                POSIX_SYSTEM
                    .iter()
                    .map(|folder| root.join(&[folder]))
                    .collect(),
            )
        };
        let sensitive = SENSITIVE
            .iter()
            .map(|(parts, words)| (home.join(parts), *words))
            .collect();
        let protected = paths
            .protected
            .iter()
            .map(|entry| (Loc::absolute(&entry.path.to_string_lossy()), entry.words))
            .collect();
        Self {
            cwd,
            home,
            workspaces,
            temps,
            sensitive,
            protected,
            system,
        }
    }

    /// Where `path` lands. It never answers [`Place::Registry`]: a path this
    /// spelled out is a file path, and the guard that reads the syntax around
    /// it says when it is not. It answers [`Place::Unknown`] only for a
    /// Windows spelling that does not say which name it is (a stream such as
    /// `x.txt:stream`, or a part before the last that ends in a space).
    #[must_use]
    pub fn place(&self, path: Spelling<'_>, flavour: Flavour) -> Place {
        self.place_hidden(path, flavour, false)
    }

    /// As [`place`](Self::place), for a pattern that may match hidden names
    /// when `hidden` is set: the shell has `dotglob` (or `globdots`, or
    /// `GLOBIGNORE`) on, so a wildcard matches a leading dot as it does on
    /// the `Windows` flavour. `hidden` changes nothing on `Windows`, whose
    /// wildcards always do, and nothing for a path without a wildcard.
    #[must_use]
    pub fn place_hidden(&self, path: Spelling<'_>, flavour: Flavour, hidden: bool) -> Place {
        self.place_as(path, flavour, hidden, true)
    }

    /// As [`place_hidden`](Self::place_hidden), for a path something is
    /// written *into* (a copy's destination, a redirect's target): a folder
    /// that merely holds a protected path is not a write of that path, so it
    /// is not `Protected`, where `place_hidden` answers `Protected` for it.
    /// Everything else is the same.
    #[must_use]
    pub fn place_into(&self, path: Spelling<'_>, flavour: Flavour, hidden: bool) -> Place {
        self.place_as(path, flavour, hidden, false)
    }

    /// `holding` says whether a harmless folder that holds a protected path
    /// is judged as that path.
    fn place_as(&self, path: Spelling<'_>, flavour: Flavour, hidden: bool, holding: bool) -> Place {
        let text = path.text();
        if let Spelling::Plain(text) = path {
            if let Some(device) = device(text, flavour) {
                return device;
            }
        }
        if known_when_run(path, flavour) {
            return Place::Unknown;
        }
        // Each part holding a wildcard stands for one entry, so a `..` after
        // it (`src/*/../../x`) still climbs; what a pattern matches lies in
        // the folder before its first wildcard part that no `..` cancels.
        let marked = mark_wildcards(text, flavour);
        let mut loc = self.locate(path.with(marked.as_deref().unwrap_or(text)), flavour);
        // From the first wildcard part on, as the text of each part.
        let wildcards: Vec<&str> = text
            .split(flavour.separators())
            .filter(|part| part.contains(WILDCARDS))
            .collect();
        let tail: Option<Vec<String>> = loc
            .parts
            .iter()
            .position(|part| part.starts_with(WILDCARD))
            .map(|at| {
                loc.parts[at..]
                    .iter()
                    .map(|part| match part.strip_prefix(WILDCARD) {
                        Some(n) => n
                            .parse::<usize>()
                            .ok()
                            .and_then(|n| wildcards.get(n).copied())
                            .unwrap_or("*")
                            .to_string(),
                        None => part.clone(),
                    })
                    .collect()
            });
        let pattern = match loc.parts.iter().position(|part| part.starts_with(WILDCARD)) {
            Some(at) => {
                loc.parts.truncate(at);
                true
            }
            None => false,
        };
        // A pattern is judged by the folder before its first wildcard part,
        // and what it can pick is read from its parts below.
        let place = self.judge(&loc, flavour, holding && !pattern);
        if !pattern {
            return place;
        }
        let place = Self::pattern_place(place, text, tail.as_deref(), flavour, hidden);
        match self.picks_protected(&loc, tail.as_deref(), flavour, hidden, place, holding) {
            Some(words) => Place::Protected(words),
            None => place,
        }
    }

    /// Where a pattern lands, from the place of the folder before its first
    /// wildcard part and what the pattern can pick in it.
    fn pattern_place(
        place: Place,
        text: &str,
        tail: Option<&[String]>,
        flavour: Flavour,
        hidden: bool,
    ) -> Place {
        if matches!(place, Place::Inside | Place::Workspace { .. }) {
            match glob::shape(text, flavour) {
                // `.g*`, `*/.git`: can match hidden entries such as `.git`.
                Shape::Hidden => {
                    return Place::Sensitive(HIDDEN);
                }
                // `*.log`, `*/*.o`: picks files inside the folder.
                Shape::Entries if place == (Place::Workspace { exact: true }) => {
                    // A PowerShell or cmd wildcard directly in the workspace
                    // folder can match the dot name `.git`, and reach what is
                    // in it; deeper down no `.git` is the model's to protect.
                    let hidden = hidden || flavour == Flavour::Windows;
                    let reaches = tail.is_some_and(|tail| {
                        let tail: Vec<&str> = tail.iter().map(String::as_str).collect();
                        glob::reaches_git(&tail, flavour, hidden)
                    });
                    if reaches {
                        return Place::Sensitive(HIDDEN);
                    }
                    return Place::Inside;
                }
                // `*`, `?*`, `*/*`: every entry, as much as the folder.
                Shape::Entries | Shape::All => {}
            }
        }
        // `/tmp/*.log`, `/tmp/build-*`: picks files inside a temporary
        // folder, which are temporary files; `/tmp/*` is still the folder.
        if place == (Place::Temp { exact: true }) && glob::shape(text, flavour) == Shape::Entries {
            return Place::Temp { exact: false };
        }
        place
    }

    /// A string that is the same for two spellings of the one file, for
    /// matching a script a line both writes and runs. `None` when `path` is
    /// not one definite file: a device or a wildcard.
    #[must_use]
    pub fn key(&self, path: Spelling<'_>, flavour: Flavour) -> Option<String> {
        let text = path.text();
        let device = matches!(path, Spelling::Plain(_)) && device(text, flavour).is_some();
        if device || glob::has_wildcard(text) {
            return None;
        }
        Some(self.locate(path, flavour).key())
    }

    fn locate(&self, path: Spelling<'_>, flavour: Flavour) -> Loc {
        let separators = flavour.separators();
        let text = match path {
            Spelling::Home(rest) => return self.home.clone().walk(rest, flavour),
            Spelling::Plain(text) => text,
        };
        if flavour == Flavour::Windows {
            if let Some((share, rest)) = unc(text) {
                return Loc::at(Root::Unc(share)).walk(rest, flavour);
            }
            if let Some((letter, rest)) = drive(text) {
                return Loc::at(Root::Drive(letter)).walk(rest, flavour);
            }
        }
        if text.starts_with(separators) {
            let root = if self.cwd.windows() {
                self.cwd.root.clone()
            } else {
                Root::Unix
            };
            return Loc::at(root).walk(text, flavour);
        }
        self.cwd.clone().walk(text, flavour)
    }

    /// Where a path lands. A protected path, or one under it, is `Protected`
    /// before anything else but the home directory itself. A verdict that
    /// would otherwise be harmless is `Protected` too when the path holds a
    /// protected one (`holding`), so a delete of the folder is a delete of
    /// it; a verdict that is already risky keeps its own place and words.
    fn judge(&self, loc: &Loc, flavour: Flavour, holding: bool) -> Place {
        if loc.parts.is_empty() {
            return Place::Top("the root of the disk");
        }
        if loc.holds(&self.home) {
            return Place::Home {
                exact: loc.is(&self.home),
            };
        }
        if let Some((_, words)) = self.protected.iter().find(|(file, _)| below(loc, file)) {
            return Place::Protected(words);
        }
        let place = self.judge_plain(loc, flavour);
        if holding && place.harmless() {
            if let Some((_, words)) = self.protected.iter().find(|(file, _)| above(loc, file)) {
                return Place::Protected(words);
            }
        }
        place
    }

    fn judge_plain(&self, loc: &Loc, flavour: Flavour) -> Place {
        for workspace in &self.workspaces {
            if loc.holds(workspace) {
                return Place::Workspace {
                    exact: loc.is(workspace),
                };
            }
            if workspace.holds(loc) {
                let first = &loc.parts[workspace.parts.len()];
                let history = first.eq_ignore_ascii_case(".git")
                    || (flavour == Flavour::Windows && short_git(first));
                return if history {
                    Place::Sensitive("the repository's history")
                } else {
                    Place::Inside
                };
            }
        }
        if let Some(temp) = self.temps.iter().find(|temp| temp.holds(loc)) {
            return Place::Temp {
                exact: temp.is(loc),
            };
        }
        if let Some((_, words)) = self.sensitive.iter().find(|(file, _)| file.holds(loc)) {
            return Place::Sensitive(words);
        }
        if self.system.iter().any(|folder| folder.holds(loc)) {
            return Place::Top("a system folder");
        }
        if loc.parts.len() == 1 {
            return Place::Top("a top-level folder");
        }
        Place::Outside
    }
}

impl Resolver {
    /// The words of a protected path that a pattern can pick, by name.
    /// `folder` is where the pattern starts (the folder before its first
    /// wildcard part), `tail` the pattern's parts from there, and `place`
    /// what the pattern would be without the protected paths.
    ///
    /// The pattern's parts are matched against the path's names below
    /// `folder`, one for one. A pattern that reaches the path itself, or goes
    /// below it, picks it, and wins over any place but the workspace or a
    /// temporary folder itself. One that stops at a folder holding the path
    /// picks that folder, which counts only where the place is harmless and
    /// the path is not only being written into (`holding`).
    fn picks_protected(
        &self,
        folder: &Loc,
        tail: Option<&[String]>,
        flavour: Flavour,
        hidden: bool,
        place: Place,
        holding: bool,
    ) -> Option<&'static str> {
        let tail = tail?;
        if matches!(
            place,
            Place::Workspace { exact: true }
                | Place::Temp { exact: true }
                | Place::Protected(_)
                | Place::Disk
                | Place::Registry
                | Place::Unknown
        ) {
            return None;
        }
        let hidden = hidden || flavour == Flavour::Windows;
        let folders = holding && place.harmless();
        self.protected.iter().find_map(|(path, words)| {
            if !above(folder, path) {
                return None;
            }
            let names = &path.parts[folder.parts.len()..];
            let windows = path.windows();
            let reach = |whole: bool| {
                let tail: Vec<&str> = tail.iter().map(String::as_str).collect();
                picks(&tail, names, whole, &|part, name| {
                    pattern_matches(part, name, flavour, hidden, windows)
                })
            };
            (reach(true) || (folders && reach(false))).then_some(*words)
        })
    }
}

/// Whether a spelled name is the protected `name`: the same without case on
/// every host (some file systems on POSIX hosts ignore it, and what a
/// protected path is spelled as is the caller's to say), or, on Windows, its
/// 8.3 short name.
fn same_name(spelled: &str, name: &str, windows: bool) -> bool {
    spelled.eq_ignore_ascii_case(name) || (windows && short_name(spelled, name))
}

/// Whether `spelled` is a protected path or under it.
fn below(spelled: &Loc, protected: &Loc) -> bool {
    protected.parts.len() <= spelled.parts.len() && lead(spelled, protected)
}

/// Whether `spelled` is a protected path or a folder holding it.
fn above(spelled: &Loc, protected: &Loc) -> bool {
    spelled.parts.len() <= protected.parts.len() && lead(spelled, protected)
}

/// Whether the parts of the shorter of the two name the same as the other's.
fn lead(spelled: &Loc, protected: &Loc) -> bool {
    let windows = spelled.windows();
    spelled.root.same(&protected.root)
        && spelled
            .parts
            .iter()
            .zip(&protected.parts)
            .all(|(spelled, name)| same_name(spelled, name, windows))
}

/// Whether a pattern part can pick `name`, or on Windows its short name,
/// without case.
fn pattern_matches(part: &str, name: &str, flavour: Flavour, hidden: bool, windows: bool) -> bool {
    let fold = |part: &str, name: &str| {
        glob::matches(part, name, flavour, hidden)
            || glob::matches(&part.to_lowercase(), &name.to_lowercase(), flavour, hidden)
    };
    fold(part, name) || (windows && short_form(name).is_some_and(|short| fold(part, &short)))
}

/// Whether the pattern parts `tail` pick the names `names` in order. A part
/// that is nothing but two or more stars may stand for any number of names
/// (a shell with `globstar`) that a `*` could match, all the rest of them
/// when it is the last, and the last name itself too. `whole` asks that every name be reached; when
/// it is not, a pattern that ends first picks the folder holding the rest.
/// The pattern going on past the last name is below it, which counts.
fn picks(
    tail: &[&str],
    names: &[String],
    whole: bool,
    matches: &dyn Fn(&str, &str) -> bool,
) -> bool {
    // `reach[j]`: parts `i..` pick names `j..`, built from the end.
    let mut reach = vec![false; names.len() + 1];
    for i in (0..=tail.len()).rev() {
        let mut row = vec![false; names.len() + 1];
        for j in (0..=names.len()).rev() {
            row[j] = if j == names.len() {
                true
            } else if i == tail.len() {
                !whole
            } else if tail[i].len() >= 2 && tail[i].bytes().all(|b| b == b'*') {
                // As many names as it takes, the last one included: a name
                // the stars take is what a part after them goes below.
                i + 1 == tail.len()
                    || reach[j]
                    || (matches("*", &names[j]) && row.get(j + 1).copied().unwrap_or(false))
            } else {
                matches(tail[i], &names[j]) && reach.get(j + 1).copied().unwrap_or(false)
            };
        }
        reach = row;
    }
    reach[0]
}

/// The parts of a relative path, with `.` and `..` applied (a `..` with
/// nothing before it is dropped): `a/./b/../c` is `a`, `c`.
#[must_use]
pub fn parts(path: &str, flavour: Flavour) -> Vec<String> {
    Loc::at(Root::Unix).walk(path, flavour).parts
}

/// A device a path names, by its spelling: `/dev/null`, `/dev/fd/<digits>`
/// and the disks under `/dev` on either flavour, and on Windows also `NUL`,
/// `CON` and the `\\.\` device namespace.
///
/// On POSIX an absolute path is judged where it lands, with `.` and `..`
/// applied, so `/dev/./null` is the null device and `/dev/fd/../../etc` is
/// not a device at all: it is `/etc`. A name that is not exactly a device
/// (`/dev/fd`, `/dev/fd/3/x`), or that ends in `/` or `/.` (descriptor 3
/// could be a folder), is not one. On Windows `/dev/...` is a real folder on
/// the current drive, so only the plain spellings count there, split at `/`
/// and never normalised. A text with a `{` can expand to paths its spelling
/// does not show, so it is never a device.
#[must_use]
pub fn device(text: &str, flavour: Flavour) -> Option<Place> {
    if text.contains('{') {
        return None;
    }
    let lower = text.to_ascii_lowercase();
    if flavour == Flavour::Windows {
        if matches!(lower.as_str(), "nul" | "nul:" | "con" | "con:") {
            return Some(Place::Null);
        }
        // The device namespace is the root of what follows: `..` cannot
        // climb out of it.
        if lower.starts_with("\\\\.\\") || lower.starts_with("//./") {
            return Some(Place::Disk);
        }
    }
    let rest = lower.strip_prefix('/')?;
    let name: Vec<String> = if flavour == Flavour::Windows {
        let plain: Vec<&str> = rest.split('/').collect();
        if plain.iter().any(|part| matches!(*part, "" | "." | "..")) {
            return None;
        }
        plain.into_iter().map(str::to_string).collect()
    } else {
        // A folder spelling (`/dev/fd/3/`, `/dev/fd/3/.`) is not a device.
        if lower.ends_with('/') || lower.ends_with("/.") || lower.ends_with("/..") {
            return None;
        }
        parts(&lower, flavour)
    };
    let [dev, name @ ..] = name.as_slice() else {
        return None;
    };
    if dev != "dev" {
        return None;
    }
    if let [fd, number] = name {
        if fd == "fd" && !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit()) {
            return Some(Place::Null);
        }
    }
    let name = name.join("/");
    if NULL_DEVICES.contains(&format!("/dev/{name}").as_str()) {
        return Some(Place::Null);
    }
    if DISK_DEVICES.iter().any(|disk| name.starts_with(disk)) {
        return Some(Place::Disk);
    }
    None
}

/// What a wildcard part becomes while a path is resolved, followed by its
/// number among the wildcard parts: no real file name holds a NUL.
const WILDCARD: &str = "\u{0}*";

/// What a pattern that can match `.git` is called in a reason.
const HIDDEN: &str = "a hidden file such as the repository's history";

/// `text` with each part that holds a wildcard replaced by [`WILDCARD`] and
/// its number; `None` when it holds none.
fn mark_wildcards(text: &str, flavour: Flavour) -> Option<String> {
    if !glob::has_wildcard(text) {
        return None;
    }
    let mut count = 0;
    Some(
        text.split(flavour.separators())
            .map(|part| {
                if part.contains(WILDCARDS) {
                    count += 1;
                    format!("{WILDCARD}{}", count - 1)
                } else {
                    part.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("/"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{testing, Protected};

    const POSIX: Flavour = Flavour::Posix;
    const WINDOWS: Flavour = Flavour::Windows;

    fn at(paths: &Paths, path: &str, flavour: Flavour) -> Place {
        Resolver::new(paths).place(Spelling::Plain(path), flavour)
    }

    fn below_home(paths: &Paths, path: &str, flavour: Flavour) -> Place {
        Resolver::new(paths).place(Spelling::Home(path), flavour)
    }

    #[test]
    fn posix_paths_land_where_they_are_spelled() {
        let paths = testing::posix();
        for (path, place) in [
            ("src/main.rs", Place::Inside),
            ("./src/../target", Place::Inside),
            ("/home/me/work/repo/x", Place::Inside),
            ("/home/me/work/repo", Place::Workspace { exact: true }),
            ("..", Place::Workspace { exact: false }),
            ("/home/me", Place::Home { exact: true }),
            ("/home/me/notes", Place::Outside),
            ("/", Place::Top("the root of the disk")),
            ("/etc/hosts", Place::Top("a system folder")),
            ("/srv", Place::Top("a system folder")),
            ("/data", Place::Top("a top-level folder")),
            ("/data/x", Place::Outside),
            ("/tmp", Place::Temp { exact: true }),
            ("/tmp/x/y", Place::Temp { exact: false }),
            (".git/config", Place::Sensitive("the repository's history")),
            ("/home/me/.ssh/id_rsa", Place::Sensitive("your SSH keys")),
            ("/dev/null", Place::Null),
            ("/dev/fd/3", Place::Null),
            ("/dev/sda1", Place::Disk),
            ("/dev/disk0", Place::Disk),
        ] {
            assert_eq!(at(&paths, path, POSIX), place, "{path}");
        }
    }

    #[test]
    fn a_posix_flavour_has_no_drives_and_no_backslashes() {
        let paths = testing::posix();
        assert_eq!(at(&paths, r"C:\x", POSIX), Place::Inside);
        assert_eq!(at(&paths, r"a\..\..\..", POSIX), Place::Inside);
        assert_eq!(at(&paths, r"\\.\PhysicalDrive0", POSIX), Place::Inside);
        assert_eq!(at(&paths, "NUL", POSIX), Place::Inside);
    }

    #[test]
    fn windows_paths_land_where_they_are_spelled() {
        let paths = testing::windows();
        for (path, place) in [
            (r"src\main.rs", Place::Inside),
            (r"C:\Users\me\dev\repo\x", Place::Inside),
            (r"c:\users\ME\DEV\repo", Place::Workspace { exact: true }),
            (r"C:\Users\me", Place::Home { exact: true }),
            (r"C:/Users/me", Place::Home { exact: true }),
            (r"C:\", Place::Top("the root of the disk")),
            (r"\Windows\System32", Place::Top("a system folder")),
            (r"D:\Windows", Place::Top("a top-level folder")),
            (r"D:\data\x", Place::Outside),
            (r"\\server\share\x", Place::Top("a top-level folder")),
            (r"\\server\share\x\y", Place::Outside),
            (
                r"C:\Users\me\AppData\Local\Temp",
                Place::Temp { exact: true },
            ),
            (r"C:\Windows\Temp\x", Place::Temp { exact: false }),
            (r"C:\Users\me\.SSH\id", Place::Sensitive("your SSH keys")),
            (r".GIT\config", Place::Sensitive("the repository's history")),
            ("nul", Place::Null),
            ("CON:", Place::Null),
            (r"\\.\PhysicalDrive0", Place::Disk),
            ("//./C:", Place::Disk),
        ] {
            assert_eq!(at(&paths, path, WINDOWS), place, "{path}");
        }
    }

    #[test]
    fn a_share_is_one_root_with_its_server_and_name() {
        let paths = testing::windows();
        let resolver = Resolver::new(&paths);
        let key = |path| resolver.key(Spelling::Plain(path), WINDOWS);
        assert_eq!(key(r"\\Srv\Share\a\B"), key("//srv/share/A/b"));
        assert_ne!(key(r"\\srv\share\a"), key(r"\\srv\other\a"));
        assert_eq!(unc(r"\\srv"), Some(("srv/".to_string(), "")));
        assert_eq!(unc(r"\\\x"), None);
    }

    #[test]
    fn a_home_spelling_is_read_from_the_home_directory() {
        let paths = testing::posix();
        for (rest, place) in [
            ("", Place::Home { exact: true }),
            ("/", Place::Home { exact: true }),
            ("/.ssh/id", Place::Sensitive("your SSH keys")),
            ("/C:/x", Place::Outside),
            ("/..", Place::Home { exact: false }),
            ("/../..", Place::Top("the root of the disk")),
            ("/work/repo/x", Place::Inside),
        ] {
            assert_eq!(below_home(&paths, rest, POSIX), place, "~{rest}");
        }
        let paths = testing::windows();
        assert_eq!(
            below_home(&paths, r"\AppData\Local\Temp\x", WINDOWS),
            Place::Temp { exact: false }
        );
    }

    #[test]
    fn a_windows_wildcard_in_the_workspace_folder_can_reach_the_repository_history() {
        let hidden = Place::Sensitive("a hidden file such as the repository's history");
        let posix = testing::posix();
        for path in [
            "*git",
            "?git",
            "[!x]git",
            "*.*",
            "????",
            "*/objects",
            "????/HEAD",
        ] {
            assert_eq!(at(&posix, path, POSIX), Place::Inside, "{path}");
        }
        let windows = testing::windows();
        for path in [
            "*git",
            "?git",
            "*GIT",
            "[!.]git",
            "[^.]git",
            "`.gi?",
            "*g\u{131}t",
            "????",
            "*\\objects",
            "*.*\\objects",
            "????\\HEAD",
            "*\\*s",
            "*\\..\\*git",
            "src\\..\\*git",
            "*/OBJECTS/pack",
        ] {
            assert_eq!(at(&windows, path, WINDOWS), hidden, "{path}");
        }
        // Not a name `.git` has, or not directly in the workspace folder.
        for path in [
            "*.tmp",
            "*gitx",
            "?git2",
            "[!x]git",
            "*\\bin",
            "*\\obj",
            "*\\*.o",
            "*\\..\\*.tmp",
            "src\\*.obj",
            "src\\*git",
            "src\\*\\bin",
            "src\\*\\objects",
            "src\\*\\..\\*git",
            "node_modules\\*\\dist",
        ] {
            assert_eq!(at(&windows, path, WINDOWS), Place::Inside, "{path}");
        }
        // A catch-all takes the folder, as on POSIX; `*.*` is one on Windows.
        assert_eq!(at(&windows, "src\\*.*", WINDOWS), Place::Inside);
        for path in ["*.*", "*", "*\\*"] {
            assert_eq!(
                at(&windows, path, WINDOWS),
                Place::Workspace { exact: true },
                "{path}"
            );
        }
    }

    #[test]
    fn a_posix_wildcard_reaches_the_repository_history_when_hidden_names_match() {
        let hidden = Place::Sensitive("a hidden file such as the repository's history");
        let posix = testing::posix();
        let resolver = Resolver::new(&posix);
        let place =
            |path: &str, flavour, on| resolver.place_hidden(Spelling::Plain(path), flavour, on);
        for path in [
            "*git",
            "?git",
            "[!x]git",
            "*.*",
            "????",
            "*/objects",
            "????/HEAD",
        ] {
            assert_eq!(place(path, POSIX, false), Place::Inside, "{path}");
            assert_eq!(place(path, POSIX, true), hidden, "{path}");
        }
        // The same picks as without the option: not a name `.git` has, or
        // not directly in the workspace folder.
        for path in [
            "*.tmp",
            "*gitx",
            "*/bin",
            "*/*.o",
            "src/*git",
            "src/*/objects",
        ] {
            assert_eq!(place(path, POSIX, true), Place::Inside, "{path}");
        }
        // A catch-all is the whole folder either way, and a path without a
        // wildcard is not read differently.
        assert_eq!(place("*", POSIX, true), Place::Workspace { exact: true });
        assert_eq!(place("src/a.rs", POSIX, true), Place::Inside);
        // `place` is the same as `place_hidden` with the flag off, and the
        // flag changes nothing on Windows, whose wildcards always match.
        let windows = testing::windows();
        let resolver = Resolver::new(&windows);
        for path in ["*git", "src\\*git", "*.tmp", "*\\bin"] {
            assert_eq!(
                resolver.place_hidden(Spelling::Plain(path), WINDOWS, true),
                resolver.place(Spelling::Plain(path), WINDOWS),
                "{path}"
            );
        }
    }

    #[test]
    fn a_pattern_that_picks_names_in_a_temporary_folder_picks_temporary_files() {
        let posix = testing::posix();
        for path in ["/tmp/*.log", "/tmp/build-*", "/var/tmp/*.log"] {
            assert_eq!(
                at(&posix, path, POSIX),
                Place::Temp { exact: false },
                "{path}"
            );
        }
        for path in ["/tmp/*", "/tmp/?*", "/tmp"] {
            assert_eq!(
                at(&posix, path, POSIX),
                Place::Temp { exact: true },
                "{path}"
            );
        }
        let windows = testing::windows();
        assert_eq!(
            at(&windows, r"C:\Users\me\AppData\Local\Temp\*.log", WINDOWS),
            Place::Temp { exact: false }
        );
        assert_eq!(
            at(&windows, r"C:\Users\me\AppData\Local\Temp\*", WINDOWS),
            Place::Temp { exact: true }
        );
    }

    #[test]
    fn a_wildcard_part_stands_for_one_entry() {
        let paths = testing::posix();
        for (path, place) in [
            ("*.log", Place::Inside),
            ("src/*/*.o", Place::Inside),
            ("*", Place::Workspace { exact: true }),
            ("*/*", Place::Workspace { exact: true }),
            ("src/*/../../..", Place::Workspace { exact: false }),
            ("src/*/../../../x", Place::Outside),
            (
                ".g*",
                Place::Sensitive("a hidden file such as the repository's history"),
            ),
            (
                "*/.git",
                Place::Sensitive("a hidden file such as the repository's history"),
            ),
            ("/home/me/*", Place::Home { exact: true }),
            ("/etc/*", Place::Top("a system folder")),
        ] {
            assert_eq!(at(&paths, path, POSIX), place, "{path}");
        }
    }

    #[test]
    fn a_workspace_beside_the_home_is_judged_by_its_own_folder() {
        let paths = Paths::new("/srv/app", "/home/me", ["/srv/app", "/srv/lib"]);
        assert_eq!(at(&paths, "/srv/lib/x", POSIX), Place::Inside);
        assert_eq!(
            at(&paths, "/srv/lib", POSIX),
            Place::Workspace { exact: true }
        );
        assert_eq!(
            at(&paths, "/srv/other", POSIX),
            Place::Top("a system folder")
        );
        let none = Paths::new("/srv/app", "/home/me", Vec::<&str>::new());
        assert_eq!(at(&none, "x", POSIX), Place::Top("a system folder"));
    }

    #[test]
    fn a_key_names_a_file_however_it_is_spelled() {
        let paths = testing::posix();
        let resolver = Resolver::new(&paths);
        let key = |path| resolver.key(Spelling::Plain(path), POSIX);
        assert_eq!(key("a/../b.sh"), key("./b.sh"));
        assert_eq!(key("b.sh"), key("/home/me/work/repo/b.sh"));
        assert_ne!(key("B.sh"), key("b.sh"));
        assert_eq!(key("/dev/null"), None);
        assert_eq!(key("*.sh"), None);
        assert_eq!(
            resolver.key(Spelling::Home(".zshrc"), POSIX),
            key("/home/me/.zshrc")
        );
        assert_eq!(resolver.key(Spelling::Home("*"), POSIX), None);

        let paths = testing::windows();
        let resolver = Resolver::new(&paths);
        let key = |path| resolver.key(Spelling::Plain(path), WINDOWS);
        assert_eq!(key(r"X.PS1"), key(r"c:/users/me/dev/repo/x.ps1"));
    }

    #[test]
    fn a_relative_working_directory_puts_every_path_outside() {
        let paths = Paths::new("repo", "/home/me", ["/home/me/repo"]);
        assert_eq!(at(&paths, "x", POSIX), Place::Outside);
        assert_eq!(at(&paths, "/x", POSIX), Place::Top("a top-level folder"));
    }

    #[test]
    fn parts_apply_dots_and_drop_a_climb_past_the_top() {
        assert_eq!(parts("a/./b/../c", POSIX), ["a", "c"]);
        assert_eq!(parts("../../a", POSIX), ["a"]);
        assert_eq!(parts(r"a\b", POSIX), [r"a\b"]);
        assert_eq!(parts(r"a\b", WINDOWS), ["a", "b"]);
    }

    #[test]
    fn a_device_is_named_by_its_spelling() {
        assert_eq!(device("/DEV/NULL", POSIX), Some(Place::Null));
        assert_eq!(device("/dev/nvme0n1", POSIX), Some(Place::Disk));
        assert_eq!(device("NUL", POSIX), None);
        assert_eq!(device("NUL", WINDOWS), Some(Place::Null));
        assert_eq!(device("src/null", WINDOWS), None);
    }

    #[test]
    fn only_a_real_device_path_is_a_device() {
        for (text, flavour, found) in [
            ("/dev/fd/0", POSIX, Some(Place::Null)),
            ("/dev/fd/12", POSIX, Some(Place::Null)),
            ("/dev/stdout", POSIX, Some(Place::Null)),
            ("/dev/stderr", POSIX, Some(Place::Null)),
            ("/dev/./null", POSIX, Some(Place::Null)),
            ("/dev//fd/../null", POSIX, Some(Place::Null)),
            ("/../dev/null", POSIX, Some(Place::Null)),
            ("/dev/mapper/vg-root", POSIX, Some(Place::Disk)),
            ("/dev/disk0", WINDOWS, Some(Place::Disk)),
            // A climb out of a device lands somewhere else.
            ("/dev/fd/../../Users/me", POSIX, None),
            ("/dev/fd/..", POSIX, None),
            ("/dev/fd/3/../../../etc/sudoers", POSIX, None),
            ("/dev/null/../../etc", POSIX, None),
            ("/dev/stderr/../x", POSIX, None),
            ("/dev/sda/../../etc", POSIX, None),
            ("/dev/disk0/..", POSIX, None),
            ("/dev/fd/../../dev/sda", POSIX, Some(Place::Disk)),
            // Names that are not exactly a device.
            ("/dev/fd", POSIX, None),
            ("/dev/fd/", POSIX, None),
            ("/dev/fd/x", POSIX, None),
            ("/dev/fd/3x", POSIX, None),
            ("/dev/fd/3/x", POSIX, None),
            ("/dev/fd/*", POSIX, None),
            ("/dev/nulls", POSIX, None),
            ("dev/null", POSIX, None),
            // Windows spellings: a name is exact, the namespace is a root.
            ("NUL", WINDOWS, Some(Place::Null)),
            ("con:", WINDOWS, Some(Place::Null)),
            (r"NUL\..\x", WINDOWS, None),
            ("NUL/x", WINDOWS, None),
            (r"CON\..\..", WINDOWS, None),
            (r"\\.\PhysicalDrive0", WINDOWS, Some(Place::Disk)),
            (r"\\.\C:\..\..\x", WINDOWS, Some(Place::Disk)),
            ("//./C:/../x", WINDOWS, Some(Place::Disk)),
            (r"\\.", WINDOWS, None),
            (r"/dev\fd\..\..\etc", WINDOWS, None),
            // On Windows `/dev` is a real folder: only the plain spellings count.
            ("/dev/null", WINDOWS, Some(Place::Null)),
            ("/dev/fd/1", WINDOWS, Some(Place::Null)),
            (r"/dev\null", WINDOWS, None),
            (r"/dev\fd\1", WINDOWS, None),
            ("/dev/./null", WINDOWS, None),
            ("//dev/null", WINDOWS, None),
            ("/dev/fd/../fd/1", WINDOWS, None),
            // A folder spelling or a brace list is no device.
            ("/dev/fd/3/", POSIX, None),
            ("/dev/fd/3/.", POSIX, None),
            ("/dev/fd/3/..", POSIX, None),
            ("/dev/null/", POSIX, None),
            ("/dev/sda/", POSIX, None),
            ("/dev/fd/{0,1}", POSIX, None),
            ("/dev/{null,sda}", POSIX, None),
            ("{/dev/null}", POSIX, None),
        ] {
            assert_eq!(device(text, flavour), found, "{text}");
        }
    }

    #[test]
    fn a_path_climbing_out_of_a_device_is_judged_where_it_lands() {
        let paths = testing::macos();
        for (path, place) in [
            ("/dev/fd/../../Users/me", Place::Home { exact: true }),
            ("/dev/fd/../..", Place::Top("the root of the disk")),
            ("/dev/fd/../../etc/sudoers", Place::Top("a system folder")),
            ("/dev/fd/../../Users", Place::Home { exact: false }),
            ("/dev/fd/2", Place::Null),
            ("/dev/./fd/2", Place::Null),
        ] {
            assert_eq!(at(&paths, path, POSIX), place, "{path}");
        }
        let resolver = Resolver::new(&paths);
        assert_eq!(resolver.key(Spelling::Plain("/dev/fd/2"), POSIX), None);
        assert_eq!(
            resolver.key(Spelling::Plain("/dev/fd/../../Users/me/x"), POSIX),
            resolver.key(Spelling::Plain("/Users/me/x"), POSIX),
        );
    }

    #[test]
    fn windows_drops_the_dots_and_spaces_a_name_ends_in() {
        let paths = testing::windows();
        let history = Place::Sensitive("the repository's history");
        for (path, place) in [
            (".git.", history),
            (".git ", history),
            (".git. .", history),
            (".GIT...", history),
            (r".git.\objects", history),
            (r"src\..\.git.", history),
            (r"C:\Users\me\dev\repo\.git.", history),
            (r"C:\Users\me\.ssh.\id", Place::Sensitive("your SSH keys")),
            ("notes.txt.", Place::Inside),
            ("notes.txt ", Place::Inside),
            ("build...", Place::Inside),
            (r"C:\Users\me\dev\repo.", Place::Workspace { exact: true }),
            // A non-breaking or ideographic space is not a space to Windows.
            (".git\u{a0}", Place::Inside),
            (".git\u{3000}", Place::Inside),
            (".git\u{a0}\\objects", Place::Inside),
            (".git\u{3000}.", Place::Inside),
            // Only a name's end is dropped.
            (" .git", Place::Inside),
            (".git.x", Place::Inside),
            (".g.it", Place::Inside),
        ] {
            assert_eq!(at(&paths, path, WINDOWS), place, "{path:?}");
        }
        // A POSIX name keeps them.
        let posix = testing::posix();
        for path in [".git.", ".git ", "notes.txt."] {
            assert_eq!(at(&posix, path, POSIX), Place::Inside, "{path:?}");
        }
        assert_eq!(parts("a./b./c. .", WINDOWS), ["a", "b", "c"]);
        assert_eq!(parts("a./b./c. .", POSIX), ["a.", "b.", "c. ."]);
        let resolver = Resolver::new(&paths);
        let key = |path| resolver.key(Spelling::Plain(path), WINDOWS);
        assert_eq!(key("run.cmd."), key("RUN.cmd"));
        assert_eq!(key("run.cmd "), key("run.cmd"));
    }

    #[test]
    fn a_short_name_directly_in_a_workspace_may_be_the_repository_history() {
        let paths = testing::windows();
        let history = Place::Sensitive("the repository's history");
        for (path, place) in [
            ("GIT~1", history),
            ("git~2", history),
            ("Git~10", history),
            ("GI3F2A~1", history),
            ("gi3f2a~2", history),
            ("GIabcd~1", history),
            ("GIT~1.", history),
            ("GIT~1 ", history),
            (r"GIT~1\objects\pack", history),
            (r"src\..\GIT~1", history),
            (r"C:\Users\me\dev\repo\GIT~1", history),
            // Not a short form of `.git`, or not a short name at all.
            ("GITIGN~1", Place::Inside),
            ("GITHUB~1", Place::Inside),
            ("GIT123~1", Place::Inside),
            ("GI3F2~1", Place::Inside),
            ("GI3F2A5~1", Place::Inside),
            ("GIZZZZ~1", Place::Inside),
            ("G\u{130}T~1", Place::Inside),
            ("PROGRA~1", Place::Inside),
            ("PROGRA~1.txt", Place::Inside),
            ("GI~1", Place::Inside),
            ("GIT~", Place::Inside),
            ("GIT~1.txt", Place::Inside),
            ("GIT~1a", Place::Inside),
            ("GIT_~1", Place::Inside),
            ("GI T~1", Place::Inside),
            ("~1", Place::Inside),
            ("XGIT~1", Place::Inside),
            // Not directly in a workspace folder.
            (r"src\GIT~1", Place::Inside),
            (r"C:\Users\me\GIT~1", Place::Outside),
            (r"D:\x\GIT~1", Place::Outside),
        ] {
            assert_eq!(at(&paths, path, WINDOWS), place, "{path}");
        }
        // A short name is a short name on Windows only.
        assert_eq!(at(&testing::posix(), "GIT~1", POSIX), Place::Inside);
    }

    #[test]
    fn a_windows_stream_suffix_is_known_only_when_it_runs() {
        let paths = testing::windows();
        for path in [
            "notes:stream",
            ".git::$INDEX_ALLOCATION",
            ".git:$I30:$INDEX_ALLOCATION",
            r"src\x:s\y",
            r"C:\Users\me\dev\repo\x:stream",
            r"C:x:stream",
            r"\\server\share\x:stream",
            "x::$DATA",
            "*.txt:stream",
        ] {
            assert_eq!(at(&paths, path, WINDOWS), Place::Unknown, "{path}");
            assert_eq!(
                Resolver::new(&paths).place(Spelling::Home(path), WINDOWS),
                Place::Unknown,
                "~/{path}"
            );
        }
        // A drive or a share is no stream, and a device name keeps its colon.
        // One letter and a colon is a drive, as Windows reads it.
        for (path, place) in [
            ("x:stream", Place::Top("a top-level folder")),
            (r"C:\Users\me\dev\repo\x", Place::Inside),
            (r"C:\Users\me", Place::Home { exact: true }),
            (r"c:", Place::Top("the root of the disk")),
            (r"\\server\share\x\y", Place::Outside),
            ("nul:", Place::Null),
            ("CON:", Place::Null),
        ] {
            assert_eq!(at(&paths, path, WINDOWS), place, "{path}");
        }
        // A POSIX file name may hold a colon.
        assert_eq!(at(&testing::posix(), "x:stream", POSIX), Place::Inside);
        // The same stream is the same script.
        let resolver = Resolver::new(&paths);
        let key = |path| resolver.key(Spelling::Plain(path), WINDOWS);
        assert_eq!(key("run.cmd:s"), key("RUN.cmd:S"));
        assert_ne!(key("run.cmd:s"), key("run.cmd"));
    }

    #[test]
    fn a_windows_part_that_cannot_be_read_is_known_only_when_it_runs() {
        let paths = testing::windows();
        let history = Place::Sensitive("the repository's history");
        for path in [
            // Before the last: only dots and spaces, but not `.` or `..`.
            r".git\...\..\objects",
            r".git\. \..\objects",
            r".git\refs\.. \..\heads",
            r"... \x",
            r"...\x",
            // Before the last: still ends in a dot or a space after one dot.
            r"C:\Users\me\dev\repo \x",
            r"..\repo.. \x",
            r"x..\y",
            r"x .\y",
            r"x \y",
            r".git .\objects",
            // The last part: only dots and spaces, but not `.` or `..`.
            "... ",
            ".. ",
            r"src\.. ",
            "....",
        ] {
            assert_eq!(at(&paths, path, WINDOWS), Place::Unknown, "{path:?}");
        }
        // A part before the last loses one dot, the last part all of them.
        for (path, place) in [
            (r".git.\objects", history),
            (r"src\..\.git.", history),
            (r".\.git.\.", history),
            (r".git\", history),
            (r"src.\x.\y.. .", Place::Inside),
            (r"src\.\x", Place::Inside),
            (r"src\..\x", Place::Inside),
        ] {
            assert_eq!(at(&paths, path, WINDOWS), place, "{path:?}");
        }
        // From a working directory inside `.git`.
        let inside = Paths::new(
            r"C:\Users\me\dev\repo\.git\hooks",
            r"C:\Users\me",
            [r"C:\Users\me\dev\repo"],
        );
        assert_eq!(at(&inside, r"...\..\..\objects", WINDOWS), Place::Unknown);
        assert_eq!(at(&inside, r"..\objects", WINDOWS), history);
        // None of it is a POSIX name's business.
        let posix = testing::posix();
        for path in ["x /y", "x../y", ".../y", "x /.. ", "x:y/z"] {
            assert_eq!(at(&posix, path, POSIX), Place::Inside, "{path:?}");
        }
    }

    const SETTINGS: &str = "the agent's settings";

    fn gated(paths: Paths, protected: &[&str]) -> Paths {
        paths.with_protected(protected.iter().map(|path| Protected::new(*path, SETTINGS)))
    }

    #[test]
    fn a_protected_path_and_everything_under_it_is_protected() {
        let paths = gated(testing::posix(), &["/home/me/.agent"]);
        let protected = Place::Protected(SETTINGS);
        for (path, place) in [
            ("/home/me/.agent", protected),
            ("/home/me/.agent/config.yaml", protected),
            ("/home/me/.agent/a/../rules", protected),
            ("/home/me/.agent/*", protected),
            ("/home/me/.agent/*.yaml", protected),
            ("/home/me/.agent/", protected),
            ("/home/me/.agent/.", protected),
            ("/home/me/x/../.agent", protected),
            // Names compare without case on every host.
            ("/home/me/.AGENT", protected),
            ("/home/me/.Agent/Rules", protected),
            // The home directory is a home directory, and keeps its words.
            ("/home/me", Place::Home { exact: true }),
            ("/home", Place::Home { exact: false }),
            // A sibling is not it.
            ("/home/me/.agents", Place::Outside),
            ("/home/me/other", Place::Outside),
        ] {
            assert_eq!(at(&paths, path, POSIX), place, "{path}");
        }
        let resolver = Resolver::new(&paths);
        assert_eq!(
            resolver.place(Spelling::Home(".agent/config.yaml"), POSIX),
            protected
        );
        assert!(!protected.harmless());
        assert_eq!(protected.words(), SETTINGS);
    }

    #[test]
    fn a_protected_path_wins_over_the_workspace_and_a_temporary_folder() {
        let paths = gated(
            testing::posix(),
            &["/home/me/work/repo/.agent", "/tmp/state"],
        );
        let protected = Place::Protected(SETTINGS);
        for (path, place) in [
            (".agent", protected),
            (".agent/rules", protected),
            (".AGENT/rules", protected),
            ("/home/me/work/repo/.agent/rules", protected),
            ("src/main.rs", Place::Inside),
            (".agentrc", Place::Inside),
            ("/tmp/state/x", protected),
            ("/tmp/other", Place::Temp { exact: false }),
        ] {
            assert_eq!(at(&paths, path, POSIX), place, "{path}");
        }
        // A workspace that is itself protected is protected throughout, and
        // is still the workspace as a whole.
        let whole = gated(testing::posix(), &["/home/me/work/repo"]);
        assert_eq!(at(&whole, "src/x", POSIX), protected);
        assert_eq!(at(&whole, ".", POSIX), protected);
        assert_eq!(at(&whole, "/home/me", POSIX), Place::Home { exact: true });
    }

    #[test]
    fn a_folder_holding_a_protected_path_is_protected_when_it_would_be_harmless() {
        let paths = gated(testing::posix(), &["/home/me/work/repo/conf/app/x.yaml"]);
        let protected = Place::Protected(SETTINGS);
        for (path, place) in [
            ("conf", protected),
            ("conf/app", protected),
            ("conf/app/x.yaml", protected),
            ("./conf/../conf/app", protected),
            ("CONF", protected),
            // Not holding it.
            ("conf/other.txt", Place::Inside),
            ("conf/app/y.yaml", Place::Inside),
            ("src", Place::Inside),
            ("confs", Place::Inside),
            // Already risky: keeps its own place and words.
            (".", Place::Workspace { exact: true }),
            ("/home/me/work/repo", Place::Workspace { exact: true }),
            ("/home/me/work", Place::Workspace { exact: false }),
            ("/home/me", Place::Home { exact: true }),
            ("/", Place::Top("the root of the disk")),
        ] {
            assert_eq!(at(&paths, path, POSIX), place, "{path}");
        }
        // A temporary folder holding one, too.
        let temp = gated(testing::posix(), &["/tmp/state/x"]);
        assert_eq!(at(&temp, "/tmp/state", POSIX), protected);
        assert_eq!(at(&temp, "/tmp", POSIX), Place::Temp { exact: true });
        // A path written into is not a write of the folder's contents.
        let resolver = Resolver::new(&paths);
        let into = |path| resolver.place_into(Spelling::Plain(path), POSIX, false);
        assert_eq!(into("conf"), Place::Inside);
        assert_eq!(into("conf/app"), Place::Inside);
        assert_eq!(into("conf/app/x.yaml"), protected);
        assert_eq!(into("conf/app/x.yaml/y"), protected);
        assert_eq!(into("conf/new.txt"), Place::Inside);
        assert_eq!(into("conf/*"), Place::Inside);
        assert_eq!(into("conf/app/*"), protected);
        assert_eq!(into("conf/app/x*"), protected);
    }

    #[test]
    fn a_pattern_that_picks_a_protected_path_or_its_folder_is_protected() {
        let paths = gated(
            testing::posix(),
            &[
                "/home/me/work/repo/settings.yaml",
                "/home/me/work/repo/.agent",
                "/home/me/work/repo/conf/app/x.yaml",
            ],
        );
        let protected = Place::Protected(SETTINGS);
        for (path, place) in [
            ("set*", protected),
            ("S*", protected),
            ("*.yaml", protected),
            ("settings.y?ml", protected),
            ("[s]ettings.yaml", protected),
            ("/home/me/work/repo/s*", protected),
            ("src/*/../../set*", protected),
            (".a*", protected),
            (".agent/*", protected),
            // Below a protected name, whether it is a folder or not.
            ("set*/x", protected),
            // A pattern that picks the folder holding one.
            ("c*", protected),
            ("conf/a*", protected),
            ("conf/a*/x.yaml", protected),
            ("*/*/*.yaml", protected),
            ("*/*/x.y*", protected),
            ("**/x.yaml", protected),
            ("conf/**", protected),
            ("conf/**/x.yaml", protected),
            ("**/**/x.yaml", protected),
            // The stars can take the protected name, and what follows goes
            // below it.
            ("**/y.yaml", protected),
            ("**/*.rs", protected),
            // What the pattern cannot pick stays the agent's own.
            ("*.log", Place::Inside),
            ("src/*.rs", Place::Inside),
            ("src/set*", Place::Inside),
            ("sr*/x", Place::Inside),
            ("conf/o*", Place::Inside),
            ("conf/*/y.yaml", Place::Inside),
            // The whole workspace is still the workspace.
            ("*", Place::Workspace { exact: true }),
        ] {
            assert_eq!(at(&paths, path, POSIX), place, "{path}");
        }
        // A pattern does not match a leading dot on POSIX unless hidden
        // names match.
        let only_hidden = gated(testing::posix(), &["/home/me/work/repo/.agent"]);
        let resolver = Resolver::new(&only_hidden);
        let hidden = |path, hidden| resolver.place_hidden(Spelling::Plain(path), POSIX, hidden);
        assert_eq!(hidden("*gent", false), Place::Inside);
        assert_eq!(hidden("*gent", true), protected);
        // A pattern in a temporary folder.
        let temp = gated(testing::posix(), &["/tmp/state/x"]);
        for (path, place) in [
            ("/tmp/state/*", protected),
            ("/tmp/state/x*", protected),
            ("/tmp/*/x", protected),
            ("/tmp/s*", protected),
            ("/tmp/state/y*", Place::Temp { exact: false }),
            ("/tmp/*.log", Place::Temp { exact: false }),
            ("/tmp/*", Place::Temp { exact: true }),
        ] {
            assert_eq!(at(&temp, path, POSIX), place, "{path}");
        }
        // A pattern that picks the protected path in the home directory says
        // so, where one that picks the home directory itself says the home.
        let home = gated(testing::posix(), &["/home/me/.agent"]);
        assert_eq!(at(&home, "/home/me/.agent*", POSIX), protected);
        assert_eq!(at(&home, "/home/me/.a*", POSIX), protected);
        assert_eq!(at(&home, "/home/me/*", POSIX), Place::Home { exact: true });
        assert_eq!(at(&home, "/home/me/x*", POSIX), Place::Home { exact: true });
    }

    #[test]
    fn globstar_stars_can_take_the_protected_name_itself() {
        let paths = gated(testing::posix(), &["/home/me/work/repo/cfg"]);
        let protected = Place::Protected(SETTINGS);
        for (path, place) in [
            ("**/rules", protected),
            ("**/*.yaml", protected),
            ("**/*.rs", protected),
            ("**/cfg", protected),
            ("**/cfg/x", protected),
            ("src/**/x", Place::Inside),
            // A star part does not take a hidden name.
            ("**", Place::Workspace { exact: true }),
        ] {
            assert_eq!(at(&paths, path, POSIX), place, "{path}");
        }
        let hidden = gated(testing::posix(), &["/home/me/work/repo/.cfg"]);
        assert_eq!(at(&hidden, "**/rules", POSIX), Place::Inside);
        let resolver = Resolver::new(&hidden);
        let on = |path| resolver.place_hidden(Spelling::Plain(path), POSIX, true);
        assert_eq!(on("**/rules"), protected);
    }

    #[test]
    fn a_windows_protected_path_compares_without_case() {
        let paths = gated(
            testing::windows(),
            &[r"C:\Users\me\.agent", r"C:\Users\me\dev\repo\.agent"],
        );
        let protected = Place::Protected(SETTINGS);
        for (path, place) in [
            (r"C:\Users\me\.agent", protected),
            (r"c:\users\ME\.AGENT\config.yaml", protected),
            (r"C:/Users/me/.agent/config.yaml", protected),
            (r"C:\Users\me\.agent.\config.yaml", protected),
            (r"C:\Users\me\.agent\*", protected),
            (r".agent\rules", protected),
            (r"src\main.rs", Place::Inside),
            (r"C:\Users\me\.agents", Place::Outside),
            (r"C:\Users\me", Place::Home { exact: true }),
        ] {
            assert_eq!(at(&paths, path, WINDOWS), place, "{path}");
        }
        let resolver = Resolver::new(&paths);
        assert_eq!(
            resolver.place(Spelling::Home(r".agent\config.yaml"), WINDOWS),
            protected
        );
        // A name Windows reads as another is judged as that name.
        assert_eq!(at(&paths, r".agent\x:stream", WINDOWS), Place::Unknown);
    }

    #[test]
    fn a_protected_path_compares_without_case_on_a_mac_too() {
        let paths = gated(testing::macos(), &["/Users/me/dev/repo/.agent"]);
        for path in [
            ".AGENT",
            ".Agent/rules",
            ".agent/rules",
            ".AGE*",
            "/Users/me/dev/repo/.AGENT",
        ] {
            assert_eq!(
                at(&paths, path, POSIX),
                Place::Protected(SETTINGS),
                "{path}"
            );
        }
    }

    #[test]
    fn a_windows_short_name_is_the_protected_name() {
        let paths = gated(
            testing::windows(),
            &[
                r"C:\Users\me\dev\repo\.agent",
                r"C:\Users\me\dev\repo\conf\settings.yaml",
            ],
        );
        let protected = Place::Protected(SETTINGS);
        for (path, place) in [
            (r"AGENT~1\rules", protected),
            (r"agent~1", protected),
            (r"AGENT~2\rules", protected),
            (r"AG1B2C~1\rules", protected),
            (r"AGENT~*\rules", protected),
            (r"conf\SETTIN~1.YAM", protected),
            (r"conf\SETTIN~1.YAML", Place::Inside),
            (r"conf\SETTIN~1", Place::Inside),
            (r"conf\settin~1.yam", protected),
            (r"conf\SETTIN~*", protected),
            // Another name's short form is another name.
            (r"AGEN~1\rules", Place::Inside),
            (r"AGENTS~1\rules", Place::Inside),
            (r"OTHER~1\rules", Place::Inside),
        ] {
            assert_eq!(at(&paths, path, WINDOWS), place, "{path}");
        }
        // A short name is a Windows thing.
        let posix = gated(testing::posix(), &["/home/me/work/repo/.agent"]);
        assert_eq!(at(&posix, "AGENT~1/rules", POSIX), Place::Inside);
    }

    #[test]
    fn a_short_name_is_read_the_way_windows_makes_it() {
        assert!(short_name("GIT~1", ".git"));
        assert!(short_name("git~12", ".git"));
        assert!(short_name("GI1A2B~1", ".git"));
        assert!(!short_name("GIT", ".git"));
        assert!(!short_name("GIT~", ".git"));
        assert!(!short_name("GITHUB~1", ".git"));
        assert!(!short_name("~1", ""));
        assert!(!short_name("GIXYZW~1", ".git"));
        assert!(short_name("SETTIN~1.YAM", "settings.yaml"));
        assert!(!short_name("SETTIN~1", "settings.yaml"));
        assert!(!short_name("SETTIN~1.YAM", "settings"));
        assert_eq!(short_form(".agent").as_deref(), Some("AGENT~1"));
        assert_eq!(short_form("settings.yaml").as_deref(), Some("SETTIN~1.YAM"));
        assert_eq!(short_form("..."), None);
        assert_eq!(short_form("notes.txt").as_deref(), Some("NOTES~1.TXT"));
    }

    #[test]
    fn protected_paths_are_added_by_each_call() {
        let paths = testing::posix();
        assert!(paths.protected.is_empty());
        let paths = paths
            .with_protected([Protected::new("/home/me/.a", "one")])
            .with_protected([Protected::new("/home/me/.b", "two")]);
        assert_eq!(at(&paths, "/home/me/.a/x", POSIX), Place::Protected("one"));
        assert_eq!(at(&paths, "/home/me/.b/x", POSIX), Place::Protected("two"));
    }

    #[test]
    fn with_no_protected_paths_nothing_changes() {
        let plain = testing::posix();
        let empty = testing::posix().with_protected([]);
        for path in [".agent", "*", "set*", "/home/me/.agent/x", "/tmp/x"] {
            assert_eq!(at(&plain, path, POSIX), at(&empty, path, POSIX), "{path}");
        }
    }
}
