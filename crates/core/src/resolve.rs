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

    /// Apply `rest`, split at `separators`, to this location.
    fn walk(mut self, rest: &str, separators: &[char]) -> Self {
        for part in rest.split(separators) {
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
        let separators = if windows {
            Flavour::Windows
        } else {
            Flavour::Posix
        }
        .separators();
        if let Some((letter, rest)) = drive(text) {
            return Self::at(Root::Drive(letter)).walk(rest, separators);
        }
        if let Some((share, rest)) = unc(text) {
            return Self::at(Root::Unc(share)).walk(rest, separators);
        }
        Self::at(Root::Unix).walk(text, separators)
    }
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
        Self {
            cwd,
            home,
            workspaces,
            temps,
            sensitive,
            system,
        }
    }

    /// Where `path` lands. It never answers [`Place::Unknown`] or
    /// [`Place::Registry`]: a path this spelled out is a file path, and the
    /// guard that reads the syntax around it says when it is neither.
    #[must_use]
    pub fn place(&self, path: Spelling<'_>, flavour: Flavour) -> Place {
        let text = path.text();
        if let Spelling::Plain(text) = path {
            if let Some(device) = device(text, flavour) {
                return device;
            }
        }
        // Each part holding a wildcard stands for one entry, so a `..` after
        // it (`src/*/../../x`) still climbs; what a pattern matches lies in
        // the folder before its first wildcard part that no `..` cancels.
        let marked = mark_wildcards(text, flavour);
        let mut loc = self.locate(path.with(marked.as_deref().unwrap_or(text)), flavour);
        let pattern = match loc.parts.iter().position(|part| part == WILDCARD) {
            Some(at) => {
                loc.parts.truncate(at);
                true
            }
            None => false,
        };
        let place = self.judge(&loc);
        if pattern && matches!(place, Place::Inside | Place::Workspace { .. }) {
            match glob::shape(text, flavour) {
                // `.g*`, `*/.git`: can match hidden entries such as `.git`.
                Shape::Hidden => {
                    return Place::Sensitive("a hidden file such as the repository's history");
                }
                // `*.log`, `*/*.o`: picks files inside the folder.
                Shape::Entries if place == (Place::Workspace { exact: true }) => {
                    return Place::Inside;
                }
                // `*`, `?*`, `*/*`: every entry, as much as the folder.
                Shape::Entries | Shape::All => {}
            }
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
            Spelling::Home(rest) => return self.home.clone().walk(rest, separators),
            Spelling::Plain(text) => text,
        };
        if flavour == Flavour::Windows {
            if let Some((share, rest)) = unc(text) {
                return Loc::at(Root::Unc(share)).walk(rest, separators);
            }
            if let Some((letter, rest)) = drive(text) {
                return Loc::at(Root::Drive(letter)).walk(rest, separators);
            }
        }
        if text.starts_with(separators) {
            let root = if self.cwd.windows() {
                self.cwd.root.clone()
            } else {
                Root::Unix
            };
            return Loc::at(root).walk(text, separators);
        }
        self.cwd.clone().walk(text, separators)
    }

    fn judge(&self, loc: &Loc) -> Place {
        if loc.parts.is_empty() {
            return Place::Top("the root of the disk");
        }
        if loc.holds(&self.home) {
            return Place::Home {
                exact: loc.is(&self.home),
            };
        }
        for workspace in &self.workspaces {
            if loc.holds(workspace) {
                return Place::Workspace {
                    exact: loc.is(workspace),
                };
            }
            if workspace.holds(loc) {
                let first = &loc.parts[workspace.parts.len()];
                return if first.eq_ignore_ascii_case(".git") {
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

/// The parts of a relative path, with `.` and `..` applied (a `..` with
/// nothing before it is dropped): `a/./b/../c` is `a`, `c`.
#[must_use]
pub fn parts(path: &str, flavour: Flavour) -> Vec<String> {
    Loc::at(Root::Unix).walk(path, flavour.separators()).parts
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

/// The part a wildcard part becomes while a path is resolved: no real file
/// name holds a NUL.
const WILDCARD: &str = "\u{0}*";

/// `text` with each part that holds a wildcard replaced by [`WILDCARD`];
/// `None` when it holds none.
fn mark_wildcards(text: &str, flavour: Flavour) -> Option<String> {
    if !glob::has_wildcard(text) {
        return None;
    }
    Some(
        text.split(flavour.separators())
            .map(|part| {
                if part.contains(WILDCARDS) {
                    WILDCARD
                } else {
                    part
                }
            })
            .collect::<Vec<_>>()
            .join("/"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing;

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
}
