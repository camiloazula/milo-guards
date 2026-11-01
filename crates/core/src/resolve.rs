//! Where a path argument resolves, by its spelling alone: POSIX paths
//! (`/home/me`) and Windows ones (`C:\Users\me`, `\\server\share`),
//! whatever the host. Windows paths compare without case, as Windows does.
//! Nothing reads the file system, so a symlink is judged by its own name.

use crate::spelling::glob::{self, Shape, WILDCARDS};
use crate::{Paths, Place, ProtectedKind, Sensitivity};

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
        if let Some((root, rest)) = windows_root(text) {
            return Self::at(root).walk(rest, Flavour::Windows);
        }
        Self::at(Root::Unix).walk(text, Flavour::Posix)
    }

    /// What macOS names the root and the data volume by. The data volume is
    /// also mounted at `/System/Volumes/Data`, the boot volume is linked at
    /// `/Volumes/<its name>`, and the data volume at `/Volumes/<its name> -
    /// Data`, so `/System/Volumes/Data/Users/me` and
    /// `/Volumes/Macintosh HD/Users/me` are `/Users/me`. The leading parts
    /// are dropped, as often as they come, however the path was spelled:
    /// every path is made absolute first (`~` and `..` applied, the working
    /// directory prepended). Names compare as a Mac's file system does, by
    /// the widest fold (`/Syſtem/Volumes/Data` is `/System/Volumes/Data`
    /// there). Everything that fails closed when it matches too much (the
    /// home directories, the secrets, protected paths) looks a path up with the
    /// links dropped on every system; the workspace and the temporary folders
    /// only on a Mac, where they are links, since elsewhere the paths do not
    /// exist and matching them would make a path that creates folders look
    /// inside the workspace.
    fn firm(mut self) -> Self {
        while let Some(link) = self.link() {
            self.parts.drain(..link);
        }
        self
    }

    /// How many leading parts are one of the links.
    fn link(&self) -> Option<usize> {
        const LINKS: [&[&str]; 3] = [
            &["System", "Volumes", "Data"],
            &["Volumes", "Macintosh HD"],
            &["Volumes", "Macintosh HD - Data"],
        ];
        if !matches!(self.root, Root::Unix) {
            return None;
        }
        LINKS
            .iter()
            .find(|link| {
                link.len() <= self.parts.len()
                    && self
                        .parts
                        .iter()
                        .zip(**link)
                        .all(|(part, name)| same_fold(part, name))
            })
            .map(|link| link.len())
    }

    /// This location with the links dropped, or `None` when it has none.
    fn stripped(&self) -> Option<Self> {
        self.link().map(|_| self.clone().firm())
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
        Spelling::Plain(text) => windows_root(text).map_or(text, |(_, rest)| rest),
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
    unc_parts(rest)
}

/// What a Windows path starts from: a drive (`C:`), a share
/// (`\\server\share`), or a long path (`\\?\C:\x`, `\\?\UNC\server\share`)
/// read as the drive or the share it names; and what follows it. `None` for
/// a path that starts at none of them, and for a long path that names
/// neither (`\\?\GLOBALROOT\...`, `\\?\Volume{...}\...`), which is a device.
fn windows_root(text: &str) -> Option<(Root, &str)> {
    if let Some(rest) = verbatim(text) {
        if let Some((letter, tail)) = drive(rest) {
            let whole = tail.is_empty() || tail.starts_with(['/', '\\']);
            return whole.then_some((Root::Drive(letter), tail));
        }
        let (kind, tail) = rest.split_once(['/', '\\']).unwrap_or((rest, ""));
        if kind.eq_ignore_ascii_case("unc") {
            let (share, tail) = unc_parts(tail)?;
            return Some((Root::Unc(share), tail));
        }
        return None;
    }
    if let Some((share, rest)) = unc(text) {
        return Some((Root::Unc(share), rest));
    }
    drive(text).map(|(letter, rest)| (Root::Drive(letter), rest))
}

/// What follows `\\?\` (with either kind of separator) when `text` starts
/// with it: the long-path prefix.
#[must_use]
pub fn verbatim(text: &str) -> Option<&str> {
    prefix(text, '?')
}

/// What follows a two-separator prefix and `mark` and one more separator
/// (`\\?\`, `//./`), each separator either kind.
fn prefix(text: &str, mark: char) -> Option<&str> {
    let mut chars = text.chars();
    let sep = |c: Option<char>| c.is_some_and(|c| matches!(c, '/' | '\\'));
    (sep(chars.next()) && sep(chars.next()) && chars.next() == Some(mark) && sep(chars.next()))
        .then_some(chars.as_str())
}

/// `server` and `share` (lower case) and what follows, from the text after
/// the separators of a share: `server\share\x`.
fn unc_parts(rest: &str) -> Option<(String, &str)> {
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

/// Files and folders under a home directory whose loss or change hurts, the
/// words a reason calls each by, and what touching it means: a key or a
/// credential (`Secret`), a file that runs or configures what runs later
/// (`Startup`), the repository's history (`History`, which is not here: a
/// workspace's own `.git` is told by its name).
///
/// This lists the places known to hold secrets; it is not a proof that
/// nowhere else does.
const SENSITIVE: [(&[&str], &str, Sensitivity); 60] = [
    (&[".ssh"], "your SSH keys", Sensitivity::Secret),
    (&[".gnupg"], "your GPG keys", Sensitivity::Secret),
    (&[".aws"], "your AWS credentials", Sensitivity::Secret),
    (&[".azure"], "your Azure credentials", Sensitivity::Secret),
    (
        &[".kube"],
        "your Kubernetes credentials",
        Sensitivity::Secret,
    ),
    (&[".docker"], "your Docker credentials", Sensitivity::Secret),
    (&[".netrc"], "your saved logins", Sensitivity::Secret),
    (
        &[".git-credentials"],
        "your git credentials",
        Sensitivity::Secret,
    ),
    (&[".npmrc"], "your npm login", Sensitivity::Secret),
    (&[".pypirc"], "your PyPI login", Sensitivity::Secret),
    (&[".vault-token"], "your Vault login", Sensitivity::Secret),
    (
        &[".oci"],
        "your Oracle Cloud credentials",
        Sensitivity::Secret,
    ),
    (
        &[".password-store"],
        "your saved passwords",
        Sensitivity::Secret,
    ),
    (&[".config", "gh"], "your GitHub login", Sensitivity::Secret),
    (
        &[".config", "gcloud"],
        "your Google Cloud credentials",
        Sensitivity::Secret,
    ),
    (
        &[".config", "git", "credentials"],
        "your git credentials",
        Sensitivity::Secret,
    ),
    (
        &[".cargo", "credentials.toml"],
        "your crates.io login",
        Sensitivity::Secret,
    ),
    (
        &[".cargo", "credentials"],
        "your crates.io login",
        Sensitivity::Secret,
    ),
    (
        &[".local", "share", "keyrings"],
        "your keyrings",
        Sensitivity::Secret,
    ),
    (
        &["Library", "Keychains"],
        "your keychains",
        Sensitivity::Secret,
    ),
    (
        &["AppData", "Roaming", "Microsoft", "Credentials"],
        "your saved Windows logins",
        Sensitivity::Secret,
    ),
    (
        &["AppData", "Local", "Microsoft", "Credentials"],
        "your saved Windows logins",
        Sensitivity::Secret,
    ),
    (
        &["AppData", "Roaming", "Microsoft", "Protect"],
        "your Windows encryption keys",
        Sensitivity::Secret,
    ),
    (
        &["AppData", "Roaming", "GitHub CLI"],
        "your GitHub login",
        Sensitivity::Secret,
    ),
    (
        &["AppData", "Roaming", "gcloud"],
        "your Google Cloud credentials",
        Sensitivity::Secret,
    ),
    (
        &["AppData", "Roaming", "gnupg"],
        "your GPG keys",
        Sensitivity::Secret,
    ),
    (
        &["AppData", "Roaming", "Microsoft", "Vault"],
        "your saved Windows logins",
        Sensitivity::Secret,
    ),
    (
        &["AppData", "Local", "Microsoft", "Vault"],
        "your saved Windows logins",
        Sensitivity::Secret,
    ),
    (
        &[".pgpass"],
        "your saved database logins",
        Sensitivity::Secret,
    ),
    (
        &[".my.cnf"],
        "your saved database logins",
        Sensitivity::Secret,
    ),
    (&[".s3cfg"], "your S3 credentials", Sensitivity::Secret),
    (
        &[".gem", "credentials"],
        "your RubyGems login",
        Sensitivity::Secret,
    ),
    (
        &[".m2", "settings.xml"],
        "your Maven logins",
        Sensitivity::Secret,
    ),
    (
        &[".terraform.d", "credentials.tfrc.json"],
        "your Terraform login",
        Sensitivity::Secret,
    ),
    (
        &[".config", "rclone"],
        "your rclone logins",
        Sensitivity::Secret,
    ),
    (
        &[".config", "op"],
        "your 1Password login",
        Sensitivity::Secret,
    ),
    (
        &[".config", "sops", "age"],
        "your encryption keys",
        Sensitivity::Secret,
    ),
    (
        &[".config", "hub"],
        "your GitHub login",
        Sensitivity::Secret,
    ),
    (&[".gitconfig"], "your git settings", Sensitivity::Startup),
    (
        &[".config", "git", "config"],
        "your git settings",
        Sensitivity::Startup,
    ),
    (
        &[".config", "powershell"],
        "your PowerShell profile",
        Sensitivity::Startup,
    ),
    (
        &[".config", "systemd", "user"],
        "the services your system starts at login",
        Sensitivity::Startup,
    ),
    (
        &["OneDrive", "Documents", "PowerShell"],
        "your PowerShell profile",
        Sensitivity::Startup,
    ),
    (
        &["OneDrive", "Documents", "WindowsPowerShell"],
        "your PowerShell profile",
        Sensitivity::Startup,
    ),
    (&[".bashrc"], "a shell startup file", Sensitivity::Startup),
    (
        &[".bash_profile"],
        "a shell startup file",
        Sensitivity::Startup,
    ),
    (
        &[".bash_login"],
        "a shell startup file",
        Sensitivity::Startup,
    ),
    (
        &[".bash_logout"],
        "a shell startup file",
        Sensitivity::Startup,
    ),
    (&[".zshrc"], "a shell startup file", Sensitivity::Startup),
    (&[".zprofile"], "a shell startup file", Sensitivity::Startup),
    (&[".zshenv"], "a shell startup file", Sensitivity::Startup),
    (&[".zlogin"], "a shell startup file", Sensitivity::Startup),
    (&[".zlogout"], "a shell startup file", Sensitivity::Startup),
    (&[".profile"], "a shell startup file", Sensitivity::Startup),
    (
        &[".config", "fish"],
        "a shell startup file",
        Sensitivity::Startup,
    ),
    (
        &["Library", "LaunchAgents"],
        "the programs macOS starts at login",
        Sensitivity::Startup,
    ),
    (
        &[".config", "autostart"],
        "the programs your desktop starts at login",
        Sensitivity::Startup,
    ),
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
        Sensitivity::Startup,
    ),
    (
        &["Documents", "PowerShell"],
        "your PowerShell profile",
        Sensitivity::Startup,
    ),
    (
        &["Documents", "WindowsPowerShell"],
        "your PowerShell profile",
        Sensitivity::Startup,
    ),
];

/// Keys and credentials the system itself keeps, under the root of a POSIX
/// system (and under `/private`, where macOS keeps `/etc` and `/var`).
const POSIX_SECRETS: [(&[&str], &str); 17] = [
    (&["etc", "shadow"], "the system's password hashes"),
    (&["etc", "gshadow"], "the system's password hashes"),
    (&["etc", "master.passwd"], "the system's password hashes"),
    (&["etc", "ssh"], "the system's SSH keys"),
    (&["etc", "ssl", "private"], "the system's private keys"),
    (
        &["etc", "pki", "tls", "private"],
        "the system's private keys",
    ),
    (&["etc", "letsencrypt"], "your certificate keys"),
    (&["etc", "wireguard"], "your WireGuard keys"),
    (&["etc", "krb5.keytab"], "the system's Kerberos keys"),
    (
        &["etc", "NetworkManager", "system-connections"],
        "your saved network passwords",
    ),
    (&["etc", "ppp"], "your saved network passwords"),
    (&["var", "db", "dslocal"], "the system's password hashes"),
    (&["run", "secrets"], "the container's secrets"),
    (&["var", "run", "secrets"], "the container's secrets"),
    (&["var", "vm"], "the memory the system keeps on disk"),
    (&["Library", "Keychains"], "the system's keychains"),
    (
        &["System", "Library", "Keychains"],
        "the system's keychains",
    ),
];

/// Where a POSIX system keeps the root user's home directory.
const ROOT_HOMES: [&[&str]; 3] = [&["root"], &["var", "root"], &["private", "var", "root"]];

/// Keys and credentials the system itself keeps, under a Windows drive.
const WINDOWS_SECRETS: [(&[&str], &str); 6] = [
    (
        &["Windows", "System32", "config"],
        "the Windows account database",
    ),
    (&["Windows", "Repair"], "the Windows account database"),
    (
        &["Windows", "System32", "Microsoft", "Protect"],
        "the Windows encryption keys",
    ),
    (&["ProgramData", "ssh"], "the system's SSH keys"),
    (
        &["ProgramData", "Microsoft", "Vault"],
        "the system's saved logins",
    ),
    (
        &["ProgramData", "Microsoft", "Crypto"],
        "the system's private keys",
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

/// A workspace folder, and whether it is itself inside something sensitive
/// (a workspace in `~/.docker/x`), where the folder's own paths stay the
/// agent's.
#[derive(Debug, Clone)]
struct Workspace {
    loc: Loc,
    in_sensitive: bool,
    /// Whether a sensitive place can be inside it (the home directory, or a
    /// folder holding one, is the workspace): only then is a path in it
    /// looked up in the sensitive places.
    holds_sensitive: bool,
}

/// Judges paths against the caller's directories.
#[derive(Debug, Clone)]
pub struct Resolver {
    cwd: Loc,
    /// Whether this is a Mac: see [`Loc::firm`].
    mac: bool,
    home: Loc,
    workspaces: Vec<Workspace>,
    temps: Vec<Loc>,
    /// What is sensitive under this home directory, and the system's own
    /// secrets by their full place.
    sensitive: Vec<(Loc, &'static str, Sensitivity)>,
    /// The folders whose entries are users' home directories: the one holding
    /// this home directory, and the places systems keep them (`/home`,
    /// `/Users`, `C:\Users`), whatever this user's own home is.
    neighbours: Vec<Loc>,
    /// The root user's home directory.
    root_homes: Vec<Loc>,
    /// Each protected path, its words, and whether it is a folder.
    protected: Vec<(Loc, &'static str, bool)>,
    system: Vec<Loc>,
}

impl Resolver {
    /// A resolver for the directories in `paths`. A Windows home directory
    /// makes it a Windows machine (its temporary and system folders are
    /// Windows ones); any other makes it a POSIX one.
    pub fn new(paths: &Paths) -> Self {
        // The home directory, protected paths and secrets are looked up with a
        // Mac's links dropped on every system (see `Loc::firm`). The
        // workspace, the working directory and the temporary folders are only
        // on a Mac: its home is under `/Users` (or root's, `/var/root`).
        let home = Loc::absolute(&paths.home.to_string_lossy()).firm();
        let mac = matches!(home.root, Root::Unix)
            && match home.parts.iter().map(String::as_str).collect::<Vec<_>>()[..] {
                [users, ..] if users.eq_ignore_ascii_case("Users") => true,
                [var, root] => var.eq_ignore_ascii_case("var") && root.eq_ignore_ascii_case("root"),
                [private, var, root] => {
                    private.eq_ignore_ascii_case("private")
                        && var.eq_ignore_ascii_case("var")
                        && root.eq_ignore_ascii_case("root")
                }
                _ => false,
            };
        let absolute = |text: &std::path::Path| {
            let loc = Loc::absolute(&text.to_string_lossy());
            if mac {
                loc.firm()
            } else {
                loc
            }
        };
        let cwd = absolute(&paths.cwd);
        let workspaces: Vec<Loc> = paths.workspaces.iter().map(|f| absolute(f)).collect();
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
        let mut sensitive: Vec<(Loc, &'static str, Sensitivity)> = SENSITIVE
            .iter()
            .map(|(parts, words, kind)| (home.join(parts), *words, *kind))
            .collect();
        let root = Loc::at(if home.windows() {
            home.root.clone()
        } else {
            Root::Unix
        });
        if home.windows() {
            sensitive.extend(
                WINDOWS_SECRETS
                    .iter()
                    .map(|(parts, words)| (root.join(parts), *words, Sensitivity::Secret)),
            );
        } else {
            for (parts, words) in POSIX_SECRETS {
                for under in [&[][..], &["private"]] {
                    let at = root.join(under).join(parts);
                    sensitive.push((at, words, Sensitivity::Secret));
                }
            }
        }
        let root_homes = if home.windows() {
            Vec::new()
        } else {
            ROOT_HOMES.iter().map(|parts| root.join(parts)).collect()
        };
        let mut neighbours: Vec<Loc> = Vec::new();
        if home.parts.len() > 1 {
            neighbours.push(Loc {
                root: home.root.clone(),
                parts: home.parts[..home.parts.len() - 1].to_vec(),
            });
        }
        if home.windows() {
            neighbours.push(root.join(&["Users"]));
            neighbours.push(Loc::at(Root::Drive('C')).join(&["Users"]));
        } else {
            neighbours.push(root.join(&["home"]));
            neighbours.push(root.join(&["Users"]));
        }
        let mut resolver = Self {
            cwd,
            mac,
            home: home.clone(),
            workspaces: Vec::new(),
            temps: Vec::new(),
            sensitive,
            neighbours,
            root_homes,
            protected: Vec::new(),
            system: Vec::new(),
        };
        let workspaces = workspaces
            .into_iter()
            .map(|loc| Workspace {
                in_sensitive: resolver.sensitive_at(&loc).is_some(),
                holds_sensitive: resolver.holds_sensitive(&loc),
                loc,
            })
            .collect();
        let protected = paths
            .protected
            .iter()
            .map(|entry| {
                (
                    Loc::absolute(&entry.path.to_string_lossy()).firm(),
                    entry.words,
                    entry.kind == ProtectedKind::Folder,
                )
            })
            .collect();
        resolver.workspaces = workspaces;
        resolver.temps = temps;
        resolver.protected = protected;
        resolver.system = system;
        resolver
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
        if let Spelling::Plain(text) = path {
            if let Some(device) = device(text, flavour) {
                return device;
            }
        }
        // A long path (`\\?\C:\x`) is the plain path it names.
        let long = self.plain(path, flavour);
        let path = long.as_deref().map_or(path, Spelling::Plain);
        let text = path.text();
        if self.elsewhere(path, flavour) || known_when_run(path, flavour) {
            return Place::Unknown;
        }
        let (loc, tail) = self.cut(path, text, flavour);
        let pattern = tail.is_some();
        // A pattern is judged by the folder before its first wildcard part,
        // and what it can pick is read from its parts below.
        let place = self.judge(&loc, flavour, holding && !pattern);
        if !pattern {
            return place;
        }
        let place = Self::pattern_place(place, text, tail.as_deref(), flavour, hidden);
        let stripped = loc.stripped();
        let strip = stripped.as_ref().unwrap_or(&loc);
        match self.picks_protected(strip, tail.as_deref(), flavour, hidden, place, holding) {
            Some(words) => Place::Protected(words),
            None => place,
        }
    }

    /// Where a path is cut at its first wildcard part: the location before
    /// it (the whole path when there is none), and, for a pattern, the text
    /// of each part from there on.
    ///
    /// Each part holding a wildcard stands for one entry, so a `..` after it
    /// (`src/*/../../x`) still climbs; what a pattern matches lies in the
    /// folder before its first wildcard part that no `..` cancels.
    fn cut(&self, path: Spelling<'_>, text: &str, flavour: Flavour) -> (Loc, Option<Vec<String>>) {
        let marked = mark_wildcards(text, flavour);
        let mut loc = self.locate_raw(path.with(marked.as_deref().unwrap_or(text)), flavour);
        let wildcards: Vec<&str> = text
            .split(flavour.separators())
            .filter(|part| part.contains(WILDCARDS))
            .collect();
        let first = loc.parts.iter().position(|part| part.starts_with(WILDCARD));
        let tail = first.map(|at| {
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
        if let Some(at) = first {
            loc.parts.truncate(at);
        }
        (loc, tail)
    }

    /// The words of a key or a credential that a pattern can pick: `~/.s*/id_rsa`
    /// picks `~/.ssh/id_rsa`, `/etc/sh*dow` the system's password hashes, and
    /// `~/.*` every dot file in the home directory, among them the secret
    /// ones. `None` for a path with no wildcard (judge it with
    /// [`place`](Self::place)), for one that is known only when it runs, and
    /// for one that picks no secret. `hidden` says a wildcard may match a
    /// leading dot, as for [`place_hidden`](Self::place_hidden).
    ///
    /// A part is matched against the names of each secret place one for one,
    /// as for the protected paths; a pattern that stops at a folder that only
    /// holds a secret picks no secret, since it reads that folder's name.
    /// What counts as a secret is the same as for `place`: this home
    /// directory's, another user's (`/home/*/.ssh`), the root user's, and the
    /// system's own.
    #[must_use]
    pub fn picks_secret(
        &self,
        path: Spelling<'_>,
        flavour: Flavour,
        hidden: bool,
    ) -> Option<&'static str> {
        let long = self.plain(path, flavour);
        let path = long.as_deref().map_or(path, Spelling::Plain);
        let text = path.text();
        if !glob::has_wildcard(text)
            || self.elsewhere(path, flavour)
            || known_when_run(path, flavour)
        {
            return None;
        }
        let (loc, tail) = self.cut(path, text, flavour);
        let tail = tail?;
        let stripped = loc.stripped();
        let folder = stripped.as_ref().unwrap_or(&loc);
        let tail: Vec<&str> = tail.iter().map(String::as_str).collect();
        let hidden = hidden || flavour == Flavour::Windows;
        let windows = folder.windows();
        // A user's name in another home directory: any part picks it.
        const USER: &str = "\u{0}user";
        let reaches = |names: &[String]| {
            picks(&tail, names, true, true, &|part, name| {
                name == USER || pattern_matches(part, name, flavour, hidden, windows)
            })
        };
        let names_of = |entry: &Loc| -> Option<Vec<String>> {
            let holds = folder.parts.len() <= entry.parts.len()
                && folder.root.same(&entry.root)
                && folder
                    .parts
                    .iter()
                    .zip(&entry.parts)
                    .all(|(spelled, name)| name == USER || same_name(spelled, name, windows));
            holds.then(|| entry.parts[folder.parts.len()..].to_vec())
        };
        // This home directory's and the system's own, by their full place.
        for (entry, words, kind) in &self.sensitive {
            if *kind == Sensitivity::Secret && names_of(entry).is_some_and(|names| reaches(&names))
            {
                return Some(words);
            }
        }
        // The same places under another user's home directory and the root
        // user's: the folder holding the homes, a user's name, then the place.
        let homes = self
            .neighbours
            .iter()
            .map(|folder| (folder, true))
            .chain(self.root_homes.iter().map(|home| (home, false)));
        for (home, with_user) in homes {
            let mut base = home.clone();
            if with_user {
                base.parts.push(USER.to_string());
            }
            for (entry, words, kind) in &SENSITIVE {
                if *kind != Sensitivity::Secret {
                    continue;
                }
                let mut whole = base.clone();
                whole.parts.extend(entry.iter().map(ToString::to_string));
                if names_of(&whole).is_some_and(|names| reaches(&names)) {
                    return Some(words);
                }
            }
        }
        None
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
                    return Place::Sensitive(HIDDEN, Sensitivity::History);
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
                        return Place::Sensitive(HIDDEN, Sensitivity::History);
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
        let device = matches!(path, Spelling::Plain(text) if device(text, flavour).is_some());
        let long = self.plain(path, flavour);
        let path = long.as_deref().map_or(path, Spelling::Plain);
        if device || glob::has_wildcard(path.text()) || self.elsewhere(path, flavour) {
            return None;
        }
        Some(self.locate(path, flavour).key())
    }

    /// The plain path a Windows long path names (`\\?\C:\x` is `C:\x`,
    /// `\\?\UNC\server\share\x` is `\\server\share\x`); `None` for a path
    /// that is not one.
    fn plain(&self, path: Spelling<'_>, flavour: Flavour) -> Option<String> {
        let Spelling::Plain(text) = path else {
            return None;
        };
        if flavour != Flavour::Windows || verbatim(text).is_none() {
            return None;
        }
        match windows_root(text)? {
            (Root::Drive(letter), rest) => Some(format!("{letter}:\\{rest}")),
            (Root::Unc(share), rest) => Some(format!("\\\\{}\\{rest}", share.replace('/', "\\"))),
            (Root::Unix, _) => None,
        }
    }

    /// Whether `path` is on a drive's own working directory (`C:x`, `C:`)
    /// and the working directory is not on that drive, so which folder it
    /// is depends on the process: known only when it runs.
    fn elsewhere(&self, path: Spelling<'_>, flavour: Flavour) -> bool {
        let Spelling::Plain(text) = path else {
            return false;
        };
        flavour == Flavour::Windows
            && drive(text).is_some_and(|(letter, rest)| {
                !rest.starts_with(flavour.separators())
                    && !matches!(self.cwd.root, Root::Drive(cwd) if cwd == letter)
            })
    }

    /// The location a path names, made absolute however it was spelled.
    fn locate(&self, path: Spelling<'_>, flavour: Flavour) -> Loc {
        self.locate_raw(path, flavour).firm()
    }

    fn locate_raw(&self, path: Spelling<'_>, flavour: Flavour) -> Loc {
        let separators = flavour.separators();
        let text = match path {
            Spelling::Home(rest) => return self.home.clone().walk(rest, flavour),
            Spelling::Plain(text) => text,
        };
        if flavour == Flavour::Windows {
            if let Some((letter, rest)) = drive(text) {
                // `C:x` is from the drive's own working directory, which is
                // the working directory when it is on that drive (`elsewhere`
                // says it is not).
                if !rest.starts_with(separators) {
                    return self.cwd.clone().walk(rest, flavour);
                }
                return Loc::at(Root::Drive(letter)).walk(rest, flavour);
            }
            if let Some((share, rest)) = unc(text) {
                return Loc::at(Root::Unc(share)).walk(rest, flavour);
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
        // The home directory, or a folder holding it. A name that is the
        // home directory's without case (a Mac's file system ignores it too)
        // or by its Windows short name is the same folder.
        let stripped = loc.stripped();
        let strip = stripped.as_ref().unwrap_or(loc);
        if strip.parts.is_empty() {
            return Place::Top("the root of the disk");
        }
        if above(strip, &self.home) {
            return Place::Home {
                exact: strip.parts.len() == self.home.parts.len(),
            };
        }
        if let Some((_, words, _)) = self.protected.iter().find(|(file, ..)| below(strip, file)) {
            return Place::Protected(words);
        }
        let place = self.judge_plain(loc, strip, flavour);
        if holding && place.harmless() {
            if let Some((_, words, _)) = self.protected.iter().find(|(file, ..)| above(strip, file))
            {
                return Place::Protected(words);
            }
        }
        place
    }

    /// `loc` is the location as spelled, `strip` the same with a Mac's links
    /// dropped. The workspace and the temporary folders are matched by the
    /// spelling on any system but a Mac, the secrets always by the stripped.
    fn judge_plain(&self, spelled: &Loc, strip: &Loc, flavour: Flavour) -> Place {
        let loc = if self.mac { strip } else { spelled };
        for workspace in &self.workspaces {
            let folder = &workspace.loc;
            if loc.holds(folder) {
                return Place::Workspace {
                    exact: loc.is(folder),
                };
            }
            if folder.holds(loc) {
                let first = &loc.parts[folder.parts.len()];
                let history =
                    same_fold(first, ".git") || (flavour == Flavour::Windows && short_git(first));
                if history {
                    return Place::Sensitive("the repository's history", Sensitivity::History);
                }
                // A workspace that holds a key's folder (the home directory
                // is the workspace) does not make the key the agent's; one
                // inside such a folder keeps its own paths.
                if workspace.holds_sensitive && !workspace.in_sensitive {
                    if let Some((words, kind)) = self.sensitive_at(strip) {
                        return Place::Sensitive(words, kind);
                    }
                }
                return Place::Inside;
            }
        }
        if let Some((words, kind)) = self.sensitive_at(strip) {
            return Place::Sensitive(words, kind);
        }
        if let Some(temp) = self.temps.iter().find(|temp| temp.holds(loc)) {
            return Place::Temp {
                exact: temp.is(loc),
            };
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

/// What a POSIX system keeps readable in `/dev`: what discards, what is
/// random or zero, and the terminal and standard streams. Every other device
/// is a way to the disk or the memory.
const DEV_READABLE: [&str; 8] = [
    "null", "zero", "random", "urandom", "tty", "stdin", "stdout", "stderr",
];

/// What is readable in `/proc` without being one process's secrets: the
/// machine's own facts. Everything else, and every process's folder (`self`
/// and a number: its environment, memory, command line, maps, and `root` and
/// `cwd`, which lead to any file), is not.
const PROC_READABLE: [&str; 6] = [
    "cpuinfo",
    "meminfo",
    "version",
    "loadavg",
    "uptime",
    "filesystems",
];

impl Resolver {
    /// The location `path` names, or `None` when it is known only when it
    /// runs (see [`place`](Self::place)).
    fn resolved(&self, path: Spelling<'_>, flavour: Flavour) -> Option<Loc> {
        let long = self.plain(path, flavour);
        let path = long.as_deref().map_or(path, Spelling::Plain);
        if self.elsewhere(path, flavour) || known_when_run(path, flavour) {
            return None;
        }
        Some(self.locate(path, flavour))
    }

    /// The words of what the kernel serves that `path` is, on a POSIX
    /// machine: a device under `/dev` that is not one of the few safe to read
    /// (`null`, `zero`, `random`, `urandom`, `tty`, the standard streams
    /// `stdin`, `stdout`, `stderr` and descriptors 0 to 2), or anything under
    /// `/proc` that is not one of the machine's own facts (`cpuinfo`,
    /// `meminfo`, ...): a process's environment, memory and command line, and
    /// its `root` and `cwd`, which lead to any file. Names compare without
    /// case, since a Mac does not; `None` for any other path and on Windows.
    ///
    /// A guard that lets reads through uses it to refuse these: they are
    /// files only by name, and what they hold is the agent's own keys.
    #[must_use]
    pub fn kernel(&self, path: Spelling<'_>, flavour: Flavour) -> Option<&'static str> {
        if flavour != Flavour::Posix {
            return None;
        }
        let loc = self.resolved(path, flavour)?;
        if !matches!(loc.root, Root::Unix) {
            return None;
        }
        let names: Vec<&str> = loc.parts.iter().map(String::as_str).collect();
        let is = |name: &str, other: &str| name.eq_ignore_ascii_case(other);
        match names.as_slice() {
            [dev, rest @ ..] if is(dev, "dev") => {
                let readable = match rest {
                    [name] => DEV_READABLE.iter().any(|ok| is(name, ok)),
                    [fd, number] => is(fd, "fd") && matches!(*number, "0" | "1" | "2"),
                    _ => false,
                };
                (!readable).then_some("a device file")
            }
            [proc, rest @ ..] if is(proc, "proc") => {
                let readable =
                    matches!(rest, [name] if PROC_READABLE.iter().any(|ok| is(name, ok)));
                (!readable).then_some("the kernel's process files")
            }
            _ => None,
        }
    }

    /// Whether `path` is in a git repository's own folder, at any depth
    /// (`vendor/x/.git/hooks/pre-commit`, not only the workspace's `.git`):
    /// `Some(words)` with what a reason calls it. A hook is a program git
    /// runs later, so it is named for that, and anything else in `.git` is
    /// the repository's history. Names read as for the workspace's own
    /// `.git`, without case and, on Windows, by short name.
    #[must_use]
    pub fn git(&self, path: Spelling<'_>, flavour: Flavour) -> Option<&'static str> {
        let loc = self.resolved(path, flavour)?;
        let windows = flavour == Flavour::Windows;
        let at = loc
            .parts
            .iter()
            .position(|part| same_fold(part, ".git") || (windows && short_git(part)))?;
        let hooks = loc
            .parts
            .get(at + 1)
            .is_some_and(|part| same_fold(part, "hooks"));
        Some(if hooks {
            "a git hook, which runs code"
        } else {
            "the repository's history"
        })
    }

    /// How `path`s are spelled on the machine these directories describe:
    /// `Windows` when the home directory is a Windows path, `Posix`
    /// otherwise, the way [`new`](Self::new) tells the two apart.
    #[must_use]
    pub fn flavour(&self) -> Flavour {
        if self.home.windows() {
            Flavour::Windows
        } else {
            Flavour::Posix
        }
    }

    /// Whether a sensitive place can lie inside `folder`: it is, or holds, a
    /// sensitive place of this home directory, another user's home
    /// directory, or the root user's. Names compare as `sensitive_at` does.
    fn holds_sensitive(&self, folder: &Loc) -> bool {
        self.sensitive
            .iter()
            .any(|(entry, ..)| above(folder, entry))
            || self.root_homes.iter().any(|home| above(folder, home))
            || self.neighbours.iter().any(|homes| {
                let shorter = folder.parts.len().min(homes.parts.len());
                folder.parts.len() <= homes.parts.len() + 1
                    && folder.root.same(&homes.root)
                    && folder.parts[..shorter]
                        .iter()
                        .zip(&homes.parts)
                        .all(|(spelled, name)| same_name(spelled, name, folder.windows()))
            })
    }

    /// The words and the [`Sensitivity`] of the sensitive place `loc` is, or
    /// is under: below this home directory, below the same place in another
    /// user's home directory (a sibling folder of this one, or the root
    /// user's), or one of the system's own secrets. Names compare without
    /// case on every host, and by their Windows short names on Windows.
    fn sensitive_at(&self, loc: &Loc) -> Option<(&'static str, Sensitivity)> {
        let windows = loc.windows();
        if let Some((_, words, kind)) = self.sensitive.iter().find(|(file, ..)| below(loc, file)) {
            return Some((words, *kind));
        }
        let tail = |home: &Loc, skip: usize| {
            let at = home.parts.len() + skip;
            (loc.parts.len() > at && lead(loc, home)).then(|| &loc.parts[at..])
        };
        let homes = self
            .neighbours
            .iter()
            .filter_map(|folder| tail(folder, 1))
            .chain(self.root_homes.iter().filter_map(|home| tail(home, 0)));
        for tail in homes {
            let hit = SENSITIVE.iter().find(|(entry, ..)| {
                entry.len() <= tail.len()
                    && tail
                        .iter()
                        .zip(*entry)
                        .all(|(spelled, name)| same_name(spelled, name, windows))
            });
            if let Some((_, words, kind)) = hit {
                return Some((words, *kind));
            }
        }
        None
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
        self.protected.iter().find_map(|(path, words, is_folder)| {
            if !above(folder, path) {
                return None;
            }
            let names = &path.parts[folder.parts.len()..];
            let windows = path.windows();
            let reach = |whole: bool| {
                let tail: Vec<&str> = tail.iter().map(String::as_str).collect();
                picks(&tail, names, whole, *is_folder, &|part, name| {
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
    same_fold(spelled, name) || (windows && spelled.contains('~') && short_name(spelled, name))
}

/// `c` as the widest reading of "the same without case" has it: the one
/// character its upper case is, then the one its lower case is, so the long
/// s `ſ`, the Kelvin sign `K`, the Ångström sign `Å`, the Ohm sign `Ω` and the
/// capital sharp s `ẞ` are an `s`, a `k`, an `å`, an `ω` and a `ß`; a
/// character whose case is more than one stays itself. APFS folds this far;
/// NTFS does not (its table maps `ſ` up and leaves the signs alone), so this
/// is used only where matching too much fails closed (the home directory,
/// the sensitive places, protected paths and `.git`), and never for the
/// workspace or a temporary folder, where it would make another folder the
/// agent's own.
fn fold(c: char) -> char {
    let upper = single(c.to_uppercase()).unwrap_or(c);
    single(upper.to_lowercase()).unwrap_or(upper)
}

/// The one character `chars` yields; `None` for none or several.
fn single(mut chars: impl Iterator<Item = char>) -> Option<char> {
    let only = chars.next()?;
    chars.next().is_none().then_some(only)
}

/// Whether two names are the same without case, by [`fold`].
fn same_fold(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
        || (!(a.is_ascii() && b.is_ascii()) && a.chars().map(fold).eq(b.chars().map(fold)))
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

/// Whether a pattern part is nothing but two or more stars.
fn is_globstar(part: &str) -> bool {
    part.len() >= 2 && part.bytes().all(|b| b == b'*')
}

/// Whether the pattern parts `tail` pick the names `names` in order. A part
/// that is nothing but two or more stars may stand for any number of names
/// (a shell with `globstar`) that a `*` could match, all the rest of them
/// when it is the last, and the last name itself too. `whole` asks that every name be reached; when
/// it is not, a pattern that ends first picks the folder holding the rest.
/// The pattern going on past the last name is below it, which counts only
/// when `below` says the last name is a folder.
fn picks(
    tail: &[&str],
    names: &[String],
    whole: bool,
    below: bool,
    matches: &dyn Fn(&str, &str) -> bool,
) -> bool {
    // `reach[j]`: parts `i..` pick names `j..`, built from the end.
    let mut reach = vec![false; names.len() + 1];
    for i in (0..=tail.len()).rev() {
        let mut row = vec![false; names.len() + 1];
        for j in (0..=names.len()).rev() {
            row[j] = if j == names.len() {
                // Every name reached: more of the pattern goes below the
                // last one, which only a folder has.
                below || tail[i..].iter().all(|part| is_globstar(part))
            } else if i == tail.len() {
                !whole
            } else if is_globstar(tail[i]) {
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

/// Whether `text` names a place on another machine: a share, spelled with two
/// separators (`\\server\share`, `//server/share`) or as a long path
/// (`\\?\UNC\server\share`, `\\.\UNC\server\share`,
/// `\\?\GLOBALROOT\Device\Mup\server\share`). Touching it contacts the
/// server, which is offered the user's Windows credentials. `false` on
/// `Posix`, where two separators are one.
///
/// Core reads a share's root only when it holds no wildcard, and a `?` is
/// one, so the root is read here: two separators start it, and what is not a
/// share is a long path or a device that is a disk (`\\?\C:\x`,
/// `\\.\PhysicalDrive0`). Windows folds repeated separators and drops `.`
/// parts, so `\\.\\UNC\host\share` and `\\.\.\UNC\host\share` are the same
/// share; a `..` could undo any of it, so a path with one counts.
#[must_use]
pub fn network(text: &str, flavour: Flavour) -> bool {
    if flavour == Flavour::Posix {
        return false;
    }
    let separators = flavour.separators();
    let mut chars = text.chars();
    if !(chars.next().is_some_and(|c| separators.contains(&c))
        && chars.next().is_some_and(|c| separators.contains(&c)))
    {
        return false;
    }
    let mut raw = text[2..].split(separators);
    let first = raw.next().unwrap_or_default();
    let rest: Vec<&str> = raw
        .filter(|part| !part.is_empty() && *part != ".")
        .collect();
    if first == ".." || rest.contains(&"..") {
        return true;
    }
    match first {
        "?" | "." => rest.first().is_some_and(|kind| {
            kind.eq_ignore_ascii_case("unc") || kind.eq_ignore_ascii_case("globalroot")
        }),
        _ => true,
    }
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
    if flavour == Flavour::Windows
        && (prefix(text, '.').is_some()
            || (verbatim(text).is_some() && windows_root(text).is_none()))
    {
        // The device namespace is the root of what follows: `..` cannot
        // climb out of it. A long path that names no drive and no share
        // (`\\?\GLOBALROOT\...`, `\\?\Volume{...}\...`) is in a namespace
        // of its own, which is as much a disk.
        return Some(Place::Disk);
    }
    if text.contains('{') {
        return None;
    }
    let lower = text.to_ascii_lowercase();
    if flavour == Flavour::Windows && matches!(lower.as_str(), "nul" | "nul:" | "con" | "con:") {
        return Some(Place::Null);
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
    use crate::{testing, Protected, ProtectedKind};

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
            (
                ".git/config",
                Place::Sensitive("the repository's history", Sensitivity::History),
            ),
            (
                "/home/me/.ssh/id_rsa",
                Place::Sensitive("your SSH keys", Sensitivity::Secret),
            ),
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
            (
                r"C:\Users\me\.SSH\id",
                Place::Sensitive("your SSH keys", Sensitivity::Secret),
            ),
            (
                r".GIT\config",
                Place::Sensitive("the repository's history", Sensitivity::History),
            ),
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
            (
                "/.ssh/id",
                Place::Sensitive("your SSH keys", Sensitivity::Secret),
            ),
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
        let hidden = Place::Sensitive(
            "a hidden file such as the repository's history",
            Sensitivity::History,
        );
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
        let hidden = Place::Sensitive(
            "a hidden file such as the repository's history",
            Sensitivity::History,
        );
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
                Place::Sensitive(
                    "a hidden file such as the repository's history",
                    Sensitivity::History,
                ),
            ),
            (
                "*/.git",
                Place::Sensitive(
                    "a hidden file such as the repository's history",
                    Sensitivity::History,
                ),
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
        let history = Place::Sensitive("the repository's history", Sensitivity::History);
        for (path, place) in [
            (".git.", history),
            (".git ", history),
            (".git. .", history),
            (".GIT...", history),
            (r".git.\objects", history),
            (r"src\..\.git.", history),
            (r"C:\Users\me\dev\repo\.git.", history),
            (
                r"C:\Users\me\.ssh.\id",
                Place::Sensitive("your SSH keys", Sensitivity::Secret),
            ),
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
        let history = Place::Sensitive("the repository's history", Sensitivity::History);
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
        // One letter and a colon is a drive, as Windows reads it; with no
        // separator after it, the drive's own working directory.
        for (path, place) in [
            ("x:stream", Place::Unknown),
            (r"C:\Users\me\dev\repo\x", Place::Inside),
            (r"C:\Users\me", Place::Home { exact: true }),
            (r"c:\", Place::Top("the root of the disk")),
            (r"c:", Place::Workspace { exact: true }),
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
        let history = Place::Sensitive("the repository's history", Sensitivity::History);
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

    /// `paths` with protected folders.
    fn gated(paths: Paths, protected: &[&str]) -> Paths {
        kinds(paths, &[], protected)
    }

    /// `paths` with protected files and folders.
    fn kinds(paths: Paths, files: &[&str], folders: &[&str]) -> Paths {
        paths.with_protected(
            files
                .iter()
                .map(|path| Protected::file(*path, SETTINGS))
                .chain(
                    folders
                        .iter()
                        .map(|path| Protected::folder(*path, SETTINGS)),
                ),
        )
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
        let paths = kinds(
            testing::posix(),
            &["/home/me/work/repo/conf/app/x.yaml"],
            &[],
        );
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
        let paths = kinds(
            testing::posix(),
            &[
                "/home/me/work/repo/settings.yaml",
                "/home/me/work/repo/conf/app/x.yaml",
            ],
            &["/home/me/work/repo/.agent"],
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
            // A protected file has nothing below it.
            ("set*/x", Place::Inside),
            ("**/y.yaml", Place::Inside),
            ("**/*.rs", Place::Inside),
            ("**/conf/*/y*", Place::Inside),
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
    fn only_a_protected_folder_has_something_below_a_pattern_part() {
        let protected = Place::Protected(SETTINGS);
        let file = kinds(
            testing::posix(),
            &["/home/me/work/repo/conf/app/x.yaml"],
            &[],
        );
        for (path, place) in [
            ("**/x.yaml", protected),
            ("**/x.*", protected),
            ("conf/**", protected),
            ("conf/*/x.yaml", protected),
            ("conf", protected),
            ("conf/app/x.yaml", protected),
            ("**/y.yaml", Place::Inside),
            ("**/*.rs", Place::Inside),
            ("**/*.pyc", Place::Inside),
            ("*/*/x.yaml/z", Place::Inside),
            ("conf/app/x.yaml/*", protected),
        ] {
            assert_eq!(at(&file, path, POSIX), place, "{path}");
        }
        let folder = gated(testing::posix(), &["/home/me/work/repo/conf/app/x.yaml"]);
        for path in ["**/y.yaml", "**/*.rs", "conf/*/x.yaml/z", "conf/app/x*/z"] {
            assert_eq!(at(&folder, path, POSIX), protected, "{path}");
        }
        assert_eq!(Protected::file("/a", "x").kind, ProtectedKind::File);
        assert_eq!(Protected::folder("/a", "x").kind, ProtectedKind::Folder);
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
        let paths = kinds(
            testing::windows(),
            &[r"C:\Users\me\dev\repo\conf\settings.yaml"],
            &[r"C:\Users\me\dev\repo\.agent"],
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
            .with_protected([Protected::folder("/home/me/.a", "one")])
            .with_protected([Protected::folder("/home/me/.b", "two")]);
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
