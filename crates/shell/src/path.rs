//! Where a path argument resolves, by its spelling alone, for a line run by
//! a given shell.
//!
//! The path model itself is [`milo_guards_core::Resolver`], which takes a
//! path spelled out as text. What is left here is what only a shell's
//! syntax gives a path a meaning for: `~` and `~user`, PowerShell's
//! provider paths (`HKLM:\Software`, `FileSystem::C:\x`) and `$null`, brace
//! lists, and a `cd` that moved the line.

use milo_guards_core::spelling::glob::{self, Shape};
use milo_guards_core::{Flavour, Paths, Spelling};

pub(crate) use milo_guards_core::Place;

use crate::unit::Arg;
use crate::Shell;

/// How `shell` spells paths: a POSIX shell's are POSIX ones, the others'
/// are Windows ones.
fn flavour(shell: Shell) -> Flavour {
    if shell == Shell::Posix {
        Flavour::Posix
    } else {
        Flavour::Windows
    }
}

/// Registry hives as PowerShell names its drives.
const REGISTRY: [&str; 6] = ["hklm", "hkcu", "hkcr", "hku", "hkcc", "registry"];

/// What a path starts from, once the shell's own syntax is read.
enum Start<'a> {
    /// The path as written: absolute, or from the working directory.
    Plain,
    /// The part below `~`.
    Home(&'a str),
    /// A PowerShell drive that is not a disk (`HKLM:`), lower case, and the
    /// path on it.
    Provider(String, &'a str),
    /// A path on a disk's drive with no separator after the colon (`C:x`,
    /// `C:*`): from that drive's own working directory. The drive letter,
    /// and the path after it.
    DriveRelative(char, &'a str),
    /// Another user's home (`~user`): the spelling does not say.
    Unknown,
}

/// The `name:` a path starts with, and what follows it: a disk's drive
/// letter (`C:`), or in PowerShell any drive (`HKLM:`, `Env:`). Read before
/// anything else, since a wildcard after it (`HKCU:*`) does not change what
/// it names.
fn qualifier(text: &str, shell: Shell) -> Option<(&str, &str)> {
    if shell == Shell::Posix {
        return None;
    }
    let (name, rest) = text.split_once(':')?;
    let named = !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric());
    let drive = name.len() == 1 && name.chars().all(|c| c.is_ascii_alphabetic());
    (named && (drive || (shell == Shell::PowerShell && name.len() > 1))).then_some((name, rest))
}

/// Read what `text` starts from. The drive is read first; then a first part
/// holding a wildcard is a pattern, not a `~`, so it is left as written.
fn start(text: &str, shell: Shell) -> Start<'_> {
    let separators = flavour(shell).separators();
    if let Some((name, rest)) = qualifier(text, shell) {
        if name.len() > 1 {
            return Start::Provider(name.to_ascii_lowercase(), rest);
        }
        let letter = name.chars().next().unwrap_or_default();
        // `C:` alone is the drive's working directory.
        if rest.is_empty() {
            return Start::DriveRelative(letter, ".");
        }
        if !rest.starts_with(separators) {
            return Start::DriveRelative(letter, rest);
        }
        return Start::Plain;
    }
    let first = text.split(separators).next().unwrap_or_default();
    if glob::has_wildcard(first) {
        return Start::Plain;
    }
    if let Some(rest) = text.strip_prefix('~') {
        return if rest.is_empty() || rest.starts_with(separators) {
            Start::Home(rest)
        } else {
            Start::Unknown
        };
    }
    Start::Plain
}

/// The drive letter a working directory is on (`C` for `C:\Users\me`).
fn drive_of(dir: &str) -> Option<char> {
    let mut chars = dir.chars();
    let letter = chars.next().filter(char::is_ascii_alphabetic)?;
    (chars.next() == Some(':')).then(|| letter.to_ascii_uppercase())
}

/// Judges path arguments against the caller's directories.
pub(crate) struct Resolver {
    core: milo_guards_core::Resolver,
    /// The drive the working directory is on, upper case; `None` when it is
    /// on no drive.
    cwd_drive: Option<char>,
}

impl Resolver {
    pub(crate) fn new(paths: &Paths) -> Self {
        Self {
            core: milo_guards_core::Resolver::new(paths),
            cwd_drive: drive_of(&paths.cwd.to_string_lossy()),
        }
    }

    /// The path `rest` names on `letter`'s drive, from the working
    /// directory when that is the drive it is on; `None` on any other
    /// drive, whose own working directory is not known.
    fn on_cwd_drive<'a>(&self, letter: char, rest: &'a str) -> Option<&'a str> {
        (self.cwd_drive == Some(letter.to_ascii_uppercase())).then_some(rest)
    }

    /// A key for the single file `arg` names from `dir`; `None` when it is
    /// not one definite file (a device, a wildcard, a brace list, unknown).
    pub(crate) fn file_key(&self, dir: Option<&Arg>, arg: &Arg, shell: Shell) -> Option<String> {
        let arg = within(dir, arg, shell);
        let text = arg.known()?;
        if device(text, shell).is_some() || brace_list(text) || glob::has_wildcard(text) {
            return None;
        }
        let flavour = flavour(shell);
        match start(text, shell) {
            Start::Plain => self.core.key(Spelling::Plain(text), flavour),
            Start::Home(rest) => self.core.key(Spelling::Home(rest), flavour),
            Start::Provider(name, rest) => {
                let parts = milo_guards_core::spelling::parts(rest, flavour).join("/");
                Some(format!("{name}:|{}", parts.to_ascii_lowercase()))
            }
            Start::DriveRelative(letter, rest) => {
                if let Some(rest) = self.on_cwd_drive(letter, rest) {
                    return self.core.key(Spelling::Plain(rest), flavour);
                }
                let parts = milo_guards_core::spelling::parts(rest, flavour).join("/");
                let letter = letter.to_ascii_uppercase();
                Some(format!("{letter}:~|{}", parts.to_ascii_lowercase()))
            }
            Start::Unknown => None,
        }
    }

    /// Where `arg` lands when `shell` runs it.
    pub(crate) fn place(&self, arg: &Arg, shell: Shell) -> Place {
        match arg.known() {
            Some(text) => self.place_of(text, shell),
            None => Place::Unknown,
        }
    }

    fn place_of(&self, text: &str, shell: Shell) -> Place {
        if let Some(device) = device(text, shell) {
            return device;
        }
        // A brace list (`{~,x}`, `x{,/../..}`) expands to paths its spelling
        // does not show.
        if brace_list(text) {
            return Place::Unknown;
        }
        // `Microsoft.PowerShell.Core\FileSystem::C:\x`: a provider-qualified
        // path is the provider's own path.
        if shell == Shell::PowerShell {
            if let Some((qualifier, rest)) = text.split_once("::") {
                let provider = qualifier
                    .rsplit('\\')
                    .next()
                    .unwrap_or(qualifier)
                    .to_ascii_lowercase();
                return match provider.as_str() {
                    "filesystem" => self.place_of(rest, shell),
                    "registry" => Place::Registry,
                    _ => Place::Outside,
                };
            }
        }
        let flavour = flavour(shell);
        match start(text, shell) {
            Start::Plain => self.core.place(Spelling::Plain(text), flavour),
            Start::Home(rest) => self.core.place(Spelling::Home(rest), flavour),
            Start::Provider(name, _) if REGISTRY.contains(&name.as_str()) => Place::Registry,
            Start::Provider(..) => Place::Outside,
            Start::DriveRelative(letter, rest) => match self.on_cwd_drive(letter, rest) {
                Some(rest) => self.core.place(Spelling::Plain(rest), flavour),
                None => Place::Outside,
            },
            Start::Unknown => Place::Unknown,
        }
    }
}

/// A device a path names: the core's, and PowerShell's and cmd's `$null`.
fn device(text: &str, shell: Shell) -> Option<Place> {
    if shell != Shell::Posix && text.eq_ignore_ascii_case("$null") {
        return Some(Place::Null);
    }
    milo_guards_core::spelling::device(text, flavour(shell))
}

/// Whether `text` holds a brace list: a `{` with a `,` before a later `}`.
fn brace_list(text: &str) -> bool {
    match (text.find('{'), text.rfind('}')) {
        (Some(open), Some(close)) if open < close => text[open..close].contains(','),
        _ => false,
    }
}

/// `text` up to the folder its first wildcard is in: `~/*` is `~`, and
/// `*.log` is `.`. What a pattern matches lies inside that folder.
fn before_wildcards(text: &str, shell: Shell) -> String {
    let Some(at) = text.find(['*', '?', '[']) else {
        return text.to_string();
    };
    let head = &text[..at];
    let separators = flavour(shell).separators();
    match head.rfind(separators) {
        Some(0) => head[..1].to_string(),
        Some(end) => head[..end].to_string(),
        None if head.starts_with('~') => "~".to_string(),
        // `HKCU:*`, `C:x*`: the drive's own working directory.
        None => match qualifier(head, shell) {
            Some((name, _)) => format!("{name}:."),
            None => ".".to_string(),
        },
    }
}

/// `path` as seen from `dir`, where an earlier `cd` moved: a relative path
/// is joined to it, and is unknown when where it moved is.
pub(crate) fn within(dir: Option<&Arg>, path: &Arg, shell: Shell) -> Arg {
    let (Some(dir), Arg::Known(text)) = (dir, path) else {
        return path.clone();
    };
    let drive =
        text.chars().next().is_some_and(|c| c.is_ascii_alphabetic()) && text[1..].starts_with(':');
    let absolute = text.starts_with(['/', '~'])
        || (shell != Shell::Posix && text.starts_with('\\'))
        || (shell != Shell::Posix && drive)
        || (shell == Shell::PowerShell
            && text.split_once(':').is_some_and(|(name, _)| name.len() > 1));
    if absolute {
        // A path on a drive's own working directory (`C:x`) is not where a
        // `cd` on another drive, or this one, left it.
        if matches!(start(text, shell), Start::DriveRelative(..)) {
            return Arg::Unknown(text.clone());
        }
        return path.clone();
    }
    match dir {
        // After `cd C:` a path is on the drive's working directory (`C:x`),
        // not at the drive's root (`C:/x`).
        Arg::Known(dir) if shell != Shell::Posix && drive_of(dir).is_some() && dir.len() == 2 => {
            Arg::Known(format!("{dir}{text}"))
        }
        Arg::Known(dir) => Arg::Known(format!("{dir}/{text}")),
        _ => Arg::Unknown(text.clone()),
    }
}

/// What a listing of `text` hands on, as a path the resolver reads: a
/// pattern that picks files (`*.bak`, `src/*.o`) or a filtered listing
/// hands files inside its folder; a folder listed whole (`.`, `*`, `~`)
/// hands everything in it, which is as much as the folder itself.
pub(crate) fn listed(text: &str, filtered: bool, shell: Shell) -> String {
    if !glob::has_wildcard(text) {
        return if filtered {
            format!("{text}/x")
        } else {
            text.to_string()
        };
    }
    // `Registry::HKEY_CURRENT_USER*`, `Microsoft.PowerShell.Core\FileSystem::C:*`:
    // the pattern is on the provider's own path, after the `::`.
    if shell == Shell::PowerShell {
        if let Some((provider, rest)) = text.split_once("::") {
            return format!("{provider}::{}", listed(rest, filtered, shell));
        }
    }
    // The drive (`C:`, `HKCU:`) is not part of the pattern.
    let body = qualifier(text, shell).map_or(text, |(_, rest)| rest);
    if glob::shape(body, flavour(shell)) == Shape::Entries {
        format!("{}/x", before_wildcards(text, shell))
    } else {
        // The whole folder: every entry, or hidden ones such as `.git`.
        before_wildcards(text, shell)
    }
}
