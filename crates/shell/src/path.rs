//! Where a path argument resolves, by its spelling alone, for a line run by
//! a given shell.
//!
//! The path model itself is [`milo_guards_core::Resolver`], which takes a
//! path spelled out as text. What is left here is what only a shell's
//! syntax gives a path a meaning for: `~` and `~user`, PowerShell's
//! provider paths (`HKLM:\Software`, `FileSystem::C:\x`) and `$null`, brace
//! lists, and a `cd` that moved the line.

use milo_guards_core::spelling::glob;
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
        if brace_list(text) || device(text, shell).is_some() || glob::has_wildcard(text) {
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

    /// Whether `arg`, written from `dir`, is a file that cannot be placed:
    /// not a device, and unknown by itself or by where `dir` moved to.
    pub(crate) fn unplaced(&self, dir: Option<&Arg>, arg: &Arg, shell: Shell) -> bool {
        if arg
            .known()
            .is_some_and(|text| device(text, shell).is_some())
        {
            return false;
        }
        within(dir, arg, shell).is_unknown()
    }

    /// Whether `arg`, written from `dir`, names a place on another machine:
    /// a UNC path (`\\server\share`, `//server/share`,
    /// `\\?\UNC\server\share`) in PowerShell or cmd. Reading it contacts
    /// the server, which is offered the user's credentials.
    ///
    /// The spelling is read by core's `spelling::network`.
    pub(crate) fn network(&self, dir: Option<&Arg>, arg: &Arg, shell: Shell) -> bool {
        if shell == Shell::Posix {
            return false;
        }
        let arg = within(dir, arg, shell);
        let Some(mut text) = arg.known() else {
            return false;
        };
        // `FileSystem::\\server\share`
        if shell == Shell::PowerShell {
            if let Some((provider, rest)) = text.split_once("::") {
                let provider = provider.rsplit('\\').next().unwrap_or(provider);
                if provider.eq_ignore_ascii_case("filesystem") {
                    text = rest;
                }
            }
        }
        milo_guards_core::spelling::network(text, flavour(shell))
    }

    /// Where `arg` lands when `shell` runs it; `hidden` says a wildcard in
    /// it may match a leading dot (`dotglob`).
    pub(crate) fn place(&self, arg: &Arg, shell: Shell, hidden: bool) -> Place {
        match arg.known() {
            Some(text) => self.place_of(text, shell, hidden, true),
            None => Place::Unknown,
        }
    }

    /// As [`place`](Self::place), for a path something is written into: a
    /// folder that only holds a protected path is not a write of it.
    pub(crate) fn place_into(&self, arg: &Arg, shell: Shell, hidden: bool) -> Place {
        match arg.known() {
            Some(text) => self.place_of(text, shell, hidden, false),
            None => Place::Unknown,
        }
    }

    /// The words of a file a tool runs on its own that a write to `arg`
    /// is, in a workspace folder at any depth (`.envrc`,
    /// `.github/workflows/ci.yml`); with `below`, one a recursive copy to it
    /// can replace, so a folder that holds one counts too (`.github`).
    /// `None` for any other path, and for one the shell reads another way
    /// (a brace list, a device, a registry or other provider path).
    pub(crate) fn startup(
        &self,
        arg: &Arg,
        shell: Shell,
        hidden: bool,
        below: bool,
    ) -> Option<&'static str> {
        self.startup_of(arg.known()?, shell, hidden, below)
    }

    fn startup_of(
        &self,
        text: &str,
        shell: Shell,
        hidden: bool,
        below: bool,
    ) -> Option<&'static str> {
        if brace_list(text) || device(text, shell).is_some() {
            return None;
        }
        if shell == Shell::PowerShell {
            if let Some((qualifier, rest)) = text.split_once("::") {
                let provider = qualifier.rsplit('\\').next().unwrap_or(qualifier);
                return provider
                    .eq_ignore_ascii_case("filesystem")
                    .then(|| self.startup_of(rest, shell, hidden, below))
                    .flatten();
            }
        }
        let flavour = flavour(shell);
        let ask = |spelling| {
            if below {
                self.core.startup_below(spelling, flavour, hidden)
            } else {
                self.core.startup(spelling, flavour, hidden)
            }
        };
        match start(text, shell) {
            Start::Plain => ask(Spelling::Plain(text)),
            Start::Home(rest) => ask(Spelling::Home(rest)),
            Start::DriveRelative(letter, rest) => {
                ask(Spelling::Plain(self.on_cwd_drive(letter, rest)?))
            }
            Start::Provider(..) | Start::Unknown => None,
        }
    }

    fn place_of(&self, text: &str, shell: Shell, hidden: bool, holding: bool) -> Place {
        let place_core = |spelling, flavour| {
            if holding {
                self.core.place_hidden(spelling, flavour, hidden)
            } else {
                self.core.place_into(spelling, flavour, hidden)
            }
        };
        // A brace list (`{~,x}`, `x{,/../..}`) expands to paths its spelling
        // does not show, so it is checked before the text is taken for a
        // device.
        if brace_list(text) {
            return Place::Unknown;
        }
        if let Some(device) = device(text, shell) {
            return device;
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
                    "filesystem" => self.place_of(rest, shell, hidden, holding),
                    "registry" => Place::Registry,
                    _ => Place::Outside,
                };
            }
        }
        let flavour = flavour(shell);
        match start(text, shell) {
            Start::Plain => place_core(Spelling::Plain(text), flavour),
            Start::Home(rest) => place_core(Spelling::Home(rest), flavour),
            Start::Provider(name, _) if REGISTRY.contains(&name.as_str()) => Place::Registry,
            Start::Provider(..) => Place::Outside,
            Start::DriveRelative(letter, rest) => match self.on_cwd_drive(letter, rest) {
                Some(rest) => place_core(Spelling::Plain(rest), flavour),
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
/// pattern is handed on as written, so the resolver judges it as it would
/// judge a delete of it (`..` applied, then what it can match); a filtered
/// listing hands files inside its folder; a folder listed whole (`.`, `~`)
/// hands everything in it, which is as much as the folder itself.
pub(crate) fn listed(text: &str, filtered: bool) -> String {
    if filtered && !glob::has_wildcard(text) {
        format!("{text}/x")
    } else {
        text.to_string()
    }
}
