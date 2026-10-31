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
    /// Another user's home (`~user`): the spelling does not say.
    Unknown,
}

/// Read what `text` starts from. A first part holding a wildcard is a
/// pattern, not a `~` or a drive, so it is left as written.
fn start(text: &str, shell: Shell) -> Start<'_> {
    let separators = flavour(shell).separators();
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
    if shell == Shell::PowerShell {
        if let Some((name, rest)) = text.split_once(':') {
            if name.len() > 1 && name.chars().all(|c| c.is_ascii_alphanumeric()) {
                return Start::Provider(name.to_ascii_lowercase(), rest);
            }
        }
    }
    Start::Plain
}

/// Judges path arguments against the caller's directories.
pub(crate) struct Resolver {
    core: milo_guards_core::Resolver,
}

impl Resolver {
    pub(crate) fn new(paths: &Paths) -> Self {
        Self {
            core: milo_guards_core::Resolver::new(paths),
        }
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
        return path.clone();
    }
    match dir {
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
