//! Where a path argument resolves, by its spelling alone, for a line run by
//! a given shell.
//!
//! The path model itself is [`milo_guards_core::Resolver`], which takes a
//! path spelled out as text. What is left here is what only a shell's
//! syntax gives a path a meaning for: `~` and `~user`, PowerShell's
//! provider paths (`HKLM:\Software`, `FileSystem::C:\x`) and `$null`, brace
//! lists, and a `cd` that moved the line.

use std::path::PathBuf;

use milo_guards_core::spelling::glob;
use milo_guards_core::{Flavour, Paths, Sensitivity, Spelling};

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
/// letter (`C:`), or in PowerShell any drive (`HKLM:`, `Env:`, a drive made
/// with `New-PSDrive`: `my_drive:`, `my-drive:`). Read before anything else,
/// since a wildcard after it (`HKCU:*`) does not change what it names. A
/// drive's name holds no separator, no wildcard and no `.` (`x.txt:stream`
/// is a file's stream, not a drive).
fn qualifier(text: &str, shell: Shell) -> Option<(&str, &str)> {
    if shell == Shell::Posix {
        return None;
    }
    let (name, rest) = text.split_once(':')?;
    if name.len() == 1 {
        return name
            .starts_with(|c: char| c.is_ascii_alphabetic())
            .then_some((name, rest));
    }
    let named = !name.is_empty()
        && !name.contains(flavour(shell).separators())
        && !glob::has_wildcard(name)
        && !name.contains('.');
    (named && shell == Shell::PowerShell).then_some((name, rest))
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
    /// Whether a plain relative path (see [`plain_relative`]) is the agent's
    /// own, since the working directory is in a workspace that holds no key.
    clear: bool,
    /// The drive the working directory is on, upper case; `None` when it is
    /// on no drive.
    cwd_drive: Option<char>,
    /// The directories, kept for `effect` only (see [`Resolver::keep`]).
    paths: Option<Paths>,
}

impl Resolver {
    pub(crate) fn new(paths: &Paths) -> Self {
        let core = milo_guards_core::Resolver::new(paths);
        Self {
            clear: core.cwd_is_clear(),
            core,
            cwd_drive: drive_of(&paths.cwd.to_string_lossy()),
            paths: None,
        }
    }

    /// Keep the directories, for what only `effect` asks: whether a path is
    /// inside a workspace folder whatever else it is, and the workspace
    /// folders themselves. `classify` does not keep them.
    pub(crate) fn keep(&mut self, paths: &Paths) {
        self.paths = Some(paths.clone());
    }

    /// The workspace folders, as spelled, when kept.
    pub(crate) fn workspaces(&self) -> Vec<String> {
        self.paths.as_ref().map_or_else(Vec::new, |paths| {
            paths
                .workspaces
                .iter()
                .map(|folder| folder.to_string_lossy().into_owned())
                .collect()
        })
    }

    /// Whether `arg` (already joined to where an earlier `cd` moved) is a path
    /// inside a workspace folder, or the folder itself, however else it is
    /// judged: a protected path or a startup file in the workspace is inside
    /// it, which the place of either does not say. Judged by the spelling
    /// alone, as the paths are (their keys, which are the same for every
    /// spelling of one file); a pattern by the folder it starts in. `false`
    /// for what cannot be read that far.
    pub(crate) fn inside_workspace(&self, arg: &Arg, shell: Shell) -> bool {
        let (Some(text), Some(paths)) = (arg.known(), self.paths.as_ref()) else {
            return false;
        };
        if brace_list(text) {
            return false;
        }
        let flavour = flavour(shell);
        let folder = pattern_folder(text);
        let spelling = match start(&folder, shell) {
            Start::Plain => Spelling::Plain(&folder),
            Start::Home(rest) => Spelling::Home(rest),
            _ => return false,
        };
        let Some(key) = self.core.key(spelling, flavour) else {
            return false;
        };
        paths.workspaces.iter().any(|workspace| {
            let text = workspace.to_string_lossy();
            self.core
                .key(Spelling::Plain(&text), flavour)
                .is_some_and(|folder| {
                    key == folder
                        || key.starts_with(&folder)
                            && (folder.ends_with('|') || key[folder.len()..].starts_with('/'))
                })
        })
    }

    /// Whether reading `arg` (joined to where an earlier `cd` moved), as a
    /// pattern the shell expands or, when `deep`, as a folder read with
    /// everything below it, can reach a secret that its place does not say.
    /// What cannot be spelled out can.
    pub(crate) fn reaches_secret(&self, arg: &Arg, shell: Shell, hidden: bool, deep: bool) -> bool {
        let Some(text) = arg.known() else {
            return true;
        };
        if brace_list(text) {
            return true;
        }
        if device(text, shell).is_some() {
            return false;
        }
        let flavour = flavour(shell);
        if shell == Shell::PowerShell {
            if let Some((qualifier, rest)) = text.split_once("::") {
                let provider = qualifier.rsplit('\\').next().unwrap_or(qualifier);
                return provider.eq_ignore_ascii_case("filesystem")
                    && self.reaches_secret(&Arg::Known(rest.to_string()), shell, hidden, deep);
            }
        }
        match start(text, shell) {
            Start::Plain => self
                .core
                .reaches_secret(Spelling::Plain(text), flavour, hidden, deep),
            Start::Home(rest) => {
                self.core
                    .reaches_secret(Spelling::Home(rest), flavour, hidden, deep)
            }
            Start::Provider(..) => false,
            Start::DriveRelative(letter, rest) => {
                self.on_cwd_drive(letter, rest).is_some_and(|rest| {
                    self.core
                        .reaches_secret(Spelling::Plain(rest), flavour, hidden, deep)
                })
            }
            Start::Unknown => true,
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

    /// The absolute path `text` (already joined to where an earlier `cd`
    /// moved) names, by its spelling: `~` and `..` applied, the working
    /// directory in front of a relative one, nothing read from the disk. `None`
    /// for what is not a place on a disk: a device, a PowerShell drive that is
    /// not a disk (`HKLM:`, `Env:`), a path on another drive's own working
    /// directory, and what cannot be spelled out (`~user`).
    pub(crate) fn absolute(&self, text: &str, shell: Shell) -> Option<PathBuf> {
        if brace_list(text) || device(text, shell).is_some() {
            return None;
        }
        let flavour = flavour(shell);
        // `FileSystem::C:\x` is the provider's own path to `C:\x`.
        if shell == Shell::PowerShell {
            if let Some((qualifier, rest)) = text.split_once("::") {
                let provider = qualifier.rsplit('\\').next().unwrap_or(qualifier);
                return provider
                    .eq_ignore_ascii_case("filesystem")
                    .then(|| self.absolute(rest, shell))
                    .flatten();
            }
        }
        match start(text, shell) {
            Start::Plain => self.core.absolute(Spelling::Plain(text), flavour),
            Start::Home(rest) => self.core.absolute(Spelling::Home(rest), flavour),
            Start::DriveRelative(letter, rest) => self
                .on_cwd_drive(letter, rest)
                .and_then(|rest| self.core.absolute(Spelling::Plain(rest), flavour)),
            Start::Provider(..) | Start::Unknown => None,
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

    /// What reading `arg`, written from `dir`, exposes when it is a key or a
    /// credential: the words for it (`your SSH keys`). A place core marks as
    /// holding one, a disk (its bytes hold every key on it) and, in a POSIX
    /// shell, what the kernel serves (`/proc/self/environ`, `/dev/mem`): the
    /// answers the file guard gives a read of the same path. `None` for
    /// anything else, a path known only when it runs included.
    pub(crate) fn secret(
        &self,
        dir: Option<&Arg>,
        arg: &Arg,
        shell: Shell,
        hidden: bool,
    ) -> Option<&'static str> {
        // Most words are a name in the workspace, which is no secret.
        if dir.is_none()
            && self.clear
            && arg.known().is_some_and(|text| plain_relative(text, shell))
        {
            return None;
        }
        let owned;
        let arg = if dir.is_some() {
            owned = within(dir, arg, shell);
            &owned
        } else {
            arg
        };
        let text = arg.known()?;
        let mut place = self.place_of(text, shell, hidden, true);
        // A Windows name the spelling does not settle (a stream, a part with
        // a trailing space) is read for the file it is a name of; PowerShell
        // takes `id_rsa::$DATA` for a provider's path, which is outside.
        if matches!(place, Place::Unknown | Place::Outside) && shell != Shell::Posix {
            if let Some(file) = without_streams(text) {
                place = self.place_of(&file, shell, hidden, true);
            }
        }
        match place {
            Place::Sensitive(words, Sensitivity::Secret) => return Some(words),
            Place::Disk => return Some("a disk, and every key on it"),
            _ => {}
        }
        self.picks(text, shell, hidden).or_else(|| {
            // What the kernel serves is not in the workspace, a temporary
            // folder or the home directory, so it is only looked for in the
            // places that are none of them (`/dev/fd/3` is the null device
            // to core, a path in another case is outside).
            if matches!(place, Place::Top(_) | Place::Outside | Place::Null) {
                self.kernel(text, shell)
            } else {
                None
            }
        })
    }

    /// The key or credential a pattern can pick (`~/.s*/id_rsa`): see
    /// [`milo_guards_core::Resolver::picks_secret`].
    fn picks(&self, text: &str, shell: Shell, hidden: bool) -> Option<&'static str> {
        if !glob::has_wildcard(text) || brace_list(text) {
            return None;
        }
        let flavour = flavour(shell);
        // `FileSystem::C:\x*` is the provider's own path.
        if shell == Shell::PowerShell {
            if let Some((qualifier, rest)) = text.split_once("::") {
                let provider = qualifier.rsplit('\\').next().unwrap_or(qualifier);
                return provider
                    .eq_ignore_ascii_case("filesystem")
                    .then(|| self.picks(rest, shell, hidden))
                    .flatten();
            }
        }
        let spelling = match start(text, shell) {
            Start::Plain => Spelling::Plain(text),
            Start::Home(rest) => Spelling::Home(rest),
            Start::DriveRelative(letter, rest) => Spelling::Plain(self.on_cwd_drive(letter, rest)?),
            Start::Provider(..) | Start::Unknown => return None,
        };
        self.core.picks_secret(spelling, flavour, hidden)
    }

    /// The words for a place that holds keys without being one: the home
    /// directory, a folder holding it, the root of the disk. Reading a
    /// folder all the way down reads what is in it.
    pub(crate) fn holder(
        &self,
        dir: Option<&Arg>,
        arg: &Arg,
        shell: Shell,
        hidden: bool,
    ) -> Option<&'static str> {
        if dir.is_none()
            && self.clear
            && arg.known().is_some_and(|text| plain_relative(text, shell))
        {
            return None;
        }
        let arg = within(dir, arg, shell);
        let text = arg.known()?;
        let holds = |place: Place| {
            matches!(
                place,
                Place::Home { .. } | Place::Top("the root of the disk")
            )
            .then(|| place.words())
        };
        if let Some(words) = holds(self.place_of(text, shell, hidden, true)) {
            return Some(words);
        }
        // A POSIX pattern part that can match `..` (`.*`) may be the parent:
        // each reading core gives is asked, as `place` asks them all.
        if shell != Shell::Posix || !glob::has_wildcard(text) || brace_list(text) {
            return None;
        }
        let spelling = match start(text, shell) {
            Start::Plain => Spelling::Plain(text),
            Start::Home(rest) => Spelling::Home(rest),
            _ => return None,
        };
        self.core
            .places(spelling, Flavour::Posix, hidden)
            .into_iter()
            .find_map(holds)
    }

    /// What the kernel serves that `text` names, in a POSIX shell: see
    /// [`milo_guards_core::Resolver::kernel`].
    fn kernel(&self, text: &str, shell: Shell) -> Option<&'static str> {
        if shell != Shell::Posix || brace_list(text) {
            return None;
        }
        let spelling = match start(text, shell) {
            Start::Plain => Spelling::Plain(text),
            Start::Home(rest) => Spelling::Home(rest),
            _ => return None,
        };
        self.core.kernel(spelling, Flavour::Posix)
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

/// Whether a path is a name or a few from the working directory and nothing
/// else: plain characters, no `..`, no `~`, no drive, no variable, no root. In
/// a workspace that holds no key it lands in the workspace.
fn plain_relative(text: &str, shell: Shell) -> bool {
    !text.is_empty()
        && !text.starts_with(['/', '\\'])
        && text.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'_' | b'-'
                        | b'.'
                        | b'/'
                        | b'\\'
                        | b' '
                        | b'+'
                        | b','
                        | b'*'
                        | b'?'
                        | b'['
                        | b']'
                )
        })
        && text.split(['/', '\\']).all(|part| part != "..")
        // A POSIX pattern part that can match `..` (`.*`, `.?`) climbs in an
        // old shell.
        && (shell != Shell::Posix
            || text.split('/').all(|part| {
                !(part.starts_with('.')
                    && glob::has_wildcard(part)
                    && glob::matches(part, "..", Flavour::Posix, false))
            }))
}

/// A Windows path with what makes its name unreadable taken off each part: a
/// stream (`id_rsa::$DATA`, `id_rsa:x`, `.ssh::$INDEX_ALLOCATION`), and the
/// dots and spaces Windows drops from the end of a name. A drive's own colon
/// stays. `None` when nothing is taken off.
fn without_streams(text: &str) -> Option<String> {
    let mut changed = false;
    let parts: Vec<&str> = text
        .split(['/', '\\'])
        .map(|part| {
            let drive = part.len() == 2 && part.ends_with(':');
            let name = if drive {
                part
            } else {
                part.split(':').next().unwrap_or(part)
            };
            let name = if matches!(name, "." | "..") {
                name
            } else {
                name.trim_end_matches([' ', '.'])
            };
            changed |= name.len() != part.len();
            name
        })
        .collect();
    // The separators are put back as `\`, which Windows reads as it reads `/`.
    changed.then(|| parts.join("\\"))
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
            && (text.contains("::")
                || qualifier(text, shell).is_some_and(|(name, _)| name.len() > 1)));
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

/// The parent folder a wildcard part can also pick, written as a path to
/// read: a part that starts with a dot and matches `..` (`.*`, `.?`) is
/// `..` in the shells whose patterns match it, so `cat .*/x` can read the
/// folder above. `None` when no part can.
pub(crate) fn climb(text: &str, shell: Shell) -> Option<String> {
    let flavour = flavour(shell);
    let mut start = 0;
    for part in text.split(flavour.separators()) {
        if part.starts_with('.')
            && glob::has_wildcard(part)
            && glob::matches(part, "..", flavour, true)
        {
            return Some(format!("{}..", &text[..start]));
        }
        start += part.len() + 1;
    }
    None
}

/// The folder a pattern starts in: what comes before its first wildcard,
/// up to the last separator before it (`.` when nothing does), or the text
/// itself when it holds none.
pub(crate) fn pattern_folder(text: &str) -> String {
    let Some(wild) = text.find(['*', '?', '[']) else {
        return text.to_string();
    };
    match text[..wild].rfind(['/', '\\']) {
        Some(0) => text[..1].to_string(),
        Some(at) => text[..at].to_string(),
        None => ".".to_string(),
    }
}
