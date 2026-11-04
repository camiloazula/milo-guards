//! Where a path argument resolves, by its spelling alone, for a line run by
//! a given shell.
//!
//! The path model itself is [`milo_guards_core::Resolver`], which takes a
//! path spelled out as text. What is left here is what only a shell's
//! syntax gives a path a meaning for: `~` and `~user`, PowerShell's
//! provider paths (`HKLM:\Software`, `FileSystem::C:\x`), PowerShell's
//! `$null`, brace lists, and a `cd` that moved the line.

use std::collections::HashMap;
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
    /// PowerShell's `Temp:` drive, the user's temporary folder (a drive of
    /// the file system since PowerShell 7.4), and the path on it.
    Temp(&'a str),
    /// A path on a disk's drive with no separator after the colon (`C:x`,
    /// `C:*`): from that drive's own working directory. The drive letter,
    /// and the path after it.
    DriveRelative(char, &'a str),
    /// Another user's home (`~user`): the spelling does not say.
    Unknown,
}

/// What is done with a `..` when a path is made absolute.
#[derive(Clone, Copy)]
enum Dots {
    /// Applied by spelling, as the guard judges a path.
    Applied,
    /// Left where it was written, for a caller that looks at the disk.
    Kept,
}

/// The `name:` a path starts with, and what follows it: a disk's drive
/// letter (`C:`), or in PowerShell any drive (`HKLM:`, `Env:`, a drive made
/// with `New-PSDrive`: `my_drive:`, `my-drive:`). A PowerShell drive's name
/// may hold any character but `: / \ . ~` and a wildcard. Read before
/// anything else, since a wildcard after it (`HKCU:*`) does not change what
/// it names (`x.txt:stream` is a file's stream, not a drive).
fn qualifier(text: &str, shell: Shell) -> Option<(&str, &str)> {
    if shell == Shell::Posix {
        return None;
    }
    let (name, rest) = text.split_once(':')?;
    let named = if shell == Shell::PowerShell {
        !name.is_empty()
            && !name.contains(['/', '\\', '.', '~'])
            && !name.contains(flavour(shell).separators())
            && !glob::has_wildcard(name)
    } else {
        is_letter(name)
    };
    named.then_some((name, rest))
}

/// Whether `name` is one ASCII letter: a disk's drive letter.
fn is_letter(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic()) && chars.next().is_none()
}

/// Read what `text` starts from. The drive is read first; then a first part
/// holding a wildcard is a pattern, not a `~`, so it is left as written.
fn start(text: &str, shell: Shell) -> Start<'_> {
    let separators = flavour(shell).separators();
    if let Some((name, rest)) = qualifier(text, shell) {
        if name.eq_ignore_ascii_case("temp") {
            return Start::Temp(rest);
        }
        if !is_letter(name) {
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

/// A path on PowerShell's `Temp:` drive as the part of it below the home
/// directory: the drive is the user's temporary folder, as `$env:TEMP` is.
fn in_temp(rest: &str) -> String {
    format!("\\AppData\\Local\\Temp\\{rest}")
}

/// What a PowerShell provider's own name (`Environment`,
/// `Microsoft.PowerShell.Core\Variable`) or a drive of it (`env`,
/// `variable`, lower case) holds when it is the session's own: its
/// environment or its variables, the words for which.
fn session(name: &str) -> Option<Place> {
    match name {
        "env" | "environment" => Some(Place::Session("the session's environment")),
        "variable" => Some(Place::Session("a session variable")),
        _ => None,
    }
}

/// A drive the line makes with `New-PSDrive`: its name, lower case, when it
/// is written out, and whether its provider is the registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Made {
    /// The drive's name; `None` when it is only known when it runs.
    pub(crate) name: Option<String>,
    /// Whether the provider is the registry, written out.
    pub(crate) registry: bool,
}

/// The drive letter a working directory is on (`C` for `C:\Users\me`).
pub(crate) fn drive_of(dir: &str) -> Option<char> {
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
    /// The drives the line makes with `New-PSDrive`, by name (lower case),
    /// each with whether every drive of that name is a registry one.
    made: HashMap<String, bool>,
    /// Whether the line makes a drive whose name is only known when it runs.
    made_unknown: bool,
}

impl Resolver {
    pub(crate) fn new(paths: &Paths) -> Self {
        let core = milo_guards_core::Resolver::new(paths);
        Self {
            clear: core.cwd_is_clear(),
            core,
            cwd_drive: drive_of(&paths.cwd.to_string_lossy()),
            paths: None,
            made: HashMap::new(),
            made_unknown: false,
        }
    }

    /// Read every path on a drive the line makes with `New-PSDrive` as
    /// that drive's provider (see [`Resolver::made_drive`]).
    pub(crate) fn made(&mut self, made: &[Made]) {
        for drive in made {
            match &drive.name {
                Some(name) => {
                    let registry = self.made.entry(name.clone()).or_insert(true);
                    *registry &= drive.registry;
                }
                None => self.made_unknown = true,
            }
        }
    }

    /// Where a PowerShell path on a drive the line makes lands: the
    /// registry for a registry drive, and only known when it runs for any
    /// other (a file system drive's root is not followed). Once the line
    /// makes a drive whose name is only known when it runs, every path on a
    /// drive is only known then, a disk's included. `None` for a path on no
    /// such drive.
    fn made_drive(&self, text: &str, shell: Shell) -> Option<Place> {
        if shell != Shell::PowerShell || (self.made.is_empty() && !self.made_unknown) {
            return None;
        }
        let (name, _) = qualifier(text, shell)?;
        if self.made_unknown {
            return Some(Place::Unknown);
        }
        self.made.get(&name.to_ascii_lowercase()).map(|&registry| {
            if registry {
                Place::Registry
            } else {
                Place::Unknown
            }
        })
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
        if self.made_drive(text, shell).is_some() {
            return false;
        }
        let flavour = flavour(shell);
        let folder = pattern_folder(text);
        let temp;
        let spelling = match start(&folder, shell) {
            Start::Plain => Spelling::Plain(&folder),
            Start::Home(rest) => Spelling::Home(rest),
            Start::Temp(rest) => {
                temp = in_temp(rest);
                Spelling::Home(&temp)
            }
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
        if let Some(place) = self.made_drive(text, shell) {
            return place == Place::Unknown;
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
            Start::Temp(rest) => {
                self.core
                    .reaches_secret(Spelling::Home(&in_temp(rest)), flavour, hidden, deep)
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
        // A device is the same in any folder: read it before the join.
        if is_device(arg, shell) {
            return None;
        }
        let arg = within(dir, arg, shell);
        let text = arg.known()?;
        if brace_list(text)
            || device(text, shell).is_some()
            || glob::has_wildcard(text)
            || self.made_drive(text, shell).is_some()
        {
            return None;
        }
        let flavour = flavour(shell);
        match start(text, shell) {
            Start::Plain => self.core.key(Spelling::Plain(text), flavour),
            Start::Home(rest) => self.core.key(Spelling::Home(rest), flavour),
            Start::Temp(rest) => self.core.key(Spelling::Home(&in_temp(rest)), flavour),
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
        self.resolved(text, shell, Dots::Applied)
    }

    /// The absolute path the system opens for `text`: as [`absolute`](Self::absolute),
    /// but every `..` stays where it was written, since the system applies it
    /// after the link before it (core's `Resolver::opened`).
    pub(crate) fn opened(&self, text: &str, shell: Shell) -> Option<PathBuf> {
        self.resolved(text, shell, Dots::Kept)
    }

    fn resolved(&self, text: &str, shell: Shell, dots: Dots) -> Option<PathBuf> {
        if brace_list(text)
            || device(text, shell).is_some()
            || self.made_drive(text, shell).is_some()
        {
            return None;
        }
        let flavour = flavour(shell);
        let make = |spelling| match dots {
            Dots::Applied => self.core.absolute(spelling, flavour),
            Dots::Kept => self.core.opened(spelling, flavour),
        };
        // `FileSystem::C:\x` is the provider's own path to `C:\x`.
        if shell == Shell::PowerShell {
            if let Some((qualifier, rest)) = text.split_once("::") {
                let provider = qualifier.rsplit('\\').next().unwrap_or(qualifier);
                return provider
                    .eq_ignore_ascii_case("filesystem")
                    .then(|| self.resolved(rest, shell, dots))
                    .flatten();
            }
        }
        match start(text, shell) {
            Start::Plain => make(Spelling::Plain(text)),
            Start::Home(rest) => make(Spelling::Home(rest)),
            Start::Temp(rest) => make(Spelling::Home(&in_temp(rest))),
            // cmd's working directory for that drive is not shown.
            Start::DriveRelative(..) if shell == Shell::Cmd => None,
            Start::DriveRelative(letter, rest) => self
                .on_cwd_drive(letter, rest)
                .and_then(|rest| make(Spelling::Plain(rest))),
            Start::Provider(..) | Start::Unknown => None,
        }
    }

    /// Whether `arg`, written from `dir`, is a file that cannot be placed:
    /// not a device, and unknown by itself or by where `dir` moved to.
    pub(crate) fn unplaced(&self, dir: Option<&Arg>, arg: &Arg, shell: Shell) -> bool {
        if is_device(arg, shell) {
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
        // From a folder only known when it runs, a name may be one in the
        // home directory, which that folder may be.
        if let Some(home) = in_unknown_folder(dir, arg, shell) {
            if let Some(words) = self.secret(None, &home, shell, hidden) {
                return Some(words);
            }
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
        if self.made_drive(text, shell).is_some() {
            return None;
        }
        let temp;
        let spelling = match start(text, shell) {
            Start::Plain => Spelling::Plain(text),
            Start::Home(rest) => Spelling::Home(rest),
            Start::Temp(rest) => {
                temp = in_temp(rest);
                Spelling::Home(&temp)
            }
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

    /// Where `arg` lands when `shell` runs it from `dir`, where an earlier
    /// `cd` moved; `hidden` says a wildcard in it may match a leading dot
    /// (`dotglob`). A device is the same in any folder, so it is read as
    /// written, before `arg` is joined to `dir`; in PowerShell only where
    /// that holds (see [`Access`]).
    pub(crate) fn place(
        &self,
        dir: Option<&Arg>,
        arg: &Arg,
        shell: Shell,
        hidden: bool,
        access: Access,
    ) -> Place {
        self.locate(dir, arg, shell, hidden, access, true)
    }

    /// As [`place`](Self::place), for a path something is written into: a
    /// folder that only holds a protected path is not a write of it.
    pub(crate) fn place_into(
        &self,
        dir: Option<&Arg>,
        arg: &Arg,
        shell: Shell,
        hidden: bool,
        access: Access,
    ) -> Place {
        self.locate(dir, arg, shell, hidden, access, false)
    }

    /// Where `arg` lands, a path already joined to where the line runs: a
    /// bare device name is read as written, as it is with no `cd` before it.
    pub(crate) fn place_joined(&self, arg: &Arg, shell: Shell, hidden: bool) -> Place {
        self.locate(None, arg, shell, hidden, Access::Item, true)
    }

    /// Where `arg` lands, as a path it holds (`holding`) or is written into.
    fn locate(
        &self,
        dir: Option<&Arg>,
        arg: &Arg,
        shell: Shell,
        hidden: bool,
        access: Access,
        holding: bool,
    ) -> Place {
        if matches!(arg, Arg::Null) {
            return Place::Null;
        }
        // On a drive the line makes, a device name is an item's name there.
        let made = dir
            .and_then(Arg::known)
            .is_some_and(|dir| self.made_drive(dir, shell).is_some());
        if let Some(device) = arg
            .known()
            .filter(|_| !made && device_in_any_folder(dir, shell, access))
            .and_then(|text| device(text, shell))
        {
            return device;
        }
        let arg = &within(dir, arg, shell);
        match arg.known() {
            Some(text) => self.place_of(text, shell, hidden, holding),
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
        if brace_list(text)
            || device(text, shell).is_some()
            || self.made_drive(text, shell).is_some()
        {
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
            Start::Temp(rest) => ask(Spelling::Home(&in_temp(rest))),
            Start::DriveRelative(letter, rest) => {
                ask(Spelling::Plain(self.on_cwd_drive(letter, rest)?))
            }
            Start::Provider(..) | Start::Unknown => None,
        }
    }

    /// The caller's words for a protected path that a program which picks
    /// the files it changes in the folder `arg` itself (a search, a patch,
    /// an archive, a recursive copy) can reach there, run from `dir`: one
    /// the folder is, is under or holds, whatever else the folder is (see
    /// `Resolver::holds_protected`). `None` for a folder only known when it
    /// runs and for one the shell reads another way (a brace list, a device,
    /// a registry or other provider path), whose own place says what it is.
    pub(crate) fn holds_protected(
        &self,
        dir: Option<&Arg>,
        arg: &Arg,
        shell: Shell,
        hidden: bool,
    ) -> Option<&'static str> {
        self.holds_protected_of(within(dir, arg, shell).known()?, shell, hidden)
    }

    /// The words of a protected path a program that changes files in a folder
    /// only known when it runs can reach (see `Resolver::any_protected`).
    pub(crate) fn any_protected(&self) -> Option<&'static str> {
        self.core.any_protected()
    }

    /// The workspace folder that holds `arg`, run from `dir`, or is it: the
    /// top of the work tree git works at from there (see
    /// `Resolver::workspace_of`). `None` when it is in none, or is only
    /// known when it runs.
    pub(crate) fn workspace_of(&self, dir: Option<&Arg>, arg: &Arg, shell: Shell) -> Option<Arg> {
        let absolute = self.absolute(within(dir, arg, shell).known()?, shell)?;
        let text = absolute.to_string_lossy();
        let top = self
            .core
            .workspace_of(Spelling::Plain(&text), flavour(shell))?;
        Some(Arg::Known(top.to_string_lossy().into_owned()))
    }

    fn holds_protected_of(&self, text: &str, shell: Shell, hidden: bool) -> Option<&'static str> {
        if brace_list(text)
            || device(text, shell).is_some()
            || self.made_drive(text, shell).is_some()
        {
            return None;
        }
        if shell == Shell::PowerShell {
            if let Some((qualifier, rest)) = text.split_once("::") {
                let provider = qualifier.rsplit('\\').next().unwrap_or(qualifier);
                return provider
                    .eq_ignore_ascii_case("filesystem")
                    .then(|| self.holds_protected_of(rest, shell, hidden))
                    .flatten();
            }
        }
        let flavour = flavour(shell);
        let ask = |spelling| self.core.holds_protected(spelling, flavour, hidden);
        match start(text, shell) {
            Start::Plain => ask(Spelling::Plain(text)),
            Start::Home(rest) => ask(Spelling::Home(rest)),
            Start::Temp(rest) => ask(Spelling::Home(&in_temp(rest))),
            Start::DriveRelative(letter, rest) => {
                ask(Spelling::Plain(self.on_cwd_drive(letter, rest)?))
            }
            Start::Provider(..) | Start::Unknown => None,
        }
    }

    fn place_of(&self, text: &str, shell: Shell, hidden: bool, holding: bool) -> Place {
        // A folder a search or a listing hands on whole is the folder, and
        // everything it holds, a protected path among them.
        if let Some(folder) = marked_folder(text, WHOLE) {
            return match self.place_spelled(folder, shell, hidden, holding) {
                place
                    if place.harmless()
                        || matches!(
                            place,
                            Place::Workspace { exact: true } | Place::Temp { exact: true }
                        ) =>
                {
                    self.holds_protected_of(folder, shell, hidden)
                        .map_or(place, Place::Protected)
                }
                place => place,
            };
        }
        let place = self.place_spelled(text, shell, hidden, holding);
        // What a search or a filtered listing finds in a folder may be any
        // entry below it, a protected one among them.
        match marked_folder(text, FOUND) {
            Some(folder) if place.harmless() => self
                .holds_protected_of(folder, shell, hidden)
                .map_or(place, Place::Protected),
            _ => place,
        }
    }

    fn place_spelled(&self, text: &str, shell: Shell, hidden: bool, holding: bool) -> Place {
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
        if let Some(place) = self.made_drive(text, shell) {
            return place;
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
                    other => session(other).unwrap_or(Place::Outside),
                };
            }
        }
        let flavour = flavour(shell);
        match start(text, shell) {
            Start::Plain => place_core(Spelling::Plain(text), flavour),
            Start::Home(rest) => place_core(Spelling::Home(rest), flavour),
            Start::Temp(rest) => place_core(Spelling::Home(&in_temp(rest)), flavour),
            Start::Provider(name, _) if REGISTRY.contains(&name.as_str()) => Place::Registry,
            // `Env:` and `Variable:` are the session's own; `Alias:` and
            // `Function:` change what a later command runs, and any other
            // provider's items are beyond the workspace.
            Start::Provider(name, _) => session(&name).unwrap_or(Place::Outside),
            // cmd keeps a working directory for every drive and the line
            // never shows where each is, so `C:x` is a place only known when
            // it runs, whichever drive the line is on. Read from the line's
            // own folder it may land somewhere that matters (`C:..\..\.ssh`):
            // then that is what it is judged as.
            Start::DriveRelative(letter, rest) if shell == Shell::Cmd => self
                .on_cwd_drive(letter, rest)
                .map(|rest| place_core(Spelling::Plain(rest), flavour))
                .filter(|place| !place.harmless())
                .unwrap_or(Place::Unknown),
            Start::DriveRelative(letter, rest) => match self.on_cwd_drive(letter, rest) {
                Some(rest) => place_core(Spelling::Plain(rest), flavour),
                None => Place::Outside,
            },
            Start::Unknown => Place::Unknown,
        }
    }
}

/// `arg`, a plain relative name (see [`plain_relative`]) written from
/// `dir`, a folder only known when it runs, as that name in the home
/// directory, which the folder may be: after a `cd` the guard cannot follow
/// (`cd "$x"`, or more folders than it keeps), `.ssh/id_rsa` may be
/// `~/.ssh/id_rsa`. `None` when `dir` is known or where the line began, or
/// `arg` is not such a name; and in cmd, which has no `~`.
pub(crate) fn in_unknown_folder(dir: Option<&Arg>, arg: &Arg, shell: Shell) -> Option<Arg> {
    if shell == Shell::Cmd || dir?.known().is_some() {
        return None;
    }
    let text = arg.known().filter(|text| plain_relative(text, shell))?;
    let sep = if shell == Shell::Posix { '/' } else { '\\' };
    Some(Arg::Known(format!("~{sep}{text}")))
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

/// What a command does with a path it names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Access {
    /// Writes a file by its file system path: a redirect, `Out-File`,
    /// `Tee-Object -FilePath`, `Invoke-WebRequest -OutFile`. These fail in a
    /// PowerShell provider that is not the file system, so a device name
    /// there is never a harmful one.
    Content,
    /// Reaches the item itself, in whatever provider the folder is: deletes,
    /// moves, changes permissions or properties of, or creates it, and
    /// `Set-Content`, `Add-Content`, `Clear-Content` and a copy or move's
    /// destination, which the `Env:`, `Variable:`, `Function:` and `Alias:`
    /// providers (content) and the registry (a key) take. In a provider other
    /// than the file system `NUL` and `CON` are ordinary item names there, so
    /// a device is read only where the folder is the file system.
    Item,
}

/// Whether a device spelling written from `dir` is a device wherever `dir`
/// is: in cmd and POSIX a `cd` is always to the file system. In PowerShell a bare
/// `NUL` or `CON` is the device for a content write (which fails elsewhere)
/// or after a `cd` to the file system; after a `cd` to the registry, `Env:`,
/// or a place only known when it runs, it is an item's name, so it joins to
/// where the `cd` went. PowerShell's `$null` is not a spelling at all (see
/// [`Arg::Null`]).
fn device_in_any_folder(dir: Option<&Arg>, shell: Shell, access: Access) -> bool {
    if shell != Shell::PowerShell || access == Access::Content {
        return true;
    }
    match dir {
        None => true,
        Some(Arg::Known(dir)) => on_file_system(dir),
        Some(_) => false,
    }
}

/// Whether a PowerShell location is on the file system: a path with no
/// provider, or one the file system provider names.
fn on_file_system(dir: &str) -> bool {
    if let Some((qualifier, _)) = dir.split_once("::") {
        let provider = qualifier.rsplit('\\').next().unwrap_or(qualifier);
        return provider.eq_ignore_ascii_case("filesystem");
    }
    !matches!(
        start(dir, Shell::PowerShell),
        Start::Provider(..) | Start::Unknown
    )
}

/// Whether `arg` is a device wherever it is written from: PowerShell's
/// `$null` value, or a spelling [`device`] reads. In a POSIX shell `$null` is
/// the variable `null`, only known when it runs; in cmd, and quoted in
/// PowerShell (`'$null'`), it is a file name.
fn is_device(arg: &Arg, shell: Shell) -> bool {
    matches!(arg, Arg::Null)
        || arg
            .known()
            .is_some_and(|text| device(text, shell).is_some())
}

/// Whether `text` names a device that holds nothing to read: the null
/// device, or in Windows the console (`NUL`, `/dev/null`, `CON`).
pub(crate) fn null_device(text: &str, shell: Shell) -> bool {
    device(text, shell) == Some(Place::Null)
}

/// A device a path names, by its spelling: the core's.
fn device(text: &str, shell: Shell) -> Option<Place> {
    milo_guards_core::spelling::device(text, flavour(shell))
}

/// Whether `text` holds a brace list: a `{` with a `,` before a later `}`.
pub(crate) fn brace_list(text: &str) -> bool {
    match (text.find('{'), text.rfind('}')) {
        (Some(open), Some(close)) if open < close => text[open..close].contains(','),
        _ => false,
    }
}

/// Whether `text` holds a brace expansion bash and zsh spell out into words:
/// a brace list, or a sequence expression (`{1..3}`, `{a..c}`, `{1..9..2}`).
pub(crate) fn brace_expansion(text: &str) -> bool {
    brace_list(text)
        || text.match_indices('{').any(|(open, _)| {
            text.get(open + 1..)
                .and_then(|rest| rest.split_once('}'))
                .is_some_and(|(inner, _)| sequence(inner))
        })
}

/// Whether `inner`, the text between a `{` and its `}`, is a sequence
/// expression: two integers or two single characters, and an integer step.
fn sequence(inner: &str) -> bool {
    let number = |part: &str| {
        let digits = part.strip_prefix(['-', '+']).unwrap_or(part);
        !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
    };
    let single = |part: &str| part.chars().count() == 1;
    let parts: Vec<&str> = inner.split("..").collect();
    let (from, to, step) = match parts.as_slice() {
        [from, to] => (*from, *to, None),
        [from, to, step] => (*from, *to, Some(*step)),
        _ => return false,
    };
    step.is_none_or(number) && ((number(from) && number(to)) || (single(from) && single(to)))
}

/// `path` as seen from `dir`, where an earlier `cd` moved: a relative path
/// is joined to it, and is unknown when where it moved is.
pub(crate) fn within(dir: Option<&Arg>, path: &Arg, shell: Shell) -> Arg {
    let (Some(dir), Arg::Known(text)) = (dir, path) else {
        return path.clone();
    };
    // In PowerShell a rooted path with no drive (`\x`, `/x`) is the root of
    // the drive or share the folder before it is on, which after a `cd` to
    // another provider is that provider's, not the file system's.
    if shell == Shell::PowerShell && rooted(text) {
        return match root_of(dir) {
            Root::Plain => path.clone(),
            Root::Drive(drive) | Root::Share(drive) => Arg::Known(format!("{drive}{text}")),
            Root::Unknown => Arg::Unknown(text.clone()),
        };
    }
    // A relative path the file system provider names (`FileSystem::x`,
    // `Microsoft.PowerShell.Core\FileSystem::x`) is from the folder the line
    // is in, as a plain one is; after a `cd` to another provider, or to a
    // place only known when it runs, where it lands is only known then.
    if shell == Shell::PowerShell {
        if let Some((qualifier, rest)) = text.split_once("::") {
            let provider = qualifier.rsplit('\\').next().unwrap_or(qualifier);
            if provider.eq_ignore_ascii_case("filesystem") && !rest.is_empty() {
                let inner = Arg::Known(rest.to_string());
                let joined = within(Some(dir), &inner, shell);
                return if joined == inner {
                    path.clone()
                } else if file_system_folder(dir) {
                    joined
                } else {
                    Arg::Unknown(text.clone())
                };
            }
        }
    }
    // `~` is the home of the provider the folder is in, and only the file
    // system has one: elsewhere the `cd ~` fails and stays where it was, so
    // the place is only known when it runs.
    if shell == Shell::PowerShell && home(text) && !file_system_folder(dir) {
        return Arg::Unknown(text.clone());
    }
    let drive =
        text.chars().next().is_some_and(|c| c.is_ascii_alphabetic()) && text[1..].starts_with(':');
    let absolute = text.starts_with(['/', '~'])
        || (shell != Shell::Posix && text.starts_with('\\'))
        || (shell != Shell::Posix && drive)
        || (shell == Shell::PowerShell
            && (text.contains("::") || qualifier(text, shell).is_some()));
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

/// Whether `text` is `~` or a path below it (`~\x`, `~/x`).
fn home(text: &str) -> bool {
    text.strip_prefix('~')
        .is_some_and(|rest| rest.is_empty() || rest.starts_with(['\\', '/']))
}

/// Whether the PowerShell folder `dir` is on the file system: a disk, or no
/// drive at all. A provider drive, a provider path, and a place only known
/// when it runs are not.
fn file_system_folder(dir: &Arg) -> bool {
    match root_of(dir) {
        Root::Plain | Root::Share(_) => true,
        Root::Drive(drive) => {
            let name = drive.trim_end_matches(':');
            is_letter(name) || name.eq_ignore_ascii_case("temp")
        }
        Root::Unknown => false,
    }
}

/// Whether `text` is a path rooted at the current drive, with no drive of its
/// own: `\x` or `/x`, but not a UNC path (`\\server\share`).
fn rooted(text: &str) -> bool {
    text.starts_with(['\\', '/']) && !text[1..].starts_with(['\\', '/'])
}

/// The drive a PowerShell folder is on, as its root is read.
enum Root {
    /// The file system's current drive: no earlier folder, or one that names
    /// no drive.
    Plain,
    /// A drive of its own: `HKCU:`, `Function:`, `C:`.
    Drive(String),
    /// A share of the file system, as its folder spells it:
    /// `\\server\share`, `\\?\UNC\server\share`.
    Share(String),
    /// Only known when it runs, or a provider path with no drive.
    Unknown,
}

/// The drive the folder `dir` is on.
fn root_of(dir: &Arg) -> Root {
    match dir {
        Arg::Known(dir) => root_of_text(dir),
        _ => Root::Unknown,
    }
}

fn root_of_text(dir: &str) -> Root {
    // `FileSystem::C:\x` is the file system's own path, and any other
    // provider's `Provider::path` has no drive to take the root of.
    if let Some((qualifier, rest)) = dir.split_once("::") {
        let provider = qualifier.rsplit('\\').next().unwrap_or(qualifier);
        return if provider.eq_ignore_ascii_case("filesystem") {
            root_of_text(rest)
        } else {
            Root::Unknown
        };
    }
    if let Some(root) = share_root(dir) {
        return root;
    }
    match qualifier(dir, Shell::PowerShell) {
        Some((name, _)) => Root::Drive(format!("{name}:")),
        None => Root::Plain,
    }
}

/// The root of a folder spelled from two separators: a share
/// (`\\server\share\x`, `\\?\UNC\server\share\x`) is its own root, a long
/// path to a drive (`\\?\C:\x`) that drive's, and anything else (a device,
/// a share with no name) has no root the guard can read. `None` for a folder
/// that does not start so.
fn share_root(dir: &str) -> Option<Root> {
    let separator = |c: char| matches!(c, '\\' | '/');
    let mut chars = dir.chars();
    if !(chars.next().is_some_and(separator) && chars.next().is_some_and(separator)) {
        return None;
    }
    let names: Vec<&str> = chars.as_str().split(separator).collect();
    // The first `count` names, each a plain name, as one root.
    let root = |count: usize| {
        let first = names.get(..count)?;
        first
            .iter()
            .all(|name| !matches!(*name, "" | "." | ".."))
            .then(|| format!("\\\\{}", first.join("\\")))
    };
    let share = match names.first().copied() {
        Some("?") => {
            let rest = milo_guards_core::spelling::verbatim(dir).unwrap_or_default();
            if let Some((letter, tail)) = rest.split_once(':') {
                if is_letter(letter) && (tail.is_empty() || tail.starts_with(separator)) {
                    return Some(Root::Drive(format!("{letter}:")));
                }
            }
            names
                .get(1)
                .filter(|kind| kind.eq_ignore_ascii_case("unc"))
                .and_then(|_| root(4))
        }
        Some(".") => None,
        _ => root(2),
    };
    Some(share.map_or(Root::Unknown, Root::Share))
}

/// What a listing of `text` hands on, as paths the resolver reads: a
/// pattern is handed on as written, so the resolver judges it as it would
/// judge a delete of it (`..` applied, then what it can match), and with
/// `recurses` also as what it finds at any depth below the folder it starts
/// in, since its last part then matches in every folder below
/// (`Get-ChildItem *.yaml -Recurse`); a filtered listing hands files inside
/// its folder; a folder listed whole (`.`, `~`) hands everything in it,
/// which is the folder itself and what it holds (see [`WHOLE`]), unless it
/// is an item handed on as itself (`Get-Item`, not `whole`).
pub(crate) fn listed(text: &str, filtered: bool, recurses: bool, whole: bool) -> Vec<String> {
    match (glob::has_wildcard(text), filtered) {
        (true, _) if recurses => vec![text.to_string(), found_below(text)],
        (false, true) => vec![found_in(text)],
        (false, false) if whole => vec![whole_of(text)],
        _ => vec![text.to_string()],
    }
}

/// The name an entry stands as that a search or a filtered listing finds
/// inside a folder (`find . -name '*.yaml'`, `Get-ChildItem -Filter`): which
/// one, the line does not show, so it may be any entry at any depth below
/// the folder. A name that is not a wildcard, a device or anything else a
/// path is read as, so the entry is judged as a plain file in the folder,
/// and then as what the folder holds. A path a line spells with it is read
/// the same way (`rm ./…`), which costs only a finding where the folder
/// holds a protected path.
pub(crate) const FOUND: &str = "\u{2026}";

/// The name that stands for a folder a search or a listing hands on whole
/// (`find . -type f`, `ls`, `Get-ChildItem -Recurse`): the folder itself,
/// judged as it is (a delete of it says so), and every entry below it,
/// which may be a protected path the folder holds. Read as [`FOUND`] is.
pub(crate) const WHOLE: &str = "\u{22ef}";

/// What a pattern whose last part matches in every folder below the one it
/// starts in finds (`Get-ChildItem *.yaml -Recurse`, `del /s *.yaml`): an
/// entry at any depth below that folder (see [`FOUND`]).
pub(crate) fn found_below(pattern: &str) -> String {
    let mut folder = pattern_folder(pattern);
    // A drive's root is its folder with the separator (`C:\*`).
    if folder.ends_with(':') {
        folder.push('\\');
    }
    found_in(&folder)
}

/// An entry a search finds inside `folder` (see [`FOUND`]).
pub(crate) fn found_in(folder: &str) -> String {
    format!("{folder}/{FOUND}")
}

/// `folder` handed on whole (see [`WHOLE`]).
pub(crate) fn whole_of(folder: &str) -> String {
    format!("{folder}/{WHOLE}")
}

/// The folder `text` stands for when it is exactly a folder handed on whole
/// (see [`WHOLE`]), not a path made from one: what a delete of it deletes.
pub(crate) fn whole_folder(text: &str) -> Option<&str> {
    let folder = text.strip_suffix(WHOLE)?.strip_suffix(['/', '\\'])?;
    Some(if folder.is_empty() { "/" } else { folder })
}

/// The folder a search or a listing found the entry `text` in, when `text`
/// is one, marked with `marker`, or is made from one (`-exec cp {} {}.bak`):
/// what comes before the first `marker` part.
fn marked_folder<'a>(text: &'a str, marker: &str) -> Option<&'a str> {
    let at = text.find(marker)?;
    let folder = text[..at].strip_suffix(['/', '\\'])?;
    Some(if folder.is_empty() { "/" } else { folder })
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
