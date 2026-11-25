//! The directories a guard judges paths against.

use std::path::PathBuf;

/// The directories a path is judged against.
///
/// Build one with [`Paths::new`], add what the caller gates with through
/// [`Paths::with_protected`], and the files it knows hold secrets through
/// [`Paths::with_secrets`]. How this machine spells another system's drives
/// the caller says too ([`Paths::with_drive_mounts`], and on WSL
/// [`Paths::with_windows_home`]). The struct is `#[non_exhaustive]`, so a
/// field added later does not break a caller; the fields stay public to read
/// and to set.
///
/// Paths are judged by their spelling alone, so these must be spelled the
/// way the paths being judged will resolve: absolute, and either all
/// canonical or all as the user wrote them. A relative `cwd` puts every
/// relative path outside the workspace, and so does a `cwd` read through a
/// symlink (`/private/tmp/…`) when the workspace is spelled without it
/// (`/tmp/…`). With no workspace at all, every path is outside.
///
/// ```
/// use milo_guards_core::Paths;
///
/// let paths = Paths::new("/home/me/work/repo", "/home/me", ["/home/me/work/repo"]);
/// assert_eq!(paths.home.to_str(), Some("/home/me"));
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Paths {
    /// Where the work happens: relative paths resolve from here.
    pub cwd: PathBuf,
    /// The user's home directory.
    pub home: PathBuf,
    /// The workspace folders: what is inside them is the agent's to change.
    pub workspaces: Vec<PathBuf>,
    /// What the caller treats as its own, such as its settings: touching any
    /// of it is a finding, even inside a workspace folder.
    pub protected: Vec<Protected>,
    /// What the caller knows holds a secret on this machine, such as a
    /// project's `.env`: reading any of it is a finding, even inside a
    /// workspace folder, as reading a key core knows of is. See [`Secret`]
    /// for what is not.
    pub secrets: Vec<Secret>,
    /// The folders this machine's POSIX paths show each Windows drive in, as
    /// a folder named for its letter: `/mnt` on WSL (`/mnt/c` is `C:\`, or
    /// the `root` WSL's `automount` setting names), `/` in Git Bash and MSYS2
    /// (`/c`), `/cygdrive` in Cygwin. A POSIX path through one is also placed
    /// where the drive's path lands. Each is an absolute POSIX path (from
    /// `/`; its empty and `.` parts are dropped, so `//mnt/./` is `/mnt`):
    /// any other spelling (empty, relative, from `~`, a Windows path) names
    /// no mount, as a [`Secret`] that names nothing is none. Empty from
    /// [`Paths::new`]: add to it with [`Paths::with_drive_mounts`].
    pub drive_mounts: Vec<PathBuf>,
    /// The user's Windows home directory, on a machine whose `home` is not
    /// one (WSL): its keys and credentials are judged as a Windows home's
    /// are, and the folder itself as a home directory. Spelled as Windows
    /// spells it, from a drive (`C:\Users\me`), or through a drive mount
    /// the caller names (`/mnt/c/Users/me`); any other spelling (a relative
    /// one, `Users\me`, or `/mnt/c/Users/me` with no mount named) names no
    /// Windows home. `None` from [`Paths::new`]: set it with
    /// [`Paths::with_windows_home`].
    pub windows_home: Option<PathBuf>,
}

/// A file or folder the caller gates with, and what a reason calls it.
///
/// The path is spelled the way the workspace folders are (absolute, and
/// canonical or as the user wrote it, like the rest of [`Paths`]). It covers
/// the path itself and everything under it, and wins over a workspace folder
/// it sits in. The resolver answers `Place::Protected` with the caller's
/// words for it.
///
/// The caller says whether it protects a file or a folder, which costs the
/// guard no I/O and lets a pattern be read the right way: only a folder can
/// have more below it, so `**/*.rs` goes into a protected folder and not past
/// a protected file. Build one with [`Protected::file`] or
/// [`Protected::folder`], and choose `folder` when unsure: a folder marked as
/// a file opens patterns below its name, where a file marked as a folder only
/// adds noise.
///
/// ```
/// use milo_guards_core::{Paths, Protected};
///
/// let paths = Paths::new("/home/me/work/repo", "/home/me", ["/home/me/work/repo"])
///     .with_protected([
///         Protected::folder("/home/me/.agent", "the agent's settings"),
///         Protected::file("/home/me/work/repo/rules.yaml", "the agent's rules"),
///     ]);
/// assert_eq!(paths.protected[0].words, "the agent's settings");
/// assert_eq!(paths.protected[1].kind, milo_guards_core::ProtectedKind::File);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Protected {
    /// The file or folder, spelled like the workspace folders.
    pub path: PathBuf,
    /// What a reason calls it, such as `the agent's settings`: it follows
    /// `deletes` or `writes to` in the reason.
    pub words: &'static str,
    /// Whether it is a file or a folder.
    pub kind: ProtectedKind,
}

/// Whether a [`Protected`] path, or a [`Secret`] one, is a file or a folder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectedKind {
    /// A file: nothing below it, so a pattern is read only as far as its name.
    File,
    /// A folder: what is under it is protected (or secret), and a pattern can
    /// go below it.
    Folder,
}

/// A file or folder the caller knows holds a secret, and what a reason
/// calls it.
///
/// Core knows where keys and credentials live (SSH keys, cloud logins, the
/// system's password hashes), not a project's own: an `.env` file, a token
/// a tool keeps in the workspace, a browser's cookie store, a password
/// vault. A caller that knows which files hold secrets on this machine names
/// them here, and the resolver answers `Place::Sensitive` with
/// `Sensitivity::Secret` and the caller's words for each, so a guard judges a
/// read of one as it judges a read of a key: the shell guard's and the file
/// guard's `read_secret`, and the shell guard's `send_secret`.
///
/// The path is spelled the way the workspace folders are (absolute, and
/// canonical or as the user wrote it, like the rest of [`Paths`]), and is
/// compared as a protected path is: without case on every host, in either
/// Unicode canonical spelling, by a Windows short name. It covers the path
/// itself and everything under it, and wins over a workspace folder it sits
/// in. A path the caller names both protected and secret is
/// `Place::Protected` to the resolver, so a write or a delete of it keeps its
/// protected finding, and a read of it is still a read of the secret: a
/// guard asks [`Resolver::named_secret`](crate::Resolver::named_secret) for
/// it.
///
/// Build one with [`Secret::file`] or [`Secret::folder`]. As for
/// [`Protected`], only a folder has something below its name for a pattern
/// to go into, and `folder` is the choice when unsure.
///
/// What it does not make a finding, as for core's own secrets:
///
/// - a recursive read or copy of a folder that holds one (`grep -r KEY .`,
///   `tar czf x.tgz .`, `cp -r . /tmp/b`) is safe to the shell guard's
///   `classify`, which names only the home directory, a folder holding it
///   and the root of a disk; its `effect` answers `ReadsOnly(Reach::Beyond)`
///   for a line that only reads so (`grep -r KEY .`, where the archive and
///   the copy are `Changes`). Once a secret is named inside the workspace, every reader that
///   walks the working directory answers `Beyond` so: `git status`, `git
///   log`, `git diff`, `git ls-files` and the rest of git, `find .`, `ls -R`,
///   `rg`, `fd`, `Get-ChildItem -Recurse`;
/// - a folder handed whole to a sender (`scp -r app host:`), for the same
///   reason;
/// - a one-level listing handed to a reader (`ls | xargs cat`, `ls -a |
///   xargs cat`, `ls deploy | xargs -I{} cat deploy/{}`, PowerShell's
///   `Get-ChildItem | Get-Content`): the guard reads the listed folder as the
///   folder, not as each name in it, so these are safe and `effect` says
///   `ReadsOnly(Reach::Workspace)`, as for a key of core's own in the same
///   place;
/// - a name alone: the path is absolute, like the rest of [`Paths`]; a
///   relative path (`.env`) or a `~` path is read from the root of the disk
///   (`/.env`, a folder named `~` there), so it names no file the caller
///   means, and `.env` anywhere below the workspace cannot be named.
///
/// ```
/// use milo_guards_core::{Paths, ProtectedKind, Secret};
///
/// let paths = Paths::new("/home/me/work/app", "/home/me", ["/home/me/work/app"])
///     .with_secrets([
///         Secret::file("/home/me/work/app/.env", "the project's environment file"),
///         Secret::folder("/home/me/.vault", "your password vault"),
///     ]);
/// assert_eq!(paths.secrets[0].words, "the project's environment file");
/// assert_eq!(paths.secrets[1].kind, ProtectedKind::Folder);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Secret {
    /// The file or folder, spelled like the workspace folders.
    pub path: PathBuf,
    /// What a reason calls it, such as `the project's environment file`: it
    /// follows `reads` in the reason (`reads the project's environment
    /// file`), as `your SSH keys` does in `reads your SSH keys`.
    pub words: &'static str,
    /// Whether it is a file or a folder.
    pub kind: ProtectedKind,
}

impl Secret {
    /// A file that holds a secret, and the words a reason calls it by.
    ///
    /// As for [`Protected::file`], a folder marked as a file opens patterns
    /// below its name; when unsure, use [`Secret::folder`].
    #[must_use]
    pub fn file(path: impl Into<PathBuf>, words: &'static str) -> Self {
        Self {
            path: path.into(),
            words,
            kind: ProtectedKind::File,
        }
    }

    /// A folder whose every file holds a secret, and the words a reason calls
    /// it by.
    #[must_use]
    pub fn folder(path: impl Into<PathBuf>, words: &'static str) -> Self {
        Self {
            path: path.into(),
            words,
            kind: ProtectedKind::Folder,
        }
    }
}

impl Protected {
    /// A protected file and the words a reason calls it by.
    ///
    /// Marking a folder as a file opens patterns below its name: `c*/rules`
    /// is not a finding for a protected folder `cfg` marked as a file. Marking
    /// a file as a folder only adds noise (`**/*.rs` is a finding). When
    /// unsure, use [`Protected::folder`].
    #[must_use]
    pub fn file(path: impl Into<PathBuf>, words: &'static str) -> Self {
        Self {
            path: path.into(),
            words,
            kind: ProtectedKind::File,
        }
    }

    /// A protected folder and the words a reason calls it by.
    #[must_use]
    pub fn folder(path: impl Into<PathBuf>, words: &'static str) -> Self {
        Self {
            path: path.into(),
            words,
            kind: ProtectedKind::Folder,
        }
    }
}

impl Paths {
    /// The directories for a working directory, a home directory and the
    /// workspace folders.
    #[must_use]
    pub fn new<W: Into<PathBuf>>(
        cwd: impl Into<PathBuf>,
        home: impl Into<PathBuf>,
        workspaces: impl IntoIterator<Item = W>,
    ) -> Self {
        Self {
            cwd: cwd.into(),
            home: home.into(),
            workspaces: workspaces.into_iter().map(Into::into).collect(),
            protected: Vec::new(),
            secrets: Vec::new(),
            drive_mounts: Vec::new(),
            windows_home: None,
        }
    }

    /// These directories with `protected` added to what the caller treats as
    /// its own. Each call adds to the list.
    #[must_use]
    pub fn with_protected(mut self, protected: impl IntoIterator<Item = Protected>) -> Self {
        self.protected.extend(protected);
        self
    }

    /// These directories with `secrets` added to what the caller knows holds
    /// a secret. Each call adds to the list.
    #[must_use]
    pub fn with_secrets(mut self, secrets: impl IntoIterator<Item = Secret>) -> Self {
        self.secrets.extend(secrets);
        self
    }

    /// These directories with `mounts` added to the folders this machine's
    /// POSIX paths show a Windows drive in. Each call adds to the list.
    ///
    /// For the lines a POSIX shell runs in Git Bash or MSYS2 (the shell guard
    /// with `Shell::Posix`), the caller spells the directories as Git Bash
    /// does, from `/` (`/c/Users/me/dev/repo`), and names the mount `/`: then
    /// a Git Bash path to the workspace is the workspace, and the drive's
    /// keys, home and system folders are what they are on Windows. The file,
    /// script and URL guards, and PowerShell and cmd lines, take Windows
    /// paths, so for them the caller keeps directories spelled the Windows
    /// way (`C:\Users\me\dev\repo`). A POSIX line judged on those is also
    /// judged as spelled, where `/c/Users/me/dev/repo` is `C:\c\Users\...`,
    /// beyond the workspace. On WSL, the working directory and the workspace
    /// are spelled alike: a workspace spelled `C:\Users\me\repo` is not that
    /// of a working directory spelled `/mnt/c/Users/me/repo`, as spelled.
    ///
    /// ```
    /// use milo_guards_core::{Flavour, Paths, Place, Resolver, Sensitivity, Spelling};
    ///
    /// // Git Bash: the directories spelled as it spells them, its mount `/`.
    /// let paths = Paths::new("/c/Users/me/dev/repo", "/c/Users/me", ["/c/Users/me/dev/repo"])
    ///     .with_drive_mounts(["/"]);
    /// let resolver = Resolver::new(&paths);
    /// let place = |path| resolver.place(Spelling::Plain(path), Flavour::Posix);
    /// assert_eq!(place("/c/Users/me/dev/repo/src/main.rs"), Place::Inside);
    /// assert_eq!(
    ///     place("/c/Users/me/.ssh/id_rsa"),
    ///     Place::Sensitive("your SSH keys", Sensitivity::Secret)
    /// );
    /// assert_eq!(place("/c/Windows"), Place::Top("a system folder"));
    /// ```
    ///
    /// ```
    /// use milo_guards_core::{Flavour, Paths, Place, Resolver, Sensitivity, Spelling};
    ///
    /// // WSL: the Windows drives are under `/mnt`, the Windows home is `C:\Users\me`.
    /// let paths = Paths::new("/home/me/work/repo", "/home/me", ["/home/me/work/repo"])
    ///     .with_drive_mounts(["/mnt"])
    ///     .with_windows_home(r"C:\Users\me");
    /// let resolver = Resolver::new(&paths);
    /// let place = |path| resolver.place(Spelling::Plain(path), Flavour::Posix);
    /// assert_eq!(
    ///     place("/mnt/c/Users/me/.ssh/id_rsa"),
    ///     Place::Sensitive("your SSH keys", Sensitivity::Secret)
    /// );
    /// assert_eq!(place("/mnt/c/Users/me"), Place::Home { exact: true });
    /// ```
    #[must_use]
    pub fn with_drive_mounts<M: Into<PathBuf>>(
        mut self,
        mounts: impl IntoIterator<Item = M>,
    ) -> Self {
        self.drive_mounts.extend(mounts.into_iter().map(Into::into));
        self
    }

    /// These directories with the user's Windows home directory set to
    /// `home`, for a machine whose own home directory is not it (WSL). A
    /// later call replaces it.
    #[must_use]
    pub fn with_windows_home(mut self, home: impl Into<PathBuf>) -> Self {
        self.windows_home = Some(home.into());
        self
    }

    /// These directories as they are spelled: the same, with no drive mount
    /// and no Windows home; `None` when neither is named. A guard judges its
    /// input on both and keeps every finding of each, so naming how this
    /// machine spells another system's drives never makes an answer less
    /// serious. [`Resolver`](crate::Resolver) answers where a path lands on
    /// the directories it is given (`/mnt/c/Windows/Temp/x` is a temporary
    /// folder through the mount): a caller of it that wants the same must
    /// ask it of these too, and keep the more serious answer.
    #[must_use]
    pub fn as_spelled(&self) -> Option<Self> {
        (!self.drive_mounts.is_empty() || self.windows_home.is_some()).then(|| Self {
            drive_mounts: Vec::new(),
            windows_home: None,
            ..self.clone()
        })
    }
}
