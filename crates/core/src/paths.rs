//! The directories a guard judges paths against.

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use crate::resolve::Prepared;

/// The directories a path is judged against.
///
/// Build one with [`Paths::new`], add what the caller gates with through
/// [`Paths::with_protected`], and the files it knows hold secrets through
/// [`Paths::with_secrets`]. What only the disk can say, the caller says too:
/// how this machine spells another system's drives
/// ([`Paths::with_drive_mounts`], and on WSL [`Paths::with_windows_home`]),
/// and the links it has resolved ([`Paths::with_links`]). The struct is
/// `#[non_exhaustive]`, so a field added later does not break a caller; the
/// fields stay public to read and to set.
///
/// Paths are judged by their spelling alone, so these must be spelled the
/// way the paths being judged will resolve: absolute, and either all
/// canonical or all as the user wrote them. A relative `cwd` puts every
/// relative path outside the workspace, and so does a `cwd` read through a
/// symlink (`/private/tmp/…`) when the workspace is spelled without it
/// (`/tmp/…`). Naming that link does not change it: a guard judges a path
/// as spelled too, where the two spellings differ, and keeps that answer.
/// The caller names the workspace by the path the agent's `cwd` uses. With
/// no workspace at all, every path is outside.
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
    /// The links the caller has resolved, each a link and where it points: a
    /// path through one is placed where it lands. See [`Links`] and [`Link`].
    pub links: Links,
}

/// A link the caller found, and where it points: a symbolic link, a
/// junction, or any other name the system follows to another place.
///
/// The guard reads no disk, so it cannot tell a link from a folder; a caller
/// that can names the links it found in the workspace folders, and a path
/// through one is placed where it lands. A write through a link into a
/// protected or a sensitive place is judged as a write there, and a read
/// through one to a key as a read of the key. A guard judges a path both as
/// it is spelled and where it lands, and keeps every finding of both, so
/// naming a link never takes a finding away.
///
/// `path` is spelled the way the workspace folders are: absolute, and
/// canonical or as the user wrote it, like the rest of [`Paths`]. One that
/// starts with `~` is read from the home directory, and any other relative
/// one from the first workspace folder (from the home directory when there
/// is none), never from the working directory, which a caller may change
/// from one call to the next. An empty `path` names nothing. A link below
/// another may be named through the first link or where that one lands.
/// The struct is `#[non_exhaustive]`, so a field added later (whether the
/// link is to a file or a folder) does not break a caller: build one with
/// [`Link::new`] or [`Link::unknown`]. `target` is the link's own text,
/// absolute or relative to the folder the link is in (`../../.ssh`),
/// spelled as the machine spells paths: a POSIX path on a POSIX machine
/// (WSL's links on a mounted drive included), a Windows one on Windows, where the raw forms a junction holds are read
/// too (`\??\C:\x`, `\\?\C:\x`, a share). A target the guard cannot place
/// (empty, longer than any system keeps, a volume or a device name), a link
/// the caller could not read ([`Link::unknown`]), a link named twice with
/// two targets, and a link the guard cannot place among the others (see
/// [`Links`]) make every path through it one only known when it runs.
///
/// ```
/// use milo_guards_core::{Link, Paths};
///
/// let paths = Paths::new("/home/me/work/repo", "/home/me", ["/home/me/work/repo"])
///     .with_links([Link::new("/home/me/work/repo/keys", "/home/me/.ssh")]);
/// let link = &paths.links.as_slice()[0];
/// assert_eq!(link.target.as_deref().and_then(|t| t.to_str()), Some("/home/me/.ssh"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Link {
    /// The link itself, spelled like the workspace folders.
    pub path: PathBuf,
    /// Where it points, as the link holds it: absolute, or from the folder
    /// the link is in. `None` for a link the caller found and could not read.
    pub target: Option<PathBuf>,
}

impl Link {
    /// A link at `path` that points to `target`.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>, target: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            target: Some(target.into()),
        }
    }

    /// A link at `path` whose target the caller could not read: every path
    /// through it is only known when it runs, which no guard calls safe to
    /// read, write or delete.
    #[must_use]
    pub fn unknown(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            target: None,
        }
    }
}

/// The links the caller has resolved.
///
/// The list is kept as given, and shared by every copy of the [`Paths`]. The
/// guards read it as a tree of names, which is built the first time a guard
/// judges with these directories, once, and kept with the list for every
/// later call and every copy: a guard's call then costs a few lookups for
/// each part of a path, however many links are named. The tree is built for
/// every field of the [`Paths`] but the working directory, which a caller
/// may change from call to call at no cost; a builder (`with_...`) builds it
/// again on first use, and a guard handed [`Paths`] whose other fields were
/// set by hand since builds its own for each call. Naming links one at a
/// time (`with_links([link])` in a loop) costs the same as naming them in
/// one call.
///
/// The tree keeps about 1.1 KB of memory for each link (measured for
/// package-manager links of five parts each and their targets), and its
/// build takes about 3 KB and a few microseconds for each while it runs, in
/// time linear in the number of links, and a counted amount of work for
/// each part of each link's name and target: a caller that starts a process
/// for each tool call builds it on every call. Past [`MOST_LINKS`]
/// links, or past the work the build may spend, the guard holds none of
/// them, and every path is only known when it runs; a link it cannot place
/// among the others (one named through more than eight links named through
/// links, or through a link it cannot place) makes the paths through it so,
/// whatever the order of the list.
#[derive(Debug, Clone, Default)]
pub struct Links {
    /// Shared, so that copying the directories copies no link.
    named: Arc<Vec<Link>>,
    /// The tree, once a guard has built it, shared by every copy.
    prepared: Arc<OnceLock<Arc<Prepared>>>,
}

/// The most links the guards hold: past it, every path is only known when
/// it runs.
pub const MOST_LINKS: usize = crate::resolve::MOST_LINKS;

impl Links {
    /// The links, in the order they were named.
    #[must_use]
    pub fn as_slice(&self) -> &[Link] {
        &self.named
    }

    /// How many links are named.
    #[must_use]
    pub fn len(&self) -> usize {
        self.named.len()
    }

    /// Whether no link is named.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.named.is_empty()
    }

    /// Each link, in the order they were named.
    pub fn iter(&self) -> std::slice::Iter<'_, Link> {
        self.named.iter()
    }

    /// The tree for `paths`: the one kept, when it was built for them; else
    /// one built now, kept when none was.
    pub(crate) fn prepared(&self, paths: &Paths) -> Arc<Prepared> {
        let kept = self.prepared.get_or_init(|| Arc::new(Prepared::new(paths)));
        if kept.is_for(paths) {
            Arc::clone(kept)
        } else {
            Arc::new(Prepared::new(paths))
        }
    }

    /// Whether the tree was built and kept, for a test of when it is.
    #[cfg(any(feature = "testing", test))]
    pub(crate) fn kept(&self) -> Option<&Arc<Prepared>> {
        self.prepared.get()
    }

    /// Forget the tree: the directories it was built for changed.
    fn forget(&mut self) {
        if self.prepared.get().is_some() {
            self.prepared = Arc::new(OnceLock::new());
        }
    }
}

impl PartialEq for Links {
    fn eq(&self, other: &Self) -> bool {
        self.named == other.named
    }
}

impl Eq for Links {}

impl<'a> IntoIterator for &'a Links {
    type Item = &'a Link;
    type IntoIter = std::slice::Iter<'a, Link>;

    fn into_iter(self) -> Self::IntoIter {
        self.named.iter()
    }
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
            links: Links::default(),
        }
    }

    /// These directories with `protected` added to what the caller treats as
    /// its own. Each call adds to the list.
    #[must_use]
    pub fn with_protected(mut self, protected: impl IntoIterator<Item = Protected>) -> Self {
        self.protected.extend(protected);
        self.links.forget();
        self
    }

    /// These directories with `secrets` added to what the caller knows holds
    /// a secret. Each call adds to the list.
    #[must_use]
    pub fn with_secrets(mut self, secrets: impl IntoIterator<Item = Secret>) -> Self {
        self.secrets.extend(secrets);
        self.links.forget();
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
        self.links.forget();
        self
    }

    /// These directories with the user's Windows home directory set to
    /// `home`, for a machine whose own home directory is not it (WSL). A
    /// later call replaces it.
    #[must_use]
    pub fn with_windows_home(mut self, home: impl Into<PathBuf>) -> Self {
        self.windows_home = Some(home.into());
        self.links.forget();
        self
    }

    /// These directories with `links` added to the links the caller has
    /// resolved (see [`Links`]). Each call adds to the list; the tree of them
    /// is built when a guard first judges with these directories, so a loop
    /// of calls costs what one call does.
    #[must_use]
    pub fn with_links(mut self, links: impl IntoIterator<Item = Link>) -> Self {
        Arc::make_mut(&mut self.links.named).extend(links);
        self.links.prepared = Arc::new(OnceLock::new());
        self
    }

    /// These directories as they are spelled: the same, with no link, no
    /// drive mount and no Windows home; `None` when none is named. A guard
    /// judges its input on the directories it is given, on these, and on
    /// [`mounts_alone`](Self::mounts_alone), and keeps every finding of
    /// each, so naming what only the disk can say never makes an answer less
    /// serious. [`Resolver`](crate::Resolver) answers where a path lands on
    /// the directories it is given (`/mnt/c/Windows/Temp/x` is a temporary
    /// folder through the mount): a caller of it that wants the same must
    /// ask it of these too, and keep the more serious answer.
    #[must_use]
    pub fn as_spelled(&self) -> Option<Self> {
        (!self.links.is_empty() || !self.drive_mounts.is_empty() || self.windows_home.is_some())
            .then(|| Self {
                cwd: self.cwd.clone(),
                home: self.home.clone(),
                workspaces: self.workspaces.clone(),
                protected: self.protected.clone(),
                secrets: self.secrets.clone(),
                drive_mounts: Vec::new(),
                windows_home: None,
                links: Links::default(),
            })
    }

    /// These directories with the links dropped and the drive mounts and the
    /// Windows home kept; `None` unless both links and one of those are
    /// named (otherwise it is these directories or
    /// [`as_spelled`](Self::as_spelled)). A guard judges on it too, so a link
    /// never takes away what a mount says.
    #[must_use]
    pub fn mounts_alone(&self) -> Option<Self> {
        (!self.links.is_empty() && (!self.drive_mounts.is_empty() || self.windows_home.is_some()))
            .then(|| Self {
                links: Links::default(),
                ..self.clone()
            })
    }

    /// Every other set of these directories a guard judges its input on,
    /// keeping every finding of each: [`as_spelled`](Self::as_spelled) and
    /// [`mounts_alone`](Self::mounts_alone), those that are named.
    #[must_use]
    pub fn also_judged_on(&self) -> Vec<Self> {
        self.as_spelled()
            .into_iter()
            .chain(self.mounts_alone())
            .collect()
    }
}
