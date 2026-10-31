//! The directories a guard judges paths against.

use std::path::PathBuf;

/// The directories a path is judged against.
///
/// Build one with [`Paths::new`], and add what the caller gates with through
/// [`Paths::with_protected`]. The struct is `#[non_exhaustive]`, so a
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
}

/// A file or folder the caller gates with, and what a reason calls it.
///
/// The path is spelled the way the workspace folders are (absolute, and
/// canonical or as the user wrote it, like the rest of [`Paths`]). It covers
/// the path itself and everything under it, and wins over a workspace folder
/// it sits in. The resolver answers `Place::Protected` with the caller's
/// words for it.
///
/// ```
/// use milo_guards_core::{Paths, Protected};
///
/// let paths = Paths::new("/home/me/work/repo", "/home/me", ["/home/me/work/repo"])
///     .with_protected([Protected::new("/home/me/.agent", "the agent's settings")]);
/// assert_eq!(paths.protected[0].words, "the agent's settings");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Protected {
    /// The file or folder, spelled like the workspace folders.
    pub path: PathBuf,
    /// What a reason calls it, such as `the agent's settings`: it follows
    /// `deletes` or `writes to` in the reason.
    pub words: &'static str,
}

impl Protected {
    /// A protected path and the words a reason calls it by.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>, words: &'static str) -> Self {
        Self {
            path: path.into(),
            words,
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
        }
    }

    /// These directories with `protected` added to what the caller treats as
    /// its own. Each call adds to the list.
    #[must_use]
    pub fn with_protected(mut self, protected: impl IntoIterator<Item = Protected>) -> Self {
        self.protected.extend(protected);
        self
    }
}
