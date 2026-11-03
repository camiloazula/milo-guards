//! Where a path lands, and what touching it means.

/// Where a path lands, and so what touching it means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Place {
    /// Inside a workspace folder: the agent's to change.
    Inside,
    /// A temporary directory itself (`exact`), or a path under one.
    Temp {
        /// The temporary directory itself, not a path under it.
        exact: bool,
    },
    /// A device that discards or echoes (`/dev/null`, `NUL`).
    Null,
    /// What lives only as long as the shell session and changes nothing on
    /// the disk: PowerShell's `Env:` and `Variable:` drives, which hold the
    /// session's environment and variables, as `$env:FOO = 'bar'` sets them.
    /// The words name which. The resolver never answers it, since no file
    /// path is one; a guard that reads such paths names it.
    Session(&'static str),
    /// A workspace folder itself (`exact`), or a folder holding one.
    Workspace {
        /// The workspace folder itself, not a folder holding it.
        exact: bool,
    },
    /// The home directory itself (`exact`), or a folder holding it.
    Home {
        /// The home directory itself, not a folder holding it.
        exact: bool,
    },
    /// The root of a disk, a system folder, or a top-level folder.
    Top(&'static str),
    /// A file or folder whose loss or change hurts: keys, credentials, shell
    /// startup files, the repository's history. The words are for a reason,
    /// and the [`Sensitivity`] says what touching it exposes or changes, so a
    /// guard can tell reading a key from reading a startup file.
    Sensitive(&'static str, Sensitivity),
    /// A file or folder the caller named as its own (`Paths::protected`),
    /// such as the agent's settings, with the caller's words for a reason.
    /// It wins over the workspace it may sit in.
    Protected(&'static str),
    /// The Windows registry. The resolver never answers it, since a registry
    /// path is no file path; a guard that reads such paths names it.
    Registry,
    /// A disk device.
    Disk,
    /// Anywhere else beyond the workspace.
    Outside,
    /// Known only when the input runs. The resolver never answers it; a
    /// guard that cannot spell a path out names it.
    Unknown,
}

/// What touching a [`Place::Sensitive`] path means.
///
/// Exhaustive on purpose, unlike [`Place`]: what a read of a place means is a
/// policy a guard decides for each kind, so a kind added later must break
/// each guard's `match` at compile time rather than fall into a fallback arm
/// that reads it as harmless.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Sensitivity {
    /// A key or a credential: reading it exposes it, writing it replaces it.
    Secret,
    /// A file that runs, or sets how something runs, later: shell startup
    /// files, git's settings, the PowerShell profile, what Windows starts at
    /// login, and a workspace's own files that a tool runs on its own
    /// (`.envrc`, `.vscode/tasks.json`, a CI workflow). Reading one is
    /// harmless; writing one is how a command is planted.
    Startup,
    /// The repository's history. Reading it is the agent's everyday work;
    /// changing it loses work.
    History,
}

impl Place {
    /// Whether touching it is the agent's own business.
    #[must_use]
    pub fn harmless(self) -> bool {
        matches!(
            self,
            Self::Inside | Self::Temp { exact: false } | Self::Null | Self::Session(_)
        )
    }

    /// The place in the words of a reason: `deletes {words}`.
    #[must_use]
    pub fn words(self) -> &'static str {
        match self {
            Self::Inside => "a path inside the workspace",
            Self::Temp { exact: true } => "a temporary folder",
            Self::Temp { exact: false } => "a temporary file",
            Self::Null => "nothing",
            Self::Workspace { exact: true } => "the whole workspace",
            Self::Workspace { exact: false } => "a folder holding the workspace",
            Self::Home { exact: true } => "your home directory",
            Self::Home { exact: false } => "a folder holding your home directory",
            Self::Top(words)
            | Self::Sensitive(words, _)
            | Self::Protected(words)
            | Self::Session(words) => words,
            Self::Registry => "the registry",
            Self::Disk => "a disk",
            Self::Outside => "a path outside the workspace",
            Self::Unknown => "a path only known when it runs",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_agents_own_places_are_harmless() {
        assert!(Place::Inside.harmless());
        assert!(Place::Temp { exact: false }.harmless());
        assert!(Place::Null.harmless());
        assert!(Place::Session("the session's environment").harmless());
        for place in [
            Place::Temp { exact: true },
            Place::Workspace { exact: true },
            Place::Workspace { exact: false },
            Place::Home { exact: true },
            Place::Home { exact: false },
            Place::Top("a system folder"),
            Place::Sensitive("your SSH keys", Sensitivity::Secret),
            Place::Sensitive("a shell startup file", Sensitivity::Startup),
            Place::Sensitive("the repository's history", Sensitivity::History),
            Place::Protected("the agent's settings"),
            Place::Registry,
            Place::Disk,
            Place::Outside,
            Place::Unknown,
        ] {
            assert!(!place.harmless(), "{place:?}");
        }
    }

    #[test]
    fn a_place_reads_as_words_in_a_reason() {
        for (place, words) in [
            (Place::Inside, "a path inside the workspace"),
            (Place::Temp { exact: true }, "a temporary folder"),
            (Place::Temp { exact: false }, "a temporary file"),
            (Place::Null, "nothing"),
            (
                Place::Session("the session's environment"),
                "the session's environment",
            ),
            (Place::Workspace { exact: true }, "the whole workspace"),
            (
                Place::Workspace { exact: false },
                "a folder holding the workspace",
            ),
            (Place::Home { exact: true }, "your home directory"),
            (
                Place::Home { exact: false },
                "a folder holding your home directory",
            ),
            (Place::Top("a system folder"), "a system folder"),
            (
                Place::Sensitive("your SSH keys", Sensitivity::Secret),
                "your SSH keys",
            ),
            (
                Place::Protected("the agent's settings"),
                "the agent's settings",
            ),
            (Place::Registry, "the registry"),
            (Place::Disk, "a disk"),
            (Place::Outside, "a path outside the workspace"),
            (Place::Unknown, "a path only known when it runs"),
        ] {
            assert_eq!(place.words(), words);
        }
    }
}
