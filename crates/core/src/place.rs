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
    /// startup files, the repository's history.
    Sensitive(&'static str),
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

impl Place {
    /// Whether touching it is the agent's own business.
    #[must_use]
    pub fn harmless(self) -> bool {
        matches!(
            self,
            Self::Inside | Self::Temp { exact: false } | Self::Null
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
            Self::Top(words) | Self::Sensitive(words) | Self::Protected(words) => words,
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
        for place in [
            Place::Temp { exact: true },
            Place::Workspace { exact: true },
            Place::Workspace { exact: false },
            Place::Home { exact: true },
            Place::Home { exact: false },
            Place::Top("a system folder"),
            Place::Sensitive("your SSH keys"),
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
            (Place::Sensitive("your SSH keys"), "your SSH keys"),
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
