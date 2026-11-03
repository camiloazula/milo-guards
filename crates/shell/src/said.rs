//! What a finding says: its reason, and what to do instead where there is a
//! real way out. A rule states both in one place, so the advice sits beside
//! the reason it answers.

use crate::{Finding, Rule};

/// What a downloaded script run straight away can be turned into.
pub(crate) const DOWNLOAD_FIRST: &str = "download the script to a file and read it first";

/// What a finding says: the reason, in a few words a permission prompt can
/// show, and, where there is a real one, what to do instead, in the same
/// voice (one short sentence, no trailing period). A plain `&str` or
/// `String` is a reason with no advice; [`Said::instead`] adds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Said {
    pub(crate) reason: String,
    pub(crate) instead: Option<String>,
}

impl Said {
    /// `reason`, with `instead` as what to do instead.
    pub(crate) fn instead(reason: impl Into<String>, instead: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            instead: Some(instead.into()),
        }
    }

    /// The finding of `rule` that says this, about `target`.
    pub(crate) fn finding(self, rule: Rule, target: Option<String>) -> Finding {
        Finding {
            rule,
            reason: self.reason,
            target,
            instead: self.instead,
        }
    }
}

impl From<&str> for Said {
    fn from(reason: &str) -> Self {
        Self {
            reason: reason.to_string(),
            instead: None,
        }
    }
}

impl From<String> for Said {
    fn from(reason: String) -> Self {
        Self {
            reason,
            instead: None,
        }
    }
}
