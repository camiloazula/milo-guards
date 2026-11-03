//! What a guard answers: safe, or risky with every reason.

use std::fmt::Debug;
use std::hash::Hash;

/// A guard's rule, seen by its wire name: what generic code (the test kit,
/// a caller that handles several guards alike) needs of any guard's rule.
///
/// A guard has one enum of rules, named `Rule` in its own crate, and
/// implements this trait for it. The guard owns the meaning of its rules;
/// what to do about each is the caller's policy and never a guard's.
///
/// A guard's enum also has an inherent `name`, so a caller that holds the
/// enum needs no import of this trait. The enum is exhaustive on purpose (a
/// new rule must break each caller's `match` at compile time, so the caller
/// decides what to do with it); see the guard's design page.
///
/// The trait is called `RuleName`, not `Rule`, so that it never clashes with
/// a guard's enum when both are in scope, as they are at the root of the
/// front-door crate.
pub trait RuleName: Copy + Eq + Hash + Debug {
    /// The rule's stable name on the wire (`delete`, `wipe_disk`). It never
    /// changes once a caller uses it, whatever the variant is called in
    /// code.
    fn name(self) -> &'static str;
}

/// What a guard concluded about what an agent is about to do.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "an assessment says whether it is safe to proceed: read it"]
pub enum Assessment<R> {
    /// No rule found anything: it can be done without asking.
    Safe,
    /// At least one rule found something; every finding, in the order the
    /// input reads.
    ///
    /// As a guard builds it, the list is never empty: a guard answers
    /// [`Safe`](Assessment::Safe) when it found nothing. A caller that builds
    /// one by hand (in a test, say) with an empty list gets an assessment
    /// that is neither safe nor explained, so do not.
    Risky(Vec<Finding<R>>),
}

impl<R> Assessment<R> {
    /// Whether it can be done without asking.
    #[must_use]
    pub fn is_safe(&self) -> bool {
        matches!(self, Self::Safe)
    }

    /// What made it risky; empty when it is safe.
    #[must_use]
    pub fn findings(&self) -> &[Finding<R>] {
        match self {
            Self::Safe => &[],
            Self::Risky(findings) => findings,
        }
    }
}

/// One reason something is risky.
///
/// A plain struct, not `#[non_exhaustive]`: each guard builds one in its own
/// crate, and a caller may build one by hand.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Finding<R> {
    /// The rule that found it.
    pub rule: R,
    /// What it would do, in a few words a permission prompt can show:
    /// `deletes your home directory`.
    pub reason: String,
    /// The part of the input it is about, as written, where there is one:
    /// `~`.
    pub target: Option<String>,
    /// What to do instead, in the same voice as `reason`, where there is a
    /// real way out: "stash the changes first (`git stash`)" beside `throws
    /// away uncommitted changes`. `None` where there is no safe general
    /// advice, as for a line that runs as root.
    pub instead: Option<String>,
}
