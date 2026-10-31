//! Guards for AI coding agents on your own machine.
//!
//! Each guard reads what an agent is about to do and says whether it is
//! safe to do without asking, or risky and why. They are built for agents
//! that work on your machine with small local models, so a guard is
//! offline and deterministic: it makes no model call, reads no file and no
//! environment variable, and gives the same answer for the same input.
//! What cannot be read is risky, never safe.
//!
//! A guard only judges. What to do with a risky answer (ask, refuse, allow
//! anyway) is the caller's policy.
//!
//! This is the one crate a caller depends on. The guards live in modules
//! behind features; the types they share are at the root:
//!
//! - [`Paths`]: the directories a guard judges paths against, built with
//!   [`Paths::new`]. A caller names what it gates with (its settings, its
//!   rules) as [`Protected`] paths, through [`Paths::with_protected`].
//! - [`Protected`]: a path the caller treats as its own, with the words a
//!   reason calls it by. Touching one is a finding, even inside the workspace.
//! - [`Assessment`]: [`Safe`](Assessment::Safe), or
//!   [`Risky`](Assessment::Risky) with a [`Finding`] for each reason.
//! - [`Finding`]: the rule that found it, a reason a prompt can show, and
//!   what it is about.
//! - [`RuleName`]: the trait every guard's rule enum implements, for code
//!   that handles the rules of any guard alike. Each guard names its enum
//!   `Rule` (for example `shell::Rule`), which is why the trait is not
//!   called `Rule` here. The enum also has its own `name` method, so the
//!   trait is not needed to read a rule's stable name on the wire.
//!
//! Each guard module has the function that judges and its own `Rule`,
//! `Assessment` and `Finding`, with the rule type filled in.
//!
//! | Feature | Module | Judges |
//! | --- | --- | --- |
//! | `shell` (default) | `shell` | a shell line: POSIX shell, PowerShell or cmd |
//!
//! ```
//! # #[cfg(feature = "shell")] {
//! use milo_local_guards::shell::{classify, Rule, Shell};
//! use milo_local_guards::Paths;
//!
//! let paths = Paths::new("/home/me/work/repo", "/home/me", ["/home/me/work/repo"]);
//!
//! // Building inside the workspace is the agent's own business.
//! assert!(classify("cargo build && rm -rf target", Shell::Posix, &paths).is_safe());
//!
//! // Deleting the home directory is not, and the answer says why.
//! let assessment = classify("rm -rf ~", Shell::Posix, &paths);
//! let finding = &assessment.findings()[0];
//! assert_eq!(finding.rule, Rule::Delete);
//! assert_eq!(finding.rule.name(), "delete");
//! assert_eq!(finding.target.as_deref(), Some("~"));
//! # }
//! ```
//!
//! What the caller gates with is named in the same `Paths`. It is judged as a
//! protected path even inside the workspace, and a reason uses the caller's
//! words:
//!
//! ```
//! # #[cfg(feature = "shell")] {
//! use milo_local_guards::shell::{classify, Rule, Shell};
//! use milo_local_guards::{Paths, Protected};
//!
//! let paths = Paths::new("/home/me/work/repo", "/home/me", ["/home/me/work/repo"])
//!     .with_protected([Protected::new("/home/me/.agent", "the agent's settings")]);
//!
//! let assessment = classify("rm ~/.agent/config.yaml", Shell::Posix, &paths);
//! assert_eq!(assessment.findings()[0].rule, Rule::Delete);
//! assert_eq!(assessment.findings()[0].reason, "deletes the agent's settings");
//! assert!(classify("cat ~/.agent/config.yaml", Shell::Posix, &paths).is_safe());
//! # }
//! ```

pub use milo_guards_core::{Assessment, Finding, Paths, Protected, RuleName};

#[cfg(feature = "shell")]
pub use milo_guards_shell as shell;

/// The README's example, compiled and run with the doctests so it cannot
/// drift from the code. Only rustdoc's doctest pass reads the file, so
/// building this crate never needs the README: a build that vendors only
/// this crate's folder still works.
#[cfg(all(doctest, feature = "shell"))]
#[allow(
    clippy::disallowed_macros,
    reason = "the README include is read by rustdoc's doctest pass only"
)]
#[doc = include_str!("../../../README.md")]
mod readme {}
