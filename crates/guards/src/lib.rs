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
//! - [`Protected`]: a file or folder the caller treats as its own, with the
//!   words a reason calls it by (`Protected::file`, `Protected::folder`). Touching one is a finding, even inside the workspace.
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
//! | `shell` (default) | `shell` | a shell line: POSIX shell, PowerShell or cmd; `shell::effect` also says whether it only reads, and whether the reads stay in the workspace |
//! | `file` (default) | `file` | one read or write of a path through a file API |
//! | `url` (default) | `url` | a URL an agent is about to fetch: its host as a parser reads it, its scheme, its user-info |
//! | `secrets` | `secrets` | a text: the keys, tokens, passwords and personal data in it, and where; `secrets::find_spans` gives the ranges to scrub |
//!
//! ```
//! # #[cfg(feature = "shell")] {
//! use milo_local_guards::shell::{classify, effect, Effect, Reach, Rule, Shell};
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
//!
//! // So is reading a key, with the file guard's answer for the same file.
//! let assessment = classify("cat ~/.ssh/id_ed25519", Shell::Posix, &paths);
//! assert_eq!(assessment.findings()[0].rule, Rule::ReadSecret);
//! assert_eq!(assessment.findings()[0].reason, "reads your SSH keys");
//!
//! // Whether a line only reads is a second answer, from the same split.
//! assert_eq!(effect("git status", Shell::Posix, &paths), Effect::ReadsOnly(Reach::Workspace));
//! // A read can still leave the project: the answer says where it lands.
//! assert_eq!(effect("cat ~/.ssh/id_ed25519", Shell::Posix, &paths), Effect::ReadsOnly(Reach::Beyond));
//! assert_eq!(effect("mkdir build", Shell::Posix, &paths), Effect::Changes);
//! assert_eq!(effect("./script.sh", Shell::Posix, &paths), Effect::Unknown);
//! # }
//! ```
//!
//! The file guard judges one read or write of one path, with the same
//! `Paths`:
//!
//! ```
//! # #[cfg(feature = "file")] {
//! use milo_local_guards::file::{judge, Access, Rule};
//! use milo_local_guards::Paths;
//!
//! let paths = Paths::new("/home/me/work/repo", "/home/me", ["/home/me/work/repo"]);
//!
//! // Reading and editing the workspace's files is the agent's own business.
//! assert!(judge(Access::Read, "src/main.rs", &paths).is_safe());
//! assert!(judge(Access::Write, "src/main.rs", &paths).is_safe());
//!
//! // Reading a key is a finding; so is writing beyond the workspace.
//! let assessment = judge(Access::Read, "~/.ssh/id_ed25519", &paths);
//! assert_eq!(assessment.findings()[0].rule, Rule::ReadSecret);
//! let assessment = judge(Access::Write, "../other/x", &paths);
//! assert_eq!(assessment.findings()[0].rule, Rule::WriteOutside);
//! # }
//! ```
//!
//! A fetch is judged by its host, however the address is spelled:
//!
//! ```
//! # #[cfg(feature = "url")] {
//! use milo_local_guards::url::{judge, Rule};
//! use milo_local_guards::Paths;
//!
//! let paths = Paths::new("/home/me/work/repo", "/home/me", ["/home/me/work/repo"]);
//!
//! assert!(judge("https://docs.rs/url", &paths).is_safe());
//!
//! // `2130706433` is `127.0.0.1`, whatever it looks like.
//! let assessment = judge("http://2130706433:9090/admin", &paths);
//! assert_eq!(assessment.findings()[0].rule, Rule::LocalAddress);
//! assert_eq!(assessment.findings()[0].rule.name(), "local_address");
//!
//! // The cloud metadata service is its own rule.
//! let assessment = judge("http://169.254.169.254/latest/meta-data/", &paths);
//! assert_eq!(assessment.findings()[0].rule, Rule::Metadata);
//! # }
//! ```
//!
//! A text is read for what it must not carry, with the `secrets` feature (off
//! by default). A finding never holds the secret, and its span says where it
//! is, so a caller can scrub it:
//!
//! ```
//! # #[cfg(feature = "secrets")] {
//! use milo_local_guards::secrets::{find, find_spans, Rule};
//!
//! assert!(find("let sha = \"3f786850e387550fdab836ed7e6dc881de23001b\";").is_safe());
//!
//! let text = "DATABASE_URL=postgres://app:fakePass0word1@db.internal/app";
//! let assessment = find(text);
//! let finding = &assessment.findings()[0];
//! assert_eq!(finding.rule, Rule::ConnectionString);
//! assert_eq!(finding.rule.name(), "connection_string");
//! assert_eq!(finding.target.as_deref(), Some("… (14 chars)"));
//!
//! let span = find_spans(text)[0];
//! assert_eq!(&text[span.start..span.end], "fakePass0word1");
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
//!     .with_protected([Protected::folder("/home/me/.agent", "the agent's settings")]);
//!
//! let assessment = classify("rm ~/.agent/config.yaml", Shell::Posix, &paths);
//! assert_eq!(assessment.findings()[0].rule, Rule::Delete);
//! assert_eq!(assessment.findings()[0].reason, "deletes the agent's settings");
//! assert!(classify("cat ~/.agent/config.yaml", Shell::Posix, &paths).is_safe());
//! # }
//! ```
//!
//! The file guard reports a write to the same path with the caller's words
//! and a rule of its own, so a caller can refuse this one and only ask on the
//! others:
//!
//! ```
//! # #[cfg(feature = "file")] {
//! use milo_local_guards::file::{judge, Access, Rule};
//! use milo_local_guards::{Paths, Protected};
//!
//! let paths = Paths::new("/home/me/work/repo", "/home/me", ["/home/me/work/repo"])
//!     .with_protected([Protected::folder("/home/me/.agent", "the agent's settings")]);
//!
//! let assessment = judge(Access::Write, "~/.agent/config.yaml", &paths);
//! assert_eq!(assessment.findings()[0].rule, Rule::WriteProtected);
//! assert_eq!(assessment.findings()[0].reason, "writes to the agent's settings");
//! assert!(judge(Access::Read, "~/.agent/config.yaml", &paths).is_safe());
//! # }
//! ```

pub use milo_guards_core::{Assessment, Finding, Paths, Protected, ProtectedKind, RuleName};

#[cfg(feature = "shell")]
pub use milo_guards_shell as shell;

#[cfg(feature = "code")]
pub use milo_guards_code as code;

#[cfg(feature = "file")]
pub use milo_guards_file as file;

#[cfg(feature = "url")]
pub use milo_guards_url as url;

#[cfg(feature = "secrets")]
pub use milo_guards_secrets as secrets;

/// The README's example, compiled and run with the doctests so it cannot
/// drift from the code. Only rustdoc's doctest pass reads the file, so
/// building this crate never needs the README: a build that vendors only
/// this crate's folder still works.
#[cfg(all(doctest, feature = "shell", feature = "file"))]
#[allow(
    clippy::disallowed_macros,
    reason = "the README include is read by rustdoc's doctest pass only"
)]
#[doc = include_str!("../../../README.md")]
mod readme {}
