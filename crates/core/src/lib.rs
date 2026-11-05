//! What every guard shares.
//!
//! A guard reads what an agent is about to do and says whether it is safe
//! to do without asking, or risky and why. This crate holds the parts of
//! that which do not depend on what is being read:
//!
//! - the verdict: [`Assessment`] is [`Safe`](Assessment::Safe) or
//!   [`Risky`](Assessment::Risky) with a [`Finding`] for each reason, and
//!   each finding names a rule of the guard's own enum, which implements
//!   [`RuleName`];
//! - the directories everything is judged against: [`Paths`], with the
//!   files the caller gates with ([`Protected`]);
//! - the path model: [`Resolver`] says where a path spelled out as text
//!   lands ([`Place`]), by its spelling alone, for POSIX and Windows
//!   ([`Flavour`]);
//! - for guard crates, helpers that take a path's spelling apart
//!   ([`spelling`]);
//! - behind the `testing` feature, the table checker and sample
//!   directories guards test themselves with (`testing`).
//!
//! It depends on nothing beyond `std`, and does no I/O: nothing here reads
//! the file system or the environment.
//!
//! ```
//! use milo_guards_core::{Flavour, Paths, Place, Resolver, Spelling};
//!
//! let paths = Paths::new("/home/me/work/repo", "/home/me", ["/home/me/work/repo"]);
//! let resolver = Resolver::new(&paths);
//! let place = |path| resolver.place(Spelling::Plain(path), Flavour::Posix);
//! assert_eq!(place("src/../target"), Place::Inside);
//! assert_eq!(place("/home/me"), Place::Home { exact: true });
//! assert_eq!(place("/etc/hosts"), Place::Top("a system folder"));
//! ```

mod paths;
mod place;
mod resolve;
pub mod spelling;
#[cfg(any(feature = "testing", test))]
pub mod testing;
mod verdict;

pub use paths::{Paths, Protected, ProtectedKind};
pub use place::{Place, Sensitivity};
pub use resolve::{Flavour, Resolver, Spelling};
pub use verdict::{Assessment, Finding, RuleName};

/// The README's example, compiled and run with the doctests so it cannot
/// drift from the code. Only rustdoc's doctest pass reads the file, so
/// building this crate never needs the README.
#[cfg(doctest)]
#[allow(
    clippy::disallowed_macros,
    reason = "the README include is read by rustdoc's doctest pass only"
)]
#[doc = include_str!("../README.md")]
mod readme {}
