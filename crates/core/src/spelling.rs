//! Helpers for guards that read how a path is spelled before they hand it
//! to the [`Resolver`](crate::Resolver).
//!
//! These are for guard crates, not for callers: a caller gives a guard its
//! [`Paths`](crate::Paths) and reads the answer. A guard uses these where its
//! input's own syntax needs the spelling of a path taken apart first, and
//! leaves everything else to the resolver. They are kept out of the crate
//! root so that the root holds only what a caller or a guard's types need.
//!
//! - [`parts`]: the parts of a relative path, with `.` and `..` applied;
//! - [`device`]: the device a path names, by its spelling;
//! - [`glob`]: wildcard patterns in a path.

pub mod glob;

pub use crate::resolve::{device, network, parts, verbatim};
