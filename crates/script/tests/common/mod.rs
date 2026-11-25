//! What the tests share: the directories code is judged against, and (in
//! [`cases`]) the runner of the case files in `tests/cases`.

#![allow(dead_code, unreachable_pub, unused_imports)]

pub mod cases;

pub use milo_guards_core::testing::{macos, posix, windows};
