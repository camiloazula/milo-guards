//! The fuzz target `script`: each input held to the promises of
//! `Target::Script` (`crates/guards/tests/common/promises.rs`).

#![no_main]
#![allow(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "the harness's macro writes an input to a file when it is asked to debug one"
)]

use fuzz::promises::{check, Target};

libfuzzer_sys::fuzz_target!(|data: &[u8]| check(Target::Script, data));
