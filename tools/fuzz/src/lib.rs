//! Fuzz targets for every entry point of the guards, and the runner that
//! seeds and runs them (`just fuzz`, CONTRIBUTING.md).
//!
//! Each target is a program of two lines in `src/bin`, built by cargo-fuzz
//! with `libFuzzer` and a nightly Rust (`rust-toolchain.toml` here names
//! it): it hands each input `libFuzzer` makes to [`promises::check`], which
//! panics on an input that breaks a promise of its entry point. The
//! promises are the gate's own: this package includes
//! `crates/guards/tests/common/promises.rs` by its path, and the gate's
//! `tests/promises.rs` holds them on the case lines changed at random, so
//! both hold one list. The seeds of a target are the text of every case of
//! the guard it fuzzes ([`seeds`], included the same way).
//!
//! It is a tool of the repository, not a guard: [`run`] starts cargo-fuzz,
//! which no crate under `crates/` may, and it is never published. It never
//! runs an input in a shell or an interpreter: a target only calls the
//! guards' functions, which run nothing.

#[path = "../../../crates/guards/tests/common/promises.rs"]
pub mod promises;
pub mod run;
#[path = "../../../crates/guards/tests/common/seeds.rs"]
pub mod seeds;
