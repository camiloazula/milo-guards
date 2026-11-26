//! What the front door's tests share: the promises every entry point keeps
//! for any input ([`promises`]), and the case files of every guard as their
//! inputs ([`seeds`]). Both are the fuzz targets' too: `tools/fuzz` includes
//! them by their paths.

pub mod promises;
pub mod seeds;
