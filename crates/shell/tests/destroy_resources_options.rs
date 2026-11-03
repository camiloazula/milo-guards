//! How a line that may destroy resources is read: the options before the
//! command (with a value or without) are skipped to find it, a rehearsal or a
//! help flag makes it safe only where the tool reads it as one, a word only
//! known when it runs is unknown where a verb could be and split where the
//! shell splits it, a loop removes every item it reaches, and kubectl's
//! replica count is read as kubectl reads it.
//!
//! The lines and their answers are in
//! `tests/cases/destroy_resources_options.cases`.

mod common;

#[test]
fn every_case_holds() {
    common::cases::check("destroy_resources_options");
}
