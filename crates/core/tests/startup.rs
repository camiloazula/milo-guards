//! Files a tool runs on its own, as the path model says it: a write into one
//! is `Sensitive` with the kind `Startup`, found at any depth in a workspace
//! folder; `place`, which a read or a delete asks, still says the workspace's
//! own. The cases, each a spelling a review could try, are in
//! `tests/cases/startup.cases`.

mod common;

#[test]
fn a_write_into_a_file_a_tool_runs_is_found_by_every_spelling() {
    common::cases::check("startup");
}
