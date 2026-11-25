//! Code that opens a path through a link the caller has resolved
//! (`Paths::links`): it is judged where the link lands. The cases are in
//! `tests/cases/resolved_links.cases`.

mod common;

#[test]
fn a_path_through_a_link_is_judged_where_it_lands() {
    common::cases::check("resolved_links");
}
