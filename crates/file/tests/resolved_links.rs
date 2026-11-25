//! The links the caller has resolved (`Paths::links`): a read or a write
//! through one is judged where it lands, a write into a protected or a
//! sensitive place there included. The cases are in
//! `tests/cases/resolved_links.cases`.

mod common;

#[test]
fn a_path_through_a_link_is_judged_where_it_lands() {
    common::cases::check("resolved_links");
}
