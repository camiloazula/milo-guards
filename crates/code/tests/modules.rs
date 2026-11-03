//! What the crate says of a module specifier and of a coding declaration
//! outside the code it reads (the cases are in `tests/cases/modules.cases`),
//! and the shape of an argument.

mod common;

use milo_guards_code::{Arg, MAX_DEPTH, MAX_LEN, MAX_TREE_DEPTH};

#[test]
fn a_specifier_and_a_coding_declaration_are_read_as_the_cases_say() {
    common::cases::check("modules");
}

#[test]
fn an_argument_is_its_value_or_the_source_of_what_is_not_known() {
    let known = Arg::Known("/home/me".to_string());
    assert_eq!(known.known(), Some("/home/me"));
    assert_eq!(known.text(), "/home/me");

    let unknown = Arg::Unknown("input()".to_string());
    assert_eq!(unknown.known(), None);
    assert_eq!(unknown.text(), "input()");

    // A path somewhere in a folder is not a value, but it has a source.
    let below = Arg::Below {
        folder: "/home/me/.ssh/".to_string(),
        source: "'/home/me/.ssh/id_' + n".to_string(),
    };
    assert_eq!(below.known(), None);
    assert_eq!(below.text(), "'/home/me/.ssh/id_' + n");
}

#[test]
fn the_limits_are_the_ones_a_caller_holds_code_to() {
    assert_eq!(MAX_DEPTH, 8);
    assert_eq!(MAX_TREE_DEPTH, 400);
    assert_eq!(MAX_LEN, 64 * 1024);
}
