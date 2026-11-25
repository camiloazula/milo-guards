//! Whether code hands a shell a list of words. The cases are in
//! `tests/cases/shell_list.cases`.

mod common;

#[test]
fn code_that_hands_a_shell_a_list_says_so() {
    common::cases::check("shell_list");
}
