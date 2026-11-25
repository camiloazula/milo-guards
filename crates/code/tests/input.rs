//! Whether code may hand a program it starts something to read on its
//! input. The cases are in `tests/cases/input.cases`.

mod common;

#[test]
fn code_that_may_give_a_program_input_says_so() {
    common::cases::check("input");
}
