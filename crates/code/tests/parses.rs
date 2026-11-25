//! Which code parses whole: the grammar reads it with no error. The cases
//! of each language are in `tests/cases/parses.cases`.

mod common;

#[test]
fn code_parses_when_its_grammar_reads_it_with_no_error() {
    common::cases::check("parses");
}
