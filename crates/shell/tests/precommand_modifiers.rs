//! zsh's precommand modifiers and `coproc` run the command after them, so
//! that command is judged like one that stands alone, and decides the
//! line's effect. A modifier turns zsh's own flags off, never bash's.
//!
//! The lines and their answers are in `tests/cases/precommand_modifiers.cases`.

mod common;

#[test]
fn every_case_holds() {
    common::cases::check("precommand_modifiers");
}
