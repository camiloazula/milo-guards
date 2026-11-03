//! zsh's precommand modifiers and `coproc` run the command after them, so
//! that command is judged like one that stands alone, and decides the
//! line's effect. A modifier turns zsh's own flags off, never bash's.
//!
//! The lines and their answers are in `tests/cases/precommand_modifiers.cases`.

mod common;

use common::posix;
use milo_guards_shell::{explain, Shell};

#[test]
fn every_case_holds() {
    common::cases::check("precommand_modifiers");
}

/// The programs `explain` reads in `line`, in order.
fn programs(line: &str) -> Vec<String> {
    explain(line, Shell::Posix, &posix())
        .units
        .iter()
        .map(|unit| unit.program.clone())
        .collect()
}

#[test]
fn the_brace_that_closes_a_coproc_group_is_no_program() {
    assert_eq!(programs("coproc { ls; }"), ["ls"]);
    assert_eq!(programs("coproc NAME { { ls; }; }"), ["ls"]);
    assert_eq!(programs("coproc NAME {\n ls\n}"), ["ls"]);
    // A nested script closes its own groups.
    assert_eq!(programs("eval 'coproc { ls; }'"), ["eval", "ls"]);
    assert_eq!(programs("bash -c 'coproc { ls; }'"), ["bash", "ls"]);
    // A `}` that closes no group a `coproc` opened is a program.
    assert_eq!(programs("coproc { ls; }; bash -c '}'"), ["ls", "bash", "}"]);
    assert_eq!(programs("ls; }"), ["ls", "}"]);
}
