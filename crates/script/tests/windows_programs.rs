//! On a Windows machine, a command run in a shell is the line as the code
//! wrote it, for cmd, and a program its words quoted for cmd. The cases are
//! in `tests/cases/windows_programs.cases`.

mod common;

#[test]
fn a_program_on_a_windows_machine_is_a_line_for_cmd() {
    common::cases::check("windows_programs");
}

/// A program cmd cannot carry has no target: the `unknown` beside it says
/// why, which a case line cannot show of the target.
#[test]
fn a_program_cmd_cannot_carry_has_no_target() {
    use milo_guards_script::{judge, Language, Rule};
    let code = "import subprocess\nsubprocess.run([\x27echo\x27, \x27100%\x27])";
    let assessment = judge(Language::Python, code, &common::windows());
    let program = assessment
        .findings()
        .iter()
        .find(|finding| finding.rule == Rule::RunProgram);
    assert_eq!(
        program.map(|finding| finding.target.as_deref()),
        Some(None),
        "{assessment:?}"
    );
}
