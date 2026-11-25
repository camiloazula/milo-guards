//! Code that starts a program says the command line, for the shell guard.
//! The cases are in `tests/cases/run_program.cases`.

mod common;

#[test]
fn a_program_the_code_starts_is_run_program_with_its_command_line() {
    common::cases::check("run_program");
}

/// A program run from a directory only known when the code runs is run from
/// a word only known when it runs: the second finding, which a case line
/// cannot name.
#[test]
fn a_program_run_from_a_directory_only_known_when_it_runs_moves_to_an_unknown_word() {
    use milo_guards_script::{judge, Language, Rule};
    let code = "import os, sys\nos.chdir(sys.argv[1])\nos.system('ls')";
    let assessment = judge(Language::Python, code, &common::posix());
    let targets: Vec<Option<&str>> = assessment
        .findings()
        .iter()
        .filter(|finding| finding.rule == Rule::RunProgram)
        .map(|finding| finding.target.as_deref())
        .collect();
    // From where it started, and from where it moved to.
    assert_eq!(
        targets,
        [Some("ls"), Some("cd -- \"$UNKNOWN\" && sh -c ls")],
        "{assessment:?}"
    );
}
