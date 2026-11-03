//! Deleting containers, cluster objects, cloud resources or an
//! infrastructure stack is `destroy_resources`; listing, describing,
//! creating and rehearsing are safe, and a command only known when it runs is
//! `unknown`. How the words of such a line are read (options, rehearsals,
//! variables, loops) is in `destroy_resources_options.rs`.
//!
//! The lines and their answers are in `tests/cases/destroy_resources.cases`;
//! here are what `sls` adds to a line's effect and the target a prompt can
//! show.

mod common;

use common::{posix, windows};
use milo_guards_shell::{classify, effect, Shell};

#[test]
fn every_case_holds() {
    common::cases::check("destroy_resources");
}

/// Whatever `git log` itself reads as, the `sls` alias adds nothing to it.
#[test]
fn sls_in_powershell_adds_nothing_to_what_a_line_reads() {
    assert_eq!(
        effect(
            "git log --oneline | sls remove",
            Shell::PowerShell,
            &windows()
        ),
        effect(
            "git log --oneline | Select-String remove",
            Shell::PowerShell,
            &windows()
        )
    );
}

#[test]
fn a_target_a_prompt_can_show() {
    let assessment = classify("kubectl delete namespace prod", Shell::Posix, &posix());
    assert_eq!(
        assessment.findings()[0].target.as_deref(),
        Some("namespace")
    );
}
