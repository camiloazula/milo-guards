//! Which text cmd's grammar reads as a comment cmd itself skips: the `rem`
//! command, or `::` at the start of a statement. Any other comment the
//! grammar reads is text cmd runs, read as the command it is or judged
//! unreadable.
//!
//! The lines and their answers are in `tests/cases/cmd_comments.cases`; the
//! time long lines with the `'VBS` marker take is in `tests/timing.rs`.

mod common;

use common::lines::VBS_MARKERS;
use common::windows;
use milo_guards_shell::{classify, Assessment, Rule, Shell};

#[test]
fn every_case_holds() {
    common::cases::check("cmd_comments");
}

#[test]
fn long_lines_with_the_vbs_marker_delete_the_root_of_the_disk() {
    // Each is the command cmd runs, however many markers it holds.
    for (what, line) in VBS_MARKERS {
        let assessment = classify(&line(64 * 1024), Shell::Cmd, &windows());
        let Assessment::Risky(found) = &assessment else {
            panic!("{what}: safe");
        };
        assert!(
            found
                .first()
                .is_some_and(|finding| finding.rule == Rule::Delete
                    && finding.reason == "deletes the root of the disk"),
            "{what}: {found:?}"
        );
    }
}
