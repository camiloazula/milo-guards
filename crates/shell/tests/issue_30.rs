//! A Windows wildcard part is read as Windows names it, and a pattern can
//! match `.git` by its 8.3 short name.

mod common;

use common::{check, windows};
use milo_guards_shell::{Rule, Shell};

#[test]
fn a_wildcard_part_is_trimmed_like_a_last_part() {
    check(
        Shell::Cmd,
        &windows(),
        &[
            "del *.obj",
            "del /q build\\*.*",
            "del /s /q *gitx.",
            "del /s /q src\\*git.",
            "rd /s /q *\\bin.",
            "del /s /q *git.\\bin",
            // The part after `.git`'s own is no short name of an entry.
            "del /s /q *\\GIT~1",
            "del /s /q *\\G*",
            "del /s /q *\\*1",
        ],
        &[
            ("del /s /q *git.", Rule::Delete),
            ("del /s /q \"*git \"", Rule::Delete),
            ("del /s /q *git...", Rule::Delete),
            ("del /s /q \"?git. .\"", Rule::Delete),
            ("del /s /q ????.", Rule::Delete),
            ("del /s /q *git.\\objects", Rule::Delete),
            ("del /s /q *git.\\objects.", Rule::Delete),
            ("del /s /q *\\obj*s.", Rule::Delete),
            ("del /s /q \"*\\HEA? \"", Rule::Delete),
            // Only the trimming of a wildcard part makes these reach `.git`.
            ("del /s /q *.", Rule::Delete),
            ("del *.", Rule::Delete),
            ("del /s /q ?*.", Rule::Delete),
            ("del /s /q *.*.", Rule::Delete),
            ("del /s /q \"*.* \"", Rule::Delete),
            ("del /s /q *\\obj*.", Rule::Delete),
            ("del /s /q \"*\\H?AD \"", Rule::Delete),
            ("del /s /q *.\\objects", Rule::Delete),
            ("del /s /q *gi?.\\objects", Rule::Delete),
            ("rd /s /q *git.", Rule::Delete),
        ],
    );
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Remove-Item -Recurse -Force *gitx.",
            "Remove-Item -Recurse -Force 'src\\*git.'",
            "Remove-Item -Recurse -Force *\\bin.",
            "Remove-Item -Recurse -Force *\\G*",
            "Remove-Item -Recurse -Force *\\GIT~1",
        ],
        &[
            ("Remove-Item -Recurse -Force *git.", Rule::Delete),
            ("Remove-Item -Recurse -Force '*git '", Rule::Delete),
            ("Remove-Item -Recurse -Force *git.\\objects", Rule::Delete),
            ("Remove-Item -Recurse -Force *\\obj*s.", Rule::Delete),
            ("Remove-Item -Recurse -Force *.", Rule::Delete),
            ("Remove-Item -Recurse -Force *\\obj*.", Rule::Delete),
        ],
    );
}

#[test]
fn a_pattern_can_match_the_short_name_of_git() {
    check(
        Shell::Cmd,
        &windows(),
        &[
            "del *.obj",
            "del /q build\\*.*",
            "del /s /q GIT~",
            "del /s /q GIT~x",
            "del /s /q GIT~1x",
            "del /s /q GI~?",
            "del /s /q GITX~?",
            "del /s /q PROGRA~?",
            "del /s /q GITHUB~?",
            "del /s /q GITIGN~?",
            "del /s /q *~x",
            "del /s /q src\\GIT~?",
            "del /s /q src\\*~1",
            "del /s /q *~1\\bin",
            "del /s /q GIT~?.txt",
            "del /s /q GI??~1",
            "del /s /q GI?????~1",
            "del /s /q GI[g-z]???~1",
            // No `~`, so no hashed short name: these are ordinary patterns.
            "del /s /q *2024*",
            "del /s /q *a*",
            "del /s /q *cafe*",
            // No literal `~`: `cmd` skips a folder a wildcard matches.
            "del /s /q git*",
            "del /s /q G*",
            "del /s /q *1",
            "del /s /q *2",
            "del /s /q Git*",
            "del /s /q ?????",
            "del /s /q git*\\objects",
        ],
        &[
            ("del /s /q GIT~?", Rule::Delete),
            ("del /s /q git~*", Rule::Delete),
            ("del /s /q GIT~[0-9]", Rule::Delete),
            ("del /s /q GIT~??", Rule::Delete),
            ("del /s /q G?T~1", Rule::Delete),
            ("del /s /q *~1", Rule::Delete),
            ("del /s /q *~?", Rule::Delete),
            ("del /s /q *T~1", Rule::Delete),
            ("del /s /q GI????~1", Rule::Delete),
            ("del /s /q GI????~?", Rule::Delete),
            ("del /s /q GI3F2?~1", Rule::Delete),
            ("del /s /q GI[0-9a-f]???~1", Rule::Delete),
            ("del /s /q GIT~?\\objects", Rule::Delete),
            ("del /s /q *~1\\objects", Rule::Delete),
            ("del /s /q *~1\\", Rule::Delete),
            ("del /s /q GIT~?.", Rule::Delete),
            ("rd /s /q GIT~?", Rule::Delete),
        ],
    );
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Remove-Item -Recurse -Force PROGRA~?",
            "Remove-Item -Recurse -Force src\\GIT~?",
            "Remove-Item -Recurse -Force *2024*",
            "Remove-Item -Recurse -Force *a*",
            "Remove-Item -Recurse -Force *cafe*",
            // No literal `~`: PowerShell matches no short name.
            "Remove-Item -Recurse -Force git*",
            "Remove-Item -Recurse -Force G*",
            "Remove-Item -Recurse -Force *1",
            "Remove-Item -Recurse -Force *2",
            "Remove-Item -Recurse -Force Git*",
            "Remove-Item -Recurse -Force git*\\objects",
        ],
        &[
            ("Remove-Item -Recurse -Force GIT~?", Rule::Delete),
            ("Remove-Item -Recurse -Force *~1", Rule::Delete),
            ("Remove-Item -Recurse -Force GIT~?\\objects", Rule::Delete),
        ],
    );
}
