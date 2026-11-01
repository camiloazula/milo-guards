//! A filtered or attribute-selected PowerShell listing piped into a delete
//! reaches `.git` when it lists hidden entries and the filter can match it,
//! and cmd's `del /s` from the workspace root reaches `.git`'s files.

mod common;

use common::{check, windows};
use milo_guards_shell::{Rule, Shell};

#[test]
fn a_filtered_hidden_listing_piped_into_a_delete_reaches_the_history() {
    check(
        Shell::PowerShell,
        &windows(),
        &[],
        &[
            (
                "Get-ChildItem -Force -Filter .git | Remove-Item -Recurse -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Force -Filter *git | Remove-Item -Recurse -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Force -Recurse -Filter .git | Remove-Item -Recurse -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Include .git -Recurse -Force | Remove-Item -Recurse -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Attributes Hidden | Remove-Item -Recurse -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Attributes H | Remove-Item -Recurse -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Attributes Hidden,Directory | Remove-Item -Recurse -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Attributes Directory,Hidden | Remove-Item -Recurse -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Attributes Hidden -Recurse | Remove-Item -Recurse -Force",
                Rule::Delete,
            ),
            (
                "gci -Hidden -Filter .git | rm -Recurse -Force",
                Rule::Delete,
            ),
            (
                "gci -Force -Include .g* -Recurse | ri -Recurse -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Force -Filter .git | Remove-Item",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Force -Exclude x -Depth 1 | Remove-Item -Recurse -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Force -Recurse -Filter HEAD | Remove-Item -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Force -Recurse -Include config,index | Remove-Item -Force",
                Rule::Delete,
            ),
        ],
    );
}

#[test]
fn a_filter_that_cannot_match_a_hidden_folder_stays_everyday() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Get-ChildItem -Filter *.log | Remove-Item",
            "Get-ChildItem -Recurse -Include *.tmp | Remove-Item",
            "Get-ChildItem -Force -Filter *.log | Remove-Item",
            "Get-ChildItem -Force -Filter *.tmp | Remove-Item -Force",
            "Get-ChildItem -Hidden -Filter *.log | Remove-Item",
            "Get-ChildItem -Attributes Directory -Filter *.tmp | Remove-Item",
            "Get-ChildItem -Attributes Hidden -Filter *.tmp | Remove-Item",
            "Get-ChildItem -Force -Exclude *.rs -Filter *.tmp | Remove-Item -Force",
            "Get-ChildItem -Force src -Filter .git | Remove-Item -Recurse -Force",
            "Get-ChildItem -Force -Filter *. | Remove-Item -Recurse -Force",
            "Get-ChildItem -Recurse -Depth 2 -Filter *.obj | Remove-Item",
            "Get-ChildItem -Filter .git | Remove-Item",
            "Get-ChildItem -Include .git -Recurse | Remove-Item",
            "Get-ChildItem -Exclude *.rs -Recurse | Remove-Item",
        ],
        &[],
    );
}

#[test]
fn the_spellings_of_the_parameters_and_values_are_read() {
    check(
        Shell::PowerShell,
        &windows(),
        &[],
        &[
            (
                "Get-ChildItem -Force -Filter .GIT | Remove-Item -Recurse -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Force -Filter '[.]git' | Remove-Item -Recurse -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Force -Filter .gi? | Remove-Item -Recurse -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Force -Filter .git. | Remove-Item -Recurse -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Force -Filter GIT~1 | Remove-Item -Recurse -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Force -Filter:.git | Remove-Item -Recurse -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Fo -Fi .git | Remove-Item -Recurse -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Force -Inc .git -r | Remove-Item -Recurse -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Force -Include @('.git') | Remove-Item -Recurse -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Force -Filter $f | Remove-Item -Recurse -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Force -Filter .git -ErrorAction 0 | Remove-Item -Recurse -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Force -Filter .git -Path src, . | Remove-Item -Recurse -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Force -Filter .git .. | Remove-Item -Recurse -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Attributes:Hidden | Remove-Item -Recurse -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Attributes Hidden+Directory | Remove-Item -Recurse -Force",
                Rule::Delete,
            ),
            (
                "gci -Attr Hidden, Directory | rm -r",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Force -Exclude *.rs | Remove-Item -Recurse -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Force -Depth 1 -Filter *.tmp | Remove-Item -Force",
                Rule::Delete,
            ),
            (
                "gci -Force -Filter .git | % { Remove-Item $_ -Recurse -Force }",
                Rule::Delete,
            ),
            (
                "gci -Force -Filter .git | ForEach-Object { Remove-Item $_.FullName -Recurse -Force }",
                Rule::Delete,
            ),
            (
                "gci -fo -filter .git | ri -r",
                Rule::Delete,
            ),
        ],
    );
}

#[test]
fn del_s_from_the_workspace_takes_the_files_of_git_when_the_pattern_can_match_them() {
    check(
        Shell::Cmd,
        &windows(),
        &[],
        &[
            ("del /s /q *.", Rule::Delete),
            ("del /s /q HEAD", Rule::Delete),
            ("del /s /q head", Rule::Delete),
            ("del /s /q config", Rule::Delete),
            ("del /s /q index", Rule::Delete),
            ("del /s HEAD", Rule::Delete),
            ("del /S /Q HEAD", Rule::Delete),
            ("del /q /s /f HEAD", Rule::Delete),
            ("erase /s /q index", Rule::Delete),
            ("del /s /q \"HEAD\"", Rule::Delete),
            ("del /s /q .\\HEAD", Rule::Delete),
            ("del /s /q %CD%\\HEAD", Rule::Delete),
            ("del /s /q src\\..\\HEAD", Rule::Delete),
            ("del /s /q C:\\Users\\me\\dev\\repo\\HEAD", Rule::Delete),
            ("del /s /q x.txt,HEAD", Rule::Delete),
            ("del /s /q *.obj config", Rule::Delete),
            ("del /s /q /a:h HEAD", Rule::Delete),
            ("del /s /q H*", Rule::Delete),
            ("del /s /q ?????", Rule::Delete),
            ("del /s /q packed-refs", Rule::Delete),
            ("del /s /q ORIG_HEAD", Rule::Delete),
            ("del /s /q COMMIT_EDITMSG", Rule::Delete),
            ("del /s /q *.pack", Rule::Delete),
            ("del /s /q pack-*", Rule::Delete),
            ("cd .. & del /s /q HEAD", Rule::Delete),
            ("del /s /q ..\\HEAD", Rule::Delete),
        ],
    );
}

#[test]
fn del_s_stays_everyday_when_it_cannot_reach_the_files_of_git() {
    check(
        Shell::Cmd,
        &windows(),
        &[
            "del /s /q *.obj",
            "del /s /q *.tmp",
            "del /s /q *.pyc",
            "del /s /q *.exe *.dll",
            "del /s /q Thumbs.db",
            "del /q /s *.log",
            "del /s /q src\\HEAD",
            "del /s /q src\\*.",
            "del /s /q C:\\Users\\me\\dev\\repo\\src\\HEAD",
            "cd src & del /s /q HEAD",
            "del /q HEAD",
            "del HEAD",
            "del /f /q config",
            "rd /s /q target",
        ],
        &[],
    );
}

#[test]
fn del_s_reads_cmds_own_wildcard_rules() {
    check(
        Shell::Cmd,
        &windows(),
        &[],
        &[
            ("del /s /q main.*", Rule::Delete),
            ("del /s /q master.*", Rule::Delete),
            ("del /s /q HEAD.*", Rule::Delete),
            ("del /s /q index.*", Rule::Delete),
            ("del /s /q config.*", Rule::Delete),
            ("del /s /q main.?", Rule::Delete),
            ("del /s /q HEAD?", Rule::Delete),
            ("del /s /q config?", Rule::Delete),
            ("del /s /q index?", Rule::Delete),
            ("del /s /q ????????", Rule::Delete),
            ("del /s /q main?.*", Rule::Delete),
            ("del /s /q HEA??.", Rule::Delete),
            ("del /s /q mai??.*", Rule::Delete),
            ("del /s /q ma?n?.?", Rule::Delete),
        ],
    );
}

#[test]
fn del_s_tries_the_short_names_of_git_files() {
    check(
        Shell::Cmd,
        &windows(),
        &[],
        &[
            ("del /s /q *.pac", Rule::Delete),
            ("del /s /q *.PAC", Rule::Delete),
            ("del /s /q COMMIT~1", Rule::Delete),
            ("del /s /q PACKED~1", Rule::Delete),
            ("del /s /q DESCRI~1", Rule::Delete),
            ("del /s /q ORIG_H~1", Rule::Delete),
            ("del /s /q FETCH_~1", Rule::Delete),
            ("del /s /q MERGE_~1", Rule::Delete),
            ("del /s /q REBASE~1", Rule::Delete),
            ("del /s /q REBASE~2", Rule::Delete),
            ("del /s /q SEQUEN~1", Rule::Delete),
            ("del /s /q WORKTR~1", Rule::Delete),
            ("del /s /q PACK-0~1.PAC", Rule::Delete),
            ("del /s /q PACK-0~1.IDX", Rule::Delete),
            ("del /s /q PACK-0~1.*", Rule::Delete),
        ],
    );
}

#[test]
fn del_s_with_cmds_rules_keeps_the_everyday_cleans_safe() {
    check(
        Shell::Cmd,
        &windows(),
        &[
            "del /s /q main.obj",
            "del /s /q *.obj",
            "del /s /q *.log",
            "del /s /q *.orig",
            "del /s /q foo.*",
            "del /s /q foo?.*",
            "del /s /q a?.txt",
            "del /s /q mainx.*",
            "del /s /q ??.obj",
            "del /s /q build.?",
        ],
        &[],
    );
}
