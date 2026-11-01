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

#[test]
fn a_filter_is_matched_against_the_short_name_of_git_too() {
    let rows: Vec<(String, Rule)> = [
        "GIT~1", "g*", "G*", "GI*", "*~1", "*1", "GIT~?", "?????", "??????", "*.", "git~1", "*~?",
        "G?T~1",
    ]
    .iter()
    .flat_map(|filter| {
        [
            format!("Get-ChildItem -Force -Filter {filter} | Remove-Item -Recurse -Force"),
            format!("gci -Hidden -Filter {filter} | rm -Recurse -Force"),
            format!("Get-ChildItem -Force -Recurse -Filter {filter} | Remove-Item -Force"),
        ]
    })
    .map(|line| (line, Rule::Delete))
    .collect();
    let rows: Vec<(&str, Rule)> = rows
        .iter()
        .map(|(line, rule)| (line.as_str(), *rule))
        .collect();
    check(Shell::PowerShell, &windows(), &[], &rows);
}

#[test]
fn an_include_is_matched_against_the_long_name_only() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Get-ChildItem -Force -Include g* | Remove-Item -Recurse -Force",
            "Get-ChildItem -Force -Include *~1 | Remove-Item -Recurse -Force",
            "Get-ChildItem -Force -Include ????? | Remove-Item -Recurse -Force",
        ],
        &[],
    );
}

#[test]
fn a_filter_that_cannot_match_the_short_name_stays_everyday() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Get-ChildItem -Force -Filter *.log | Remove-Item -Recurse -Force",
            "Get-ChildItem -Force -Filter *.tmp | Remove-Item -Recurse -Force",
            "Get-ChildItem -Force -Filter go.* | Remove-Item -Recurse -Force",
            "Get-ChildItem -Force -Filter .gitignore | Remove-Item -Recurse -Force",
            "Get-ChildItem -Force -Filter ?? | Remove-Item -Recurse -Force",
        ],
        &[],
    );
}

#[test]
fn a_recursive_hidden_listing_hands_on_git_only_when_a_pattern_can_reach_it() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Get-ChildItem -Include bin,obj -Recurse -Force | Remove-Item -Recurse -Force",
            "Get-ChildItem -Recurse -Force -Directory -Filter node_modules | Remove-Item -Recurse -Force",
            "Get-ChildItem -Force -Recurse -Include *.tmp | Remove-Item",
            "Get-ChildItem -Recurse -Force -Filter *.orig | Remove-Item",
            "Get-ChildItem -Recurse -Hidden -Filter *.bak | Remove-Item -Force",
            "Get-ChildItem -Force -Depth 3 -Include bin,obj | Remove-Item -Recurse -Force",
            "Get-ChildItem -Force -Depth 1 -Filter *.tmp | Remove-Item -Force",
        ],
        &[
            (
                "Get-ChildItem -Force -Recurse -Filter HEAD | Remove-Item -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Force -Recurse -Include config,index | Remove-Item -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Force -Recurse -Filter .git | Remove-Item -Recurse -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Force -Recurse -Include bin,HEAD | Remove-Item -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Force -Recurse -Filter $f | Remove-Item -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Force -Recurse -Include $a,obj | Remove-Item -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Force -Recurse -Filter *.pack | Remove-Item -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem C:\\Users\\me -Force -Recurse -Filter id_rsa | Remove-Item -Force",
                Rule::Delete,
            ),
        ],
    );
}

#[test]
fn a_recursive_hidden_listing_reaches_the_folders_and_objects_below_the_top_of_git() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Get-ChildItem -Force -Recurse -Include bin,obj,Debug | Remove-Item -Recurse -Force",
            "Get-ChildItem -Force -Recurse -Filter node_modules | Remove-Item -Recurse -Force",
            "Get-ChildItem -Force -Recurse -Include *.tmp,*.orig,*.log | Remove-Item -Force",
            "Get-ChildItem -Force -Recurse -Directory -Filter obj | Remove-Item -Recurse -Force",
            "Get-ChildItem -Force -Recurse -Filter Debug | Remove-Item -Recurse -Force",
        ],
        &[
            (
                "Get-ChildItem -Force -Recurse -Filter pack | Remove-Item -Recurse -Force",
                Rule::Delete,
            ),
            (
                "gci -Force -Recurse -Filter pack | rm -r -fo",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Force -Recurse -Include heads | Remove-Item -Recurse -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Force -Recurse -Include tags | Remove-Item -Recurse -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Force -Recurse -Filter remotes | Remove-Item -Recurse -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Force -Recurse -Include origin | Remove-Item -Recurse -Force",
                Rule::Delete,
            ),
            (
                "gci -fo -r -include pack,heads | % { Remove-Item $_.FullName -Recurse -Force }",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Force -Recurse -Filter ?? | Remove-Item -Recurse -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Force -Recurse -Include ?? | Remove-Item -Recurse -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Force -Recurse -Directory -Filter ?? | Remove-Item -Recurse -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Force -Recurse -Directory -Include ?? | Remove-Item -Recurse -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Force -Recurse -Filter 1* | Remove-Item -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Force -Recurse -Filter *7* | Remove-Item -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Force -Recurse -Include [a-f]* | Remove-Item -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Force -Recurse -Filter pack-1* | Remove-Item -Force",
                Rule::Delete,
            ),
        ],
    );
}

#[test]
fn del_s_reaches_the_objects_of_git_by_the_shape_of_their_names() {
    check(
        Shell::Cmd,
        &windows(),
        &[
            "del /s /q *.tmp",
            "del /s /q *.orig",
            "del /s /q *.log",
            "del /s /q *.obj",
            "del /s /q bin",
            "del /s /q obj",
            "del /s /q node_modules",
            "del /s /q Debug",
        ],
        &[
            ("del /s /q 1*", Rule::Delete),
            ("del /s /q *7*", Rule::Delete),
            ("del /s /q ??", Rule::Delete),
            ("del /s /q pack", Rule::Delete),
            ("del /s /q origin", Rule::Delete),
            ("del /s /q ??????~1", Rule::Delete),
            ("del /s /q ab*~1", Rule::Delete),
        ],
    );
}

#[test]
fn a_filter_reads_the_dos_wildcards_of_the_file_system() {
    let rows: Vec<(String, Rule)> = [
        "'<'", "'.gi<'", "'.g>>>'", "'.git>'", "'.git\"'", "'.gi\"t'", "'.gi>t'", "'<.git'", "'.<'",
    ]
    .iter()
    .flat_map(|filter| {
        [
            format!("Get-ChildItem -Force -Filter {filter} | Remove-Item -Recurse -Force"),
            format!("Get-ChildItem -Recurse -Force -Filter {filter} | Remove-Item -Recurse -Force"),
        ]
    })
    .map(|line| (line, Rule::Delete))
    .collect();
    let rows: Vec<(&str, Rule)> = rows
        .iter()
        .map(|(line, rule)| (line.as_str(), *rule))
        .collect();
    check(Shell::PowerShell, &windows(), &[], &rows);
}

#[test]
fn a_recursive_filter_with_dos_wildcards_reaches_the_names_of_git() {
    check(
        Shell::PowerShell,
        &windows(),
        &[],
        &[
            (
                "Get-ChildItem -Recurse -Force -Filter \"HEA<\" | Remove-Item -Recurse -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Recurse -Force -Filter 'HEA>' | Remove-Item -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Recurse -Force -Filter \"a<\" | Remove-Item -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Recurse -Force -Filter \"o<\" | Remove-Item -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Recurse -Force -Filter 'HEAD\"' | Remove-Item -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Recurse -Force -Filter 'conf>>>' | Remove-Item -Force",
                Rule::Delete,
            ),
        ],
    );
}

#[test]
fn an_include_reads_the_dos_characters_as_plain_ones() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Get-ChildItem -Force -Include '<' | Remove-Item -Recurse -Force",
            "Get-ChildItem -Force -Include '.gi<' | Remove-Item -Recurse -Force",
            "Get-ChildItem -Recurse -Force -Include 'HEA<' | Remove-Item -Force",
            "Get-ChildItem -Recurse -Force -Include 'HEA>' | Remove-Item -Force",
        ],
        &[],
    );
}

#[test]
fn a_filter_with_dos_characters_that_cannot_reach_git_stays_everyday() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Get-ChildItem -Recurse -Force -Filter '*.t>' | Remove-Item -Force",
            "Get-ChildItem -Recurse -Force -Filter 'node_modules\"' | Remove-Item -Force",
            "Get-ChildItem -Recurse -Force -Filter 'x<.tmp' | Remove-Item -Force",
            "Get-ChildItem -Force -Filter 'b>>n' | Remove-Item -Force",
        ],
        &[],
    );
}

#[test]
fn del_s_reads_the_dos_wildcards() {
    check(
        Shell::Cmd,
        &windows(),
        &[
            "del /s /q \"foo<.obj\"",
            "del /s /q \"a>>.txt\"",
            "del /s /q \"*.ob>\"",
            "del /s /q main.obj",
        ],
        &[
            ("del /s /q \"HEA>\"", Rule::Delete),
            ("del /s /q \"HEA<\"", Rule::Delete),
            ("del /s /q \"<\"", Rule::Delete),
            ("del /s /q \"conf>>>\"", Rule::Delete),
            ("del /s /q \"mai<\"", Rule::Delete),
        ],
    );
}

#[test]
fn stash_is_one_of_the_names_git_holds() {
    check(
        Shell::PowerShell,
        &windows(),
        &[],
        &[
            (
                "Get-ChildItem -Recurse -Force -Filter stash | Remove-Item -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Recurse -Force -Filter *stash* | Remove-Item -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Recurse -Force -Include stash | Remove-Item -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Recurse -Hidden -Filter sta* | Remove-Item -Force",
                Rule::Delete,
            ),
        ],
    );
    check(
        Shell::Cmd,
        &windows(),
        &[],
        &[
            ("del /s /q stash", Rule::Delete),
            ("del /s /q *stash*", Rule::Delete),
            ("del /s /q STASH", Rule::Delete),
            ("del /s /q sta??", Rule::Delete),
        ],
    );
}

#[test]
fn every_dot_before_a_wildcard_can_match_nothing_in_a_filter() {
    let long = "*.".repeat(25_000);
    let long = format!("Get-ChildItem -Recurse -Force -Filter {long} | Remove-Item -Force");
    let mut lines: Vec<String> = vec![
        "Get-ChildItem -Recurse -Force -Filter HEAD.*.* | Remove-Item -Force".into(),
        "Get-ChildItem -Force -Filter *.*.*.* | Remove-Item -Recurse -Force".into(),
        long,
    ];
    for filter in [
        "config.*.*",
        "config.?.?",
        "objects.*.*",
        "HEAD.?.*",
        "*.?.?",
        "*.*.*.*",
    ] {
        for flags in [
            "-Recurse -Force",
            "-Recurse -Force -Depth 3",
            "-Hidden -Recurse",
            "-Recurse -Attributes Hidden",
        ] {
            lines.push(format!(
                "Get-ChildItem {flags} -Filter {filter} | Remove-Item -Recurse -Force"
            ));
        }
    }
    let rows: Vec<(&str, Rule)> = lines
        .iter()
        .map(|line| (line.as_str(), Rule::Delete))
        .collect();
    check(Shell::PowerShell, &windows(), &[], &rows);
}

#[test]
fn del_s_reads_every_dot_before_a_wildcard_as_a_dos_dot() {
    check(
        Shell::Cmd,
        &windows(),
        &[],
        &[
            ("del /s /q HEAD.*.*", Rule::Delete),
            ("del /s /q config.*.*", Rule::Delete),
            ("del /s /q *.?.?", Rule::Delete),
            ("del /s /q *.*.*.*", Rule::Delete),
        ],
    );
}

#[test]
fn a_dot_before_a_literal_stays_a_plain_dot() {
    check(
        Shell::Cmd,
        &windows(),
        &[
            "del /s /q *.obj",
            "del /s /q *.tmp",
            "del /s /q main.obj",
            "del /s /q foo.*",
            "del /s /q test.*.js",
        ],
        &[],
    );
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Get-ChildItem -Recurse -Force -Filter *.obj | Remove-Item -Force",
            "Get-ChildItem -Recurse -Force -Filter *.tmp | Remove-Item -Force",
            "Get-ChildItem -Recurse -Force -Filter test.*.js | Remove-Item -Force",
        ],
        &[],
    );
}
