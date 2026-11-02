//! Which names a Windows wildcard matches. Windows has no hidden dot names,
//! so `*git` matches `.git`, `*.*` is every entry, and a wildcard part is
//! trimmed of its trailing dots and spaces like a last part; a pattern can
//! match `.git` by its 8.3 short name. A listing piped into a delete is
//! judged as the delete of its pattern: a filtered or attribute-selected
//! PowerShell listing reaches `.git` when it lists hidden entries and its
//! filter can match a name there (the file system's short names and DOS
//! wildcards included), and cmd's `del /s` from the workspace reaches the
//! files of `.git` its pattern can match, by cmd's own wildcard rules.

mod common;

use common::{check, classify, windows};
use milo_guards_shell::{Paths, Rule, Shell};

#[test]
fn a_windows_wildcard_can_match_a_dot_name() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Remove-Item -Recurse *.tmp",
            "Remove-Item -Recurse -Force *.TMP",
            "Remove-Item -Recurse -Force *gitx",
            "Remove-Item -Recurse -Force ?git2",
            "Remove-Item -Recurse -Force '[!x]git'",
            "Remove-Item -Recurse -Force *\\bin, *\\obj",
            "Remove-Item -Recurse -Force src\\*\\bin",
            "Remove-Item -Recurse -Force src\\*git",
            "Remove-Item -Recurse -Force node_modules\\*\\dist",
            "Remove-Item -Recurse -Force *\\*.o",
        ],
        &[
            ("Remove-Item -Recurse -Force *git", Rule::Delete),
            ("Remove-Item -Recurse -Force ?git", Rule::Delete),
            ("Remove-Item -Recurse -Force *GIT", Rule::Delete),
            ("Remove-Item -Recurse -Force '[!.]git'", Rule::Delete),
            ("Remove-Item -Recurse -Force '[^.]git'", Rule::Delete),
            ("Remove-Item -Recurse -Force '`.gi?'", Rule::Delete),
            ("Remove-Item -Recurse -Force ????", Rule::Delete),
            ("Remove-Item -Recurse -Force *\\objects", Rule::Delete),
            ("Remove-Item -Recurse -Force ????\\HEAD", Rule::Delete),
            ("Remove-Item -Recurse -Force *g?t\\objects", Rule::Delete),
            (
                "Remove-Item -Recurse -Force *\\bin, *\\objects",
                Rule::Delete,
            ),
            ("Get-ChildItem *git | Remove-Item -Recurse", Rule::Delete),
            (
                "Get-ChildItem *\\objects | Remove-Item -Recurse",
                Rule::Delete,
            ),
        ],
    );
    check(
        Shell::Cmd,
        &windows(),
        &[
            "rd /s /q *gitx",
            "del /q *.tmp",
            "rd /s /q *\\bin",
            "rd /s /q src\\*\\bin",
        ],
        &[
            ("rd /s /q *git", Rule::Delete),
            ("rd /s /q ?git", Rule::Delete),
            ("rd /s /q ?GIT", Rule::Delete),
            ("rmdir /s /q *g?t", Rule::Delete),
            ("rd /s /q [.]git", Rule::Delete),
            ("rd /s /q *\\objects", Rule::Delete),
            ("rd /s /q ????\\HEAD", Rule::Delete),
        ],
    );
    let finding = classify("rd /s /q *git", Shell::Cmd, &windows());
    assert_eq!(
        finding.findings()[0].reason,
        "deletes a hidden file such as the repository's history"
    );
    let quoted = classify(
        "Remove-Item -Recurse -Force '[!.]git'",
        Shell::PowerShell,
        &windows(),
    );
    assert_eq!(
        quoted.findings()[0].reason,
        "deletes a hidden file such as the repository's history"
    );
}

#[test]
fn star_dot_star_is_every_entry_on_windows() {
    check(
        Shell::Cmd,
        &windows(),
        &["del /q build\\*.*"],
        &[("del /q *", Rule::Delete), ("del /q *.*", Rule::Delete)],
    );
    check(
        Shell::PowerShell,
        &windows(),
        &["Remove-Item -Recurse build\\*.*"],
        &[("Remove-Item -Recurse -Force *.*", Rule::Delete)],
    );
    let all = classify("del /q *", Shell::Cmd, &windows());
    let dotted = classify("del /q *.*", Shell::Cmd, &windows());
    // Judged alike: the same rule and reason (only the target text differs).
    assert_eq!(all.findings()[0].rule, dotted.findings()[0].rule);
    assert_eq!(all.findings()[0].reason, dotted.findings()[0].reason);
    assert_eq!(dotted.findings()[0].reason, "deletes the whole workspace");
}

#[test]
fn a_listing_is_judged_as_the_delete_of_its_pattern_is() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Get-ChildItem *.log | Remove-Item",
            "Get-ChildItem -Force x*\\..\\*.tmp | Remove-Item -Recurse -Force",
            "Get-ChildItem -Force *\\bin | Remove-Item -Recurse -Force",
        ],
        &[
            ("Remove-Item -Recurse -Force *\\modules", Rule::Delete),
            ("Remove-Item -Recurse -Force *\\lfs", Rule::Delete),
            ("Remove-Item -Recurse -Force *\\worktrees", Rule::Delete),
            (
                "Get-ChildItem -Force x*\\..\\*git | Remove-Item -Recurse -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Force x*\\..\\*\\objects | Remove-Item -Recurse -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Force src\\*\\..\\..\\*git | Remove-Item -Recurse -Force",
                Rule::Delete,
            ),
            ("Get-ChildItem -Force *git | Remove-Item", Rule::Delete),
        ],
    );
    let listed = classify(
        "Get-ChildItem -Force *git | Remove-Item",
        Shell::PowerShell,
        &windows(),
    );
    assert_eq!(
        listed.findings()[0].reason,
        "deletes a hidden file such as the repository's history"
    );
}

#[test]
fn a_pattern_that_picks_names_in_a_temporary_folder_is_temporary_files_on_windows() {
    check(
        Shell::PowerShell,
        &windows(),
        &["Get-ChildItem C:\\Users\\me\\AppData\\Local\\Temp\\*.log | Remove-Item"],
        &[(
            "Remove-Item -Recurse C:\\Users\\me\\AppData\\Local\\Temp\\*",
            Rule::Delete,
        )],
    );
}

#[test]
fn a_windows_spelling_of_git_says_what_it_deletes() {
    for line in ["rd /s /q .git.", "rd /s /q \".git \"", "rd /s /q GIT~1"] {
        let found = classify(line, Shell::Cmd, &windows());
        assert_eq!(
            found.findings()[0].reason,
            "deletes the repository's history",
            "{line}"
        );
    }
    let found = classify("rd /s /q .git::$INDEX_ALLOCATION", Shell::Cmd, &windows());
    assert_eq!(
        found.findings()[0].reason,
        "deletes a path only known when it runs"
    );
}

#[test]
fn a_part_before_the_last_that_windows_may_trim_is_known_only_when_it_runs() {
    // Windows reads `.` and `..` first, then drops one trailing dot from a
    // part, and every dot and space only from the last. A part this does not
    // read to a name is known only when it runs.
    check(
        Shell::Cmd,
        &windows(),
        &[
            "rd /s /q src.\\build.",
            "del /q src\\.\\build\\x.obj",
            "del /q src\\..\\build\\x.obj.",
        ],
        &[
            ("rd /s /q .git\\...\\..\\objects", Rule::Delete),
            ("rd /s /q \".git\\. \\..\\objects\"", Rule::Delete),
            ("rd /s /q \".git\\refs\\.. \\..\\heads\"", Rule::Delete),
            ("rd /s /q \"C:\\Users\\me\\dev\\repo \\x\"", Rule::Delete),
            ("rd /s /q \"..\\repo.. \\x\"", Rule::Delete),
            ("rd /s /q \".\\.git .\\objects\"", Rule::Delete),
            ("rd /s /q \"src\\.. \\.git\"", Rule::Delete),
            ("rd /s /q \"x \\y\"", Rule::Delete),
            ("rd /s /q \"src\\.. \"", Rule::Delete),
            ("rd /s /q ....", Rule::Delete),
        ],
    );
    check(
        Shell::PowerShell,
        &windows(),
        &["Remove-Item src.\\build."],
        &[
            (
                "Remove-Item -Recurse -Force '.git\\...\\..\\objects'",
                Rule::Delete,
            ),
            (
                "Remove-Item -Recurse -Force '.git\\. \\..\\objects'",
                Rule::Delete,
            ),
            (
                "Remove-Item -Recurse -Force '.git\\refs\\.. \\..\\heads'",
                Rule::Delete,
            ),
            (
                "Remove-Item -Recurse 'C:\\Users\\me\\dev\\repo \\x'",
                Rule::Delete,
            ),
        ],
    );
    // From a working directory inside `.git`.
    let inside = Paths::new(
        "C:\\Users\\me\\dev\\repo\\.git\\hooks",
        "C:\\Users\\me",
        ["C:\\Users\\me\\dev\\repo"],
    );
    check(
        Shell::Cmd,
        &inside,
        &[],
        &[
            ("rd /s /q ...\\..\\..\\objects", Rule::Delete),
            ("rd /s /q ..\\objects", Rule::Delete),
        ],
    );
}

#[test]
fn a_wildcard_part_is_trimmed_like_a_last_part() {
    check(
        Shell::Cmd,
        &windows(),
        &[
            "del *.obj",
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
            // No literal `~`: `cmd` skips a folder a wildcard matches.
            "del /s /q git*",
            "del /s /q G*",
            "del /s /q Git*",
            "del /s /q git*\\objects",
        ],
        &[
            // No `~`, so no hashed short name, but a `del /s` from the
            // workspace searches `.git` too and takes the files of it that
            // the pattern matches (an object by the shape of its name,
            // `index`, `heads`).
            ("del /s /q *2024*", Rule::Delete),
            ("del /s /q *a*", Rule::Delete),
            ("del /s /q *cafe*", Rule::Delete),
            ("del /s /q *1", Rule::Delete),
            ("del /s /q *2", Rule::Delete),
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

/// `filters` each piped into a delete by every listing of `listings`, the
/// `{filter}` in a listing replaced by the filter.
fn listed(listings: &[&str], filters: &[&str]) -> Vec<String> {
    filters
        .iter()
        .flat_map(|filter| {
            listings
                .iter()
                .map(move |listing| listing.replace("{filter}", filter))
        })
        .collect()
}

/// Each of `lines` deletes, in PowerShell on a Windows machine.
fn all_delete(lines: &[String]) {
    let rows: Vec<(&str, Rule)> = lines
        .iter()
        .map(|line| (line.as_str(), Rule::Delete))
        .collect();
    check(Shell::PowerShell, &windows(), &[], &rows);
}

#[test]
fn a_filtered_hidden_listing_piped_into_a_delete_reaches_the_history() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            // A filter that cannot match a hidden folder, or a listing that
            // does not list hidden entries.
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
            // The spellings of the parameters and their values.
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
            ("gci -Attr Hidden, Directory | rm -r", Rule::Delete),
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
            ("gci -fo -filter .git | ri -r", Rule::Delete),
        ],
    );
}

/// A filter is matched against the short name of `.git` (`GIT~1`) as well
/// as its name; an include only against the name.
#[test]
fn a_filter_is_matched_against_the_short_name_of_git_too() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Get-ChildItem -Force -Include g* | Remove-Item -Recurse -Force",
            "Get-ChildItem -Force -Include *~1 | Remove-Item -Recurse -Force",
            "Get-ChildItem -Force -Include ????? | Remove-Item -Recurse -Force",
            // A filter that cannot match the short name either.
            "Get-ChildItem -Force -Filter *.log | Remove-Item -Recurse -Force",
            "Get-ChildItem -Force -Filter *.tmp | Remove-Item -Recurse -Force",
            "Get-ChildItem -Force -Filter go.* | Remove-Item -Recurse -Force",
            "Get-ChildItem -Force -Filter .gitignore | Remove-Item -Recurse -Force",
            "Get-ChildItem -Force -Filter ?? | Remove-Item -Recurse -Force",
        ],
        &[],
    );
    all_delete(&listed(
        &[
            "Get-ChildItem -Force -Filter {filter} | Remove-Item -Recurse -Force",
            "gci -Hidden -Filter {filter} | rm -Recurse -Force",
            "Get-ChildItem -Force -Recurse -Filter {filter} | Remove-Item -Force",
        ],
        &[
            "GIT~1", "g*", "G*", "GI*", "*~1", "*1", "GIT~?", "?????", "??????", "*.", "git~1",
            "*~?", "G?T~1",
        ],
    ));
}

/// A recursive listing of hidden entries hands on what is below the top of
/// `.git` (its files, folders and objects, by name or by the shape of the
/// name) when a pattern can match one.
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
            "Get-ChildItem -Force -Recurse -Include bin,obj,Debug | Remove-Item -Recurse -Force",
            "Get-ChildItem -Force -Recurse -Filter node_modules | Remove-Item -Recurse -Force",
            "Get-ChildItem -Force -Recurse -Include *.tmp,*.orig,*.log | Remove-Item -Force",
            "Get-ChildItem -Force -Recurse -Directory -Filter obj | Remove-Item -Recurse -Force",
            "Get-ChildItem -Force -Recurse -Filter Debug | Remove-Item -Recurse -Force",
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
            // The folders and objects below the top of `.git`.
            (
                "Get-ChildItem -Force -Recurse -Filter pack | Remove-Item -Recurse -Force",
                Rule::Delete,
            ),
            ("gci -Force -Recurse -Filter pack | rm -r -fo", Rule::Delete),
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
            // `stash` is one of the names `.git` holds.
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
}

#[test]
fn del_s_from_the_workspace_takes_the_files_of_git_when_the_pattern_can_match_them() {
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
        ],
        &[
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

/// cmd matches `*` and `?` its own way (`x.*` takes `x`, `x?` takes `x`),
/// which reaches the names `.git` holds; the everyday cleans stay safe.
#[test]
fn del_s_reads_cmds_own_wildcard_rules() {
    check(
        Shell::Cmd,
        &windows(),
        &[
            "del /s /q main.obj",
            "del /s /q *.log",
            "del /s /q *.orig",
            "del /s /q foo.*",
            "del /s /q foo?.*",
            "del /s /q a?.txt",
            "del /s /q mainx.*",
            "del /s /q ??.obj",
            "del /s /q build.?",
        ],
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

/// `del /s` reaches the folders and objects of `.git` by the shape of their
/// names, `stash` among them.
#[test]
fn del_s_reaches_the_objects_of_git_by_the_shape_of_their_names() {
    check(
        Shell::Cmd,
        &windows(),
        &[
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
            ("del /s /q stash", Rule::Delete),
            ("del /s /q *stash*", Rule::Delete),
            ("del /s /q STASH", Rule::Delete),
            ("del /s /q sta??", Rule::Delete),
        ],
    );
}

/// The file system reads `<`, `>` and `"` in a filter as DOS wildcards (`*`,
/// `?` and `.`), so they can reach the names of `.git`; an include reads them
/// as plain characters, and so does cmd's `del` in a quoted name.
#[test]
fn a_filter_reads_the_dos_wildcards_of_the_file_system() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Get-ChildItem -Force -Include '<' | Remove-Item -Recurse -Force",
            "Get-ChildItem -Force -Include '.gi<' | Remove-Item -Recurse -Force",
            "Get-ChildItem -Recurse -Force -Include 'HEA<' | Remove-Item -Force",
            "Get-ChildItem -Recurse -Force -Include 'HEA>' | Remove-Item -Force",
            // A filter with DOS characters that cannot reach `.git`.
            "Get-ChildItem -Recurse -Force -Filter '*.t>' | Remove-Item -Force",
            "Get-ChildItem -Recurse -Force -Filter 'node_modules\"' | Remove-Item -Force",
            "Get-ChildItem -Recurse -Force -Filter 'x<.tmp' | Remove-Item -Force",
            "Get-ChildItem -Force -Filter 'b>>n' | Remove-Item -Force",
        ],
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
    all_delete(&listed(
        &[
            "Get-ChildItem -Force -Filter {filter} | Remove-Item -Recurse -Force",
            "Get-ChildItem -Recurse -Force -Filter {filter} | Remove-Item -Recurse -Force",
        ],
        &[
            "'<'", "'.gi<'", "'.g>>>'", "'.git>'", "'.git\"'", "'.gi\"t'", "'.gi>t'", "'<.git'",
            "'.<'",
        ],
    ));
    check(
        Shell::Cmd,
        &windows(),
        &[
            "del /s /q \"foo<.obj\"",
            "del /s /q \"a>>.txt\"",
            "del /s /q \"*.ob>\"",
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

/// A dot before a wildcard can match nothing, as in DOS, in a filter and in
/// `del`; a dot before a literal stays a plain dot.
#[test]
fn every_dot_before_a_wildcard_can_match_nothing() {
    let long = "*.".repeat(25_000);
    let mut lines: Vec<String> = vec![
        "Get-ChildItem -Recurse -Force -Filter HEAD.*.* | Remove-Item -Force".into(),
        "Get-ChildItem -Force -Filter *.*.*.* | Remove-Item -Recurse -Force".into(),
        format!("Get-ChildItem -Recurse -Force -Filter {long} | Remove-Item -Force"),
    ];
    lines.extend(listed(
        &[
            "Get-ChildItem -Recurse -Force -Filter {filter} | Remove-Item -Recurse -Force",
            "Get-ChildItem -Recurse -Force -Depth 3 -Filter {filter} | Remove-Item -Recurse -Force",
            "Get-ChildItem -Hidden -Recurse -Filter {filter} | Remove-Item -Recurse -Force",
            "Get-ChildItem -Recurse -Attributes Hidden -Filter {filter} | Remove-Item -Recurse -Force",
        ],
        &[
            "config.*.*",
            "config.?.?",
            "objects.*.*",
            "HEAD.?.*",
            "*.?.?",
            "*.*.*.*",
        ],
    ));
    all_delete(&lines);
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
    check(
        Shell::Cmd,
        &windows(),
        &["del /s /q test.*.js"],
        &[
            ("del /s /q HEAD.*.*", Rule::Delete),
            ("del /s /q config.*.*", Rule::Delete),
            ("del /s /q *.?.?", Rule::Delete),
            ("del /s /q *.*.*.*", Rule::Delete),
        ],
    );
}

#[test]
fn del_s_from_the_workspace_spelt_as_a_long_path_reaches_the_history() {
    check(
        Shell::Cmd,
        &windows(),
        &["del /s /q \\\\?\\C:\\Users\\me\\dev\\repo\\src\\HEAD"],
        &[
            (
                "del /s /q \\\\?\\C:\\Users\\me\\dev\\repo\\HEAD",
                Rule::Delete,
            ),
            (
                "del /s /q \"\\\\?\\C:\\Users\\me\\dev\\repo\\HEAD\"",
                Rule::Delete,
            ),
            ("del /s /q //?/C:/Users/me/dev/repo/HEAD", Rule::Delete),
            (
                "del /s /q \\\\?\\c:\\users\\me\\dev\\repo\\HEAD",
                Rule::Delete,
            ),
            (
                "del /s /q \\\\?\\C:\\Users\\me\\dev\\repo\\config",
                Rule::Delete,
            ),
            (
                "del /s /q \\\\?\\C:\\Users\\me\\dev\\repo\\??",
                Rule::Delete,
            ),
        ],
    );
    check(
        Shell::PowerShell,
        &windows(),
        &[],
        &[(
            "cmd /c del /s /q \\\\?\\C:\\Users\\me\\dev\\repo\\HEAD",
            Rule::Delete,
        )],
    );
}
