//! Which names a Windows wildcard matches. Windows has no hidden dot names,
//! so `*git` matches `.git`, `*.*` is every entry, and a wildcard part is
//! trimmed of its trailing dots and spaces like a last part; a pattern can
//! match `.git` by its 8.3 short name. A listing piped into a delete is
//! judged as the delete of its pattern: a filtered or attribute-selected
//! PowerShell listing reaches `.git` when it lists hidden entries and its
//! filter can match a name there (the file system's short names and DOS
//! wildcards included), and cmd's `del /s` from the workspace reaches the
//! files of `.git` its pattern can match, by cmd's own wildcard rules.
//!
//! The lines and their answers are in `tests/cases/windows_wildcards.cases`;
//! here are the lines made for each listing and filter, and a long filter.

mod common;

use common::{check, windows};
use milo_guards_shell::{Rule, Shell};

#[test]
fn every_case_holds() {
    common::cases::check("windows_wildcards");
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

/// A filter is matched against the short name of `.git` (`GIT~1`) as well
/// as its name, by each listing.
#[test]
fn a_filter_is_matched_against_the_short_name_of_git_too() {
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

/// The file system reads `<`, `>` and `"` in a filter as DOS wildcards, by
/// each listing.
#[test]
fn a_filter_reads_the_dos_wildcards_of_the_file_system() {
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
}

/// A dot before a wildcard can match nothing, by each listing, and in a
/// filter of 25,000 of them.
#[test]
fn every_dot_before_a_wildcard_can_match_nothing() {
    let long = "*.".repeat(25_000);
    let mut lines: Vec<String> = vec![format!(
        "Get-ChildItem -Recurse -Force -Filter {long} | Remove-Item -Force"
    )];
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
}
