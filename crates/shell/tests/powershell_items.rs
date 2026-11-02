//! PowerShell item cmdlets judged by where their path lands: a registry key
//! is `SystemSettings`, as `Remove-Item` on it is, and an item beyond the
//! workspace is a delete or an overwrite. Every path of a list and every
//! positional counts; what `Get-Item` or a listing hands on down a pipeline is
//! the item (a listing that shows hidden files hands those on too); a
//! `-LiteralPath` alias, a splat, a common parameter or a switch never hides
//! which argument is the item; and `Start-Process` reads its program under
//! every alias of `-FilePath`. cmd's renames are not provider paths.
//!
//! The lines and their answers are in `tests/cases/powershell_items.cases`;
//! here are a list of thousands of paths and the timing of a long hidden
//! listing.

mod common;

use common::{check, rules, took, windows};
use milo_guards_shell::{Rule, Shell};

#[test]
fn every_case_holds() {
    common::cases::check("powershell_items");
}

/// The registry key at the end of a list of thousands of paths is still
/// judged.
#[test]
fn clear_item_judges_the_last_path_of_a_long_list() {
    let many = format!("Clear-Item src\\x, {}HKCU:\\y", "src\\x, ".repeat(5000));
    check(
        Shell::PowerShell,
        &windows(),
        &[],
        &[(many.as_str(), Rule::SystemSettings)],
    );
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn a_long_hidden_listing_is_read_quickly() {
    // Each place is also judged for the secret it may reach, so a line of
    // this many is slow in the debug build for that alone; these are far
    // over the `MAX_HIDDEN_MATCHES` pairs the hidden match reads.
    let items = "a,".repeat(1250);
    let words = "b ".repeat(1250);
    let paths = "-Path x ".repeat(500);
    let includes = "a,".repeat(500);
    for line in [
        format!("gci -fo -r -Include {items}a {words} | ren -NewName x"),
        format!("gci -fo -r {paths} -Include {includes}a | ren -NewName x"),
        format!("gci -fo -r -Filter a {paths} | ren -NewName x"),
    ] {
        // Each of the thousands of words is resolved against the protected
        // names, which costs about a millisecond in a debug build; a
        // quadratic read would take minutes.
        let took = took(&line, Shell::PowerShell, &windows());
        assert!(
            took < std::time::Duration::from_secs(3),
            "{} bytes took {took:?}",
            line.len()
        );
        let rules = rules(&line, Shell::PowerShell, &windows());
        assert!(!rules.is_empty(), "a long hidden listing is read as safe");
    }
}
