//! PowerShell item cmdlets judged by where their path lands: a registry key
//! is `SystemSettings`, as `Remove-Item` on it is, and an item beyond the
//! workspace is a delete or an overwrite. Every path of a list and every
//! positional counts; what `Get-Item` or a listing hands on down a pipeline is
//! the item (a listing that shows hidden files hands those on too); a
//! `-LiteralPath` alias, a splat, a common parameter or a switch never hides
//! which argument is the item; and `Start-Process` reads its program under
//! every alias of `-FilePath`. A write cmdlet reads its parameters by its
//! own names, and `--` ends them; a stage that only narrows hands on what
//! the stage before lists; and `Remove-Item`'s own `-Include` narrows a
//! wildcard. cmd's renames are not provider paths.
//!
//! The lines and their answers are in `tests/cases/powershell_items.cases`;
//! here are a list of thousands of paths, a long hidden listing, and long
//! lists and pipelines of the item cmdlets. Their time is in
//! `tests/timing.rs`.

mod common;

use common::lines::{long_hidden_listings, long_item_cmdlet_lines};
use common::{check, rules, windows};
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
fn a_long_hidden_listing_is_not_read_as_safe() {
    // Far over the `MAX_HIDDEN_MATCHES` pairs the hidden match reads (the
    // time is in `timing.rs`).
    for line in long_hidden_listings() {
        let rules = rules(&line, Shell::PowerShell, &windows());
        assert!(!rules.is_empty(), "a long hidden listing is read as safe");
    }
}

#[test]
fn long_lists_and_pipelines_of_the_item_cmdlets_are_not_read_as_safe() {
    for line in long_item_cmdlet_lines() {
        assert!(line.len() <= 64 * 1024, "{}", line.len());
        let rules = rules(&line, Shell::PowerShell, &windows());
        assert!(!rules.is_empty(), "a long line is read as safe: {line:.80}");
    }
}
