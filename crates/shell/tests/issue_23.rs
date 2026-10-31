//! PowerShell item cmdlets judged by where their path lands (a registry key
//! is `SystemSettings`, as `Remove-Item` on it is), and drives made with
//! `New-PSDrive` (`my_drive:`, `my-drive:`) read as drives.

mod common;

use common::{check, windows};
use milo_guards_shell::{Rule, Shell};

#[test]
fn item_cmdlets_on_the_registry_change_the_system() {
    check(
        Shell::PowerShell,
        &windows(),
        &[],
        &[
            ("Clear-Item HKCU:\\Software\\x", Rule::SystemSettings),
            ("Clear-Item -Path HKCU:\\Software\\x", Rule::SystemSettings),
            (
                "Clear-Item -LiteralPath HKCU:\\Software\\x",
                Rule::SystemSettings,
            ),
            ("Rename-Item HKCU:\\Software\\x y", Rule::SystemSettings),
            (
                "Rename-Item -Path HKCU:\\Software\\x -NewName y",
                Rule::SystemSettings,
            ),
            (
                "Rename-Item -NewName y HKCU:\\Software\\x",
                Rule::SystemSettings,
            ),
            ("Set-Item HKLM:\\SYSTEM\\x -Value 1", Rule::SystemSettings),
            (
                "Set-Item -Path HKLM:\\SYSTEM\\x -Value 1",
                Rule::SystemSettings,
            ),
            ("New-Item HKCU:\\Software\\x -Force", Rule::SystemSettings),
            (
                "New-Item -Path HKCU:\\Software -Name x -Force",
                Rule::SystemSettings,
            ),
            (
                "Move-Item HKCU:\\Software\\x HKCU:\\Software\\y",
                Rule::SystemSettings,
            ),
            ("Move-Item HKCU:\\Software\\x src\\y", Rule::SystemSettings),
            (
                "Copy-Item HKCU:\\Software\\x HKCU:\\Software\\y -Force",
                Rule::SystemSettings,
            ),
            (
                "Copy-Item -Path src\\x -Destination HKCU:\\Software\\y -Force",
                Rule::SystemSettings,
            ),
            ("Clear-Item hklm:*", Rule::SystemSettings),
            ("Set-Item HKCU:*", Rule::SystemSettings),
            (
                "Rename-Item Registry::HKEY_CURRENT_USER\\Software\\x y",
                Rule::SystemSettings,
            ),
            (
                "Clear-Item Microsoft.PowerShell.Core\\Registry::HKEY_CURRENT_USER\\x",
                Rule::SystemSettings,
            ),
            (
                "cd src; Rename-Item Microsoft.PowerShell.Core\\Registry::HKEY_CURRENT_USER\\x y",
                Rule::SystemSettings,
            ),
        ],
    );
}

#[test]
fn item_cmdlet_aliases_are_judged_the_same() {
    check(
        Shell::PowerShell,
        &windows(),
        &[],
        &[
            ("cli HKCU:\\Software\\x", Rule::SystemSettings),
            ("ren HKCU:\\Software\\x y", Rule::SystemSettings),
            ("rni HKCU:\\Software\\x y", Rule::SystemSettings),
            ("si HKLM:\\SYSTEM\\x -Value 1", Rule::SystemSettings),
            ("ni HKCU:\\Software\\x -Force", Rule::SystemSettings),
            (
                "mi HKCU:\\Software\\x HKCU:\\Software\\y",
                Rule::SystemSettings,
            ),
            (
                "move HKCU:\\Software\\x HKCU:\\Software\\y",
                Rule::SystemSettings,
            ),
            (
                "cpi HKCU:\\Software\\x HKCU:\\Software\\y -Force",
                Rule::SystemSettings,
            ),
            ("clp HKCU:\\Software\\x -Name y", Rule::SystemSettings),
            (
                "rnp HKCU:\\Software\\x -Name y -NewName z",
                Rule::SystemSettings,
            ),
            (
                "cpp -Path HKCU:\\Software\\x -Name y -Destination HKCU:\\Software\\z",
                Rule::SystemSettings,
            ),
            (
                "mp HKCU:\\Software\\x y HKCU:\\Software\\z",
                Rule::SystemSettings,
            ),
        ],
    );
}

#[test]
fn registry_value_cmdlets_are_judged_by_their_place() {
    check(
        Shell::PowerShell,
        &windows(),
        &[],
        &[
            (
                "Clear-ItemProperty -Path HKCU:\\Software\\x -Name y",
                Rule::SystemSettings,
            ),
            (
                "Rename-ItemProperty -Path HKCU:\\Software\\x -Name y -NewName z",
                Rule::SystemSettings,
            ),
            (
                "Copy-ItemProperty -Path HKCU:\\Software\\x -Name y -Destination HKCU:\\Software\\z",
                Rule::SystemSettings,
            ),
            (
                "Move-ItemProperty HKCU:\\Software\\x y HKCU:\\Software\\z",
                Rule::SystemSettings,
            ),
        ],
    );
}

#[test]
fn item_cmdlets_beyond_the_workspace_are_risky() {
    check(
        Shell::PowerShell,
        &windows(),
        &[],
        &[
            ("Rename-Item C:\\Users\\me\\x y", Rule::Delete),
            ("Rename-Item ~\\.ssh\\id_rsa key", Rule::Delete),
            ("Rename-Item $p y", Rule::Delete),
            (
                "Rename-Item -Path src\\a -NewName ..\\..\\b",
                Rule::Overwrite,
            ),
            ("cd C:\\Users\\me; Rename-Item x y", Rule::Delete),
            ("Set-Item Env:FOO bar", Rule::Overwrite),
            ("Clear-Item Variable:x", Rule::Overwrite),
            ("Get-ChildItem ~ | Rename-Item -NewName x", Rule::Delete),
            (
                "Get-ChildItem ~ | ForEach-Object { Rename-Item $_.FullName -NewName x }",
                Rule::Delete,
            ),
            ("Get-ChildItem .. | Rename-Item -NewName x", Rule::Delete),
            ("Get-ChildItem ~ | Move-Item -Destination x", Rule::Delete),
            (
                "Get-ChildItem HKCU:\\Software\\x | Rename-Item -NewName y",
                Rule::SystemSettings,
            ),
            (
                "Get-ChildItem HKCU:\\Software\\x | Clear-Item",
                Rule::SystemSettings,
            ),
        ],
    );
}

#[test]
fn item_cmdlets_inside_the_workspace_stay_safe() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Rename-Item src\\a.rs b.rs",
            "Rename-Item -Path src\\a.rs -NewName b.rs",
            "Rename-Item -LiteralPath src\\a.rs -NewName b.rs",
            "Rename-Item -NewName b.rs src\\a.rs",
            "Rename-Item -Path src\\a.rs -NewName $name",
            "rni src\\a.rs b.rs",
            "ren src\\a.rs b.rs",
            "Get-ChildItem | Rename-Item -NewName { $_.Name + 'x' }",
            "Get-ChildItem *.txt | Rename-Item -NewName { $_.Name + 'x' }",
            "Get-ChildItem src | Rename-Item -NewName { $_.Name + 'x' }",
            "Get-ChildItem *.txt | ForEach-Object { Rename-Item $_ -NewName x }",
            "Move-Item src\\a src\\b",
            "Get-ChildItem src | Move-Item -Destination old",
            "Copy-Item src\\a src\\b -Force",
            "New-Item -ItemType Directory build -Force",
            "New-Item -Path build\\out.txt -Force",
            "Get-ItemProperty HKCU:\\Software\\x",
            "Get-Item HKLM:\\SYSTEM\\x",
            "Copy-Item HKCU:\\Software\\x src\\y -Force",
        ],
        &[],
    );
}

#[test]
fn cmd_renames_are_not_provider_paths() {
    check(
        Shell::Cmd,
        &windows(),
        &["ren a.txt b.txt", "rename src\\a.rs b.rs"],
        &[],
    );
}

#[test]
fn a_drive_name_may_hold_an_underscore_or_a_dash() {
    check(
        Shell::PowerShell,
        &windows(),
        &[],
        &[
            ("Remove-Item -Recurse my_drive:*", Rule::Delete),
            ("Remove-Item -Recurse my-drive:\\*", Rule::Delete),
            ("Remove-Item -Recurse my_drive:\\x", Rule::Delete),
            ("Remove-Item -Recurse my_drive:x", Rule::Delete),
            ("Remove-Item -Recurse -Force My-Drive:*", Rule::Delete),
            ("Remove-Item -Recurse -Path my_drive:*", Rule::Delete),
            ("rm -r my_drive:*", Rule::Delete),
            (
                "Get-ChildItem my_drive:* | Remove-Item -Recurse",
                Rule::Delete,
            ),
            ("Set-Content my_drive:x 'y'", Rule::Overwrite),
            ("'x' > my-drive:out.txt", Rule::Overwrite),
            ("Move-Item my_drive:x src\\y", Rule::Delete),
            ("Copy-Item src\\x my-drive:y", Rule::Overwrite),
            ("Rename-Item my_drive:x y", Rule::Delete),
            (
                "cd C:\\Users\\me; Remove-Item -Recurse my_drive:*",
                Rule::Delete,
            ),
            ("cd src; Remove-Item -Recurse my_drive:*", Rule::Delete),
        ],
    );
}

#[test]
fn a_name_with_a_separator_a_wildcard_or_a_dot_is_not_a_drive() {
    check(
        Shell::PowerShell,
        &windows(),
        &[],
        &[
            // A stream of a file: known only when it runs.
            ("Remove-Item -Recurse x.txt:stream", Rule::Delete),
            ("Remove-Item -Recurse src\\a:stream", Rule::Delete),
            ("Remove-Item -Recurse .\\a:b", Rule::Delete),
            ("Remove-Item -Recurse a*:b", Rule::Delete),
            ("Remove-Item -Recurse 'a?:b'", Rule::Delete),
        ],
    );
}
