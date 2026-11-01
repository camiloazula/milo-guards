//! PowerShell item cmdlets judged by where their path lands (a registry key
//! is `SystemSettings`, as `Remove-Item` on it is), and drives made with
//! `New-PSDrive` (`my_drive:`, `my-drive:`) read as drives.

mod common;

use common::{check, windows};
use milo_guards_shell::{Paths, Rule, Shell};

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
            "gci -Force -Filter '?it' | Move-Item -Destination old",
            "gci -Force -Include *.log, *.tmp | Move-Item -Destination trash",
            "gci -Attributes Hidden -Filter *.tmp | Move-Item -Destination trash",
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

fn two_workspaces() -> Paths {
    Paths::new(
        r"C:\Users\me\dev\repo",
        r"C:\Users\me",
        [r"C:\Users\me\dev\repo", r"D:\ws2"],
    )
}

#[test]
fn get_item_hands_on_the_workspace_itself() {
    check(
        Shell::PowerShell,
        &windows(),
        &[],
        &[
            ("Rename-Item . old", Rule::Delete),
            ("Get-Item . | Rename-Item -NewName old", Rule::Delete),
            ("gi . | ren -NewName old", Rule::Delete),
            (
                "cd ~; Get-Item C:\\Users\\me\\dev\\repo | Rename-Item -NewName old",
                Rule::Delete,
            ),
            (
                "Get-Item C:\\Users\\me\\dev\\repo | Move-Item -Destination src\\old",
                Rule::Delete,
            ),
        ],
    );
    check(
        Shell::PowerShell,
        &two_workspaces(),
        &[],
        &[
            ("Rename-Item D:\\ws2 old", Rule::Delete),
            (
                "Move-Item D:\\ws2 C:\\Users\\me\\dev\\repo\\old",
                Rule::Delete,
            ),
            (
                "Get-Item D:\\ws2 | ForEach-Object { Rename-Item $_ old }",
                Rule::Delete,
            ),
            (
                "Get-Item D:\\ws2 | Move-Item -Destination C:\\Users\\me\\dev\\repo\\old",
                Rule::Delete,
            ),
        ],
    );
}

#[test]
fn what_get_item_and_listings_hand_on_inside_the_workspace_stays_safe() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Get-Item * | Rename-Item -NewName { $_.Name + 1 }",
            "Get-ChildItem | Rename-Item -NewName { $_.Name + 1 }",
            "Get-ChildItem . | Rename-Item -NewName { $_.Name + 1 }",
            "Get-Item src | Rename-Item -NewName old",
        ],
        &[],
    );
}

#[test]
fn a_common_parameter_before_the_path_does_not_hide_it() {
    let mut risky: Vec<(String, Rule)> = Vec::new();
    for common in [
        "-ErrorAction SilentlyContinue",
        "-ea 0",
        "-OutVariable o",
        "-OutBuffer 1",
        "-WarningAction 0",
        "-InformationAction 0",
        "-ProgressAction 0",
        "-proga 0",
        "-ErrorVariable e",
        "-PipelineVariable p",
    ] {
        for line in [
            format!("Clear-Item {common} HKCU:\\Software\\x"),
            format!("Rename-Item {common} HKCU:\\Software\\x y"),
            format!("Set-Item {common} HKCU:\\Software\\x -Value 1"),
        ] {
            risky.push((line, Rule::SystemSettings));
        }
    }
    for line in [
        "New-Item -ErrorAction 0 HKCU:\\Software\\x -Force",
        "Copy-Item -ErrorAction 0 src\\x HKCU:\\y -Force",
    ] {
        risky.push((line.to_owned(), Rule::SystemSettings));
    }
    risky.push((
        "Set-Content -ErrorAction Stop C:\\Windows\\x y".to_owned(),
        Rule::Overwrite,
    ));
    risky.push((
        "Remove-Item -ErrorAction SilentlyContinue C:\\Windows\\x".to_owned(),
        Rule::Delete,
    ));
    risky.push((
        "Remove-Item -ea 0 -Recurse -Force C:\\Windows\\x".to_owned(),
        Rule::Delete,
    ));
    let rows: Vec<(&str, Rule)> = risky
        .iter()
        .map(|(line, rule)| (line.as_str(), *rule))
        .collect();
    check(Shell::PowerShell, &windows(), &[], &rows);
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Clear-Item -ErrorAction SilentlyContinue src\\x",
            "Rename-Item -ea 0 src\\x y",
            "Set-Item -ea 0 src\\x -Value 1",
        ],
        &[],
    );
}

#[test]
fn clear_item_and_set_item_judge_every_path_of_a_list() {
    let many = format!("Clear-Item src\\x, {}HKCU:\\y", "src\\x, ".repeat(5000));
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Clear-Item src\\a, src\\b",
            "Set-Item src\\a, src\\b -Value 1",
            "Set-Item src\\a, src\\b 1",
            "Set-Item src\\a 1",
            "Set-Item src\\a",
            "Set-Item -Path src\\a 1",
        ],
        &[
            (
                "Clear-Item src\\a, HKCU:\\Software\\y",
                Rule::SystemSettings,
            ),
            (
                "Clear-Item -Path src\\a,HKCU:\\Software\\y",
                Rule::SystemSettings,
            ),
            (
                "Clear-Item -LiteralPath src\\a,HKCU:\\Software\\y",
                Rule::SystemSettings,
            ),
            ("Set-Item src\\a,HKLM:\\x -Value 1", Rule::SystemSettings),
            (
                "Set-Item -Path src\\a,HKLM:\\x -Value 1",
                Rule::SystemSettings,
            ),
            ("Set-Item src\\a,HKLM:\\x 1", Rule::SystemSettings),
            ("Set-Item -Path src\\a,HKLM:\\x 1", Rule::SystemSettings),
            ("Set-Item src\\a, HKLM:\\x, 1", Rule::SystemSettings),
            (many.as_str(), Rule::SystemSettings),
        ],
    );
}

#[test]
fn set_item_judges_every_positional_of_a_list() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Set-Item src\\a 1",
            "Set-Item src\\a, src\\b 1",
            "Set-Item -Path src\\a -Value 1",
        ],
        &[
            ("Set-Item src\\a, HKLM:\\x", Rule::SystemSettings),
            ("Set-Item src\\a,HKLM:\\x", Rule::SystemSettings),
            (
                "si src\\a,HKCU:\\Software\\Classes\\x",
                Rule::SystemSettings,
            ),
            ("Set-Item src\\a, HKLM:\\x 1", Rule::SystemSettings),
            ("Set-Item HKLM:\\x", Rule::SystemSettings),
        ],
    );
}

#[test]
fn rename_item_judges_every_positional_and_path() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Rename-Item src\\a.rs b.rs",
            "Rename-Item -n y src\\x",
            "Rename-Item -- src\\x y",
            "Rename-Item src\\a.rs $name",
            "Rename-Item src\\a.rs ($x + '.bak')",
            "Get-ChildItem | ForEach-Object { Rename-Item $_ ($_.Name + 1) }",
            "Rename-Item -Path src\\a, src\\b -NewName c",
        ],
        &[
            ("Rename-Item -n y HKCU:\\Software\\x", Rule::SystemSettings),
            ("Rename-Item -N y C:\\Windows\\x", Rule::Delete),
            ("Rename-Item -- HKCU:\\Software\\x y", Rule::SystemSettings),
            ("Rename-Item -- C:\\Windows\\x y", Rule::Delete),
            ("Rename-Item -n y $p", Rule::Delete),
            ("Rename-Item -- $p y", Rule::Delete),
            (
                "Rename-Item -Path src\\a,C:\\Windows\\x -NewName y",
                Rule::Delete,
            ),
            ("Rename-Item src\\a, C:\\Windows\\x y", Rule::Delete),
        ],
    );
}

#[test]
fn move_item_judges_every_source_of_a_list() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Move-Item -Path src\\a,src\\b -Destination src\\d",
            "Move-Item src\\a, src\\b -Destination src\\d",
            "Move-Item -Path src\\a src\\d",
            "Move-Item src\\a src\\d",
            "Move-Item -LiteralPath src\\a,src\\b -Destination src\\d",
        ],
        &[
            (
                "Move-Item -Path src\\a,C:\\Windows\\x -Destination src\\d",
                Rule::Delete,
            ),
            (
                "Move-Item -Path src\\a,HKCU:\\Software\\x -Destination src\\d",
                Rule::SystemSettings,
            ),
            (
                "Move-Item src\\a, C:\\Windows\\x -Destination src\\d",
                Rule::Delete,
            ),
            (
                "Move-Item -LiteralPath src\\a,~\\x -Destination src\\d",
                Rule::Delete,
            ),
            ("Move-Item -Path src\\a,C:\\Windows\\x src\\d", Rule::Delete),
            ("Move-Item src\\a, C:\\Windows\\x src\\d", Rule::Delete),
        ],
    );
}

#[test]
fn a_force_or_hidden_listing_hands_on_the_hidden_files() {
    check(
        Shell::PowerShell,
        &windows(),
        &["Get-ChildItem | Rename-Item -NewName { $_.Name + 1 }"],
        &[
            (
                "Get-ChildItem -Force | Rename-Item -NewName { $_.Name + 1 }",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Hidden | Rename-Item -NewName { $_.Name + 1 }",
                Rule::Delete,
            ),
            ("gci -fo | ren -NewName { $_.Name + 1 }", Rule::Delete),
            (
                "Get-ChildItem -Force | Move-Item -Destination old",
                Rule::Delete,
            ),
            ("ls -Force | mi -Destination old", Rule::Delete),
            (
                "Get-ChildItem -Force | ForEach-Object { Rename-Item $_ ($_.Name + 1) }",
                Rule::Delete,
            ),
            ("Move-Item .git old", Rule::Delete),
            ("Rename-Item .git x", Rule::Delete),
        ],
    );
}

#[test]
fn the_hidden_alias_and_attributes_list_hidden_files_too() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Get-ChildItem -Attributes Directory | Rename-Item -NewName { $_.Name + 1 }",
            "gci -ad | Rename-Item -NewName { $_.Name + 1 }",
            "gci -Attributes ReadOnly | Move-Item -Destination old",
        ],
        &[
            ("gci -ah | Rename-Item -NewName x", Rule::Delete),
            (
                "gci -ah | ForEach-Object { Rename-Item $_ x }",
                Rule::Delete,
            ),
            ("gci -ah | Move-Item -Destination old", Rule::Delete),
            (
                "Get-ChildItem -Attributes Hidden | Rename-Item -NewName x",
                Rule::Delete,
            ),
            (
                "gci -Attributes h | Move-Item -Destination old",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Attributes !Directory+Hidden | Rename-Item -NewName x",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Attributes Directory,Hidden | Rename-Item -NewName x",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Attributes $a | Rename-Item -NewName x",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Attributes:Hidden | Rename-Item -NewName x",
                Rule::Delete,
            ),
        ],
    );
}

#[test]
fn a_depth_listing_is_not_read_as_a_listing_of_its_value() {
    check(
        Shell::PowerShell,
        &windows(),
        &["Get-ChildItem -Depth 1 | Rename-Item -NewName { $_.Name + 1 }"],
        &[
            ("gci -Depth 1 -Force | Rename-Item -NewName x", Rule::Delete),
            ("gci -Force -Depth 1 | Clear-Item", Rule::Overwrite),
            (
                "Get-ChildItem -Depth 1 | Remove-Item -Recurse -Force",
                Rule::Delete,
            ),
        ],
    );
}

#[test]
fn a_filtered_force_listing_still_hands_on_the_hidden_files() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "gci -Force -Filter *.tmp | Move-Item -Destination trash",
            "gci -Hidden -Filter *.tmp | Move-Item -Destination trash",
            "gci -Force -Include *.tmp | Move-Item -Destination trash",
            "Get-ChildItem -Filter .git | Move-Item -Destination old",
            "Get-ChildItem -Filter * | Rename-Item -NewName x",
            "Get-ChildItem -Force src -Filter .git | Move-Item -Destination old",
        ],
        &[
            (
                "Get-ChildItem -Force -Filter .git | Move-Item -Destination old",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Force -Include .git | Move-Item -Destination old",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Force -Include .git,x | Move-Item -Destination old",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Force -Include x,.git | Move-Item -Destination old",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Force -Exclude x | Rename-Item -NewName x",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Force -Filter * | Rename-Item -NewName x",
                Rule::Delete,
            ),
            (
                "gci -Force -Filter *it | Move-Item -Destination old",
                Rule::Delete,
            ),
            (
                "gci -Force -Filter $f | Move-Item -Destination old",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Hidden -Filter .g* | Rename-Item -NewName x",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Force -Recurse -Filter config | Rename-Item -NewName x",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Force -Depth 2 -Filter config | Rename-Item -NewName x",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Force -Filter .git | Remove-Item -Recurse",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -Force ~ -Filter .ssh | Move-Item -Destination old",
                Rule::Delete,
            ),
            (
                "Get-Item -Force -Filter .git | Move-Item -Destination old",
                Rule::Delete,
            ),
        ],
    );
}

#[test]
fn the_aliases_of_literalpath_name_the_item() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Rename-Item src\\y -LP src\\x",
            "Rename-Item y -PSPath src\\x",
            "Set-ItemProperty y -LP src\\x -Value 1",
        ],
        &[
            ("Rename-Item y -PSPath $p", Rule::Delete),
            ("Rename-Item y -LP $p", Rule::Delete),
            ("Rename-Item y -psp C:\\Windows\\x", Rule::Delete),
            ("Rename-Item y -LP (Get-Item C:\\Windows\\x)", Rule::Delete),
            ("Rename-Item y -LP C:\\Windows\\x", Rule::Delete),
            (
                "Rename-Item y -PSPath HKCU:\\Software\\x",
                Rule::SystemSettings,
            ),
            (
                "Clear-ItemProperty y -PSPath HKCU:\\Software\\x",
                Rule::SystemSettings,
            ),
            (
                "Rename-ItemProperty y -PSPath HKCU:\\Software\\x -NewName z",
                Rule::SystemSettings,
            ),
            (
                "Set-ItemProperty y -LP HKCU:\\Software\\x -Value 1",
                Rule::SystemSettings,
            ),
            (
                "Clear-ItemProperty y -LP HKCU:\\Software\\x",
                Rule::SystemSettings,
            ),
        ],
    );
}

#[test]
fn a_splat_hides_which_argument_is_the_item() {
    check(
        Shell::PowerShell,
        &windows(),
        &["Rename-Item src\\y z"],
        &[
            ("Rename-Item y @p", Rule::Delete),
            ("Rename-Item y @args", Rule::Delete),
            ("Rename-Item @p y", Rule::Delete),
            ("Clear-ItemProperty y @p", Rule::Overwrite),
            ("Rename-ItemProperty y @p", Rule::Overwrite),
        ],
    );
}

#[test]
fn a_common_parameter_after_the_destination_does_not_become_it() {
    check(
        Shell::PowerShell,
        &windows(),
        &["Copy-Item src\\a src\\b -proga 0"],
        &[
            ("Copy-Item src\\a C:\\Windows\\x -proga 0", Rule::Overwrite),
            (
                "Set-ItemProperty -proga 0 HKLM:\\x -Name y -Value 1",
                Rule::SystemSettings,
            ),
            ("Set-Content -proga 0 C:\\Windows\\x y", Rule::Overwrite),
            ("Out-File -proga 0 C:\\Windows\\x", Rule::Overwrite),
            ("Set-Acl -proga 0 C:\\Windows\\x $a", Rule::Permissions),
        ],
    );
}

#[test]
fn start_process_reads_its_program_under_every_alias_of_filepath() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Start-Process -PSPath notepad",
            "Start-Process -Path notepad",
        ],
        &[
            ("Start-Process -PSPath cmd -Verb RunAs", Rule::Elevated),
            ("Start-Process -Path cmd -Verb RunAs", Rule::Elevated),
            ("Start-Process -LiteralPath cmd -Verb RunAs", Rule::Elevated),
            ("Start-Process -psp cmd -Verb RunAs", Rule::Elevated),
            ("Start-Process -PSPath $p", Rule::Unknown),
            ("Start-Process -Path $p", Rule::Unknown),
            ("saps -PSPath $p", Rule::Unknown),
            ("start -PSPath $p", Rule::Unknown),
            (
                "Start-Process -PSPath powershell -ArgumentList '-c Remove-Item -Recurse ~'",
                Rule::RunInput,
            ),
            (
                "Start-Process -psp cmd -ArgumentList '/c rd /s /q C:\\'",
                Rule::Delete,
            ),
        ],
    );
}

#[test]
fn the_file_switch_of_a_listing_does_not_take_the_folder() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Get-ChildItem -File src | Rename-Item -NewName x",
            "ls -File | Rename-Item -NewName x",
        ],
        &[
            ("Get-ChildItem -File ~ | Rename-Item -NewName x", Rule::Delete),
            (
                "Get-ChildItem -File ~\\Downloads | Rename-Item -NewName { $_.Name -replace \" \",\"_\" }",
                Rule::Delete,
            ),
            ("ls -File ~ | Rename-Item -NewName x", Rule::Delete),
            ("dir -File C:\\Windows | ren -NewName x", Rule::Delete),
            (
                "Get-ChildItem -File HKCU:\\Software | Rename-Item -NewName x",
                Rule::SystemSettings,
            ),
            ("Get-ChildItem -File ~ | Clear-Item", Rule::Overwrite),
            (
                "Get-ChildItem -File ~ | Move-Item -Destination old",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -File ~ | ForEach-Object { Rename-Item $_ x }",
                Rule::Delete,
            ),
            (
                "Get-ChildItem -File ~ | ForEach-Object { Move-Item $_ old }",
                Rule::Delete,
            ),
            ("Get-ChildItem ~ -File | Rename-Item -NewName x", Rule::Delete),
            (
                "Get-ChildItem -File:$true ~ | Rename-Item -NewName x",
                Rule::Delete,
            ),
        ],
    );
}

#[test]
#[allow(
    clippy::disallowed_methods,
    reason = "the guard keeps no clock; only this test times it, to catch a quadratic read"
)]
fn a_long_hidden_listing_is_read_quickly() {
    let items = "a,".repeat(5000);
    let words = "b ".repeat(5000);
    let paths = "-Path x ".repeat(2000);
    let includes = "a,".repeat(2000);
    for line in [
        format!("gci -fo -r -Include {items}a {words} | ren -NewName x"),
        format!("gci -fo -r {paths} -Include {includes}a | ren -NewName x"),
        format!("gci -fo -r -Filter a {paths} | ren -NewName x"),
    ] {
        let started = std::time::Instant::now();
        let rules = common::rules(&line, Shell::PowerShell, &windows());
        let took = started.elapsed();
        assert!(
            took < std::time::Duration::from_millis(500),
            "{} bytes took {took:?}",
            line.len()
        );
        assert!(!rules.is_empty(), "a long hidden listing is read as safe");
    }
}
