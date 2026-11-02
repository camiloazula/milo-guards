//! Where `Set-Location` leaves a PowerShell line, so what follows is judged
//! in that provider: a drive made with `New-PSDrive` (a name of any character
//! but `: / \ . ~`, made later in the text) is a drive; in the registry,
//! `Env:`, `Function:` and the like a bare `NUL` or `CON` is an item there,
//! not the device; a rooted path or `~` after a `cd` stays on the drive of
//! that `cd`; a single letter is a disk unless the line makes it a drive; and
//! a `Set-Location` fed by the pipeline, `cd -` and `cd -- -` go to a place
//! only known when it runs.

mod common;

use common::{check, windows};
use milo_guards_shell::{Rule, Shell};

#[test]
fn a_drive_name_may_hold_any_character_but_a_separator_or_a_dot() {
    check(
        Shell::PowerShell,
        &windows(),
        &[],
        &[
            // `_` and `-`.
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
            // A drive made with such a name and entered.
            (
                "New-PSDrive -Name my_reg -PSProvider Registry -Root HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run; cd my_reg:; Remove-Item NUL -Recurse",
                Rule::Delete,
            ),
            (
                "New-PSDrive -Name my-reg -PSProvider Registry -Root HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run; cd my-reg:; Remove-Item NUL -Recurse",
                Rule::Delete,
            ),
            (
                "New-PSDrive -Name my_fn -PSProvider Function -Root \\; cd my_fn:; Set-Content NUL 'Remove-Item -Recurse -Force ~'; NUL",
                Rule::Overwrite,
            ),
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

#[test]
fn a_drive_made_later_in_the_text_is_still_a_drive() {
    // The drive is made after the `cd` in the text, in a function body or a
    // loop that runs after it.
    check(
        Shell::PowerShell,
        &windows(),
        &[],
        &[
            (
                "function g { cd X:; Remove-Item NUL -Recurse }; New-PSDrive -Name X -PSProvider Registry -Root HKCU:\\Software; g",
                Rule::Delete,
            ),
            (
                "function g { cd X:; Set-Content NUL 'x'; NUL }; New-PSDrive -Name X -PSProvider Function -Root \\; g",
                Rule::Overwrite,
            ),
            (
                "foreach ($i in 1..2) { cd X:; Set-Content NUL 'x'; New-PSDrive -Name X -PSProvider Function -Root \\ }",
                Rule::Overwrite,
            ),
        ],
    );
}

#[test]
fn a_single_letter_drive_is_a_disk_unless_the_line_makes_a_drive() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "cd D:; Remove-Item NUL",
            "cd D:\\x; Remove-Item NUL",
            "cd C:\\x; Set-Content NUL x",
            // A drive that is made, but never entered.
            "New-PSDrive -Name X -PSProvider Registry -Root HKCU:\\Software; Remove-Item NUL",
        ],
        &[
            (
                "New-PSDrive -Name X -PSProvider Function -Root \\; cd X:; Set-Content NUL 'Remove-Item -Recurse -Force ~'; NUL",
                Rule::Overwrite,
            ),
            (
                "New-PSDrive -Name X -PSProvider Registry -Root HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run; cd X:; Remove-Item NUL -Recurse",
                Rule::Delete,
            ),
            (
                "ndr -Name X -PSProvider Registry -Root HKCU:\\Software; cd X:\\Foo; Remove-Item NUL -Recurse",
                Rule::Delete,
            ),
            (
                "mount X Registry HKCU:\\Software; Set-Location X:; Remove-Item NUL",
                Rule::Delete,
            ),
            (
                "New-PSDrive -Name X -PSProvider Function -Root \\; pushd X:\\; Set-Content NUL x",
                Rule::Overwrite,
            ),
        ],
    );
}

#[test]
fn an_item_named_like_a_device_in_a_provider_is_an_item() {
    // In the registry, `Env:` and the like `NUL` and `CON` are ordinary item
    // names: deleting, moving or changing one changes that item, so the item
    // cmdlets judge it as the provider's item.
    check(
        Shell::PowerShell,
        &windows(),
        &[
            // A write or a redirect fails there, so it stays harmless.
            "cd HKCU:\\Software\\Foo; python x.py > NUL",
            "cd HKCU:\\Software\\Foo; python x.py > $null",
            "cd HKCU:\\Software\\Foo; python x.py | Out-File NUL",
            // After a cd to the file system it is the device.
            "cd C:\\other; Remove-Item NUL",
            "cd C:\\other; python x.py > CON",
            // `$null` is the null value in any provider.
            "cd HKCU:\\Software\\Foo; Remove-Item $null",
            "python x.py > $null",
        ],
        &[
            (
                "cd HKCU:\\Software\\Foo; Remove-Item NUL -Recurse",
                Rule::SystemSettings,
            ),
            (
                "Set-Location HKLM:\\SOFTWARE\\Foo; Remove-Item nul",
                Rule::SystemSettings,
            ),
            (
                "Push-Location HKCU:\\Software\\Foo; Remove-Item NUL",
                Rule::SystemSettings,
            ),
            ("sl HKCU:\\Software\\Foo; ri NUL", Rule::SystemSettings),
            (
                "cd Registry::HKEY_CURRENT_USER\\Software\\Foo; Remove-Item NUL",
                Rule::SystemSettings,
            ),
            (
                "cd HKCU:\\Software\\Foo; Remove-ItemProperty -Path NUL -Name x",
                Rule::SystemSettings,
            ),
            (
                "cd HKCU:\\Software\\Foo; Set-ItemProperty -Path NUL -Name x -Value 1",
                Rule::SystemSettings,
            ),
            (
                "cd HKCU:\\Software\\Foo; New-Item NUL -Force",
                Rule::SystemSettings,
            ),
            // A registry key moved is a registry change, as `Remove-Item`.
            (
                "cd HKCU:\\Software\\Foo; Move-Item NUL Bar",
                Rule::SystemSettings,
            ),
            (
                "cd HKLM:\\SOFTWARE\\Foo; Clear-Item NUL",
                Rule::SystemSettings,
            ),
            (
                "cd HKLM:\\SOFTWARE\\Foo; Clear-Item CON",
                Rule::SystemSettings,
            ),
            (
                "cd HKLM:\\SOFTWARE\\Foo; Set-Item NUL -Value 1",
                Rule::SystemSettings,
            ),
            ("cd HKLM:\\SOFTWARE\\Foo; si NUL 1", Rule::SystemSettings),
            ("cd HKLM:\\SOFTWARE\\Foo; cli NUL", Rule::SystemSettings),
            (
                "cd HKLM:\\SOFTWARE\\Foo; Clear-Item -Path NUL",
                Rule::SystemSettings,
            ),
            (
                "cd HKLM:\\SOFTWARE\\Foo; Clear-Item -LiteralPath NUL",
                Rule::SystemSettings,
            ),
            (
                "cd HKLM:\\SOFTWARE\\Foo; Get-Item NUL | Clear-Item",
                Rule::SystemSettings,
            ),
            ("cd HKCU:\\Software; Clear-Item NUL", Rule::SystemSettings),
            (
                "cd Registry::HKEY_LOCAL_MACHINE\\SOFTWARE; Clear-Item NUL",
                Rule::SystemSettings,
            ),
            (
                "cd HKLM:\\SOFTWARE\\Foo; Move-ItemProperty NUL CON -Name x",
                Rule::SystemSettings,
            ),
            (
                "cd HKLM:\\SOFTWARE\\Foo; Copy-ItemProperty NUL CON -Name x",
                Rule::SystemSettings,
            ),
            (
                "cd HKLM:\\SOFTWARE\\Foo; Move-ItemProperty -Path NUL -Destination CON -Name x",
                Rule::SystemSettings,
            ),
            (
                "cd HKLM:\\SOFTWARE\\Foo; Copy-ItemProperty -Path NUL -Destination CON -Name x",
                Rule::SystemSettings,
            ),
            // A place only known when it runs may be a registry key.
            ("cd $key; Remove-Item NUL -Recurse", Rule::Delete),
            ("cd $key; Remove-Item NUL", Rule::Delete),
            ("cd $dir; ri nul -r", Rule::Delete),
            ("cd $dir; rm -r -fo CON", Rule::Delete),
            (
                "cd $dir; Remove-Item -LiteralPath NUL -Recurse",
                Rule::Delete,
            ),
            ("cd $key; Clear-Item NUL", Rule::Overwrite),
            (
                "cd $key; Move-ItemProperty NUL CON -Name x",
                Rule::Overwrite,
            ),
            // The providers that are not the registry.
            ("cd Env:; Remove-Item NUL", Rule::Delete),
            ("cd Variable:; Remove-Item NUL", Rule::Delete),
            ("cd Function:; Remove-Item CON", Rule::Delete),
            ("cd Cert:\\CurrentUser\\My; Remove-Item NUL", Rule::Delete),
            ("cd Env:; Set-Item NUL -Value x", Rule::Overwrite),
            ("cd Variable:; Set-Item NUL -Value x", Rule::Overwrite),
            ("cd 1:; Set-Item NUL -Value 1", Rule::Overwrite),
            (
                "cd Function:; Set-Item NUL -Value 'Remove-Item ~ -Recurse'; NUL",
                Rule::Overwrite,
            ),
            (
                "cd Alias:; Set-Item NUL -Value Remove-Item",
                Rule::Overwrite,
            ),
        ],
    );
}

#[test]
fn a_content_write_that_a_provider_takes_is_an_item() {
    // Only a file system path fails in another provider (a redirect,
    // `Out-File`, `Tee-Object`, `-OutFile`). `Set-Content` and the like take
    // an item of `Function:`, `Alias:`, `Env:` and `Variable:`, and a copy's
    // destination is a key in the registry.
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "cd HKCU:\\Software\\Foo; python x.py | Tee-Object -FilePath NUL",
            "cd HKCU:\\Software\\Foo; Invoke-WebRequest http://x/y -OutFile NUL",
            "cd C:\\other; Set-Content NUL x",
            "cd C:\\other; Copy-Item x NUL",
        ],
        &[
            (
                "cd Function:; Set-Content NUL 'Remove-Item -Recurse -Force ~'; NUL",
                Rule::Overwrite,
            ),
            (
                "cd Alias:; Set-Content NUL Remove-Item; NUL -Recurse -Force ~",
                Rule::Overwrite,
            ),
            (
                "cd Function:; Add-Content NUL 'Remove-Item -Recurse -Force ~'; NUL",
                Rule::Overwrite,
            ),
            ("cd Env:; Clear-Content NUL", Rule::Overwrite),
            (
                "cd HKCU:\\Software\\Foo; Copy-Item Bar NUL -Recurse",
                Rule::SystemSettings,
            ),
            (
                "cd HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion; Copy-Item -Path HKCU:\\Software\\Evil -Destination NUL -Recurse -Force",
                Rule::SystemSettings,
            ),
            ("cd $key; Copy-Item x NUL -Recurse", Rule::Overwrite),
            ("cd $key; Move-Item x NUL", Rule::Overwrite),
        ],
    );
}

#[test]
fn a_rooted_path_after_a_cd_stays_on_the_drive_of_that_cd() {
    // `cd \` is the root of the current drive: after a `cd` to the registry,
    // `Function:` or a place only known when it runs, that is not the file
    // system, so `NUL` there is an item.
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "cd Function:; cd \\; cd C:\\x; Remove-Item NUL",
            "cd C:\\x; cd \\; Remove-Item NUL",
            "cd \\; Remove-Item NUL",
            "cd C:\\x; cd /; Remove-Item NUL",
            "cd Function:; cd C:\\x; Remove-Item NUL",
        ],
        &[
            (
                "cd Function:; cd \\; Set-Content NUL 'Remove-Item -Recurse -Force ~'; NUL",
                Rule::Overwrite,
            ),
            (
                "cd HKCU:\\Software\\Foo; cd \\; Remove-Item NUL -Recurse",
                Rule::SystemSettings,
            ),
            (
                "cd HKCU:\\Software\\Foo; cd \\Software\\Foo; Set-ItemProperty NUL -Name x -Value 1",
                Rule::SystemSettings,
            ),
            (
                "cd HKCU:\\Software\\Foo; Set-Location \\; New-Item NUL -Force",
                Rule::SystemSettings,
            ),
            (
                "cd HKCU:\\Software\\Foo; pushd \\Software; Remove-Item NUL -Recurse",
                Rule::SystemSettings,
            ),
            ("cd Function:; cd /; Set-Content NUL x", Rule::Overwrite),
            ("cd $key; cd \\; Remove-Item NUL -Recurse", Rule::Delete),
            ("cd $key; cd \\Software; New-Item NUL -Force", Rule::Overwrite),
            // A provider path with no drive has no root to read.
            (
                "cd Registry::HKEY_CURRENT_USER\\Software\\Foo; cd \\; Remove-Item NUL",
                Rule::Delete,
            ),
            // A rooted path written after the `cd` is rooted on its drive too.
            (
                "cd HKCU:\\Software\\Foo; Remove-Item \\Software\\Run -Recurse",
                Rule::SystemSettings,
            ),
        ],
    );
}

#[test]
fn home_after_a_cd_to_a_place_without_one_is_not_the_file_system() {
    // `~` is the home of the provider the folder is in. The registry,
    // `Function:` and the like have none, so the `cd ~` fails and the line
    // stays where it was.
    check(
        Shell::PowerShell,
        &windows(),
        &[
            // The file system has a home.
            "cd C:\\x; cd ~; Remove-Item NUL",
            "cd ~; Remove-Item NUL",
            "cd x; cd ~; Remove-Item NUL",
            "cd FileSystem::C:\\x; cd ~; Remove-Item NUL",
        ],
        &[
            (
                "cd HKCU:\\Software\\Foo; cd ~; Remove-Item NUL -Recurse",
                Rule::Delete,
            ),
            (
                "cd HKCU:\\Software\\Foo; cd ~\\x; Remove-Item NUL -Recurse",
                Rule::Delete,
            ),
            (
                "cd HKCU:\\Software\\Foo; cd ~/x; Remove-Item NUL -Recurse",
                Rule::Delete,
            ),
            (
                "cd Function:; cd ~; Set-Content NUL 'x'; NUL",
                Rule::Overwrite,
            ),
            (
                "cd HKCU:\\Software; cd; Remove-Item NUL -Recurse",
                Rule::Delete,
            ),
            (
                "cd HKCU:\\Software; Set-Location; Remove-Item NUL -Recurse",
                Rule::Delete,
            ),
            (
                "cd Registry::HKEY_CURRENT_USER\\Software; cd ~; Remove-Item NUL -Recurse",
                Rule::Delete,
            ),
            ("cd $dir; cd ~; Remove-Item NUL -Recurse", Rule::Delete),
        ],
    );
}

#[test]
fn a_set_location_fed_by_the_pipeline_does_not_go_home() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "cd; Remove-Item NUL",
            "Set-Location | Out-Null; Remove-Item NUL",
        ],
        &[
            (
                "Get-Item HKCU:\\Software | Set-Location; Remove-Item NUL -Recurse",
                Rule::Delete,
            ),
            (
                "'HKCU:\\Software' | cd; Remove-Item NUL -Recurse",
                Rule::Delete,
            ),
            ("$k | cd; Remove-Item NUL -Recurse", Rule::Delete),
            (
                "Get-Item HKCU:\\Software | Push-Location; Remove-Item NUL -Recurse",
                Rule::Delete,
            ),
        ],
    );
}

#[test]
fn a_powershell_cd_dash_is_a_step_in_location_history() {
    // `cd -` and `cd +` go back or forward in location history: the place is
    // only known when it runs, not a folder named `-`.
    check(
        Shell::PowerShell,
        &windows(),
        &[],
        &[
            (
                "cd HKCU:\\Software; cd C:\\x; cd -; Remove-Item NUL -Recurse",
                Rule::Delete,
            ),
            (
                "cd HKCU:\\Software; cd C:\\x; Set-Location -; Remove-Item NUL -Recurse",
                Rule::Delete,
            ),
            (
                "cd HKCU:\\Software; cd C:\\x; sl -; Remove-Item NUL -Recurse",
                Rule::Delete,
            ),
            (
                "cd $k; cd C:\\x; cd -; Remove-Item NUL -Recurse",
                Rule::Delete,
            ),
            (
                "cd Function:; cd C:\\x; cd -; Set-Content NUL 'rm -r -fo ~'; NUL",
                Rule::Overwrite,
            ),
            (
                "cd C:\\Windows\\System32; cd C:\\Users\\me\\dev\\repo; cd -; Remove-Item -Recurse -Force *",
                Rule::Delete,
            ),
            (
                "cd C:\\Windows\\System32; cd C:\\Users\\me\\dev\\repo; Set-Location -Path -; Remove-Item -Recurse -Force *",
                Rule::Delete,
            ),
        ],
    );
}

#[test]
fn the_end_of_parameters_token_is_not_the_path_of_a_cd() {
    // `--` ends the parameters, so `cd -- -` is the history step and
    // `cd -- X` goes to X.
    check(
        Shell::PowerShell,
        &windows(),
        &["cd -- src; npm test", "cd -- .\\src; npm test"],
        &[
            (
                "cd HKCU:\\Software; cd C:\\x; cd -- -; Remove-Item NUL -Recurse",
                Rule::Delete,
            ),
            (
                "cd HKCU:\\Software; cd C:\\x; Set-Location -- -; Remove-Item NUL -Recurse",
                Rule::Delete,
            ),
            (
                "cd C:\\Windows\\System32; cd C:\\Users\\me\\dev\\repo; cd -- -; Remove-Item -Recurse -Force *",
                Rule::Delete,
            ),
            (
                "cd C:\\Windows\\System32; cd C:\\Users\\me\\dev\\repo; cd -- +; Remove-Item -Recurse -Force *",
                Rule::Delete,
            ),
            (
                "cd -- C:\\Windows\\System32; Remove-Item -Recurse -Force *",
                Rule::Delete,
            ),
        ],
    );
}
