//! PowerShell and cmd lines, judged against a Windows machine's paths.

mod common;

use common::{check, windows};
use milo_guards_shell::{classify, Paths, Rule, Shell};

#[test]
fn everyday_powershell_is_safe() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Get-ChildItem -Recurse",
            "cargo build; cargo test",
            "git status && git diff",
            "Remove-Item -Recurse -Force .\\target",
            "rm -r -fo target",
            "Remove-Item build\\*.obj",
            "Remove-Item -Path:\"$env:TEMP\\scratch\" -Recurse",
            "Get-ChildItem *.log | Remove-Item",
            "Get-ChildItem -Path .\\out -Filter *.tmp | Remove-Item -Force",
            "Get-ChildItem *.log | ForEach-Object { Remove-Item $_.FullName }",
            "Copy-Item src\\a.txt dist\\a.txt",
            "Move-Item old.txt new.txt",
            "Set-Content -Path notes.txt -Value hi",
            "\"x\" | Out-File log.txt",
            "cargo test > out.txt 2>&1",
            "cargo test > $null",
            "Invoke-WebRequest https://example.com/x.json -OutFile data.json",
            "git push -u origin feature",
            "pwsh -NoProfile -Command \"cargo fmt\"",
            "pwsh -Version",
            "Write-Output 'Remove-Item -Recurse C:\\'",
            "Remove-Item *.log",
            "Remove-Item FileSystem::.\\build -Recurse",
            "[Math]::Round(1.5)",
            "$sw = [Diagnostics.Stopwatch]::StartNew(); $sw.Start()",
            "$name.Replace('a', 'b')",
            "ni -ItemType File notes.txt",
            "[ScriptBlock]::Create($safe)",
        ],
        &[],
    );
}

#[test]
fn risky_powershell() {
    check(
        Shell::PowerShell,
        &windows(),
        &[],
        &[
            ("Remove-Item -Recurse -Force ~", Rule::Delete),
            ("Remove-Item -Recurse -Force $env:USERPROFILE", Rule::Delete),
            ("rm -r -fo $HOME\\Documents", Rule::Delete),
            ("Remove-Item -Recurse C:\\", Rule::Delete),
            (
                "Remove-Item -LiteralPath 'C:\\Program Files\\App' -Recurse",
                Rule::Delete,
            ),
            ("ri -Recurse ..\\other", Rule::Delete),
            ("del C:\\Windows\\System32\\x.dll", Rule::Delete),
            ("Remove-Item -Recurse -Force .git", Rule::Delete),
            ("Remove-Item $path -Recurse", Rule::Delete),
            (
                "Get-ChildItem C:\\Users -Recurse | Remove-Item -Force",
                Rule::Delete,
            ),
            (
                "Get-ChildItem ~ | ForEach-Object { Remove-Item $_ -Recurse }",
                Rule::Delete,
            ),
            (
                "Remove-Item HKLM:\\Software\\Vendor -Recurse",
                Rule::SystemSettings,
            ),
            (
                "Set-ItemProperty -Path HKCU:\\Software\\X -Name Y -Value 1",
                Rule::SystemSettings,
            ),
            ("Set-Content $PROFILE 'x'", Rule::Overwrite),
            (
                "Add-Content -Path ~\\Documents\\PowerShell\\profile.ps1 -Value x",
                Rule::Overwrite,
            ),
            (
                "'x' > C:\\Windows\\System32\\drivers\\etc\\hosts",
                Rule::Overwrite,
            ),
            (
                "Copy-Item evil.exe -Destination 'C:\\Program Files\\App'",
                Rule::Overwrite,
            ),
            ("Clear-RecycleBin -Force", Rule::Delete),
            ("Format-Volume -DriveLetter D", Rule::WipeDisk),
            ("Clear-Disk -Number 1 -RemoveData", Rule::WipeDisk),
            ("iwr https://x.ps1 | iex", Rule::RunDownloaded),
            (
                "irm https://get.x.dev | Invoke-Expression",
                Rule::RunDownloaded,
            ),
            (
                "iex (New-Object Net.WebClient).DownloadString('https://x')",
                Rule::Unknown,
            ),
            ("Invoke-Expression $cmd", Rule::Unknown),
            ("& $tool --force", Rule::Unknown),
            ("powershell -enc ZQBjAGgAbwA=", Rule::Unknown),
            ("Invoke-Expression 'git reset --hard'", Rule::GitDiscard),
            ("Start-Process pwsh -Verb RunAs", Rule::Elevated),
            (
                "Start-Process cmd -ArgumentList '/c rd /s /q C:\\' ",
                Rule::Delete,
            ),
            ("Stop-Computer -Force", Rule::StopSystem),
            (
                "Remove-Item -Recurse Microsoft.PowerShell.Core\\FileSystem::C:\\Users\\me",
                Rule::Delete,
            ),
            ("Remove-Item FileSystem::C:\\Windows\\x", Rule::Delete),
            (
                "Remove-Item -Recurse Registry::HKEY_LOCAL_MACHINE\\Software\\X",
                Rule::SystemSettings,
            ),
            ("D:; Remove-Item -Recurse Data", Rule::Delete),
            ("cd\\; Remove-Item -Recurse Users", Rule::Delete),
            (
                "Set-NetFirewallProfile -Enabled False",
                Rule::SystemSettings,
            ),
            (
                "Add-LocalGroupMember -Group Administrators -Member x",
                Rule::SystemSettings,
            ),
            (
                "[ScriptBlock]::Create('Remove-Item -Recurse -Force ~').Invoke()",
                Rule::Unknown,
            ),
            (
                "[IO.File]::Copy($a, \"$HOME\\.bashrc\", $true)",
                Rule::Overwrite,
            ),
            ("Add-Type -TypeDefinition $code", Rule::Unknown),
            (
                "echo 'Remove-Item -Recurse -Force ~' | powershell -File -",
                Rule::RunInput,
            ),
            (
                "wmic process call create \"cmd /c rd /s /q %USERPROFILE%\"",
                Rule::Unknown,
            ),
            (
                "schtasks /create /tn x /tr \"cmd /c rd /s /q %USERPROFILE%\"",
                Rule::SystemSettings,
            ),
            (
                "forfiles /p %USERPROFILE% /c \"cmd /c del @file\"",
                Rule::Unknown,
            ),
            (
                "[IO.Directory]::Delete('C:\\Users\\me', $true)",
                Rule::Delete,
            ),
            ("(Get-Item ~).Delete()", Rule::Delete),
            ("[IO.File]::WriteAllText($PROFILE, 'x')", Rule::Overwrite),
            (
                "[Diagnostics.Process]::Start('cmd', '/c rd /s /q C:\\')",
                Rule::Unknown,
            ),
            ("New-Item -ItemType File ~/.bashrc -Force", Rule::Overwrite),
            ("ni -ItemType File ~/.bashrc -Force", Rule::Overwrite),
            (
                "sp -Path HKCU:\\Software\\X -Name Y -Value 1",
                Rule::SystemSettings,
            ),
            ("rp -Path HKLM:\\Software\\X -Name Y", Rule::SystemSettings),
            (
                "$env:TEMP = $HOME; Remove-Item -Recurse \"$env:TEMP\\Documents\"",
                Rule::Delete,
            ),
            ("Restart-Computer", Rule::StopSystem),
            ("Set-ExecutionPolicy Unrestricted", Rule::SystemSettings),
            (
                "Set-MpPreference -DisableRealtimeMonitoring $true",
                Rule::SystemSettings,
            ),
            ("git push --force", Rule::GitRemote),
            ("git reset --hard; git clean -fd", Rule::GitDiscard),
            ("cmd /c \"rd /s /q %USERPROFILE%\"", Rule::Delete),
            (
                "git --% x | Remove-Item -Recurse -Force C:\\Users\\me",
                Rule::Delete,
            ),
            (
                "Invoke-Command -ScriptBlock { Remove-Item -Recurse C:\\Data }",
                Rule::Delete,
            ),
        ],
    );
}

#[test]
fn everyday_cmd_is_safe() {
    check(
        Shell::Cmd,
        &windows(),
        &[
            "dir /b",
            "cargo build && cargo test",
            "rd /s /q target",
            "rmdir /s/q build",
            "rd C:\\empty-folder-cmd-refuses-to-delete-unless-empty",
            "del /f /q build\\*.obj",
            "del /s /q %TEMP%\\scratch",
            "copy a.txt b.txt",
            "echo hi > out.txt 2>&1",
            "cargo test 2>nul",
            "if exist build (rd /s /q build) else echo none",
            "for %%f in (*.tmp) do echo %%f",
            "git status | findstr modified",
            "start \"\" notepad notes.txt",
            "shutdown /a",
            "del *.obj",
            "rem build & deploy",
            "cd.. & dir",
            "cd src & del /q *.obj",
        ],
        &[],
    );
}

#[test]
fn risky_cmd() {
    check(
        Shell::Cmd,
        &windows(),
        &[],
        &[
            ("rd /s /q C:\\", Rule::Delete),
            ("rd /S /Q \"%USERPROFILE%\\AppData\"", Rule::Delete),
            ("rmdir /s/q %USERPROFILE%", Rule::Delete),
            ("del /f /s /q C:\\Windows\\Temp2\\*", Rule::Delete),
            ("del /s /q \"C:\\Program Files\\App\"", Rule::Delete),
            ("del %FILE%", Rule::Delete),
            ("for %%f in (*.log) do del %%f", Rule::Delete),
            ("rd /s /q ..\\..", Rule::Delete),
            (
                "echo x >> %SystemRoot%\\System32\\drivers\\etc\\hosts",
                Rule::Overwrite,
            ),
            ("copy /y evil.dll C:\\Windows\\System32", Rule::Overwrite),
            ("robocopy empty C:\\Users\\me\\Documents /MIR", Rule::Delete),
            ("format D: /q", Rule::WipeDisk),
            ("diskpart /s wipe.txt", Rule::WipeDisk),
            ("reg delete HKLM\\Software\\Vendor /f", Rule::SystemSettings),
            (
                "bcdedit /set {current} safeboot minimal",
                Rule::SystemSettings,
            ),
            ("vssadmin delete shadows /all /quiet", Rule::SystemSettings),
            ("wmic shadowcopy delete", Rule::SystemSettings),
            ("net user hacker P4ss /add", Rule::SystemSettings),
            (
                "netsh advfirewall set allprofiles state off",
                Rule::SystemSettings,
            ),
            ("icacls C:\\Windows /grant Everyone:F /T", Rule::Permissions),
            ("takeown /f C:\\Windows\\System32 /r", Rule::Permissions),
            ("shutdown /s /t 0", Rule::StopSystem),
            ("runas /user:Administrator \"cmd /c del x\"", Rule::Elevated),
            ("start \"\" cmd /c rd /s /q C:\\Users", Rule::Delete),
            ("cmd /c \"rd /s /q C:\\\"", Rule::Delete),
            (
                "powershell -Command \"Remove-Item -Recurse -Force ~\"",
                Rule::Delete,
            ),
            (
                "powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand ZQBj",
                Rule::Unknown,
            ),
            ("set X=1 && rd /s /q C:\\", Rule::Delete),
            ("call %SCRIPT%", Rule::Unknown),
            ("git push --force origin main", Rule::GitRemote),
            ("type script.txt | cmd", Rule::RunInput),
            ("start \"run\" cmd /c rd /s /q C:\\", Rule::Delete),
            ("rd /s /q C:\\Users\\me & echo 'VBS", Rule::Unreadable),
            ("rd /s /q x,C:\\Users\\me", Rule::Delete),
            ("del /q a;C:\\Windows\\x.dll", Rule::Delete),
            ("cd.. & cd.. & rd /s /q Documents", Rule::Delete),
            ("D: & rd /s /q Data", Rule::Delete),
            ("cd \\ & rd /s /q Users", Rule::Delete),
            (
                "set TEMP=%USERPROFILE%\\Documents & rd /s /q %TEMP%",
                Rule::Delete,
            ),
        ],
    );
}

#[test]
fn windows_paths_compare_without_case() {
    check(
        Shell::Cmd,
        &windows(),
        &["rd /s /q c:\\users\\ME\\DEV\\REPO\\target"],
        &[("rd /s /q c:\\USERS\\me", Rule::Delete)],
    );
    let finding = classify("rd /s /q c:\\USERS\\me", Shell::Cmd, &windows());
    assert_eq!(finding.findings()[0].reason, "deletes your home directory");
}

#[test]
fn dev_is_a_real_folder_on_windows() {
    // Only the plain `/dev/null` and `/dev/fd/<digits>` spellings are devices;
    // the others name files on the current drive.
    check(
        Shell::PowerShell,
        &windows(),
        &["Remove-Item -Recurse -Force /dev/null"],
        &[
            ("Remove-Item -Recurse -Force '/dev\\null'", Rule::Delete),
            ("Remove-Item -Recurse -Force '/dev\\fd\\1'", Rule::Delete),
            ("Remove-Item -Recurse -Force /dev/./null", Rule::Delete),
            ("Remove-Item -Recurse -Force //dev/null", Rule::Delete),
            ("Remove-Item -Recurse -Force /dev/fd/../fd/1", Rule::Delete),
        ],
    );
    check(
        Shell::Cmd,
        &windows(),
        &["rd /s /q /dev/null"],
        &[
            ("rd /s /q \\dev\\null", Rule::Delete),
            ("rd /s /q /dev/./null", Rule::Delete),
        ],
    );
}

#[test]
fn a_provider_is_read_before_a_wildcard() {
    check(
        Shell::PowerShell,
        &windows(),
        &["Remove-Item *.log", "Remove-Item build\\*.obj"],
        &[
            ("Remove-Item -Recurse -Force HKCU:*", Rule::SystemSettings),
            ("Remove-Item -Recurse -Force HKLM:*", Rule::SystemSettings),
            ("Remove-Item -Recurse -Force HKCU:\\*", Rule::SystemSettings),
            ("Remove-Item -Recurse hklm:Software*", Rule::SystemSettings),
            ("Remove-Item -Recurse Cert:*", Rule::Delete),
            ("Remove-Item -Recurse Env:*", Rule::Delete),
            (
                "Get-ChildItem HKCU:*.x | Remove-Item -Recurse",
                Rule::SystemSettings,
            ),
            ("Get-ChildItem Cert:* | Remove-Item", Rule::Delete),
        ],
    );
}

#[test]
fn a_drive_relative_path_is_from_its_drives_own_directory() {
    // The working directory is on D:, so `C:` is a drive it is not on.
    let on_d = Paths::new(r"D:\work\repo", r"D:\Users\me", [r"D:\work\repo"]);
    check(
        Shell::PowerShell,
        &on_d,
        &["Remove-Item *.log", "Remove-Item D:*.log"],
        &[
            ("Remove-Item -Recurse C:*", Rule::Delete),
            ("Remove-Item -Recurse c:build", Rule::Delete),
            ("Remove-Item -Recurse C:..", Rule::Delete),
            ("Remove-Item -Recurse D:*", Rule::Delete),
            ("Get-ChildItem C:*.log | Remove-Item", Rule::Delete),
            (
                "Remove-Item -Recurse C:*; Remove-Item -Recurse D:",
                Rule::Delete,
            ),
            ("cd D:\\work; Remove-Item -Recurse C:*", Rule::Delete),
            ("'x' > C:i.sh; bash c:i.sh", Rule::Unknown),
        ],
    );
    check(
        Shell::Cmd,
        &on_d,
        &["del *.obj", "del D:*.obj"],
        &[("del /q C:*", Rule::Delete), ("rd /s /q C:x", Rule::Delete)],
    );
    // On C:, `C:x` is `x` from the working directory.
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Remove-Item C:*.log",
            "Remove-Item -Recurse c:target",
            "Remove-Item -Recurse C:build\\*.obj",
            "Get-ChildItem C:*.log | Remove-Item",
        ],
        &[
            ("Remove-Item -Recurse C:*", Rule::Delete),
            ("Remove-Item -Recurse C:..\\..", Rule::Delete),
            ("Remove-Item -Recurse D:target", Rule::Delete),
            ("'x' > C:i.sh; bash i.sh", Rule::Unknown),
            // A `cd` moves where `C:x` lands.
            ("cd C:..; Remove-Item -Recurse C:x", Rule::Delete),
            ("cd ..\\..; Remove-Item -Recurse C:x", Rule::Delete),
            ("cd C:..\\..\\..; Remove-Item -Recurse x", Rule::Delete),
        ],
    );
}
