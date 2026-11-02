//! The `Reach` of a PowerShell or cmd line that only reads: where its reads
//! land from the workspace and from other working directories, a protected
//! `.agent` at the workspace's root (the workspace's own), a Windows wildcard
//! that matches a hidden name and so reaches a hidden folder that holds a
//! secret, and the values of `Get-ChildItem -Depth` and `-Attributes`. The
//! plain readers of the plain workspace are in `effect.rs`; POSIX is in
//! `reach.rs`.

mod common;

use common::{check_effect, windows};
use milo_guards_shell::{Effect, Paths, Protected, Reach, Shell};

const STAYS: Effect = Effect::ReadsOnly(Reach::Workspace);
const BEYOND: Effect = Effect::ReadsOnly(Reach::Beyond);

const AGENT: &str = "the agent's settings";

/// A Windows machine whose agent runs in `cwd`, in the workspace
/// `C:\Users\me\dev\repo`.
fn windows_in(cwd: &str) -> Paths {
    Paths::new(cwd, r"C:\Users\me", [r"C:\Users\me\dev\repo"])
}

/// The plain workspace with a protected `.agent` folder at its root.
fn agent_windows() -> Paths {
    windows().with_protected([Protected::folder(r"C:\Users\me\dev\repo\.agent", AGENT)])
}

/// A Windows machine whose workspace is the home folder.
fn windows_home() -> Paths {
    Paths::new(r"C:\Users\me", r"C:\Users\me", [r"C:\Users\me"])
}

/// A Windows machine whose workspace is `AppData\Roaming`, which holds
/// `gcloud`'s login.
fn windows_roaming() -> Paths {
    Paths::new(
        r"C:\Users\me\AppData\Roaming",
        r"C:\Users\me",
        [r"C:\Users\me\AppData\Roaming"],
    )
}

#[test]
fn powershell_reads_say_where_they_land() {
    check_effect(
        Shell::PowerShell,
        &windows(),
        STAYS,
        &[
            "Get-ChildItem src",
            "Get-ChildItem -Path src",
            "Get-ChildItem .",
            "Get-ChildItem .\\src",
            "Get-ChildItem C:\\Users\\me\\dev\\repo",
            "Get-ChildItem C:\\Users\\me\\dev\\repo\\src",
            "Get-ChildItem c:\\users\\me\\dev\\REPO\\src",
            "gci",
            "gci -Recurse -Filter *.rs",
            "Get-Content src\\main.rs",
            "Get-Content -Path a.txt",
            "Get-Content -LiteralPath a.txt",
            "Get-Content .\\a.txt",
            "Get-Content C:\\Users\\me\\dev\\repo\\a.txt",
            "Resolve-Path src",
            "Select-String TODO a.txt",
            "Get-ChildItem -Recurse | Select-String TODO",
            "ls | Get-Content",
            "echo hi",
            "pwd",
            "git diff",
            "git -C src status",
            "git -C . status",
            "git diff HEAD~1 -- src",
            "cd src; cd ..; ls",
            "cd .; ls",
            "cd C:\\Users\\me\\dev\\repo\\src; Get-ChildItem",
            "$env:TEMP",
        ],
    );
    check_effect(
        Shell::PowerShell,
        &windows(),
        BEYOND,
        &[
            "Get-Content ~/.ssh/id_ed25519",
            "Get-Content ~\\.ssh\\id_ed25519",
            "Get-Content C:\\Users\\me\\.ssh\\id_ed25519",
            "Get-Content C:\\USERS\\ME\\.ssh\\id_rsa",
            "Get-Content C:\\Users\\me\\a.txt",
            "Get-Content C:\\Windows\\win.ini",
            "Get-Content \\\\?\\C:\\Users\\me\\a.txt",
            "Get-Content \\\\?\\C:\\Windows\\win.ini",
            "Get-Content /not/a/share",
            "Get-Content /etc/passwd",
            "Get-Content $HOME",
            "Get-Content -Path ~/.ssh/id_rsa",
            "Get-Content -LiteralPath C:\\Windows\\win.ini",
            "Get-Content ..\\x",
            "Get-Content src\\..\\..\\x",
            "Get-Content a.txt, ~/.ssh/id_rsa",
            "cat ~/.ssh/id_rsa",
            "gc ~/.ssh/id_rsa",
            "type ~/.ssh/id_rsa",
            "Get-ChildItem ~",
            "Get-ChildItem ~/",
            "Get-ChildItem C:\\",
            "Get-ChildItem D:\\",
            "Get-ChildItem -Path C:\\Users\\me",
            "Get-ChildItem C:\\Users",
            "Get-ChildItem C:\\Users\\me\\dev",
            "Get-ChildItem C:\\Users\\me\\dev\\repo\\..",
            "Get-ChildItem C:\\Users\\me\\dev\\repo2",
            "Get-ChildItem C:\\Windows\\System32",
            "Get-ChildItem $env:TEMP",
            "Get-ChildItem $HOME",
            "Get-ChildItem ..",
            "Get-ChildItem ..\\other",
            "Get-ChildItem -Path ..",
            "Get-ChildItem -Recurse ~",
            "Get-ChildItem HKLM:\\Software",
            "Get-ChildItem HKCU:\\",
            "Get-ChildItem Registry::HKEY_LOCAL_MACHINE",
            "Get-ChildItem Env:",
            "Get-ChildItem FileSystem::C:\\Windows",
            "ls ~",
            "dir ~",
            "gci C:\\",
            "Get-Item ~/.ssh/id_rsa",
            "Test-Path ~/.ssh/id_rsa",
            "Resolve-Path ~",
            "Select-String -Path ~/.ssh/* -Pattern x",
            "Select-String -Path C:\\Windows\\*.ini -Pattern x",
            "Select-String x ~/.ssh/id_rsa",
            "Select-String -Pattern x -Path ..\\x",
            "git -C ~/other status",
            "git -C .. status",
            "git -C C:\\ status",
            "git -C C:\\Users\\me status",
            "git blame --contents ~/x f",
            "cd ~; Get-ChildItem",
            "cd ~; ls",
            "cd ..; ls",
            "cd ../..; Get-ChildItem",
            "cd C:\\; dir",
            "cd C:\\Users\\me; Get-ChildItem",
            "cd C:\\Windows; Get-ChildItem",
            "cd ..\\other; ls",
            "cd src; cd ..\\..; ls",
            "Set-Location ~; ls",
            "Set-Location ..; ls",
            "Set-Location -Path ~; ls",
            "Set-Location C:\\Windows; Get-ChildItem",
            "Set-Location ~",
            "Set-Location C:\\",
            "cd ~",
            "pushd ~; ls",
            "Push-Location ~; ls",
            "Get-ChildItem ~ | Get-Content",
            "Get-ChildItem C:\\ | Select-String x",
            "Get-ChildItem -Recurse C:\\ | Select-String x",
            "Get-ChildItem C:\\ | Where-Object { $true } | Get-Content",
        ],
    );
    // From elsewhere (from the workspace itself, the tables above and
    // `effect.rs` hold each of these).
    for (cwd, expected) in [
        (r"C:\Users\me\dev\repo\src", STAYS),
        (r"c:\users\me\dev\REPO\src", STAYS),
        (r"C:\Users\me\dev\repo2", BEYOND),
        (r"C:\Users\me\dev", BEYOND),
        (r"C:\Users\me", BEYOND),
        (r"C:\Windows", BEYOND),
        (r"C:\", BEYOND),
        (r"D:\work", BEYOND),
    ] {
        check_effect(
            Shell::PowerShell,
            &windows_in(cwd),
            expected,
            &[
                "Get-ChildItem",
                "ls",
                "dir",
                "gci -Recurse -Filter *.rs",
                "Get-ChildItem -Recurse | Select-String TODO",
                "git status",
                "git log --oneline",
                "git diff",
                "ls | Get-Content",
            ],
        );
    }
    check_effect(
        Shell::PowerShell,
        &windows_in(r"C:\Windows"),
        STAYS,
        &[
            "Write-Output hi",
            "Write-Host hi",
            "pwd",
            "Get-Location",
            "Get-Content C:\\Users\\me\\dev\\repo\\a.txt",
            "Get-ChildItem C:\\Users\\me\\dev\\repo\\src",
            "Get-ChildItem -Path C:\\Users\\me\\dev\\repo",
            "git -C C:\\Users\\me\\dev\\repo status",
            "Select-String TODO C:\\Users\\me\\dev\\repo\\a.txt",
            "Set-Location C:\\Users\\me\\dev\\repo; Get-ChildItem",
            "Test-Path C:\\Users\\me\\dev\\repo\\a",
            "$null",
        ],
    );
    check_effect(
        Shell::PowerShell,
        &windows_in(r"C:\Users\me\dev\repo\src"),
        STAYS,
        &[
            "cd ..; ls",
            "Set-Location ..; Get-ChildItem",
            "cd ..; git status",
            "cd .\\..; ls",
        ],
    );
    check_effect(
        Shell::PowerShell,
        &windows_in(r"C:\Users\me\dev\repo\src"),
        BEYOND,
        &[
            "cd ..\\..; ls",
            "cd ..\\..\\..; Get-ChildItem",
            "Set-Location ..\\..; ls",
            "cd ..\\..; git status",
        ],
    );
}

#[test]
fn cmd_reads_say_where_they_land() {
    check_effect(
        Shell::Cmd,
        &windows(),
        STAYS,
        &[
            "dir src",
            "dir .",
            "dir .\\src",
            "dir C:\\Users\\me\\dev\\repo",
            "dir c:\\users\\me\\dev\\REPO\\src",
            "type src\\main.rs",
            "type C:\\Users\\me\\dev\\repo\\a.txt",
            "findstr TODO a.txt",
            "echo hi > nul",
            "cd /d C:\\Users\\me\\dev\\repo\\src && dir",
            "cd src && cd .. && dir",
            "git log --oneline",
            "git -C src log",
        ],
    );
    check_effect(
        Shell::Cmd,
        &windows(),
        BEYOND,
        &[
            "type C:\\Windows\\win.ini",
            "type C:\\Users\\me\\.ssh\\id_rsa",
            "type C:\\Users\\me\\a.txt",
            "type ..\\x",
            "type \"C:\\Users\\me\\a.txt\"",
            "type \\\\?\\C:\\Windows\\win.ini",
            "type C:\\USERS\\ME\\.ssh\\id_rsa",
            "type a.txt ..\\b.txt",
            "dir \\\\?\\C:\\Users\\me",
            "dir C:\\",
            "dir C:\\Users",
            "dir C:\\Users\\me",
            "dir C:\\Windows",
            "dir C:\\Users\\me\\dev\\repo\\..",
            "dir C:\\Users\\me\\dev\\repo2",
            "dir D:\\",
            "dir ..",
            "dir ..\\other",
            "dir /s C:\\",
            "dir /s /b C:\\Users\\me",
            "findstr x C:\\Windows\\win.ini",
            "findstr /s x C:\\Windows\\*.ini",
            "findstr /s TODO ..\\*.rs",
            "findstr /g:C:\\Windows\\win.ini y",
            "findstr /d:C:\\Windows x *",
            "findstr /d:src;C:\\Windows x *",
            "type a.txt | findstr x C:\\Windows\\win.ini",
            "cd ..",
            "cd .. && dir",
            "cd ..\\.. && dir",
            "cd C:\\ && dir",
            "cd /d C:\\ && dir",
            "cd /d C:\\Users\\me && dir",
            "cd /d C:\\Windows && type win.ini",
            "cd /d C:\\Users\\me\\dev\\repo\\.. && dir",
            "cd src && cd ..\\.. && dir",
            "cd ..\\other && dir",
            "git -C .. status",
            "git -C C:\\ status",
            "git -C C:\\Users\\me status",
            "git blame --contents C:\\Windows\\win.ini f",
            "type a.txt && cd .. && dir",
        ],
    );
    // From elsewhere (from the workspace itself, the tables above and
    // `effect.rs` hold each of these).
    for (cwd, expected) in [
        (r"C:\Users\me\dev\repo\src", STAYS),
        (r"C:\Users\me\dev\repo2", BEYOND),
        (r"C:\Users\me", BEYOND),
        (r"C:\Windows", BEYOND),
        (r"C:\", BEYOND),
        (r"D:\work", BEYOND),
    ] {
        check_effect(
            Shell::Cmd,
            &windows_in(cwd),
            expected,
            &[
                "dir",
                "dir /s",
                "dir /s /b *.rs",
                "git status",
                "git log --oneline",
            ],
        );
    }
    check_effect(
        Shell::Cmd,
        &windows_in(r"C:\Windows"),
        STAYS,
        &[
            "echo hi",
            "cd",
            "type C:\\Users\\me\\dev\\repo\\a.txt",
            "dir C:\\Users\\me\\dev\\repo\\src",
            "git -C C:\\Users\\me\\dev\\repo status",
            "cd /d C:\\Users\\me\\dev\\repo && dir",
        ],
    );
}

#[test]
fn a_protected_path_on_windows_is_the_workspace() {
    check_effect(
        Shell::PowerShell,
        &agent_windows(),
        STAYS,
        &[
            "Get-Content .agent\\config.yaml",
            "Get-Content .agent/config.yaml",
            "Get-Content .\\.agent\\config.yaml",
            "Get-Content .AGENT\\config.yaml",
            "Get-Content AGENT~1\\config.yaml",
            "Get-Content src\\..\\.agent\\config.yaml",
            "Get-Content C:\\Users\\me\\dev\\repo\\.agent\\config.yaml",
            "Get-Content C:\\USERS\\ME\\DEV\\REPO\\.AGENT\\config.yaml",
            "Get-ChildItem .agent",
            "Get-ChildItem .agent\\*",
            "Get-Content .age*\\config.yaml",
            "Get-Content .agent\\*.yaml",
            "Get-Content *\\config.yaml",
            "Select-String x .agent\\config.yaml",
            "Select-String -Path .agent\\* -Pattern x",
            "Set-Location .agent; Get-Content config.yaml",
            "Get-ChildItem -Recurse | Select-String x",
            "Get-ChildItem -Recurse -Filter *.yaml | Get-Content",
            "Get-ChildItem | Get-Content",
            // What is beside it.
            "Get-ChildItem",
            "Get-ChildItem src",
            "Get-Content src\\main.rs",
            "Get-Content Cargo.toml",
            "Get-Content .agentx\\x",
            "git status",
            "Get-ChildItem src -Recurse | Select-String x",
            // Wildcards and listings under the root.
            "gci",
            "gci -Recurse",
            "gci -Force",
            "gci .agent",
            "Get-Content .agent\\x",
            "Get-Content .AGENT\\x",
            "Get-Content .\\*\\x",
            "Get-Content *\\x",
            "Select-String -Path *\\* -Pattern x",
            "Select-String -Path * -Pattern x",
            "Select-String x *",
            "Get-Content README.md",
            "git show HEAD:.agent/x",
            "Select-String -Path .\\*\\* -Pattern x",
            "Select-String -Pattern x -Path *\\*",
            "sls x *\\*",
            "Get-Content -Path *\\*",
            "gc *\\*",
            "Get-Content *\\*",
            "Select-String -Path .\\.agent\\x -Pattern x",
            "Select-String -Path *\\x -Pattern x",
            "Select-String x .agent\\x",
            "Select-String -LiteralPath .agent\\x -Pattern x",
        ],
    );
    check_effect(
        Shell::PowerShell,
        &agent_windows(),
        BEYOND,
        &[
            "Set-Location ~; gci",
            "Push-Location ~; gci",
            "Set-Location ..; Get-ChildItem",
            "cd ~; gci",
            "Get-Content ~\\.ssh\\id_rsa",
            "Get-Content C:\\Windows\\win.ini",
            "Test-Path ~\\.ssh\\id_rsa",
            "Resolve-Path ~",
            "Get-Item ~",
            "Get-ChildItem C:\\",
            "Get-ChildItem ..",
        ],
    );
    check_effect(
        Shell::PowerShell,
        &agent_windows(),
        Effect::Unknown,
        &["Get-Content $HOME\\x"],
    );
    check_effect(
        Shell::Cmd,
        &agent_windows(),
        STAYS,
        &[
            "type .agent\\config.yaml",
            "type .agent/config.yaml",
            "type .AGENT\\config.yaml",
            "type AGENT~1\\config.yaml",
            "type src\\..\\.agent\\config.yaml",
            "type C:\\Users\\me\\dev\\repo\\.agent\\config.yaml",
            "dir .agent",
            "findstr x .agent\\config.yaml",
            "findstr /s x *",
            "findstr /s x *.yaml",
            "findstr /s /i password *",
            "cd .agent && type config.yaml",
            "type .age*\\config.yaml",
            "type *\\config.yaml",
            // What is beside it.
            "dir",
            "dir src",
            "type src\\main.rs",
            "type Cargo.toml",
            "type .agentx\\x",
            "findstr /s x src\\*.rs",
            "findstr x Cargo.toml",
            "git status",
            // Wildcards and listings under the root.
            "cd & dir",
            "dir /s",
            "dir /a",
            "type .agent\\x",
            "type .AGENT\\x",
            "findstr x *",
            "findstr x .agent\\*",
            "findstr /s x src\\*",
            "type README.md",
            "findstr x *\\*",
            "findstr x .\\.agent\\x",
            "type *\\x",
        ],
    );
    check_effect(
        Shell::Cmd,
        &agent_windows(),
        BEYOND,
        &[
            "cd /d C:\\ & dir",
            "cd .. & dir",
            "dir %USERPROFILE%",
            "type %USERPROFILE%\\x",
            "dir ..",
            "type C:\\Windows\\win.ini",
            "pushd C:\\ & dir",
            "cd /d D:\\ & dir",
        ],
    );
    check_effect(
        Shell::Cmd,
        &agent_windows(),
        Effect::Unknown,
        &[
            ".",
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s",
        ],
    );
}

// A Windows wildcard matches a hidden name, so `*\*` reaches a hidden folder.

#[test]
fn a_windows_wildcard_reaches_a_hidden_folder_that_holds_a_secret() {
    // The home folder and `AppData\Roaming` each hold a hidden folder of
    // secrets below them.
    for paths in [windows_home(), windows_roaming()] {
        check_effect(
            Shell::PowerShell,
            &paths,
            BEYOND,
            &[
                "Get-Content *\\*",
                "Get-Content -Path *\\*",
                "Get-Content .\\*\\*",
                "gc *\\*",
                "cat *\\*",
                "type *\\*",
                "Select-String -Path *\\* -Pattern x",
                "Select-String -Pattern x -Path *\\*",
                "Select-String -Path .\\*\\* -Pattern x",
                "sls x *\\*",
                "Get-ChildItem -Recurse",
                "gci -r",
                "gci -Rec",
                "Get-ChildItem -Depth 2",
                "Get-ChildItem -Recurse | Select-String x",
                "Get-ChildItem -Recurse -Filter *.yaml | Get-Content",
                "gci -Recurse",
                "Get-Content .\\*\\x",
                "Get-Content *\\x",
                "Select-String -Path * -Pattern x",
                "Select-String x *",
                "Select-String -Path *\\x -Pattern x",
                // What is beyond the folder.
                "Set-Location ~; gci",
                "Push-Location ~; gci",
                "Set-Location ..; Get-ChildItem",
                "cd ~; gci",
                "Get-Content ~\\.ssh\\id_rsa",
                "Get-Content C:\\Windows\\win.ini",
                "git status",
                "git show HEAD:.agent/x",
                "Test-Path ~\\.ssh\\id_rsa",
                "Resolve-Path ~",
                "Get-Item ~",
                "Get-ChildItem C:\\",
                "Get-ChildItem ..",
            ],
        );
        check_effect(
            Shell::PowerShell,
            &paths,
            STAYS,
            &[
                "gci .agent",
                "Get-Content .agent\\x",
                "Get-Content .AGENT\\x",
                "Get-Content README.md",
                "Select-String -Path .agent\\* -Pattern x",
                "Select-String -Path .\\.agent\\x -Pattern x",
                "Select-String x .agent\\x",
                "Select-String -LiteralPath .agent\\x -Pattern x",
            ],
        );
        check_effect(
            Shell::PowerShell,
            &paths,
            Effect::Unknown,
            &["Get-Content $HOME\\x"],
        );
        check_effect(
            Shell::Cmd,
            &paths,
            BEYOND,
            &[
                "findstr x *\\*",
                "findstr /s x *",
                "findstr /s x *.yaml",
                "findstr /s /i x *",
                "type *\\x",
                "type *\\*",
                "dir /s",
                "dir /s /b",
                "dir /s/b",
                "dir *\\*",
                "findstr x *",
                // What is beyond the folder.
                "cd /d C:\\ & dir",
                "cd .. & dir",
                "dir %USERPROFILE%",
                "dir ..",
                "type C:\\Windows\\win.ini",
                "pushd C:\\ & dir",
                "cd /d D:\\ & dir",
            ],
        );
        check_effect(
            Shell::Cmd,
            &paths,
            STAYS,
            &[
                "dir .agent",
                "type .agent\\x",
                "type .AGENT\\x",
                "findstr x .agent\\*",
                "findstr /s x src\\*",
                "type README.md",
                "findstr x .\\.agent\\x",
            ],
        );
        check_effect(
            Shell::Cmd,
            &paths,
            Effect::Unknown,
            &[
                ".",
                "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s",
            ],
        );
    }
    // From the home folder, with the workspace there: a key.
    check_effect(
        Shell::PowerShell,
        &windows_home(),
        BEYOND,
        &[
            "Get-Content .ssh\\id_rsa",
            "Get-Content .\\.ssh\\id_rsa",
            "Get-Content C:\\Users\\me\\.ssh\\id_rsa",
            "Get-Content .ss*\\id_rsa",
            "Get-ChildItem .ssh",
            "Get-ChildItem",
            "gci",
            "gci -Force",
        ],
    );
    check_effect(
        Shell::PowerShell,
        &windows_home(),
        STAYS,
        &[
            "Get-Content src\\main.rs",
            "Get-ChildItem src",
            "Get-ChildItem -Recurse src",
            "Get-Content src\\*",
            "Select-String -Path src\\*.rs -Pattern x",
            "Get-Content .bashrc",
            "Get-Content .gitconfig",
            "Write-Output hi",
        ],
    );
    check_effect(
        Shell::Cmd,
        &windows_home(),
        STAYS,
        &[
            "dir src",
            "dir /s src",
            "type src\\*.rs",
            "echo hi",
            "type %USERPROFILE%\\x",
        ],
    );
    check_effect(
        Shell::Cmd,
        &windows_home(),
        BEYOND,
        &[
            "type .ssh\\id_rsa",
            "dir .ssh",
            "dir",
            "dir /a",
            "type C:\\Users\\me\\.ssh\\id_rsa",
            "cd & dir",
        ],
    );
    // From `AppData\Roaming`: the folder's own listing holds no hidden
    // folder, and the home folder is beyond it.
    check_effect(
        Shell::PowerShell,
        &windows_roaming(),
        STAYS,
        &["gci", "gci -Force"],
    );
    check_effect(
        Shell::Cmd,
        &windows_roaming(),
        STAYS,
        &["cd & dir", "dir", "dir /a"],
    );
    check_effect(
        Shell::Cmd,
        &windows_roaming(),
        BEYOND,
        &["type %USERPROFILE%\\x"],
    );
    // Beneath the workspace's root, with no secret to reach.
    check_effect(
        Shell::PowerShell,
        &windows(),
        STAYS,
        &[
            "Get-Content *\\*",
            "Select-String -Path *\\* -Pattern x",
            "Get-ChildItem -Recurse",
            "Get-ChildItem -Recurse | Select-String x",
            "gc *\\x",
        ],
    );
    check_effect(
        Shell::Cmd,
        &windows(),
        STAYS,
        &["findstr x *\\*", "findstr /s x *", "type *\\x"],
    );
}

#[test]
fn get_childitem_takes_depth_and_attributes_with_a_value() {
    // The value is no place, so the folder is the working directory.
    check_effect(
        Shell::PowerShell,
        &windows(),
        STAYS,
        &[
            "Get-ChildItem -Depth 2",
            "gci -dep 2",
            "ls -Attributes Hidden",
            "dir -at !System",
            "gci -Attributes Hidden+System src",
        ],
    );
    check_effect(
        Shell::PowerShell,
        &windows_in(r"C:\Windows"),
        BEYOND,
        &["Get-ChildItem -Depth 2", "gci -Attributes Hidden"],
    );
    // A value that is a path is a place.
    check_effect(
        Shell::PowerShell,
        &windows(),
        BEYOND,
        &[
            "Get-ChildItem -Depth C:\\Windows",
            "gci -Attributes ~",
            "gci -at ..\\x",
        ],
    );
}

#[test]
fn a_path_relative_to_the_repository_root_is_read_from_the_root_too() {
    // As in `reach.rs`: a path git reads from the repository's root is judged
    // from the working directory and from each workspace folder.
    let windows = Paths::new(r"C:\Users\me\proj", r"C:\Users\me", [r"C:\Users\me"]);
    check_effect(
        Shell::PowerShell,
        &windows,
        BEYOND,
        &["git show HEAD:.ssh/id_rsa", "git show :/.ssh/id_rsa"],
    );
    check_effect(
        Shell::PowerShell,
        &windows,
        STAYS,
        &["git show HEAD:src/lib.rs", "git show :/src/lib.rs"],
    );
}
