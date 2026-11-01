//! Reads and writes judged against a Windows machine's paths: every
//! spelling Windows reads as one name must be judged as that name.

mod common;

use common::{exactly, risky, safe, windows};
use milo_guards_file::{Access, Paths, Rule};

#[test]
fn everyday_reads_are_safe() {
    safe(
        Access::Read,
        &windows(),
        &[
            r"src\main.rs",
            r".\Cargo.toml",
            "src/main.rs",
            r"C:\Users\me\dev\repo\src\x.rs",
            r"c:\users\me\DEV\REPO\x",
            r"C:\Windows\System32\drivers\etc\hosts",
            r"C:\Windows\notepad.exe",
            r"C:\Program Files\App\x.dll",
            r"C:\Users\me\notes.txt",
            r"~\notes.txt",
            "~/notes.txt",
            "~",
            r"~\",
            "NUL",
            "nul",
            "CON",
            r"C:\Users\me\AppData\Local\Temp\x.log",
            r"C:\Windows\Temp\x",
            // The repository's history is not a secret.
            r".git\config",
            r".GIT\config",
            r".git.\config",
            r"GIT~1\config",
            r"\\?\C:\Users\me\dev\repo\.git\config",
            // Startup files are read for what they say.
            r"~\.zshrc",
            r"~\Documents\PowerShell\profile.ps1",
            r"C:\Users\me\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\x.lnk",
            // Beside a secret place is not under it.
            r"C:\Users\me\.sshx\id",
            r"C:\Users\me\.ssh.d\id",
            r"C:\Users\me\SSH~2.txt",
            r"C:\Windows\System32\drivers\etc\hosts",
            r"C:\Windows\System32\configx\x",
            // A long path to a plain file, and a drive-relative one.
            r"\\?\C:\Windows\System32\drivers\etc\hosts",
            r"\\?\C:\Users\me\dev\repo\src\x.rs",
            "C:x",
            r"c:src\x.rs",
            r"\Users\me\dev\repo\x",
            // A POSIX path is read from the working directory's drive.
            "/Windows/notepad.exe",
            // Characters that are plain in a file name.
            r"app\[id]\page.tsx",
            "price$.txt",
            "docs/100%.md",
            "a%20b.txt",
        ],
    );
}

#[test]
fn a_read_of_a_key_or_a_credential_is_a_finding() {
    risky(
        Access::Read,
        &windows(),
        &[
            (r"C:\Users\me\.ssh\id_rsa", Rule::ReadSecret),
            (r"C:\Users\me\.aws\credentials", Rule::ReadSecret),
            (r"C:\Users\me\.kube\config", Rule::ReadSecret),
            (r"C:\Users\me\.npmrc", Rule::ReadSecret),
            (
                r"C:\Users\me\AppData\Roaming\Microsoft\Credentials\x",
                Rule::ReadSecret,
            ),
            (
                r"C:\Users\me\AppData\Roaming\Microsoft\Protect\S-1-5\x",
                Rule::ReadSecret,
            ),
            (r"C:\Windows\System32\config\SAM", Rule::ReadSecret),
            (r"C:\ProgramData\ssh\ssh_host_rsa_key", Rule::ReadSecret),
            // Another user's.
            (r"C:\Users\other\.ssh\id_rsa", Rule::ReadSecret),
            (r"..\..\..\other\.ssh\id_rsa", Rule::ReadSecret),
            (r"~\..\other\.ssh\id_rsa", Rule::ReadSecret),
            // A disk, and a namespace that is not a file path at all.
            (r"\\.\PhysicalDrive0", Rule::ReadSecret),
            (r"\\.\C:", Rule::ReadSecret),
            (
                r"\\?\GLOBALROOT\Device\Harddisk0\Partition1",
                Rule::ReadSecret,
            ),
            // Accepted false alarm: a public key is under `.ssh`.
            (r"C:\Users\me\.ssh\id_rsa.pub", Rule::ReadSecret),
        ],
    );
}

#[test]
fn every_spelling_of_a_key_is_the_key() {
    let spellings = [
        r"C:\Users\me\.ssh\id_rsa",
        "C:/Users/me/.ssh/id_rsa",
        r"C:/Users\me/.ssh\id_rsa",
        r"C:\Users\me\.ssh\\id_rsa",
        r"C:\Users\me\.ssh\.\id_rsa",
        r"C:\Users\me\.ssh\x\..\id_rsa",
        r"C:\\Users\\me\\.ssh\\id_rsa",
        // Case.
        r"c:\users\me\.ssh\id_rsa",
        r"C:\USERS\ME\.SSH\ID_RSA",
        r"C:\Users\Me\.Ssh\Id_Rsa",
        // What Windows drops from a name.
        r"C:\Users\me\.ssh.\id_rsa",
        r"C:\Users\me\.ssh\id_rsa.",
        r"C:\Users\me\.ssh\id_rsa ",
        r"C:\Users\me\.ssh\id_rsa. . ",
        r"C:\Users\me.\.ssh\id_rsa",
        // Short names: the folder's own, and the long name's.
        r"C:\Users\me\SSH~1\id_rsa",
        r"C:\Users\me\ssh~1\ID_RS~1",
        r"C:\Users\me\SSH~2\id_rsa",
        r"C:\Users\ME\SSH~1",
        // Rooted, drive-relative, climbing, and from the home directory.
        r"\Users\me\.ssh\id_rsa",
        "/Users/me/.ssh/id_rsa",
        r"\Users\me\dev\repo\..\..\.ssh\id_rsa",
        r"~\.ssh\id_rsa",
        "~/.ssh/id_rsa",
        r"~\.SSH\id_rsa",
        r"~\SSH~1\id_rsa",
        r"~\.\.ssh\id_rsa",
        r"~\x\..\.ssh\id_rsa",
        r"..\..\.ssh\id_rsa",
        r"src\..\..\..\.ssh\id_rsa",
        r"C:..\..\.ssh\id_rsa",
        r"c:..\..\.SSH\id_rsa",
        r"C:src\..\..\..\.ssh\id_rsa",
        r"C:\Users\me\dev\repo\..\..\.ssh\id_rsa",
        // A long path, with either separator.
        r"\\?\C:\Users\me\.ssh\id_rsa",
        r"\\?\c:\users\me\.SSH\id_rsa",
        "//?/C:/Users/me/.ssh/id_rsa",
        r"\/?\C:\Users\me\.ssh\id_rsa",
        r"\\?\C:\Users\me\SSH~1\id_rsa",
        r"\\?\C:\Users\me\dev\repo\..\..\.ssh\id_rsa",
    ];
    let reads: Vec<(&str, Rule)> = spellings
        .iter()
        .map(|path| (*path, Rule::ReadSecret))
        .collect();
    risky(Access::Read, &windows(), &reads);
    let writes: Vec<(&str, Rule)> = spellings
        .iter()
        .map(|path| (*path, Rule::WriteSensitive))
        .collect();
    risky(Access::Write, &windows(), &writes);
}

#[test]
fn a_device_namespace_is_a_disk_whatever_it_names() {
    // `\\.\C:\x` is `C:\x` to Windows, and `\\?\GLOBALROOT\...` can be
    // any file by an object name: both are judged as the disk they reach.
    for path in [
        r"\\.\C:\Users\me\.ssh\id_rsa",
        "//./C:/Users/me/.ssh/id_rsa",
        r"\/.\C:\Users\me\.ssh\id_rsa",
        r"/\.\C:\Users\me\.ssh\id_rsa",
        r"\\.\\C:\Users\me\.ssh\id_rsa",
        r"\\.\C:\Users\me\dev\repo\x",
        r"\\.\PhysicalDrive0",
        r"\\.\pipe\x",
        r"\\?\Volume{26a21bda-a627-11d7-9931-806e6f6e6963}\Users\me\.ssh\id_rsa",
        r"\\?\C:x",
        r"\\?\",
        r"\\?\X",
        r"\\?\PhysicalDrive0",
    ] {
        exactly(Access::Read, &windows(), &[(path, &[Rule::ReadSecret][..])]);
        exactly(
            Access::Write,
            &windows(),
            &[(path, &[Rule::WriteOutside][..])],
        );
    }
    // `GLOBALROOT` can also be a share (`\\?\GLOBALROOT\Device\Mup\server\share`),
    // so it is one as well.
    for path in [
        r"\\.\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Users\me\.ssh\id_rsa",
        r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Users\me\.ssh\id_rsa",
        r"\\?\globalroot\x",
        // A share with no server.
        r"\\?\UNC",
        r"\\?\UNC\",
    ] {
        exactly(
            Access::Read,
            &windows(),
            &[(path, &[Rule::ReadSecret, Rule::NetworkShare][..])],
        );
        exactly(
            Access::Write,
            &windows(),
            &[(path, &[Rule::WriteOutside, Rule::NetworkShare][..])],
        );
    }
}

#[test]
fn everyday_writes_are_safe() {
    safe(
        Access::Write,
        &windows(),
        &[
            r"src\main.rs",
            r".\x",
            "src/x",
            r"C:\Users\me\dev\repo\x",
            r"c:\USERS\me\dev\repo\x",
            "C:/Users/me/dev/repo/x",
            r"\Users\me\dev\repo\x",
            r".gitignore",
            r".github\workflows\ci.yml",
            r".gitx\config",
            "C:x",
            r"c:src\x.rs",
            r"app\[id]\page.tsx",
            "price$.txt",
            // A temporary file, and the null device.
            r"C:\Users\me\AppData\Local\Temp\x",
            r"C:\Windows\Temp\x",
            r"~\AppData\Local\Temp\x",
            "NUL",
            "nul",
            "NUL:",
            // A long path to the workspace.
            r"\\?\C:\Users\me\dev\repo\x",
            r"\\?\c:\users\me\dev\repo\x",
            "//?/C:/Users/me/dev/repo/x",
        ],
    );
}

#[test]
fn a_write_beyond_the_workspace_is_a_finding() {
    risky(
        Access::Write,
        &windows(),
        &[
            (r"C:\Users\me\notes.txt", Rule::WriteOutside),
            (r"~\notes.txt", Rule::WriteOutside),
            ("~/notes.txt", Rule::WriteOutside),
            (r"C:\Windows\x", Rule::WriteOutside),
            (r"C:\Windows\System32\drivers\etc\hosts", Rule::WriteOutside),
            (r"C:\Program Files\x", Rule::WriteOutside),
            (r"D:\x", Rule::WriteOutside),
            (r"D:\x\y", Rule::WriteOutside),
            (r"..\other\x", Rule::WriteOutside),
            (r"..\..\x", Rule::WriteOutside),
            (r"C:..\..\x", Rule::WriteOutside),
            (r"\x", Rule::WriteOutside),
            (r"C:\", Rule::WriteOutside),
            ("C:/", Rule::WriteOutside),
            (r"\\?\C:\", Rule::WriteOutside),
            // The workspace itself, and the folders around it.
            (".", Rule::WriteOutside),
            (r"C:\Users\me\dev\repo", Rule::WriteOutside),
            ("C:", Rule::WriteOutside),
            (r"c:.", Rule::WriteOutside),
            ("..", Rule::WriteOutside),
            (r"C:\Users\me", Rule::WriteOutside),
            ("~", Rule::WriteOutside),
            (r"C:\Users", Rule::WriteOutside),
            // A disk, and a long path that is no drive.
            (r"\\.\PhysicalDrive0", Rule::WriteOutside),
            (r"\\.\C:\x", Rule::WriteOutside),
            (r"\\?\GLOBALROOT\x", Rule::WriteOutside),
            (r"\\?\C:x", Rule::WriteOutside),
            // Another drive and a share are not the workspace, even by the
            // same path.
            (r"\\?\D:\Users\me\dev\repo\x", Rule::WriteOutside),
            (r"\\srv\share\Users\me\dev\repo\x", Rule::WriteOutside),
        ],
    );
}

#[test]
fn a_write_to_a_key_a_startup_file_or_the_history_is_a_finding() {
    risky(
        Access::Write,
        &windows(),
        &[
            (r"C:\Users\me\.ssh\config", Rule::WriteSensitive),
            (r"~\.ssh\authorized_keys", Rule::WriteSensitive),
            (r"C:\Users\me\.aws\credentials", Rule::WriteSensitive),
            (r"C:\Windows\System32\config\SAM", Rule::WriteSensitive),
            (r"C:\Users\other\.ssh\authorized_keys", Rule::WriteSensitive),
            (r"C:\ProgramData\ssh\sshd_config", Rule::WriteSensitive),
            // What Windows starts, by any name for it.
            (
                r"C:\Users\me\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\x.bat",
                Rule::WriteSensitive,
            ),
            (
                r"~\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\x.bat",
                Rule::WriteSensitive,
            ),
            (r"~\Documents\PowerShell\profile.ps1", Rule::WriteSensitive),
            (
                r"~\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1",
                Rule::WriteSensitive,
            ),
            (
                r"C:\Users\me\DOCUME~1\POWERS~1\profile.ps1",
                Rule::WriteSensitive,
            ),
            (r"~\.zshrc", Rule::WriteSensitive),
            (r"~\.gitconfig", Rule::WriteSensitive),
            // The repository's history, by every name Windows gives it.
            (r".git\HEAD", Rule::WriteSensitive),
            (".git/HEAD", Rule::WriteSensitive),
            (r".git", Rule::WriteSensitive),
            (r".git\", Rule::WriteSensitive),
            (r".git.\HEAD", Rule::WriteSensitive),
            (r".git\HEAD.", Rule::WriteSensitive),
            (r".git\HEAD ", Rule::WriteSensitive),
            (r".GIT\HEAD", Rule::WriteSensitive),
            (r"GIT~1\HEAD", Rule::WriteSensitive),
            (r"git~1\head", Rule::WriteSensitive),
            (r"src\..\.git\HEAD", Rule::WriteSensitive),
            (r"C:\Users\me\dev\repo\.git\HEAD", Rule::WriteSensitive),
            (r"c:\users\me\dev\repo\.GIT\HEAD", Rule::WriteSensitive),
            (r"\\?\C:\Users\me\dev\repo\.git\HEAD", Rule::WriteSensitive),
            (r"C:.git\HEAD", Rule::WriteSensitive),
            (r"C:..\..\.ssh\config", Rule::WriteSensitive),
        ],
    );
}

#[test]
fn a_path_that_is_not_one_literal_path_is_unreadable() {
    let rows: Vec<(&str, Rule)> = [
        "",
        // A variable.
        r"%USERPROFILE%\.ssh\id_rsa",
        r"%APPDATA%\x",
        r"%ProgramFiles(x86)%\x",
        r"$env:USERPROFILE\x",
        r"${env:HOME}\x",
        r"$HOME\x",
        r"$(Get-Location)\x",
        r"`$HOME\x",
        r"C:\Users\me\x.txt::$DATA",
        r"C:\Users\me\.ssh::$INDEX_ALLOCATION\id_rsa",
        // A wildcard.
        r"~\*",
        r"\\server\share\*",
        r"C:\Users\me\dev\repo\*.rs",
        r"C:\Users\me\.ss?\id_rsa",
        r"C:\Users\me\.s*\id_rsa",
        "C:*",
        r"\\?\C:\x*",
        r"\\?\C:\Users\me\dev\repo\x?",
        r"\\?\?",
        // Another user's `~`.
        r"~root\x",
        "~me",
        r"~.ssh\id_rsa",
        // A name Windows reads at run time: a stream, a name of dots and
        // spaces, a folder name that ends in a space or two dots.
        r"C:\Users\me\x.txt:stream",
        "x.txt:stream",
        r"C:\Users\me\.ssh:stream\id_rsa",
        r".git:$I30:$INDEX_ALLOCATION\HEAD",
        r".git ::$INDEX_ALLOCATION\HEAD",
        r"C:\Users\me\.ssh \id_rsa",
        r"C:\Users\me\.ssh..\id_rsa",
        r".git \HEAD",
        r"...",
        r"C:\Users\me\...\x",
        r"x\. \y",
        r"src\ \x",
        // Another drive's own working directory is not known.
        "D:x",
        "D:",
        r"d:..\..\x",
        r"D:.ssh\id_rsa",
        r"E:*",
    ]
    .iter()
    .map(|path| (*path, Rule::Unreadable))
    .collect();
    for access in [Access::Read, Access::Write] {
        risky(access, &windows(), &rows);
    }
}

#[test]
fn a_drive_relative_path_is_from_the_working_directory_on_that_drive() {
    // On the drive the working directory is on: from it.
    exactly(
        Access::Read,
        &windows(),
        &[
            ("C:x", &[]),
            ("C:.git\\config", &[]),
            (r"C:..\..\.ssh\id_rsa", &[Rule::ReadSecret]),
            (r"C:..\..\notes.txt", &[]),
            (r"D:x", &[Rule::Unreadable]),
        ],
    );
    exactly(
        Access::Write,
        &windows(),
        &[
            ("C:x", &[]),
            (r"C:..\..\notes.txt", &[Rule::WriteOutside]),
            (r"C:..", &[Rule::WriteOutside]),
            (r"D:x", &[Rule::Unreadable]),
        ],
    );
    // A working directory on D:, with a second workspace on C:.
    let paths = Paths::new(
        r"D:\work",
        r"C:\Users\me",
        [r"D:\work", r"C:\Users\me\dev\repo"],
    );
    exactly(
        Access::Write,
        &paths,
        &[
            ("D:x", &[]),
            (r"D:..\x", &[Rule::WriteOutside]),
            ("C:x", &[Rule::Unreadable]),
            (r"C:\Users\me\dev\repo\x", &[]),
            (r"C:\Users\me\.ssh\config", &[Rule::WriteSensitive]),
        ],
    );
    exactly(
        Access::Read,
        &paths,
        &[
            ("C:x", &[Rule::Unreadable]),
            (r"C:\Users\me\.ssh\id_rsa", &[Rule::ReadSecret]),
            ("x", &[]),
        ],
    );
}

#[test]
fn a_network_share_is_a_finding_whatever_it_is_spelled() {
    for share in [
        r"\\server\share\x",
        "//server/share/x",
        r"\\server\share",
        r"\\server",
        r"\\?\UNC\server\share\x",
        r"\\?\unc\server\share\x",
        "//?/UNC/server/share/x",
        r"\\localhost\C$\Users\me\.ssh\id_rsa",
        r"\\127.0.0.1\C$\x",
        r"\\wsl$\Ubuntu\home\me\.ssh\id_rsa",
        r"\\wsl.localhost\Ubuntu\home\me\x",
        r"\\server\..\x",
    ] {
        let rules = common::rules(Access::Read, &windows(), share);
        assert!(rules.contains(&Rule::NetworkShare), "{share}: {rules:?}");
        let rules = common::rules(Access::Write, &windows(), share);
        assert!(rules.contains(&Rule::NetworkShare), "{share}: {rules:?}");
    }
    exactly(
        Access::Read,
        &windows(),
        &[
            (r"\\server\share\x", &[Rule::NetworkShare][..]),
            (r"\\?\UNC\server\share\x", &[Rule::NetworkShare][..]),
            (
                r"\\localhost\C$\Users\me\.ssh\id_rsa",
                &[Rule::NetworkShare][..],
            ),
            // The device namespace is a disk as well.
            (
                r"\\.\UNC\server\share\x",
                &[Rule::ReadSecret, Rule::NetworkShare][..],
            ),
            (
                r"\\?\GLOBALROOT\Device\Mup\server\share\x",
                &[Rule::ReadSecret, Rule::NetworkShare][..],
            ),
            // A share that cannot be told apart from what it says is both.
            (
                r"\\server\share\*",
                &[Rule::Unreadable, Rule::NetworkShare][..],
            ),
            (r"\\*\share", &[Rule::Unreadable, Rule::NetworkShare][..]),
        ],
    );
    exactly(
        Access::Write,
        &windows(),
        &[
            (
                r"\\server\share\x",
                &[Rule::WriteOutside, Rule::NetworkShare][..],
            ),
            (
                r"\\?\UNC\server\share\x",
                &[Rule::WriteOutside, Rule::NetworkShare][..],
            ),
            (
                r"\\server\share",
                &[Rule::WriteOutside, Rule::NetworkShare][..],
            ),
        ],
    );
    // Not a share: a drive, a long path to one, a device.
    for local in [
        r"C:\x",
        r"\x",
        r"\\?\C:\x",
        "//?/C:/x",
        "/x",
        r"C:\\x",
        r"src\x",
    ] {
        let rules = common::rules(Access::Read, &windows(), local);
        assert!(!rules.contains(&Rule::NetworkShare), "{local}: {rules:?}");
    }
    // On a POSIX machine two separators are one.
    exactly(
        Access::Read,
        &common::posix(),
        &[("//server/share/x", &[]), (r"\\server\share\x", &[])],
    );
}

#[test]
fn a_workspace_on_a_share_is_the_agents_own() {
    let paths = Paths::new(r"\\srv\share\repo", r"C:\Users\me", [r"\\srv\share\repo"]);
    exactly(
        Access::Write,
        &paths,
        &[
            ("src/x", &[]),
            (r"\\srv\share\repo\src\x", &[]),
            (r"\\SRV\Share\repo\src\x", &[]),
            (r"\\?\UNC\srv\share\repo\src\x", &[]),
            (
                r"\\srv\share\other\x",
                &[Rule::WriteOutside, Rule::NetworkShare],
            ),
            (
                r"\\evil\share\repo\src\x",
                &[Rule::WriteOutside, Rule::NetworkShare],
            ),
            (r"\\srv\share\repo\.git\HEAD", &[Rule::WriteSensitive]),
            (r"\\srv\share\repo", &[Rule::WriteOutside]),
        ],
    );
    exactly(
        Access::Read,
        &paths,
        &[
            (r"\\srv\share\repo\src\x", &[]),
            (r"\\srv\share\repo\.git\config", &[]),
            (r"\\srv\share\other\x", &[Rule::NetworkShare]),
            (r"\\evil\share\x", &[Rule::NetworkShare]),
        ],
    );
}

#[test]
fn a_workspace_spelled_as_a_long_path_is_still_the_workspace() {
    // A canonical path on Windows carries the long-path prefix.
    let paths = Paths::new(
        r"\\?\C:\Users\me\dev\repo",
        r"\\?\C:\Users\me",
        [r"\\?\C:\Users\me\dev\repo"],
    );
    exactly(
        Access::Write,
        &paths,
        &[
            ("src/x", &[]),
            (r"C:\Users\me\dev\repo\src\x", &[]),
            (r"\\?\C:\Users\me\dev\repo\src\x", &[]),
            (r"C:\Users\me\notes.txt", &[Rule::WriteOutside]),
            (r"C:\Users\me\.ssh\config", &[Rule::WriteSensitive]),
        ],
    );
    exactly(
        Access::Read,
        &paths,
        &[
            (r"C:\Users\me\.ssh\id_rsa", &[Rule::ReadSecret]),
            (r"\\?\C:\Users\me\.ssh\id_rsa", &[Rule::ReadSecret]),
            ("src/x", &[]),
        ],
    );
}

#[test]
fn a_home_directory_with_a_long_name_is_judged_by_its_short_name_too() {
    let paths = Paths::new(
        r"C:\Users\Camilo Azula\dev\repo",
        r"C:\Users\Camilo Azula",
        [r"C:\Users\Camilo Azula\dev\repo"],
    );
    exactly(
        Access::Read,
        &paths,
        &[
            (r"C:\Users\Camilo Azula\.ssh\id_rsa", &[Rule::ReadSecret]),
            (r"C:\Users\CAMILO~1\.ssh\id_rsa", &[Rule::ReadSecret]),
            (r"C:\Users\camilo~1\SSH~1\id_rsa", &[Rule::ReadSecret]),
            (r"C:\Users\CAMILO~1\.aws\credentials", &[Rule::ReadSecret]),
            (r"C:\Users\CAMILO~1\notes.txt", &[]),
            (r"C:\Users\CAMILO~1\dev\repo\src\x.rs", &[]),
            (r"~\.ssh\id_rsa", &[Rule::ReadSecret]),
        ],
    );
    exactly(
        Access::Write,
        &paths,
        &[
            (r"C:\Users\CAMILO~1\.ssh\config", &[Rule::WriteSensitive]),
            (r"C:\Users\CAMILO~1\notes.txt", &[Rule::WriteOutside]),
            (r"C:\Users\CAMILO~1", &[Rule::WriteOutside]),
            // The workspace by its short name is, conservatively, beyond it.
            (r"C:\Users\CAMILO~1\dev\repo\x", &[Rule::WriteOutside]),
            (r"C:\Users\Camilo Azula\dev\repo\x", &[]),
        ],
    );
}

#[test]
fn a_workspace_that_is_the_home_directory_keeps_its_keys() {
    let paths = Paths::new(r"C:\Users\me", r"C:\Users\me", [r"C:\Users\me"]);
    exactly(
        Access::Read,
        &paths,
        &[
            (r".ssh\id_rsa", &[Rule::ReadSecret]),
            (r"SSH~1\id_rsa", &[Rule::ReadSecret]),
            (r"C:\Users\ME\.SSH\id_rsa", &[Rule::ReadSecret]),
            (r"src\x.rs", &[]),
        ],
    );
    exactly(
        Access::Write,
        &paths,
        &[
            (r".ssh\config", &[Rule::WriteSensitive]),
            (r".git\HEAD", &[Rule::WriteSensitive]),
            (r"src\x.rs", &[]),
        ],
    );
}

#[test]
fn only_the_names_ntfs_folds_make_the_workspace_the_workspace() {
    // The Kelvin sign, the Ångström sign, the Ohm sign and the capital sharp
    // s are not the letters they look like to NTFS: a folder by those names
    // is another folder, so a write to it is beyond the workspace.
    for (workspace, other) in [
        ("work", "wor\u{212a}"),
        ("wor\u{e5}", "wor\u{212b}"),
        ("wor\u{3c9}", "wor\u{2126}"),
        ("stra\u{df}e", "stra\u{1e9e}e"),
    ] {
        let dir = format!(r"C:\Users\me\{workspace}");
        let paths = Paths::new(dir.as_str(), r"C:\Users\me", [dir.as_str()]);
        let folded = format!(r"C:\Users\me\{other}\x");
        let same = format!(r"C:\Users\me\{workspace}\x");
        exactly(
            Access::Write,
            &paths,
            &[
                (same.as_str(), &[][..]),
                (folded.as_str(), &[Rule::WriteOutside][..]),
            ],
        );
    }
    // Where matching too much fails closed, they still match: the home
    // directory, a key's folder, a protected path.
    let kim = Paths::new(r"C:\Users\Kim\dev", r"C:\Users\Kim", [r"C:\Users\Kim\dev"]);
    exactly(
        Access::Read,
        &kim,
        &[
            (
                "C:\\Users\\\u{212a}im\\.ssh\\id_rsa",
                &[Rule::ReadSecret][..],
            ),
            (
                "C:\\Users\\Kim\\.\u{212a}ube\\config",
                &[Rule::ReadSecret][..],
            ),
        ],
    );
}

#[test]
fn the_credential_stores_and_startup_places_that_have_twins_are_listed() {
    risky(
        Access::Read,
        &windows(),
        &[
            (
                r"C:\Users\me\AppData\Roaming\GitHub CLI\hosts.yml",
                Rule::ReadSecret,
            ),
            (r"~\AppData\Roaming\GitHub CLI\hosts.yml", Rule::ReadSecret),
            (
                r"C:\Users\me\AppData\Roaming\gcloud\credentials.db",
                Rule::ReadSecret,
            ),
            (
                r"C:\Users\me\AppData\Roaming\gnupg\private-keys-v1.d\x.key",
                Rule::ReadSecret,
            ),
            (
                r"C:\Users\me\AppData\Local\Microsoft\Vault\x",
                Rule::ReadSecret,
            ),
            (
                r"C:\Users\me\AppData\Roaming\Microsoft\Vault\x",
                Rule::ReadSecret,
            ),
            (r"C:\ProgramData\Microsoft\Vault\x", Rule::ReadSecret),
            (
                r"C:\Users\me\APPDAT~1\Roaming\GITHUB~1\hosts.yml",
                Rule::ReadSecret,
            ),
            // Another user's, whatever this user's home is.
            (
                r"C:\Users\alice\AppData\Roaming\GitHub CLI\hosts.yml",
                Rule::ReadSecret,
            ),
        ],
    );
    risky(
        Access::Write,
        &windows(),
        &[
            (r"C:\Users\me\.config\git\config", Rule::WriteSensitive),
            (
                r"~\.config\powershell\Microsoft.PowerShell_profile.ps1",
                Rule::WriteSensitive,
            ),
            (
                r"C:\Users\me\OneDrive\Documents\PowerShell\profile.ps1",
                Rule::WriteSensitive,
            ),
            (
                r"C:\Users\me\OneDrive\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1",
                Rule::WriteSensitive,
            ),
            (
                r"C:\Users\me\onedrive\documents\powershell\profile.ps1",
                Rule::WriteSensitive,
            ),
            (
                r"C:\Users\me\.config\systemd\user\x.service",
                Rule::WriteSensitive,
            ),
        ],
    );
    safe(
        Access::Read,
        &windows(),
        &[
            r"C:\Users\me\OneDrive\Documents\PowerShell\profile.ps1",
            r"C:\Users\me\.config\git\config",
        ],
    );
}

#[test]
fn another_users_home_is_one_whatever_this_users_home_is() {
    let paths = Paths::new(
        r"D:\profiles\me\repo",
        r"D:\profiles\me",
        [r"D:\profiles\me\repo"],
    );
    risky(
        Access::Read,
        &paths,
        &[
            (r"C:\Users\alice\.ssh\id_rsa", Rule::ReadSecret),
            (r"c:\users\ALICE\.SSH\id_rsa", Rule::ReadSecret),
            (r"D:\Users\alice\.ssh\id_rsa", Rule::ReadSecret),
            (r"D:\profiles\alice\.ssh\id_rsa", Rule::ReadSecret),
        ],
    );
    safe(Access::Read, &paths, &[r"C:\Users\alice\notes.txt"]);
}

#[test]
fn a_git_folder_at_any_depth_is_history_and_its_hooks_run_code() {
    risky(
        Access::Write,
        &windows(),
        &[
            (r"src\.git\x", Rule::WriteSensitive),
            (r"src\GIT~1\x", Rule::WriteSensitive),
            (r"vendor\x\.git\hooks\pre-commit", Rule::WriteSensitive),
            (r"vendor\x\GIT~1\hooks\pre-commit", Rule::WriteSensitive),
            (r"vendor\x\.git.\hooks\pre-commit", Rule::WriteSensitive),
            (r"vendor\x\.GIT\HOOKS\pre-commit", Rule::WriteSensitive),
            (r"..\other\.git\hooks\x", Rule::WriteSensitive),
        ],
    );
    safe(
        Access::Read,
        &windows(),
        &[r"vendor\x\.git\hooks\pre-commit", r"vendor\x\.git\config"],
    );
    for (path, reason) in [
        (
            r"vendor\x\.git\hooks\pre-commit",
            "writes to a git hook, which runs code",
        ),
        (
            r"vendor\x\.git\config",
            "writes to the repository's history",
        ),
    ] {
        let found = milo_guards_file::judge(Access::Write, path, &windows());
        assert_eq!(found.findings().len(), 1, "{path}");
        assert_eq!(found.findings()[0].reason, reason, "{path}");
    }
    safe(
        Access::Write,
        &windows(),
        &[r"src\GITHUB~1\x", r"src\.github\x", r"hooks\x"],
    );
}
