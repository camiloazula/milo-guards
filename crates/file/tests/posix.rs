//! Reads and writes judged against a POSIX machine's paths, and a Mac's.

mod common;

use common::{exactly, macos, posix, risky, safe};
use milo_guards_file::{judge, Access, Paths, Protected, Rule};

/// Where the agent works, with the home directory as the workspace.
fn home() -> Paths {
    Paths::new("/home/me", "/home/me", ["/home/me"])
}

#[test]
fn everyday_reads_are_safe() {
    safe(
        Access::Read,
        &posix(),
        &[
            "src/main.rs",
            "./Cargo.toml",
            "README.md",
            "/home/me/work/repo/src/lib.rs",
            "src/../Cargo.lock",
            "/etc/hosts",
            "/etc/passwd",
            "/etc/os-release",
            "/usr/include/stdio.h",
            "/proc/cpuinfo",
            "/home/me/notes.txt",
            "~/notes.txt",
            "~/Documents/todo.md",
            "~",
            "~/",
            "../other/x.rs",
            "/tmp/build.log",
            "/dev/null",
            "/dev/zero",
            "/dev/urandom",
            // The repository's history is not a secret.
            ".git/config",
            ".git/HEAD",
            ".git/objects/ab/cdef",
            "/home/me/work/repo/.git/config",
            ".GIT/config",
            // Startup files and git's settings are read for what they say.
            "~/.zshrc",
            "~/.bashrc",
            "~/.profile",
            "~/.gitconfig",
            "~/.config/fish/config.fish",
            "~/.bash_logout",
            // Beside a secret place is not under it.
            "/home/me/.sshx/id_rsa",
            "/home/me/.ssh.d/id_rsa",
            "~/.config/other/x",
            "~/.configx/gh/hosts.yml",
            "~/.cargo/config.toml",
            "~/.cargo/registry/index",
            "/home/me/.awsx/credentials",
            "/etc/sshd_config",
            "/etc/shadowx",
            "/etc/ssl/certs/ca-certificates.crt",
            // A backslash is a plain character in a POSIX name.
            "~/.ssh\\id_rsa",
            // Characters that are plain in a file name.
            "app/[id]/page.tsx",
            "src/routes/[slug]/+page.svelte",
            "price$.txt",
            "a$",
            "dir$/x",
            "docs/100%.md",
            "a%20b.txt",
            "50%/60%",
            "a.$",
            "a/~b",
            "weird name (1).txt",
            "'quoted'.txt",
        ],
    );
}

#[test]
fn a_read_of_a_key_or_a_credential_is_a_finding() {
    risky(
        Access::Read,
        &posix(),
        &[
            ("~/.ssh/id_ed25519", Rule::ReadSecret),
            ("/home/me/.aws/credentials", Rule::ReadSecret),
            ("~/.gnupg/private-keys-v1.d/x.key", Rule::ReadSecret),
            ("~/.docker/config.json", Rule::ReadSecret),
            ("~/.kube/config", Rule::ReadSecret),
            ("~/.azure/accessTokens.json", Rule::ReadSecret),
            ("~/.netrc", Rule::ReadSecret),
            ("~/.git-credentials", Rule::ReadSecret),
            ("~/.npmrc", Rule::ReadSecret),
            ("~/.pypirc", Rule::ReadSecret),
            ("~/.vault-token", Rule::ReadSecret),
            ("~/.password-store/x.gpg", Rule::ReadSecret),
            ("~/.config/gh/hosts.yml", Rule::ReadSecret),
            ("~/.config/gcloud/credentials.db", Rule::ReadSecret),
            ("~/.config/git/credentials", Rule::ReadSecret),
            ("~/.cargo/credentials.toml", Rule::ReadSecret),
            ("~/.local/share/keyrings/login.keyring", Rule::ReadSecret),
            ("/etc/shadow", Rule::ReadSecret),
            ("/etc/gshadow", Rule::ReadSecret),
            ("/etc/ssh/ssh_host_ed25519_key", Rule::ReadSecret),
            ("/etc/ssl/private/ssl-cert-snakeoil.key", Rule::ReadSecret),
            ("/etc/wireguard/wg0.conf", Rule::ReadSecret),
            // Another user's, and the root user's.
            ("/home/other/.ssh/id_rsa", Rule::ReadSecret),
            ("../../../other/.ssh/id_rsa", Rule::ReadSecret),
            ("~/../other/.aws/credentials", Rule::ReadSecret),
            ("/root/.ssh/id_rsa", Rule::ReadSecret),
            ("/var/root/.ssh/id_rsa", Rule::ReadSecret),
            // The bytes of a disk hold every key on it.
            ("/dev/sda", Rule::ReadSecret),
            ("/dev/sda1", Rule::ReadSecret),
            ("/dev/nvme0n1", Rule::ReadSecret),
            ("/dev/disk0", Rule::ReadSecret),
            ("/dev/mapper/root", Rule::ReadSecret),
            // Accepted false alarms: the table says "under", not "which
            // file", so a public key and the list of hosts are findings too.
            ("~/.ssh/id_ed25519.pub", Rule::ReadSecret),
            ("~/.ssh/known_hosts", Rule::ReadSecret),
            ("~/.ssh/config", Rule::ReadSecret),
            ("~/.docker/contexts/meta/x/meta.json", Rule::ReadSecret),
            ("~/.config/gh/config.yml", Rule::ReadSecret),
            ("/etc/ssh/sshd_config", Rule::ReadSecret),
            ("/etc/ssh/ssh_host_ed25519_key.pub", Rule::ReadSecret),
        ],
    );
}

#[test]
fn every_spelling_of_a_key_is_the_key() {
    let spellings = [
        "~/.ssh/id_rsa",
        "/home/me/.ssh/id_rsa",
        "/home/me/.ssh//id_rsa",
        "/home/me/./.ssh/id_rsa",
        "/home/me/.ssh/./id_rsa",
        "/home/me/.ssh/x/../id_rsa",
        "/home/me/../me/.ssh/id_rsa",
        "/../home/me/.ssh/id_rsa",
        "//home/me/.ssh/id_rsa",
        "///home///me/.ssh/id_rsa",
        "~/.ssh/../.ssh/id_rsa",
        "~/./.ssh/id_rsa",
        "~//.ssh/id_rsa",
        "~/work/../.ssh/id_rsa",
        "~/../me/.ssh/id_rsa",
        "../../.ssh/id_rsa",
        "src/../../../.ssh/id_rsa",
        "/home/me/work/repo/../../.ssh/id_rsa",
        // Case: a Mac's file system and a Windows one ignore it.
        "~/.SSH/id_rsa",
        "~/.Ssh/ID_RSA",
        "/HOME/ME/.ssh/id_rsa",
        "/Home/Me/.SSH/Id_Rsa",
        // The long s and the Kelvin sign are an `s` and a `k` to them.
        "/home/me/.\u{17f}sh/id_rsa",
        "/home/me/.\u{17f}\u{17f}h/id_rsa",
        // The folder and what is under it.
        "~/.ssh",
        "/home/me/.ssh/",
        "/home/me/.ssh/id_rsa/",
        "/home/me/.ssh/id_rsa/.",
        "/home/me/.ssh/id_rsa/..",
    ];
    for access in [Access::Read, Access::Write] {
        let rows: Vec<(&str, Rule)> = spellings
            .iter()
            .map(|path| {
                let rule = match access {
                    Access::Read => Rule::ReadSecret,
                    Access::Write => Rule::WriteSensitive,
                };
                (*path, rule)
            })
            .collect();
        risky(access, &posix(), &rows);
    }
}

#[test]
fn the_kelvin_sign_is_a_k() {
    risky(
        Access::Read,
        &posix(),
        &[("/home/me/.\u{212a}ube/config", Rule::ReadSecret)],
    );
}

#[test]
fn every_spelling_of_a_workspace_file_is_safe() {
    let spellings = [
        "src/main.rs",
        "./src/main.rs",
        "src//main.rs",
        "src/./main.rs",
        "src/../src/main.rs",
        "/home/me/work/repo/src/main.rs",
        "/home/me/work/repo//src///main.rs",
        "/home/me/work/./repo/src/main.rs",
        "../repo/src/main.rs",
        "/home/me/work/other/../repo/src/main.rs",
        "~/work/repo/src/main.rs",
        "~/work/../work/repo/src/main.rs",
    ];
    for access in [Access::Read, Access::Write] {
        safe(access, &posix(), &spellings);
    }
}

#[test]
fn everyday_writes_are_safe() {
    safe(
        Access::Write,
        &posix(),
        &[
            "src/main.rs",
            "./x",
            "new/dir/file.txt",
            "/home/me/work/repo/x",
            "src/../x",
            ".gitignore",
            ".gitattributes",
            ".gitx/config",
            "x.git/config",
            ".env",
            ".hidden",
            "node_modules/.bin/tool",
            "target/debug/build.log",
            "app/[id]/page.tsx",
            "src/routes/[slug]/+page.svelte",
            "price$.txt",
            "docs/100%.md",
            "a/~b",
            // A temporary file, and the null device.
            "/tmp/x",
            "/tmp/a/b/c.txt",
            "/var/tmp/x",
            "/private/tmp/x",
            "/dev/null",
            "/dev/stderr",
            "/dev/fd/1",
            // Beside a sensitive place is not it.
            "/home/me/work/repo/.sshx",
            "src/.ssh.rs",
        ],
    );
}

#[test]
fn a_write_beyond_the_workspace_is_a_finding() {
    risky(
        Access::Write,
        &posix(),
        &[
            ("../other/x", Rule::WriteOutside),
            ("src/../../x", Rule::WriteOutside),
            ("~/notes.txt", Rule::WriteOutside),
            ("/home/me/x", Rule::WriteOutside),
            ("/home/me/work/other/x", Rule::WriteOutside),
            ("/etc/hosts", Rule::WriteOutside),
            ("/usr/local/bin/tool", Rule::WriteOutside),
            ("/x", Rule::WriteOutside),
            ("/", Rule::WriteOutside),
            ("//", Rule::WriteOutside),
            ("/..", Rule::WriteOutside),
            // The workspace itself, and the folders around it.
            (".", Rule::WriteOutside),
            ("./", Rule::WriteOutside),
            ("src/..", Rule::WriteOutside),
            ("/home/me/work/repo", Rule::WriteOutside),
            ("/home/me/work", Rule::WriteOutside),
            ("..", Rule::WriteOutside),
            ("/home/me", Rule::WriteOutside),
            ("~", Rule::WriteOutside),
            ("~/", Rule::WriteOutside),
            ("/home", Rule::WriteOutside),
            ("/tmp", Rule::WriteOutside),
            ("/tmp/", Rule::WriteOutside),
            // A disk.
            ("/dev/sda", Rule::WriteOutside),
            ("/dev/disk0", Rule::WriteOutside),
            // Case does not make a path the workspace's.
            ("/HOME/me/work/repo/x", Rule::WriteOutside),
            ("/home/me/WORK/repo/x", Rule::WriteOutside),
        ],
    );
}

#[test]
fn a_write_to_a_key_a_startup_file_or_the_history_is_a_finding() {
    risky(
        Access::Write,
        &posix(),
        &[
            ("~/.ssh/config", Rule::WriteSensitive),
            ("~/.ssh/authorized_keys", Rule::WriteSensitive),
            ("~/.aws/credentials", Rule::WriteSensitive),
            ("~/.gnupg/gpg.conf", Rule::WriteSensitive),
            ("~/.netrc", Rule::WriteSensitive),
            ("~/.npmrc", Rule::WriteSensitive),
            ("~/.zshrc", Rule::WriteSensitive),
            ("~/.bashrc", Rule::WriteSensitive),
            ("~/.bash_profile", Rule::WriteSensitive),
            ("~/.zprofile", Rule::WriteSensitive),
            ("~/.zshenv", Rule::WriteSensitive),
            ("~/.profile", Rule::WriteSensitive),
            ("~/.gitconfig", Rule::WriteSensitive),
            ("~/.config/fish/config.fish", Rule::WriteSensitive),
            ("~/.config/autostart/x.desktop", Rule::WriteSensitive),
            ("/home/me/.ZSHRC", Rule::WriteSensitive),
            // The repository's history, spelled any way.
            (".git/HEAD", Rule::WriteSensitive),
            (".git/config", Rule::WriteSensitive),
            (".git/hooks/pre-commit", Rule::WriteSensitive),
            (".git", Rule::WriteSensitive),
            (".git/", Rule::WriteSensitive),
            ("./.git/HEAD", Rule::WriteSensitive),
            (".GIT/HEAD", Rule::WriteSensitive),
            ("src/../.git/HEAD", Rule::WriteSensitive),
            ("/home/me/work/repo/.git/config", Rule::WriteSensitive),
            ("~/work/repo/.git/config", Rule::WriteSensitive),
            // The system's own, and another user's.
            ("/etc/shadow", Rule::WriteSensitive),
            ("/root/.ssh/authorized_keys", Rule::WriteSensitive),
            ("/home/other/.ssh/authorized_keys", Rule::WriteSensitive),
            ("/home/other/.bashrc", Rule::WriteSensitive),
        ],
    );
}

#[test]
fn a_path_that_is_not_one_literal_path_is_unreadable() {
    let rows: Vec<(&str, Rule)> = [
        "",
        "\0",
        "a\0b",
        "src/main.rs\0.txt",
        " src/main.rs",
        "\tsrc/x",
        "\n",
        "src/x\n",
        "src/a\nb",
        "src/\u{1b}[31mx",
        "src/\u{7f}x",
        "src/\u{85}x",
        "\u{a0}x",
        "\u{3000}x",
        // A wildcard.
        "*",
        "*.rs",
        "src/*.rs",
        "src/?.rs",
        "src/**/x",
        "src/x?",
        "~/.ss?/id_rsa",
        "~/.s*/id_rsa",
        "/home/me/.ssh/id_*",
        "/home/me/.ssh/*",
        "/etc/sh*dow",
        // A variable.
        "$HOME/x",
        "$HOME",
        "${HOME}/.ssh/id_rsa",
        "$(pwd)/x",
        "`pwd`/x",
        "$PWD/x",
        "$1",
        "$$",
        "~/$X",
        "src/$name.rs",
        "$'\\x2essh'/id_rsa",
        "$\"x\"",
        "x/$ x/$y",
        "%USERPROFILE%/.ssh/id_rsa",
        "%HOME%",
        "src/%NAME%.rs",
        "$env:USERPROFILE/x",
        "${env:HOME}/x",
        // Another user's home directory is not one this can name.
        "~root/.ssh/id_rsa",
        "~me/x",
        "~me",
        "~+/x",
        "~-/x",
        "~~",
        "~.ssh/id_rsa",
        // A backslash does not end the name after `~` on a POSIX machine.
        "~\\.ssh/id_rsa",
        // A pattern in a class, where it is not the agent's own folder.
        "~/[.]ssh/id_rsa",
        "/etc/[h]osts",
        "[.]git/config",
        "~/.s[s]h/id_rsa",
        "/home/me/.ssh/id_[r]sa",
    ]
    .iter()
    .map(|path| (*path, Rule::Unreadable))
    .collect();
    for access in [Access::Read, Access::Write] {
        risky(access, &posix(), &rows);
    }
}

#[test]
fn an_unreadable_path_has_one_finding_with_the_reason() {
    for (path, reason) in [
        ("", "is empty"),
        ("a\0b", "has a control character"),
        (" x", "starts with a space"),
        ("*.rs", "has a wildcard"),
        ("src/x?", "has a wildcard"),
        ("$HOME/x", "has a variable or a command"),
        ("%USERPROFILE%/x", "has a variable or a command"),
        ("~root/x", "is another user's home directory"),
        (
            "/etc/[h]osts",
            "has a pattern that can name more than one file",
        ),
    ] {
        let assessment = judge(Access::Read, path, &posix());
        assert_eq!(assessment.findings().len(), 1, "{path}");
        assert_eq!(assessment.findings()[0].rule, Rule::Unreadable, "{path}");
        assert_eq!(assessment.findings()[0].reason, reason, "{path}");
        assert_eq!(assessment.findings()[0].target.as_deref(), Some(path));
    }
}

#[test]
fn a_path_longer_than_the_limit_is_unreadable() {
    let at_the_limit = "a".repeat(milo_guards_file::MAX_PATH_LEN);
    safe(Access::Read, &posix(), &[&at_the_limit]);
    safe(Access::Write, &posix(), &[&at_the_limit]);
    for long in [
        "a".repeat(milo_guards_file::MAX_PATH_LEN + 1),
        "a/".repeat(milo_guards_file::MAX_PATH_LEN / 2 + 1),
        "../".repeat(5_000) + "etc/shadow",
    ] {
        for access in [Access::Read, Access::Write] {
            let assessment = judge(access, &long, &posix());
            assert_eq!(assessment.findings().len(), 1);
            assert_eq!(assessment.findings()[0].rule, Rule::Unreadable);
            // The finding does not carry a path that long.
            assert_eq!(assessment.findings()[0].target, None);
        }
    }
}

#[test]
fn a_finding_names_what_it_would_do_and_the_path() {
    let reasons = |access, path| {
        judge(access, path, &posix())
            .findings()
            .iter()
            .map(|finding| (finding.rule, finding.reason.clone(), finding.target.clone()))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        reasons(Access::Read, "~/.ssh/id_ed25519"),
        [(
            Rule::ReadSecret,
            "reads your SSH keys".to_string(),
            Some("~/.ssh/id_ed25519".to_string())
        )]
    );
    for (access, path, rule, reason) in [
        (
            Access::Read,
            "/etc/shadow",
            Rule::ReadSecret,
            "reads the system's password hashes",
        ),
        (
            Access::Read,
            "/dev/sda",
            Rule::ReadSecret,
            "reads a disk, and every key on it",
        ),
        (
            Access::Write,
            "../other/x",
            Rule::WriteOutside,
            "writes to a path outside the workspace",
        ),
        (
            Access::Write,
            "/etc/hosts",
            Rule::WriteOutside,
            "writes to a system folder",
        ),
        (
            Access::Write,
            "~",
            Rule::WriteOutside,
            "writes to your home directory",
        ),
        (
            Access::Write,
            ".",
            Rule::WriteOutside,
            "writes to the whole workspace",
        ),
        (
            Access::Write,
            "/tmp",
            Rule::WriteOutside,
            "writes to a temporary folder",
        ),
        (
            Access::Write,
            "/dev/sda",
            Rule::WriteOutside,
            "writes to a disk",
        ),
        (
            Access::Write,
            "~/.zshrc",
            Rule::WriteSensitive,
            "writes to a shell startup file",
        ),
        (
            Access::Write,
            ".git/HEAD",
            Rule::WriteSensitive,
            "writes to the repository's history",
        ),
        (
            Access::Write,
            "~/.aws/credentials",
            Rule::WriteSensitive,
            "writes to your AWS credentials",
        ),
    ] {
        let found = reasons(access, path);
        assert_eq!(found.len(), 1, "{path}: {found:?}");
        assert_eq!(found[0].0, rule, "{path}");
        assert_eq!(found[0].1, reason, "{path}");
        assert_eq!(found[0].2.as_deref(), Some(path), "{path}");
    }
}

#[test]
fn a_tilde_is_the_home_directory_and_also_a_folder_of_that_name() {
    // A file API may not expand `~`, so `~/x` may be a folder named `~` in
    // the working directory: both are judged, and either one is a finding.
    let outside = Paths::new("/etc", "/home/me", ["/home/me"]);
    exactly(
        Access::Write,
        &outside,
        &[
            // The home directory is the workspace, the working directory
            // is not: `~/x` is safe as home and not as a folder in `/etc`.
            ("~/x", &[Rule::WriteOutside]),
            ("x", &[Rule::WriteOutside]),
            ("/home/me/x", &[]),
        ],
    );
    // A `~` folder in the workspace is no key.
    exactly(
        Access::Read,
        &posix(),
        &[
            ("~/.ssh/id_rsa", &[Rule::ReadSecret]),
            ("./~/.ssh/id_rsa", &[]),
            ("~/x", &[]),
        ],
    );
}

#[test]
fn the_home_directory_as_the_workspace_keeps_its_keys() {
    let paths = home();
    exactly(
        Access::Read,
        &paths,
        &[
            (".ssh/id_rsa", &[Rule::ReadSecret]),
            ("~/.ssh/id_rsa", &[Rule::ReadSecret]),
            ("/home/me/.aws/credentials", &[Rule::ReadSecret]),
            ("/home/other/.ssh/id_rsa", &[Rule::ReadSecret]),
            (".zshrc", &[]),
            ("src/main.rs", &[]),
            (".sshx/id", &[]),
        ],
    );
    exactly(
        Access::Write,
        &paths,
        &[
            (".ssh/authorized_keys", &[Rule::WriteSensitive]),
            ("~/.ssh/authorized_keys", &[Rule::WriteSensitive]),
            (".zshrc", &[Rule::WriteSensitive]),
            (".git/config", &[Rule::WriteSensitive]),
            ("src/main.rs", &[]),
            ("notes.txt", &[]),
            ("~/notes.txt", &[]),
            (".sshx/id", &[]),
            ("..", &[Rule::WriteOutside]),
            (".", &[Rule::WriteOutside]),
        ],
    );
}

#[test]
fn a_read_and_a_write_can_break_different_rules() {
    exactly(
        Access::Read,
        &posix(),
        &[
            ("/etc/shadow", &[Rule::ReadSecret]),
            ("/etc/hosts", &[]),
            ("~/.zshrc", &[]),
        ],
    );
    exactly(
        Access::Write,
        &posix(),
        &[
            ("/etc/shadow", &[Rule::WriteSensitive]),
            ("/etc/hosts", &[Rule::WriteOutside]),
            ("~/.zshrc", &[Rule::WriteSensitive]),
        ],
    );
}

#[test]
fn a_path_inside_a_workspace_that_is_under_a_key_folder_is_the_agents() {
    let nested = Paths::new(
        "/home/me/.docker/proj",
        "/home/me",
        ["/home/me/.docker/proj"],
    );
    safe(Access::Write, &nested, &["src/x.rs", "./y"]);
    safe(Access::Read, &nested, &["src/x.rs"]);
    risky(
        Access::Read,
        &nested,
        &[("/home/me/.docker/config.json", Rule::ReadSecret)],
    );
}

#[test]
fn everyday_reads_on_a_mac_are_safe() {
    safe(
        Access::Read,
        &macos(),
        &[
            "src/main.rs",
            "/Users/me/dev/repo/src/lib.rs",
            "/System/Library/CoreServices/SystemVersion.plist",
            "/Applications/Safari.app/Contents/Info.plist",
            "/private/etc/hosts",
            "/etc/hosts",
            "~/Library/Preferences/com.apple.finder.plist",
            "~/Library/Application Support/Code/User/settings.json",
            "~/Documents/x.pdf",
            "/tmp/x",
            "/var/folders/zz/abc/T/x",
            "/Users/me/dev/repo/.git/config",
            "~/Library/LaunchAgents/com.example.plist",
            "~/.zshrc",
        ],
    );
}

#[test]
fn a_read_of_a_key_on_a_mac_is_a_finding() {
    risky(
        Access::Read,
        &macos(),
        &[
            ("~/.ssh/id_ed25519", Rule::ReadSecret),
            ("~/Library/Keychains/login.keychain-db", Rule::ReadSecret),
            ("~/library/keychains/login.keychain-db", Rule::ReadSecret),
            ("/Users/me/LIBRARY/KEYCHAINS/x", Rule::ReadSecret),
            ("/Library/Keychains/System.keychain", Rule::ReadSecret),
            (
                "/System/Library/Keychains/SystemRootCertificates.keychain",
                Rule::ReadSecret,
            ),
            ("/private/etc/master.passwd", Rule::ReadSecret),
            ("/etc/master.passwd", Rule::ReadSecret),
            (
                "/private/var/db/dslocal/nodes/Default/users/me.plist",
                Rule::ReadSecret,
            ),
            (
                "/var/db/dslocal/nodes/Default/users/me.plist",
                Rule::ReadSecret,
            ),
            ("/Users/me/.ssh/id_rsa", Rule::ReadSecret),
            // The home directory by another case, and through the data
            // volume the system mounts the same files at.
            ("/users/me/.ssh/id_rsa", Rule::ReadSecret),
            ("/USERS/ME/.SSH/ID_RSA", Rule::ReadSecret),
            (
                "/System/Volumes/Data/Users/me/.ssh/id_rsa",
                Rule::ReadSecret,
            ),
            (
                "/System/Volumes/Data/private/etc/master.passwd",
                Rule::ReadSecret,
            ),
            ("/Users/other/.ssh/id_rsa", Rule::ReadSecret),
            ("/Users/Shared/.ssh/id_rsa", Rule::ReadSecret),
            ("/var/root/.ssh/id_rsa", Rule::ReadSecret),
            ("/private/var/root/.ssh/id_rsa", Rule::ReadSecret),
        ],
    );
}

#[test]
fn writes_on_a_mac() {
    safe(
        Access::Write,
        &macos(),
        &[
            "src/main.rs",
            "/Users/me/dev/repo/x",
            "/tmp/x",
            "/private/tmp/x",
            "/var/folders/zz/abc/T/x",
            "/private/var/folders/zz/abc/T/x",
            "/dev/null",
            // The data volume holds the workspace too.
            "/System/Volumes/Data/Users/me/dev/repo/x",
        ],
    );
    risky(
        Access::Write,
        &macos(),
        &[
            ("~/notes.txt", Rule::WriteOutside),
            ("~/Library/Preferences/x.plist", Rule::WriteOutside),
            ("/Applications/x", Rule::WriteOutside),
            ("/System/Library/x", Rule::WriteOutside),
            ("/Library/LaunchDaemons/x.plist", Rule::WriteOutside),
            (
                "/System/Volumes/Data/Users/me/notes.txt",
                Rule::WriteOutside,
            ),
            ("~/Library/LaunchAgents/x.plist", Rule::WriteSensitive),
            (
                "/Users/me/Library/launchagents/x.plist",
                Rule::WriteSensitive,
            ),
            ("~/.zshrc", Rule::WriteSensitive),
            (
                "~/Library/Keychains/login.keychain-db",
                Rule::WriteSensitive,
            ),
            (".git/config", Rule::WriteSensitive),
            ("/etc/master.passwd", Rule::WriteSensitive),
            // Accepted false alarm: a Mac ignores case, so this is the
            // workspace, spelled by another case than the caller's.
            ("/Users/me/DEV/repo/x", Rule::WriteOutside),
        ],
    );
}

#[test]
fn a_workspace_on_a_mac_spelled_by_another_case_than_the_home_still_holds_its_keys() {
    let paths = Paths::new("/Users/ME", "/Users/me", ["/Users/ME"]);
    risky(
        Access::Read,
        &paths,
        &[
            (".ssh/id_rsa", Rule::ReadSecret),
            ("/Users/me/.ssh/id_rsa", Rule::ReadSecret),
        ],
    );
    risky(
        Access::Write,
        &paths,
        &[(".ssh/authorized_keys", Rule::WriteSensitive)],
    );
}

#[test]
fn a_path_on_a_machine_with_no_workspace_is_outside() {
    let none = Paths::new("/srv/app", "/home/me", Vec::<&str>::new());
    safe(Access::Read, &none, &["x", "/etc/hosts"]);
    risky(
        Access::Write,
        &none,
        &[
            ("x", Rule::WriteOutside),
            ("/home/me/work/repo/x", Rule::WriteOutside),
        ],
    );
    safe(Access::Write, &none, &["/tmp/x", "/dev/null"]);
}

#[test]
fn a_relative_working_directory_puts_every_path_outside() {
    let paths = Paths::new("repo", "/home/me", ["/home/me/repo"]);
    risky(Access::Write, &paths, &[("x", Rule::WriteOutside)]);
    risky(Access::Read, &paths, &[("~/.ssh/id_rsa", Rule::ReadSecret)]);
}

#[test]
fn the_data_volume_and_the_boot_volume_are_the_root_however_the_path_is_spelled() {
    let rows = |path: &'static str| (path, Rule::ReadSecret);
    risky(
        Access::Read,
        &macos(),
        &[
            rows("/System/Volumes/Data/Users/me/.ssh/id_ed25519"),
            rows("/system/volumes/data/Users/me/.ssh/id_ed25519"),
            rows("../../../../System/Volumes/Data/Users/me/.ssh/id_ed25519"),
            rows("../../../../system/volumes/data/users/me/.ssh/id_ed25519"),
            rows("~/../../System/Volumes/Data/Users/me/.ssh/id_ed25519"),
            rows("~/../../Volumes/Macintosh HD/Users/me/.ssh/id_ed25519"),
            rows("/Volumes/Macintosh HD/Users/me/.ssh/id_ed25519"),
            rows("/volumes/macintosh hd/Users/me/.ssh/id_ed25519"),
            rows("/Volumes/Macintosh HD - Data/Users/me/.ssh/id_ed25519"),
            rows("../../../../Volumes/Macintosh HD/Users/me/.ssh/id_ed25519"),
            rows("/Volumes/Macintosh HD/System/Volumes/Data/Users/me/.ssh/id"),
            rows("/System/Volumes/Data/private/etc/master.passwd"),
            rows("/Volumes/Macintosh HD/private/etc/master.passwd"),
            rows("/Volumes/Macintosh HD/dev/mem"),
            rows("/System/Volumes/Data/proc/self/environ"),
            rows("/Sy\u{17f}tem/Volumes/Data/Users/me/.ssh/id_rsa"),
            rows("/Volume\u{17f}/Macintosh HD/Users/me/.ssh/id_rsa"),
            rows("/Volumes/Macinto\u{17f}h HD/Users/me/.ssh/id_rsa"),
            rows("/Sy\u{17f}tem/Volume\u{17f}/Data/Users/me/.ssh/id_rsa"),
        ],
    );
    // A working directory at the root, with the workspace elsewhere.
    let at_root = Paths::new("/", "/Users/me", ["/Users/me/dev/repo"]);
    risky(
        Access::Read,
        &at_root,
        &[
            rows("System/Volumes/Data/Users/me/.ssh/id_rsa"),
            rows("Volumes/Macintosh HD/Users/me/.ssh/id_rsa"),
            rows("Users/me/.ssh/id_rsa"),
            rows("proc/self/environ"),
            rows("dev/mem"),
        ],
    );
    // The same links reach the workspace, and a temporary folder.
    safe(
        Access::Write,
        &macos(),
        &[
            "/System/Volumes/Data/Users/me/dev/repo/x",
            "/Volumes/Macintosh HD/Users/me/dev/repo/x",
            "../../../../Volumes/Macintosh HD/Users/me/dev/repo/x",
            "../../../../System/Volumes/Data/tmp/x",
            // A Mac's file system folds the long s to `s`: the same folders.
            "/Sy\u{17f}tem/Volumes/Data/Users/me/dev/repo/x",
            "/Volume\u{17f}/Macintosh HD/Users/me/dev/repo/x",
            "/volume\u{17f}/macinto\u{17f}h hd/Users/me/dev/repo/x",
        ],
    );
    risky(
        Access::Write,
        &macos(),
        &[
            (
                "../../../../System/Volumes/Data/Users/me/notes.txt",
                Rule::WriteOutside,
            ),
            ("/Volumes/Backup/Users/me/dev/repo/x", Rule::WriteOutside),
            (
                "../../../../System/Volumes/Data/Users/me/.zshrc",
                Rule::WriteSensitive,
            ),
            (
                "~/../../Volumes/Macintosh HD/Users/me/.zshrc",
                Rule::WriteSensitive,
            ),
        ],
    );
}

#[test]
fn a_device_or_a_kernel_file_is_not_a_file_to_read() {
    let mut rows: Vec<(&str, Rule)> = [
        "/dev/mem",
        "/dev/kmem",
        "/dev/port",
        "/dev/loop0",
        "/dev/root",
        "/dev/nbd0",
        "/dev/zd0",
        "/dev/vda1",
        "/dev/pts/0",
        "/dev/ptmx",
        "/dev/console",
        "/dev/shm/x",
        "/dev/fd/3",
        "/dev/fd/10",
        "/dev/fd/00",
        "/dev/null/x",
        "/dev/stdin/x",
        "/dev",
        "/DEV/MEM",
        "/dev/../dev/mem",
        "/dev/./mem",
        "../../../../../dev/mem",
        "~/../../../dev/mem",
        "/proc/self/environ",
        "/proc/1/environ",
        "/proc/thread-self/environ",
        "/proc/self/task/1/environ",
        "/proc/self/mem",
        "/proc/self/cmdline",
        "/proc/self/maps",
        "/proc/self/status",
        "/proc/self/fd/3",
        "/proc/self/root/home/me/.ssh/id_rsa",
        "/proc/1234/root/etc/hosts",
        "/proc/self/cwd/x",
        "/proc/self/cwd/../../.ssh/id_rsa",
        "/proc/kcore",
        "/proc/kallsyms",
        "/proc/sys/kernel/hostname",
        "/proc",
        "/PROC/SELF/ENVIRON",
        "/proc/./self/environ",
        "src/../../../../../../proc/self/environ",
    ]
    .iter()
    .map(|path| (*path, Rule::ReadSecret))
    .collect();
    // Reads that are not a secret on a Mac, too (a Mac has no `/proc`, but
    // the path is read the same way).
    rows.push(("/dev/disk2s1", Rule::ReadSecret));
    risky(Access::Read, &posix(), &rows);
    risky(Access::Read, &macos(), &rows);
    // What is readable: what discards, what is random or zero, the terminal
    // and the standard streams, and the machine's own facts.
    safe(
        Access::Read,
        &posix(),
        &[
            "/dev/null",
            "/dev/zero",
            "/dev/random",
            "/dev/urandom",
            "/dev/tty",
            "/dev/stdin",
            "/dev/stdout",
            "/dev/stderr",
            "/dev/fd/0",
            "/dev/fd/1",
            "/dev/fd/2",
            "/DEV/NULL",
            "/dev/./null",
            "/proc/cpuinfo",
            "/proc/meminfo",
            "/proc/version",
            "/proc/loadavg",
            "/proc/uptime",
            "/proc/filesystems",
            "/home/me/dev/mem",
            "/home/me/proc/self/environ",
            "src/dev/mem",
            "dev/mem",
            "proc/self/environ",
            "/devx/mem",
            "/processes/x",
        ],
    );
    exactly(
        Access::Read,
        &posix(),
        &[
            ("/dev/mem", &[Rule::ReadSecret][..]),
            ("/proc/self/environ", &[Rule::ReadSecret][..]),
            // A disk keeps its own words.
            ("/dev/sda", &[Rule::ReadSecret][..]),
        ],
    );
    for (path, reason) in [
        ("/dev/mem", "reads a device file"),
        ("/dev/loop0", "reads a device file"),
        ("/proc/self/environ", "reads the kernel's process files"),
        (
            "/proc/self/root/etc/hosts",
            "reads the kernel's process files",
        ),
        ("/dev/sda", "reads a disk, and every key on it"),
    ] {
        let found = judge(Access::Read, path, &posix());
        assert_eq!(found.findings().len(), 1, "{path}");
        assert_eq!(found.findings()[0].reason, reason, "{path}");
    }
    // A write to a device is judged by its place: `/dev/null` takes it, any
    // other is beyond the workspace.
    exactly(
        Access::Write,
        &posix(),
        &[
            ("/dev/null", &[][..]),
            ("/dev/mem", &[Rule::WriteOutside][..]),
            ("/proc/self/mem", &[Rule::WriteOutside][..]),
            ("/proc/self/environ", &[Rule::WriteOutside][..]),
        ],
    );
}

#[test]
fn another_users_home_is_one_whatever_this_users_home_is() {
    for paths in [
        Paths::new("/root/repo", "/root", ["/root/repo"]),
        Paths::new("/var/lib/ci/repo", "/var/lib/ci", ["/var/lib/ci/repo"]),
        Paths::new("/srv/x", "/srv/x", ["/srv/x"]),
    ] {
        risky(
            Access::Read,
            &paths,
            &[
                ("/home/alice/.ssh/id_rsa", Rule::ReadSecret),
                ("/HOME/ALICE/.SSH/id_rsa", Rule::ReadSecret),
                ("/Users/alice/.aws/credentials", Rule::ReadSecret),
                ("/home/alice/.config/gh/hosts.yml", Rule::ReadSecret),
            ],
        );
        risky(
            Access::Write,
            &paths,
            &[
                ("/home/alice/.ssh/authorized_keys", Rule::WriteSensitive),
                ("/home/alice/.zshrc", Rule::WriteSensitive),
                ("/home/alice/notes.txt", Rule::WriteOutside),
            ],
        );
        safe(Access::Read, &paths, &["/home/alice/notes.txt"]);
    }
}

#[test]
fn the_credential_stores_and_startup_places_that_have_twins_are_listed() {
    risky(
        Access::Write,
        &posix(),
        &[
            ("~/.config/git/config", Rule::WriteSensitive),
            (
                "~/.config/powershell/Microsoft.PowerShell_profile.ps1",
                Rule::WriteSensitive,
            ),
            ("~/.config/powershell/", Rule::WriteSensitive),
            ("~/.config/systemd/user/x.service", Rule::WriteSensitive),
            (
                "~/.config/systemd/user/default.target.wants/x",
                Rule::WriteSensitive,
            ),
            ("~/.CONFIG/Git/Config", Rule::WriteSensitive),
        ],
    );
    safe(
        Access::Read,
        &posix(),
        &[
            "~/.config/git/config",
            "~/.config/powershell/profile.ps1",
            "~/.config/systemd/user/x.service",
            "~/.config/git/ignore",
        ],
    );
    risky(
        Access::Write,
        &posix(),
        &[("~/.config/systemd/system/x", Rule::WriteOutside)],
    );
}

#[test]
fn a_git_folder_at_any_depth_is_history_and_its_hooks_run_code() {
    let rules = |access, path| common::rules(access, &posix(), path);
    for path in [
        ".git/hooks/pre-commit",
        ".GIT/Hooks/pre-commit",
        "vendor/x/.git/hooks/pre-commit",
        "vendor/x/.git/hooks/",
        "vendor/x/.git/../.git/hooks/pre-commit",
        "../other/.git/hooks/post-merge",
        "~/work/other/.git/hooks/x",
        "/tmp/clone/.git/hooks/pre-push",
        "a/b/c/d/e/.git/hooks/pre-commit",
        ".git/modules/m/hooks/pre-commit",
    ] {
        assert!(
            rules(Access::Write, path).contains(&Rule::WriteSensitive),
            "{path}"
        );
        assert_eq!(rules(Access::Read, path), [], "{path}");
    }
    for path in [
        "vendor/x/.git/config",
        "vendor/x/.git/HEAD",
        "packages/app/.git",
        "packages/app/.git/",
        "packages/app/.GIT/objects/ab/cd",
        "a/b/c/d/e/.git/index",
        "/tmp/clone/.git/config",
        "~/work/other/.git/config",
    ] {
        assert!(
            rules(Access::Write, path).contains(&Rule::WriteSensitive),
            "{path}"
        );
        assert_eq!(rules(Access::Read, path), [], "{path}");
    }
    // Reasons: a hook says it runs code; the rest is the history.
    for (path, reason) in [
        (
            ".git/hooks/pre-commit",
            "writes to a git hook, which runs code",
        ),
        (
            "vendor/x/.git/hooks/pre-commit",
            "writes to a git hook, which runs code",
        ),
        (".git/config", "writes to the repository's history"),
        ("vendor/x/.git/config", "writes to the repository's history"),
        (".git", "writes to the repository's history"),
    ] {
        let found = judge(Access::Write, path, &posix());
        assert_eq!(found.findings().len(), 1, "{path}: {found:?}");
        assert_eq!(found.findings()[0].reason, reason, "{path}");
    }
    // Not a git folder.
    safe(
        Access::Write,
        &posix(),
        &[
            "src/main.rs",
            ".gitignore",
            ".github/hooks/x",
            "hooks/pre-commit",
            "scripts/hooks/pre-commit",
            "x.git/hooks/x",
            "src/.gitx/hooks/x",
            "git/hooks/x",
        ],
    );
}

#[test]
fn more_credential_stores_are_listed() {
    let rows: Vec<(&str, Rule)> = [
        "~/.pgpass",
        "~/.my.cnf",
        "~/.s3cfg",
        "~/.gem/credentials",
        "~/.m2/settings.xml",
        "~/.terraform.d/credentials.tfrc.json",
        "~/.config/rclone/rclone.conf",
        "~/.config/op/config",
        "~/.config/sops/age/keys.txt",
        "~/.config/hub",
    ]
    .iter()
    .map(|path| (*path, Rule::ReadSecret))
    .collect();
    risky(Access::Read, &posix(), &rows);
    safe(
        Access::Read,
        &posix(),
        &[
            "~/.gem/specs",
            "~/.m2/repository/x.jar",
            "~/.terraform.d/plugins/x",
        ],
    );
}

#[test]
fn a_write_to_a_device_is_beyond_the_workspace_unless_it_discards() {
    exactly(
        Access::Write,
        &posix(),
        &[
            ("/dev/fd/3", &[Rule::WriteOutside][..]),
            ("/dev/fd/10", &[Rule::WriteOutside][..]),
            ("/dev/shm/x", &[Rule::WriteOutside][..]),
            ("/dev/null", &[][..]),
            ("/dev/stdout", &[][..]),
            ("/dev/stderr", &[][..]),
            ("/dev/fd/1", &[][..]),
            ("/dev/tty", &[][..]),
        ],
    );
}

#[test]
fn a_macs_links_to_the_root_are_not_links_on_any_other_system() {
    // On Linux these paths do not exist, and a write creates folders outside
    // the workspace: they are not the workspace's, and not the root.
    for path in [
        "/Volumes/Macintosh HD/home/me/work/repo/x",
        "/System/Volumes/Data/home/me/work/repo/x",
        "/volumes/macintosh hd/home/me/work/repo/x",
        "/Volume\u{17f}/Macintosh HD/home/me/work/repo/x",
        "/Sy\u{17f}tem/Volumes/Data/home/me/work/repo/x",
        "/Volumes/Macintosh HD - Data/home/me/work/repo/x",
        "../../../../Volumes/Macintosh HD/home/me/work/repo/x",
        "/System/Volumes/Data/tmp/x",
    ] {
        exactly(
            Access::Write,
            &posix(),
            &[(path, &[Rule::WriteOutside][..])],
        );
    }
    // A read of a secret is a finding however it is spelled: the links are
    // dropped on every system when looking one up, which is noise on Linux
    // (accepted: matching too much fails closed).
    risky(
        Access::Read,
        &posix(),
        &[
            (
                "/Volumes/Macintosh HD/home/me/.ssh/id_rsa",
                Rule::ReadSecret,
            ),
            ("/System/Volumes/Data/home/me/.ssh/id_rsa", Rule::ReadSecret),
            ("/System/Volumes/Data/etc/shadow", Rule::ReadSecret),
            ("/Volumes/Macintosh HD/etc/shadow", Rule::ReadSecret),
            ("/System/Volumes/Data/proc/self/environ", Rule::ReadSecret),
            ("/Volumes/Macintosh HD/dev/mem", Rule::ReadSecret),
        ],
    );
    safe(
        Access::Read,
        &posix(),
        &[
            "/Volumes/Macintosh HD/home/me/work/repo/src/main.rs",
            "/Volumes/Backup/x",
        ],
    );
    // On a Mac, whose home is under `/Users`, the same paths are the root.
    risky(
        Access::Read,
        &macos(),
        &[
            ("/Volumes/Macintosh HD/etc/shadow", Rule::ReadSecret),
            ("/System/Volumes/Data/etc/shadow", Rule::ReadSecret),
        ],
    );
}

#[test]
fn a_containers_secrets_and_the_memory_a_system_keeps_on_disk_are_secrets() {
    risky(
        Access::Read,
        &posix(),
        &[
            ("/run/secrets/x", Rule::ReadSecret),
            ("/run/secrets", Rule::ReadSecret),
            ("/RUN/Secrets/db_password", Rule::ReadSecret),
            (
                "/var/run/secrets/kubernetes.io/serviceaccount/token",
                Rule::ReadSecret,
            ),
            (
                "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
                Rule::ReadSecret,
            ),
            ("/var/vm/sleepimage", Rule::ReadSecret),
            ("/private/var/vm/sleepimage", Rule::ReadSecret),
            ("/private/var/vm/swapfile0", Rule::ReadSecret),
            ("/private/var/vm/swapfile1.encrypted", Rule::ReadSecret),
        ],
    );
    risky(
        Access::Read,
        &macos(),
        &[
            ("/private/var/vm/sleepimage", Rule::ReadSecret),
            (
                "/System/Volumes/Data/private/var/vm/sleepimage",
                Rule::ReadSecret,
            ),
        ],
    );
    safe(
        Access::Read,
        &posix(),
        &[
            "/run/user/1000/x",
            "/run/secrets-x/y",
            "/var/run/docker.pid",
            "/var/vmx/x",
            "/var/lib/x",
        ],
    );
    risky(
        Access::Write,
        &posix(),
        &[
            ("/run/secrets/x", Rule::WriteSensitive),
            ("/private/var/vm/sleepimage", Rule::WriteSensitive),
        ],
    );
}

#[test]
fn a_mac_whose_home_is_roots_reads_every_link_spelling() {
    for home in ["/var/root", "/private/var/root"] {
        let paths = Paths::new("/tmp/w", home, ["/tmp/w"]);
        let rows: Vec<(&str, Rule)> = [
            "/System/Volumes/Data/Users/alice/.ssh/id_rsa",
            "/Volumes/Macintosh HD/Users/alice/.ssh/id_rsa",
            "/Volumes/Macintosh HD/var/root/.ssh/id_rsa",
            "/Volumes/Macintosh HD/private/var/root/.ssh/id_rsa",
            "/System/Volumes/Data/private/var/root/.ssh/id_rsa",
            "/Volumes/Macintosh HD/etc/master.passwd",
            "/System/Volumes/Data/private/var/db/dslocal/nodes/Default/users/x.plist",
            "/Sy\u{17f}tem/Volumes/Data/Users/alice/.ssh/id_rsa",
            "/Volumes/Macintosh HD - Data/Users/alice/.ssh/id_rsa",
        ]
        .iter()
        .map(|path| (*path, Rule::ReadSecret))
        .collect();
        risky(Access::Read, &paths, &rows);
        // The workspace by a link, on such a Mac.
        safe(
            Access::Write,
            &paths,
            &[
                "/System/Volumes/Data/tmp/w/x",
                "/Volumes/Macintosh HD/tmp/w/x",
                "/tmp/w/x",
            ],
        );
        risky(
            Access::Write,
            &paths,
            &[
                (
                    "/Volumes/Macintosh HD/Users/alice/.zshrc",
                    Rule::WriteSensitive,
                ),
                (
                    "/Volumes/Macintosh HD/etc/master.passwd",
                    Rule::WriteSensitive,
                ),
            ],
        );
    }
    // On Linux a link-spelled write into the workspace stays outside it.
    exactly(
        Access::Write,
        &posix(),
        &[
            (
                "/Volumes/Macintosh HD/home/me/work/repo/x",
                &[Rule::WriteOutside][..],
            ),
            (
                "/System/Volumes/Data/home/me/work/repo/x",
                &[Rule::WriteOutside][..],
            ),
        ],
    );
    // A protected path by a link is protected on any system.
    let protected =
        posix().with_protected([Protected::folder("/home/me/.agent", "the agent's settings")]);
    exactly(
        Access::Write,
        &protected,
        &[(
            "/Volumes/Macintosh HD/home/me/.agent/x",
            &[Rule::WriteProtected][..],
        )],
    );
}
