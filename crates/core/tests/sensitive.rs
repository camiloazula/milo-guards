//! What the path model says about keys, credentials and the paths that reach
//! them by another spelling: the kind of a sensitive place, names without
//! case, Windows short names, other users' homes, long paths and drive-
//! relative paths. Each row is a spelling a review could try.

use milo_guards_core::spelling::network;
use milo_guards_core::{Flavour, Paths, Place, Resolver, Sensitivity, Spelling};

const POSIX: Flavour = Flavour::Posix;
const WINDOWS: Flavour = Flavour::Windows;

fn posix() -> Paths {
    Paths::new("/home/me/work/repo", "/home/me", ["/home/me/work/repo"])
}

fn mac() -> Paths {
    Paths::new("/Users/me/dev/repo", "/Users/me", ["/Users/me/dev/repo"])
}

fn windows() -> Paths {
    Paths::new(
        r"C:\Users\me\dev\repo",
        r"C:\Users\me",
        [r"C:\Users\me\dev\repo"],
    )
}

/// A home directory whose name is longer than a short name.
fn camilo() -> Paths {
    Paths::new(
        r"C:\Users\Camilo Azula\dev\repo",
        r"C:\Users\Camilo Azula",
        [r"C:\Users\Camilo Azula\dev\repo"],
    )
}

fn at(paths: &Paths, path: &str, flavour: Flavour) -> Place {
    Resolver::new(paths).place(Spelling::Plain(path), flavour)
}

fn secret(words: &'static str) -> Place {
    Place::Sensitive(words, Sensitivity::Secret)
}

fn startup(words: &'static str) -> Place {
    Place::Sensitive(words, Sensitivity::Startup)
}

const HISTORY: Place = Place::Sensitive("the repository's history", Sensitivity::History);

fn rows(paths: &Paths, flavour: Flavour, rows: &[(&str, Place)]) {
    let wrong: Vec<String> = rows
        .iter()
        .filter_map(|(path, place)| {
            let got = at(paths, path, flavour);
            (got != *place).then(|| format!("{path}: expected {place:?}, got {got:?}"))
        })
        .collect();
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn a_sensitive_place_says_what_touching_it_means() {
    rows(
        &posix(),
        POSIX,
        &[
            ("/home/me/.ssh/id_ed25519", secret("your SSH keys")),
            ("/home/me/.aws/credentials", secret("your AWS credentials")),
            ("/home/me/.netrc", secret("your saved logins")),
            ("/home/me/.npmrc", secret("your npm login")),
            ("/home/me/.config/gh/hosts.yml", secret("your GitHub login")),
            ("/home/me/.zshrc", startup("a shell startup file")),
            ("/home/me/.bashrc", startup("a shell startup file")),
            ("/home/me/.gitconfig", startup("your git settings")),
            (
                "/home/me/.config/autostart/x.desktop",
                startup("the programs your desktop starts at login"),
            ),
            (".git/config", HISTORY),
            (".git", HISTORY),
            // Only what is listed: the name beside it is not.
            ("/home/me/.sshx/id", Place::Outside),
            ("/home/me/.configx/gh/x", Place::Outside),
            ("/home/me/.config/other", Place::Outside),
            ("/home/me/.zshrc.bak", Place::Outside),
        ],
    );
}

#[test]
fn names_compare_without_case_on_every_host() {
    rows(
        &posix(),
        POSIX,
        &[
            ("/home/me/.SSH/ID_RSA", secret("your SSH keys")),
            ("/home/me/.Aws/credentials", secret("your AWS credentials")),
            ("/home/me/.ZSHRC", startup("a shell startup file")),
            ("/HOME/ME/.ssh/id_rsa", secret("your SSH keys")),
            ("/home/me/.Config/GH/hosts.yml", secret("your GitHub login")),
            ("/ETC/SHADOW", secret("the system's password hashes")),
            // The folders the home directory sits in, and the home itself,
            // are the home however they are cased.
            ("/HOME/ME", Place::Home { exact: true }),
            ("/HOME", Place::Home { exact: false }),
        ],
    );
    rows(
        &mac(),
        POSIX,
        &[
            ("/users/me/.ssh/id_rsa", secret("your SSH keys")),
            ("/USERS/ME/Library/keychains/x", secret("your keychains")),
        ],
    );
    // A file system that ignores case reads these characters as an `s` and
    // a `k`: the long s, and the Kelvin sign.
    rows(
        &posix(),
        POSIX,
        &[
            ("/home/me/.\u{17f}sh/id_rsa", secret("your SSH keys")),
            (
                "/home/me/.\u{212a}ube/config",
                secret("your Kubernetes credentials"),
            ),
        ],
    );
    // What is not the home or a sensitive place is not made one by case: a
    // folder the workspace lies in is compared as it is spelled.
    assert_eq!(at(&posix(), "/HOME/me/work/repo/x", POSIX), Place::Outside);
}

#[test]
fn a_windows_short_name_is_the_name_it_shortens() {
    let paths = camilo();
    rows(
        &paths,
        WINDOWS,
        &[
            (
                r"C:\Users\Camilo Azula\.ssh\id_rsa",
                secret("your SSH keys"),
            ),
            // The home directory by its short name.
            (r"C:\Users\CAMILO~1\.ssh\id_rsa", secret("your SSH keys")),
            (r"C:\Users\camilo~1\.SSH\id_rsa", secret("your SSH keys")),
            // The folder by its short name too (`.ssh` has none of its own:
            // Windows makes `SSH~1`).
            (r"C:\Users\CAMILO~1\SSH~1\id_rsa", secret("your SSH keys")),
            (
                r"C:\Users\Camilo Azula\AWS~1\credentials",
                secret("your AWS credentials"),
            ),
            (
                r"C:\Users\Camilo Azula\BASHRC~1",
                startup("a shell startup file"),
            ),
            (r"C:\Users\CAMILO~1", Place::Home { exact: true }),
            (r"C:\Users\CAMILO~1\notes.txt", Place::Outside),
            (r"C:\Users\CAMILO~1\.sshx\id", Place::Outside),
            // A name that is no short name of the home is another user's.
            (r"C:\Users\CAMIL~1\.ssh\id_rsa", secret("your SSH keys")),
            (r"C:\Users\CAMIL~1\notes.txt", Place::Outside),
            (r"C:\Users\CAMILO~1\SSH~X\id_rsa", Place::Outside),
        ],
    );
    // A POSIX name has no short form.
    assert_eq!(at(&posix(), "/home/me/SSH~1/id_rsa", POSIX), Place::Outside);
}

#[test]
fn a_workspace_that_holds_a_key_does_not_make_it_the_agents() {
    // The home directory is the workspace.
    let home = Paths::new("/home/me", "/home/me", ["/home/me"]);
    rows(
        &home,
        POSIX,
        &[
            (".ssh/id_rsa", secret("your SSH keys")),
            ("/home/me/.aws/credentials", secret("your AWS credentials")),
            (".zshrc", startup("a shell startup file")),
            (".git/config", HISTORY),
            ("src/main.rs", Place::Inside),
            (".sshx/id", Place::Inside),
        ],
    );
    // A folder above the home directory is the workspace.
    let above = Paths::new("/home", "/home/me", ["/home"]);
    rows(
        &above,
        POSIX,
        &[
            ("me/.ssh/id_rsa", secret("your SSH keys")),
            ("other/.ssh/id_rsa", secret("your SSH keys")),
            ("other/notes.txt", Place::Inside),
        ],
    );
    // The other user's home directory is the workspace.
    let other = Paths::new("/home/other", "/home/me", ["/home/other"]);
    rows(
        &other,
        POSIX,
        &[
            (".ssh/id_rsa", secret("your SSH keys")),
            ("src/x.rs", Place::Inside),
        ],
    );
    // A workspace inside a sensitive folder keeps what is inside it.
    let nested = Paths::new(
        "/home/me/.docker/proj",
        "/home/me",
        ["/home/me/.docker/proj"],
    );
    rows(
        &nested,
        POSIX,
        &[
            ("src/x.rs", Place::Inside),
            (
                "/home/me/.docker/config.json",
                secret("your Docker credentials"),
            ),
        ],
    );
    // On Windows the same, by short names and with a different case.
    let win = Paths::new(
        r"C:\Users\Camilo Azula",
        r"C:\Users\Camilo Azula",
        [r"C:\Users\Camilo Azula"],
    );
    rows(
        &win,
        WINDOWS,
        &[
            (r".ssh\id_rsa", secret("your SSH keys")),
            (r"SSH~1\id_rsa", secret("your SSH keys")),
            (r"C:\USERS\CAMILO~1\.SSH\id_rsa", secret("your SSH keys")),
            (r"src\x.rs", Place::Inside),
        ],
    );
    // A workspace spelled with another case than the home still holds it.
    let cased = Paths::new("/Users/ME", "/Users/me", ["/Users/ME"]);
    rows(&cased, POSIX, &[(".ssh/id_rsa", secret("your SSH keys"))]);
}

#[test]
fn another_users_home_has_the_same_keys() {
    rows(
        &posix(),
        POSIX,
        &[
            ("/home/other/.ssh/id_rsa", secret("your SSH keys")),
            ("/home/OTHER/.SSH/id_rsa", secret("your SSH keys")),
            (
                "../../../other/.aws/credentials",
                secret("your AWS credentials"),
            ),
            ("/home/other/.zshrc", startup("a shell startup file")),
            ("/home/other/notes.txt", Place::Outside),
            ("/root/.ssh/id_rsa", secret("your SSH keys")),
            ("/root/.bashrc", startup("a shell startup file")),
            ("/var/root/.ssh/id_rsa", secret("your SSH keys")),
            ("/private/var/root/.ssh/id_rsa", secret("your SSH keys")),
            ("/root/notes", Place::Top("a system folder")),
        ],
    );
    rows(
        &mac(),
        POSIX,
        &[
            ("/Users/other/.ssh/id_rsa", secret("your SSH keys")),
            ("/Users/Shared/.ssh/id_rsa", secret("your SSH keys")),
            (
                "/Users/other/Library/Keychains/login.keychain-db",
                secret("your keychains"),
            ),
            ("/Users/other/Documents/x", Place::Outside),
        ],
    );
    rows(
        &windows(),
        WINDOWS,
        &[
            (r"C:\Users\other\.ssh\id_rsa", secret("your SSH keys")),
            (r"C:\Users\OTHER\.SSH\ID_RSA", secret("your SSH keys")),
            (r"C:\Users\OTHER~1\SSH~1\id_rsa", secret("your SSH keys")),
            (r"C:\Users\other\notes.txt", Place::Outside),
        ],
    );
}

#[test]
fn the_systems_own_secrets_are_secrets() {
    rows(
        &posix(),
        POSIX,
        &[
            ("/etc/shadow", secret("the system's password hashes")),
            ("/etc/gshadow", secret("the system's password hashes")),
            (
                "/etc/ssh/ssh_host_ed25519_key",
                secret("the system's SSH keys"),
            ),
            (
                "/etc/ssl/private/key.pem",
                secret("the system's private keys"),
            ),
            ("/etc/wireguard/wg0.conf", secret("your WireGuard keys")),
            (
                "/private/etc/master.passwd",
                secret("the system's password hashes"),
            ),
            (
                "/private/var/db/dslocal/nodes/Default/users/me.plist",
                secret("the system's password hashes"),
            ),
            ("/etc/hosts", Place::Top("a system folder")),
            ("/etc/passwd", Place::Top("a system folder")),
            ("/etc/shadowx", Place::Top("a system folder")),
            ("/etc/ssl/certs/ca.pem", Place::Top("a system folder")),
        ],
    );
    rows(
        &windows(),
        WINDOWS,
        &[
            (
                r"C:\Windows\System32\config\SAM",
                secret("the Windows account database"),
            ),
            (
                r"c:\windows\system32\config\sam",
                secret("the Windows account database"),
            ),
            (
                r"C:\ProgramData\ssh\ssh_host_rsa_key",
                secret("the system's SSH keys"),
            ),
            (
                r"C:\Windows\System32\drivers\etc\hosts",
                Place::Top("a system folder"),
            ),
        ],
    );
}

#[test]
fn the_data_volume_is_the_root_on_a_mac() {
    rows(
        &mac(),
        POSIX,
        &[
            (
                "/System/Volumes/Data/Users/me/.ssh/id_rsa",
                secret("your SSH keys"),
            ),
            ("/system/volumes/data/Users/me/dev/repo/x", Place::Inside),
            (
                "/System/Volumes/Data/private/etc/shadow",
                secret("the system's password hashes"),
            ),
            (
                "/System/Volumes/Data/System/Volumes/Data/Users/me/.ssh/id",
                secret("your SSH keys"),
            ),
            ("/System/Volumes/Data/Users/me", Place::Home { exact: true }),
            // Nothing after the three parts is no data volume path.
            ("/System/Volumes/Data", Place::Top("the root of the disk")),
            ("/System/Volumes/Preboot/x", Place::Top("a system folder")),
        ],
    );
}

#[test]
fn a_long_path_is_the_drive_or_share_it_names() {
    rows(
        &windows(),
        WINDOWS,
        &[
            (r"\\?\C:\Users\me\.ssh\id_rsa", secret("your SSH keys")),
            (r"\\?\c:\users\me\.SSH\id_rsa", secret("your SSH keys")),
            ("//?/C:/Users/me/.ssh/id_rsa", secret("your SSH keys")),
            (r"\/?\C:\Users\me\.ssh\id_rsa", secret("your SSH keys")),
            (r"\\?\C:\Users\me\dev\repo\src\x.rs", Place::Inside),
            (r"\\?\C:\Users\me\dev\repo\.git\config", HISTORY),
            (r"\\?\C:\Users\me", Place::Home { exact: true }),
            (r"\\?\C:\", Place::Top("the root of the disk")),
            (r"\\?\C:", Place::Top("the root of the disk")),
            (r"\\?\D:\x\y", Place::Outside),
            (r"\\?\UNC\srv\share\x\y", Place::Outside),
            (r"\\?\unc\srv\share\x\y", Place::Outside),
            // No drive and no share: a namespace of its own.
            (
                r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Users\me\.ssh\id_rsa",
                Place::Disk,
            ),
            (
                r"\\?\Volume{26a21bda-a627-11d7-9931-806e6f6e6963}\Users\me\x",
                Place::Disk,
            ),
            (r"\\?\C:x", Place::Disk),
            (r"\\?\UNC", Place::Disk),
            (r"\\?\UNC\", Place::Disk),
            (r"\\?\", Place::Disk),
            (r"\\.\C:\Users\me\.ssh\id_rsa", Place::Disk),
            ("//./C:/Users/me/.ssh/id_rsa", Place::Disk),
            (r"\/.\C:\Users\me\.ssh\id_rsa", Place::Disk),
            (r"\\.\PhysicalDrive0", Place::Disk),
        ],
    );
    // The folders the caller names may be spelled as a long path too: a
    // canonical path on Windows has the prefix.
    let verbatim = Paths::new(
        r"\\?\C:\Users\me\dev\repo",
        r"\\?\C:\Users\me",
        [r"\\?\C:\Users\me\dev\repo"],
    );
    rows(
        &verbatim,
        WINDOWS,
        &[
            (r"C:\Users\me\.ssh\id_rsa", secret("your SSH keys")),
            (r"src\x.rs", Place::Inside),
            (r"C:\Users\me\dev\repo\src\x.rs", Place::Inside),
            (r"\\?\C:\Users\me\dev\repo\src\x.rs", Place::Inside),
        ],
    );
    assert_eq!(Resolver::new(&verbatim).flavour(), WINDOWS);
    // A POSIX name may hold a backslash and a question mark: no long path.
    assert_eq!(at(&posix(), r"\\?\C:\x", POSIX), Place::Inside);
    // Wildcards in a long path are read as they are in any other.
    assert_eq!(
        at(&windows(), r"\\?\C:\Users\me\dev\repo\src\*.rs", WINDOWS),
        Place::Inside
    );
}

#[test]
fn a_drive_relative_path_is_from_the_drives_working_directory() {
    let paths = windows();
    rows(
        &paths,
        WINDOWS,
        &[
            // On the drive the working directory is on: relative to it.
            (r"C:x", Place::Inside),
            (r"c:src\x.rs", Place::Inside),
            (r"C:.git\config", HISTORY),
            (r"C:..\..\.ssh\id_rsa", secret("your SSH keys")),
            (r"C:..\..", Place::Home { exact: true }),
            (r"C:", Place::Workspace { exact: true }),
            (r"C:..", Place::Workspace { exact: false }),
            // A drive's root keeps its separator.
            (r"C:\x", Place::Top("a top-level folder")),
            (r"C:\", Place::Top("the root of the disk")),
            (r"C:/", Place::Top("the root of the disk")),
            // On any other drive the folder is not known.
            (r"D:x", Place::Unknown),
            (r"D:", Place::Unknown),
            (r"d:..\..\x", Place::Unknown),
            (r"D:\x\y", Place::Outside),
        ],
    );
    let resolver = Resolver::new(&paths);
    let key = |path| resolver.key(Spelling::Plain(path), WINDOWS);
    assert_eq!(key("C:x.ps1"), key(r"c:\users\me\dev\repo\x.ps1"));
    assert_eq!(key("D:x.ps1"), None);
    // A working directory on another drive.
    let d = Paths::new(
        r"D:\work",
        r"C:\Users\me",
        [r"D:\work", r"C:\Users\me\dev\repo"],
    );
    rows(
        &d,
        WINDOWS,
        &[
            ("D:x", Place::Inside),
            ("C:x", Place::Unknown),
            (r"C:\Users\me\.ssh\id_rsa", secret("your SSH keys")),
        ],
    );
    // POSIX has no drives.
    assert_eq!(at(&posix(), "C:x", POSIX), Place::Inside);
}

#[test]
fn a_share_is_told_by_its_spelling() {
    for share in [
        r"\\server\share\x",
        "//server/share/x",
        r"\\server",
        r"\\?\UNC\server\share\x",
        r"\\?\unc\server\share",
        r"\\.\UNC\server\share\x",
        r"\\.\\UNC\host\share\x",
        r"\\.\.\UNC\host\share\x",
        "//./UNC/server/share/x",
        r"\\?\GLOBALROOT\Device\Mup\host\share\x",
        r"\\.\GLOBALROOT\Device\Mup\host\share\x",
        r"\\*\share",
        r"\\localhost\C$\Users\me\.ssh\id_rsa",
        r"\\wsl$\Ubuntu\home\me\.ssh\id_rsa",
        r"\\?\..\x",
        r"\\server\..\x",
    ] {
        assert!(network(share, WINDOWS), "{share}");
    }
    for local in [
        r"C:\x",
        r"\x",
        "x",
        "",
        r"\\?\C:\x",
        r"\\.\PhysicalDrive0",
        r"\\?\Volume{1}\x",
        r"\\.\C:\x",
    ] {
        assert!(!network(local, WINDOWS), "{local}");
    }
    // On POSIX two separators are one.
    for text in [r"\\server\share\x", "//server/share/x", r"\\?\UNC\a\b"] {
        assert!(!network(text, POSIX), "{text}");
    }
}

#[test]
fn the_flavour_follows_the_home_directory() {
    assert_eq!(Resolver::new(&posix()).flavour(), POSIX);
    assert_eq!(Resolver::new(&mac()).flavour(), POSIX);
    assert_eq!(Resolver::new(&windows()).flavour(), WINDOWS);
    let share = Paths::new(r"\\srv\home\me", r"\\srv\home\me", [r"\\srv\home\me"]);
    assert_eq!(Resolver::new(&share).flavour(), WINDOWS);
    assert_eq!(
        Resolver::new(&Paths::new("", "", Vec::<&str>::new())).flavour(),
        POSIX
    );
}

#[test]
fn the_data_volume_and_the_boot_volume_are_the_root_however_the_path_is_spelled() {
    let sshkey = secret("your SSH keys");
    let mac_root = Paths::new("/", "/Users/me", ["/Users/me/dev/repo"]);
    rows(
        &mac(),
        POSIX,
        &[
            // Absolute, relative, and from `~`: every path is made absolute
            // first, and then the links are read.
            ("/System/Volumes/Data/Users/me/.ssh/id_ed25519", sshkey),
            (
                "../../../../System/Volumes/Data/Users/me/.ssh/id_ed25519",
                sshkey,
            ),
            (
                "../../../../../../../../System/Volumes/Data/Users/me/.ssh/id",
                sshkey,
            ),
            ("/Volumes/Macintosh HD/Users/me/.ssh/id_ed25519", sshkey),
            ("/volumes/macintosh hd/users/me/.ssh/id_ed25519", sshkey),
            ("/VOLUMES/MACINTOSH HD/Users/me/.ssh/id_ed25519", sshkey),
            (
                "/Volumes/Macintosh HD - Data/Users/me/.ssh/id_ed25519",
                sshkey,
            ),
            ("../../../../Volumes/Macintosh HD/Users/me/.ssh/id", sshkey),
            // Links to links.
            (
                "/Volumes/Macintosh HD/System/Volumes/Data/Users/me/.ssh/id",
                sshkey,
            ),
            (
                "/System/Volumes/Data/Volumes/Macintosh HD/Users/me/.ssh/id",
                sshkey,
            ),
            (
                "/System/Volumes/Data/System/Volumes/Data/Users/me/.ssh/id",
                sshkey,
            ),
            // The workspace, and the temporary folders, by the same links.
            ("/System/Volumes/Data/Users/me/dev/repo/x", Place::Inside),
            ("/Volumes/Macintosh HD/Users/me/dev/repo/x", Place::Inside),
            (
                "../../../../Volumes/Macintosh HD/tmp/x",
                Place::Temp { exact: false },
            ),
            // The links alone are the root, and another volume is not.
            ("/System/Volumes/Data", Place::Top("the root of the disk")),
            ("/Volumes/Macintosh HD", Place::Top("the root of the disk")),
            (
                "/Volumes/Macintosh HD - Data",
                Place::Top("the root of the disk"),
            ),
            ("/Volumes/Backup/Users/me/.ssh/id_rsa", Place::Outside),
            (
                "/Volumes/Macintosh HD2/Users/me/.ssh/id_rsa",
                Place::Outside,
            ),
            ("/Volumes", Place::Top("a top-level folder")),
            ("/System/Volumes/Preboot/x", Place::Top("a system folder")),
        ],
    );
    // From `~`: the home directory, and `..` out of it to the links.
    for rest in [
        "../../System/Volumes/Data/Users/me/.ssh/id_ed25519",
        "../../system/volumes/data/Users/me/.ssh/id_ed25519",
        "../../Volumes/Macintosh HD/Users/me/.ssh/id_ed25519",
        "../../../../../../System/Volumes/Data/Users/me/.ssh/id_ed25519",
    ] {
        assert_eq!(
            Resolver::new(&mac()).place(Spelling::Home(rest), POSIX),
            sshkey,
            "~/{rest}"
        );
    }
    // A working directory at the root: a relative path starts there.
    rows(
        &mac_root,
        POSIX,
        &[
            ("System/Volumes/Data/Users/me/.ssh/id_rsa", sshkey),
            ("Volumes/Macintosh HD/Users/me/.ssh/id_rsa", sshkey),
            ("Users/me/.ssh/id_rsa", sshkey),
        ],
    );
    // A Mac's file system folds the long s to `s`: the same folders.
    rows(
        &mac(),
        POSIX,
        &[
            ("/Sy\u{17f}tem/Volumes/Data/Users/me/.ssh/id_rsa", sshkey),
            ("/Volume\u{17f}/Macintosh HD/Users/me/.ssh/id_rsa", sshkey),
            (
                "/Sy\u{17f}tem/Volumes/Data/Users/me/dev/repo/x",
                Place::Inside,
            ),
            (
                "/Volume\u{17f}/Macinto\u{17f}h HD/Users/me/dev/repo/x",
                Place::Inside,
            ),
        ],
    );
}

#[test]
fn a_macs_links_are_read_only_on_a_mac() {
    // A Mac has its home under `/Users`. On any other system the paths do
    // not exist: a write creates folders, so they must not be the root.
    for paths in [posix(), Paths::new("/srv/x", "/srv/x", ["/srv/x"])] {
        rows(
            &paths,
            POSIX,
            &[
                ("/Volumes/Macintosh HD/home/me/work/repo/x", Place::Outside),
                (
                    "/System/Volumes/Data/home/me/.ssh/id_rsa",
                    Place::Top("a system folder"),
                ),
                ("/Volumes/Macintosh HD/etc/shadow", Place::Outside),
            ],
        );
    }
    let linux = Resolver::new(&posix());
    for path in [
        "/System/Volumes/Data/dev/mem",
        "/Volumes/Macintosh HD/dev/mem",
    ] {
        assert_eq!(linux.kernel(Spelling::Plain(path), POSIX), None, "{path}");
        assert!(
            Resolver::new(&mac())
                .kernel(Spelling::Plain(path), POSIX)
                .is_some(),
            "{path}"
        );
    }
    // A Mac spelled by its data volume is still a Mac.
    let data = Paths::new(
        "/System/Volumes/Data/Users/me/dev/repo",
        "/System/Volumes/Data/Users/me",
        ["/System/Volumes/Data/Users/me/dev/repo"],
    );
    rows(
        &data,
        POSIX,
        &[
            ("/Users/me/dev/repo/x", Place::Inside),
            ("x", Place::Inside),
            (
                "/Volumes/Macintosh HD/Users/me/.ssh/id_rsa",
                secret("your SSH keys"),
            ),
        ],
    );
}

#[test]
fn only_the_names_ntfs_folds_make_the_workspace_the_workspace() {
    // The Kelvin sign, the Ångström sign, the Ohm sign and the capital sharp
    // s fold to `k`, `å`, `ω` and `ß` in the widest reading (APFS), not on
    // NTFS: a folder by those names is another folder, so it is not the
    // workspace's own. Matching too much here would open a hole.
    for (workspace, other) in [
        ("work", "wor\u{212a}"),
        ("WORK", "wor\u{212a}"),
        ("wor\u{e5}", "wor\u{212b}"),
        ("wor\u{c5}", "wor\u{212b}"),
        ("wor\u{3c9}", "wor\u{2126}"),
        ("wor\u{3a9}", "wor\u{2126}"),
        ("stra\u{df}e", "stra\u{1e9e}e"),
        ("work", "wor\u{17f}"),
    ] {
        let dir = format!(r"C:\Users\me\{workspace}");
        let paths = Paths::new(dir.as_str(), r"C:\Users\me", [dir.as_str()]);
        let same = format!(r"{dir}\x");
        let folded = format!(r"C:\Users\me\{other}\x");
        assert_eq!(at(&paths, &same, WINDOWS), Place::Inside, "{same}");
        assert_eq!(at(&paths, &folded, WINDOWS), Place::Outside, "{folded}");
        let folded = format!(r"C:\Users\me\{other}");
        assert_eq!(at(&paths, &folded, WINDOWS), Place::Outside, "{folded}");
        let folded = format!(r"C:\USERS\ME\{}\x", other.to_uppercase());
        assert_ne!(at(&paths, &folded, WINDOWS), Place::Inside, "{folded}");
    }
    // Where matching too much fails closed, the wide fold stays: the home
    // directory, a sensitive place, a protected path and the repository's
    // history.
    let kim = Paths::new(r"C:\Users\Kim\dev", r"C:\Users\Kim", [r"C:\Users\Kim\dev"]);
    rows(
        &kim,
        WINDOWS,
        &[
            (
                "C:\\Users\\\u{212a}im\\.ssh\\id_rsa",
                secret("your SSH keys"),
            ),
            (
                "C:\\Users\\Kim\\.\u{212a}ube\\config",
                secret("your Kubernetes credentials"),
            ),
            ("C:\\Users\\Kim\\dev\\.G\u{130}T\\x", Place::Inside),
        ],
    );
}

#[test]
fn another_users_home_is_one_whatever_this_users_home_is() {
    let sshkey = secret("your SSH keys");
    for paths in [
        Paths::new("/root/repo", "/root", ["/root/repo"]),
        Paths::new("/var/lib/ci/repo", "/var/lib/ci", ["/var/lib/ci/repo"]),
        Paths::new("/srv/x", "/srv/x", ["/srv/x"]),
        Paths::new("/ci", "/ci", ["/ci"]),
    ] {
        rows(
            &paths,
            POSIX,
            &[
                ("/home/alice/.ssh/id_rsa", sshkey),
                ("/HOME/Alice/.SSH/id_rsa", sshkey),
                (
                    "/Users/alice/.aws/credentials",
                    secret("your AWS credentials"),
                ),
                ("/home/alice/.zshrc", startup("a shell startup file")),
                ("/home/alice/notes.txt", Place::Outside),
            ],
        );
    }
    let d = Paths::new(
        r"D:\profiles\me\repo",
        r"D:\profiles\me",
        [r"D:\profiles\me\repo"],
    );
    rows(
        &d,
        WINDOWS,
        &[
            (r"C:\Users\alice\.ssh\id_rsa", sshkey),
            (r"D:\Users\alice\.ssh\id_rsa", sshkey),
            (r"D:\profiles\alice\.ssh\id_rsa", sshkey),
            (r"C:\Users\alice\notes.txt", Place::Outside),
        ],
    );
}

#[test]
fn the_credential_stores_and_startup_places_that_have_twins_are_listed() {
    let win = windows();
    rows(
        &win,
        WINDOWS,
        &[
            (
                r"C:\Users\me\AppData\Roaming\GitHub CLI\hosts.yml",
                secret("your GitHub login"),
            ),
            (
                r"C:\Users\me\AppData\Roaming\gcloud\credentials.db",
                secret("your Google Cloud credentials"),
            ),
            (
                r"C:\Users\me\AppData\Roaming\gnupg\private-keys-v1.d\x.key",
                secret("your GPG keys"),
            ),
            (
                r"C:\Users\me\AppData\Local\Microsoft\Vault\x",
                secret("your saved Windows logins"),
            ),
            (
                r"C:\Users\me\AppData\Roaming\Microsoft\Vault\x",
                secret("your saved Windows logins"),
            ),
            (
                r"C:\ProgramData\Microsoft\Vault\x",
                secret("the system's saved logins"),
            ),
            (
                r"C:\Users\me\APPDAT~1\Roaming\GITHUB~1\hosts.yml",
                secret("your GitHub login"),
            ),
            (
                r"C:\Users\me\.config\git\config",
                startup("your git settings"),
            ),
            (
                r"C:\Users\me\.config\powershell\profile.ps1",
                startup("your PowerShell profile"),
            ),
            (
                r"C:\Users\me\OneDrive\Documents\PowerShell\profile.ps1",
                startup("your PowerShell profile"),
            ),
            (
                r"C:\Users\me\OneDrive\Documents\WindowsPowerShell\profile.ps1",
                startup("your PowerShell profile"),
            ),
            (
                r"C:\Users\me\.config\systemd\user\x.service",
                startup("the services your system starts at login"),
            ),
        ],
    );
    rows(
        &posix(),
        POSIX,
        &[
            ("/home/me/.config/git/config", startup("your git settings")),
            (
                "/home/me/.config/powershell/Microsoft.PowerShell_profile.ps1",
                startup("your PowerShell profile"),
            ),
            (
                "/home/me/.config/systemd/user/x.service",
                startup("the services your system starts at login"),
            ),
            (
                "/home/me/.config/git/credentials",
                secret("your git credentials"),
            ),
            ("/home/me/.config/git/ignore", Place::Outside),
            ("/home/me/.config/systemd/system/x", Place::Outside),
        ],
    );
}

#[test]
fn the_kernel_serves_files_that_are_not_files() {
    let mac = Resolver::new(&mac());
    let px = Resolver::new(&posix());
    let words = |r: &Resolver, path: &str| r.kernel(Spelling::Plain(path), POSIX);
    for path in [
        "/dev/mem",
        "/dev/kmem",
        "/dev/port",
        "/dev/sda",
        "/dev/sda1",
        "/dev/nvme0n1",
        "/dev/disk0",
        "/dev/rdisk0s1",
        "/dev/loop0",
        "/dev/root",
        "/dev/nbd0",
        "/dev/zd0",
        "/dev/mapper/root",
        "/dev/pts/0",
        "/dev/ptmx",
        "/dev/console",
        "/dev/shm/x",
        "/dev/fd/3",
        "/dev/fd/10",
        "/dev/fd/00",
        "/dev/fd",
        "/dev/fd/0/x",
        "/dev/null/x",
        "/dev",
        "/DEV/MEM",
        "/dev/../dev/mem",
        "/dev/./mem",
        "/proc/self/environ",
        "/proc/1/environ",
        "/proc/thread-self/environ",
        "/proc/self/task/1/environ",
        "/proc/self/mem",
        "/proc/self/cmdline",
        "/proc/self/maps",
        "/proc/self/smaps",
        "/proc/self/status",
        "/proc/self/fd/3",
        "/proc/self/root/home/me/.ssh/id_rsa",
        "/proc/self/root",
        "/proc/1234/root/etc/shadow",
        "/proc/self/cwd/x",
        "/proc/self/cwd/../../.ssh/id_rsa",
        "/proc/kcore",
        "/proc/kallsyms",
        "/proc/sys/kernel/randomize_va_space",
        "/proc",
        "/PROC/self/environ",
        "/proc/cpuinfo/x",
    ] {
        assert!(words(&mac, path).is_some(), "{path}");
        assert!(words(&px, path).is_some(), "{path}");
    }
    for path in [
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
        "/dev/x/../null",
        "/proc/cpuinfo",
        "/proc/meminfo",
        "/proc/version",
        "/proc/loadavg",
        "/proc/uptime",
        "/proc/filesystems",
        "/etc/hosts",
        "/devx/mem",
        "/dev2/mem",
        "/processes/x",
        "/home/me/dev/mem",
        "/home/me/proc/self/environ",
        "src/dev/mem",
        "/System/Volumes/Preboot/dev/mem",
    ] {
        assert_eq!(words(&mac, path), None, "{path}");
    }
    assert_eq!(words(&px, "/dev/mem"), Some("a device file"));
    assert_eq!(
        words(&px, "/proc/self/environ"),
        Some("the kernel's process files")
    );
    // From the working directory, `~`, and by `..`.
    let root = Resolver::new(&Paths::new("/", "/home/me", ["/home/me/work/repo"]));
    assert!(root
        .kernel(Spelling::Plain("proc/self/environ"), POSIX)
        .is_some());
    assert!(root.kernel(Spelling::Plain("dev/mem"), POSIX).is_some());
    assert!(root.kernel(Spelling::Plain("dev/null"), POSIX).is_none());
    assert!(px
        .kernel(Spelling::Home("../../../proc/self/environ"), POSIX)
        .is_some());
    assert!(px
        .kernel(Spelling::Plain("../../../../../dev/mem"), POSIX)
        .is_some());
    assert!(px
        .kernel(Spelling::Plain("src/../../../../../../proc/kcore"), POSIX)
        .is_some());
    // Windows has no `/dev` of this kind: the device namespace is a disk.
    let win = Resolver::new(&windows());
    assert_eq!(win.kernel(Spelling::Plain("/dev/mem"), WINDOWS), None);
    assert_eq!(
        win.kernel(Spelling::Plain(r"\proc\self\environ"), WINDOWS),
        None
    );
}

#[test]
fn a_git_folder_at_any_depth_is_the_repositorys_own() {
    let history = Some("the repository's history");
    let hook = Some("a git hook, which runs code");
    let px = Resolver::new(&posix());
    let git = |path: &str| px.git(Spelling::Plain(path), POSIX);
    for (path, words) in [
        (".git/config", history),
        (".git", history),
        (".git/HEAD", history),
        (".git/objects/ab/cd", history),
        (".GIT/config", history),
        ("vendor/x/.git/config", history),
        ("vendor/x/.git/HEAD", history),
        ("a/b/c/d/.git", history),
        ("/tmp/clone/.git/config", history),
        ("~/work/other/.git/config", history),
        (".git/hooks/pre-commit", hook),
        (".git/hooks", hook),
        (".GIT/HOOKS/pre-commit", hook),
        ("vendor/x/.git/hooks/pre-commit", hook),
        ("vendor/x/.git/hooks/", hook),
        ("../other/.git/hooks/post-merge", hook),
        ("vendor/x/.git/../.git/hooks/pre-commit", hook),
        // A repository inside a repository inside a repository.
        (".git/modules/m/hooks/pre-commit", history),
        ("sub/.git/modules/m/.git/hooks/x", history),
        ("src/main.rs", None),
        (".gitignore", None),
        (".github/hooks/x", None),
        ("hooks/pre-commit", None),
        ("x.git/config", None),
        ("src/.gitx/hooks/x", None),
        ("git/hooks/x", None),
    ] {
        assert_eq!(git(path), words, "{path}");
    }
    let win = Resolver::new(&windows());
    let git = |path: &str| win.git(Spelling::Plain(path), WINDOWS);
    for (path, words) in [
        (r"src\.git\config", history),
        (r"src\GIT~1\config", history),
        (r"vendor\x\git~2\hooks\pre-commit", hook),
        (r"vendor\x\.git.\hooks\pre-commit", hook),
        (r"vendor\x\.git\hooks.\pre-commit", hook),
        (r"vendor\x\.git\HOOKS\pre-commit", hook),
        (r"vendor\x\.git\HOOKS~1\pre-commit", history),
        (r"C:\Users\me\dev\repo\vendor\.git\hooks\x", hook),
        (r"src\GITHUB~1\x", None),
        (r"src\x.rs", None),
    ] {
        assert_eq!(git(path), words, "{path}");
    }
    // Known only when it runs: no answer.
    assert_eq!(git(r"vendor\.git::$INDEX_ALLOCATION\hooks\x"), None);
    assert_eq!(git("D:vendor/.git/x"), None);
}
