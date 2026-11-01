//! `Resolver::picks_secret`: which keys and credentials a pattern can name.
//! A pattern is read by the folder before its first wildcard part and by what
//! its parts can match below, as a protected path is; a part is matched
//! against each secret place's names one for one.

use milo_guards_core::{Flavour, Paths, Resolver, Spelling};

const POSIX: Flavour = Flavour::Posix;
const WINDOWS: Flavour = Flavour::Windows;

fn posix() -> Paths {
    Paths::new("/home/me/work/repo", "/home/me", ["/home/me/work/repo"])
}

fn windows() -> Paths {
    Paths::new(
        r"C:\Users\me\dev\repo",
        r"C:\Users\me",
        [r"C:\Users\me\dev\repo"],
    )
}

fn picks(paths: &Paths, flavour: Flavour, hidden: bool, pattern: &str) -> Option<&'static str> {
    Resolver::new(paths).picks_secret(Spelling::Plain(pattern), flavour, hidden)
}

fn rows(
    paths: &Paths,
    flavour: Flavour,
    hidden: bool,
    secret: &[(&str, &'static str)],
    none: &[&str],
) {
    let mut wrong: Vec<String> = secret
        .iter()
        .filter_map(|(pattern, words)| {
            let got = picks(paths, flavour, hidden, pattern);
            (got != Some(*words)).then(|| format!("{pattern}: expected {words:?}, got {got:?}"))
        })
        .collect();
    wrong.extend(none.iter().filter_map(|pattern| {
        let got = picks(paths, flavour, hidden, pattern);
        got.map(|words| format!("{pattern}: expected none, got {words:?}"))
    }));
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn a_pattern_that_can_name_a_key_picks_it() {
    rows(
        &posix(),
        POSIX,
        false,
        &[
            ("/home/me/.s*/id_rsa", "your SSH keys"),
            ("/home/me/.ss?/id_rsa", "your SSH keys"),
            ("/home/me/.[s]sh/id_rsa", "your SSH keys"),
            ("/home/me/.ssh/id_*", "your SSH keys"),
            ("/home/me/.ssh/*", "your SSH keys"),
            ("/home/me/.ssh/**", "your SSH keys"),
            ("/home/me/.s*", "your SSH keys"),
            ("/home/me/.*", "your SSH keys"),
            ("/home/me/.*rc", "your saved logins"),
            ("/home/me/.aw*/credentials", "your AWS credentials"),
            ("/home/me/.config/g*/hosts.yml", "your GitHub login"),
            ("/home/me/.*/id_rsa", "your SSH keys"),
            ("/etc/sh*dow", "the system's password hashes"),
            ("/etc/shad?w", "the system's password hashes"),
            ("/etc/ssh/ssh_host_*_key", "the system's SSH keys"),
            ("/etc/ssl/priv*/x.key", "the system's private keys"),
            ("/e*/shadow", "the system's password hashes"),
            ("/home/*/.ssh/id_rsa", "your SSH keys"),
            ("/home/al*/.ssh/id_rsa", "your SSH keys"),
            ("/home/alice/.s*/id_rsa", "your SSH keys"),
            ("/home/*/.aws/credentials", "your AWS credentials"),
            ("/h*/*/.ssh", "your SSH keys"),
            ("/root/.s*/id_rsa", "your SSH keys"),
            ("/ro*/.ssh/id_rsa", "your SSH keys"),
            ("/var/root/.ss*/id_rsa", "your SSH keys"),
            ("/home/me/../me/.s*/id_rsa", "your SSH keys"),
            ("/home/me/x/../.s*/id_rsa", "your SSH keys"),
            ("/home/me/.SS?/ID_RSA", "your SSH keys"),
            ("/run/secrets/*", "the container's secrets"),
            ("/home/me/.config/*", "your GitHub login"),
            ("/etc/*", "the system's password hashes"),
        ],
        &[
            // A pattern that names no hidden entry does not match one without
            // `dotglob`.
            "/home/me/*",
            "/home/me/*/x",
            "/home/me/*.txt",
            "/home/me/work/*.rs",
            "/home/me/work/*/id_rsa",
            "/home/me/*/id_rsa",
            // A name is matched whole.
            "/home/me/.sshx/*",
            "/home/me/.ssh2/*",
            "/home/me/.s*x/id_rsa",
            "/home/me/.aw??/credentials",
            "/home/me/.aws2*/x",
            // A part that is a startup file or the history is not a secret.
            "/home/me/.zsh*",
            "/home/me/.bash*",
            "/home/me/.gitconf*",
            "/home/me/.zshr?",
            // A pattern that only stops at a folder holding a secret reads
            // that folder's name.
            "/home/*",
            "/h*",
            "/home/me/.conf*",
            "/et?/ho*",
            "/etc/host*",
            "/usr/*/x",
            // A path with no wildcard is for `place`.
            "/home/me/.ssh/id_rsa",
            "/etc/shadow",
            "/home/me/work",
            "/tmp/*.log",
        ],
    );
}

#[test]
fn a_pattern_in_the_workspace_is_the_agents_unless_it_holds_the_keys() {
    let own = posix();
    rows(
        &own,
        POSIX,
        false,
        &[],
        &[
            "/home/me/work/repo/.s*/id_rsa",
            "/home/me/work/repo/*/x",
            "/home/me/work/repo/.*",
        ],
    );
    // The home directory as the workspace holds its keys.
    let home = Paths::new("/home/me", "/home/me", ["/home/me"]);
    rows(
        &home,
        POSIX,
        false,
        &[("/home/me/.s*/id_rsa", "your SSH keys")],
        &["/home/me/src/*"],
    );
}

#[test]
fn a_wildcard_that_matches_a_leading_dot_picks_what_a_dot_picks() {
    // `dotglob` (or `globdots`, or `GLOBIGNORE`) lets `*` match `.ssh`.
    rows(
        &posix(),
        POSIX,
        true,
        &[
            ("/home/me/*", "your SSH keys"),
            ("/home/me/*/id_rsa", "your SSH keys"),
            ("/home/me/?ssh/*", "your SSH keys"),
            ("/etc/*", "the system's password hashes"),
        ],
        &["/home/me/*.txt", "/home/me/work/*.rs", "/home/me/x*"],
    );
}

#[test]
fn a_windows_wildcard_matches_a_leading_dot_as_it_is() {
    rows(
        &windows(),
        WINDOWS,
        false,
        &[
            (r"C:\Users\me\.s*\id_rsa", "your SSH keys"),
            (r"C:\Users\me\.ssh\*", "your SSH keys"),
            (r"C:\Users\me\*", "your SSH keys"),
            (r"C:\Users\me\*\id_rsa", "your SSH keys"),
            (r"C:\Users\me\.*", "your SSH keys"),
            (r"c:\users\me\.SS?\id_rsa", "your SSH keys"),
            (r"C:\Users\me\SSH~*\id_rsa", "your SSH keys"),
            (
                r"C:\Users\me\AppData\Roaming\Microsoft\Cred*\x",
                "your saved Windows logins",
            ),
            (
                r"C:\Users\me\AppData\*\Microsoft\Credentials\x",
                "your saved Windows logins",
            ),
            (r"C:\Users\*\.ssh\id_rsa", "your SSH keys"),
            (r"C:\Users\*\.aws\*", "your AWS credentials"),
            (
                r"C:\Windows\System32\config\S*",
                "the Windows account database",
            ),
            (
                r"C:\Windows\Sys*\config\SAM",
                "the Windows account database",
            ),
            (r"C:\Win*\repair\sam", "the Windows account database"),
            (r"\\?\C:\Users\me\.s*\id_rsa", "your SSH keys"),
        ],
        &[
            r"C:\Users\me\*.txt",
            r"C:\Users\me\Documents\*",
            r"C:\Users\me\dev\repo\*",
            r"C:\Users\me\.zsh*",
            r"C:\Windows\System32\drivers\*",
            r"C:\Windows\*.log",
            r"C:\Users\Public\Documents\*.txt",
        ],
    );
}

#[test]
fn a_path_known_only_when_it_runs_picks_nothing() {
    let paths = windows();
    // A drive's own working directory on a drive the working directory is not
    // on is known only when it runs.
    assert_eq!(picks(&paths, WINDOWS, false, r"D:.s*\id_rsa"), None);
    assert_eq!(picks(&paths, WINDOWS, false, ""), None);
}
