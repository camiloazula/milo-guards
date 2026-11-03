//! `read_secret`: a read of a key or a credential, through every program the
//! guard knows opens a file, a `<` redirect, a listing piped into a reader,
//! a folder read all the way down, and every spelling of the paths core
//! knows hold one, in POSIX shells, on a Mac, in PowerShell and in cmd.
//! Reading the repository's history, a startup file, `.env` or a file only
//! known when the line runs is not a finding. A read of a key reads only and
//! reaches beyond the workspace. Sending a secret off the machine is
//! `send_secret`, in `send_secret.rs`.
//!
//! The lines and their answers are in `tests/cases/read_secret.cases`; here
//! is the target a finding names.

mod common;

use common::{classify, posix};
use milo_guards_shell::{Rule, Shell};

#[test]
fn every_case_holds() {
    common::cases::check("read_secret");
}

/// The argument a finding names, beside its reason (whose words are cases).
#[test]
fn a_finding_names_its_argument() {
    let paths = posix();
    for (line, target) in [
        ("cat ~/.ssh/id_ed25519", "~/.ssh/id_ed25519"),
        ("head -c 100 ~/.aws/credentials", "~/.aws/credentials"),
        ("grep key ~/.netrc", "~/.netrc"),
        ("base64 < ~/.ssh/id_rsa", "~/.ssh/id_rsa"),
        ("cat /etc/shadow", "/etc/shadow"),
        ("cat /proc/self/environ", "/proc/self/environ"),
        ("dd if=/dev/sda", "/dev/sda"),
        ("cp ~/.ssh/id_ed25519 keys/", "~/.ssh/id_ed25519"),
        ("ls ~/.ssh | xargs cat", "<input>"),
    ] {
        let assessment = classify(line, Shell::Posix, &paths);
        let finding = assessment
            .findings()
            .iter()
            .find(|finding| finding.rule == Rule::ReadSecret)
            .unwrap_or_else(|| panic!("no read_secret finding: {line}"));
        assert_eq!(finding.target.as_deref(), Some(target), "{line}");
    }
}
