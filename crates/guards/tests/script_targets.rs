//! The command line the script guard gives for a program the code starts is
//! one the shell guard reads as the machine's shell runs it: cmd on Windows,
//! where `os.system`, `shell=True` and `child_process.exec` run `cmd.exe`,
//! and POSIX elsewhere. What the shell guard finds in it is what the program
//! does, and a caller adds it to the script guard's answer; the code stays
//! `unknown`, so a safe answer for every target never makes it safe.

#![cfg(all(feature = "shell", feature = "script"))]

use milo_guards::script::{self, Language};
use milo_guards::shell::{self, Shell};
use milo_guards::Paths;

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

/// The targets of the script guard's `run_program` findings for `code`.
fn targets(language: Language, code: &str, paths: &Paths) -> Vec<String> {
    script::judge(language, code, paths)
        .findings()
        .iter()
        .filter(|finding| finding.rule == script::Rule::RunProgram)
        .filter_map(|finding| finding.target.clone())
        .collect()
}

/// The shell guard's shell for the script guard's targets on `paths`.
fn shell_of(paths: &Paths) -> Shell {
    match script::target_shell(paths) {
        script::TargetShell::Posix => Shell::Posix,
        script::TargetShell::Cmd => Shell::Cmd,
    }
}

/// The rules and reasons the shell guard finds in `line`.
fn found(line: &str, shell: Shell, paths: &Paths) -> Vec<(&'static str, String)> {
    shell::classify(line, shell, paths)
        .findings()
        .iter()
        .map(|finding| (finding.rule.name(), finding.reason.clone()))
        .collect()
}

#[test]
fn a_windows_target_read_by_cmd_finds_what_the_program_does() {
    let paths = windows();
    for (code, rule, reason) in [
        (
            r"import os; os.system('rd /s /q C:\\Users\\me')",
            "delete",
            "deletes your home directory",
        ),
        (
            r"import os; os.system('type C:\\Users\\me\\.ssh\\id_rsa')",
            "read_secret",
            "reads your SSH keys",
        ),
        (
            r"import os; os.system('echo x > C:\\Users\\me\\.ssh\\authorized_keys')",
            "overwrite",
            "writes to your SSH keys",
        ),
        (
            "import os; os.system('format D: /y')",
            "wipe_disk",
            "formats a disk",
        ),
        (
            "import os; os.system('rd /s /q %USERPROFILE%')",
            "delete",
            "deletes your home directory",
        ),
        (
            r"import subprocess; subprocess.run(['rm', '-rf', 'C:\\Users\\me'])",
            "delete",
            "deletes your home directory",
        ),
        (
            r"import subprocess; subprocess.run(['cmd', '/c', 'rd /s /q C:\\Users\\me'])",
            "delete",
            "deletes your home directory",
        ),
        (
            r"import os; os.chdir('C:\\Users\\me'); os.system('type .ssh\\id_rsa')",
            "read_secret",
            "reads your SSH keys",
        ),
        (
            r"import subprocess; subprocess.run(['del', '.bashrc'], cwd='C:\\Users\\me')",
            "delete",
            "deletes a shell startup file",
        ),
    ] {
        let lines = targets(Language::Python, code, &paths);
        assert!(!lines.is_empty(), "{code}");
        let finds = lines.iter().any(|line| {
            found(line, shell_of(&paths), &paths)
                .iter()
                .any(|(name, said)| *name == rule && said == reason)
        });
        assert!(
            finds,
            "{code}: {lines:?} read by cmd: {:?}",
            lines
                .iter()
                .map(|line| found(line, shell_of(&paths), &paths))
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn a_posix_target_read_by_a_posix_shell_finds_what_the_program_does() {
    let paths = posix();
    for (language, code, rule, reason) in [
        (
            Language::Python,
            "import subprocess; subprocess.run(['rm', '-rf', '~'])",
            "delete",
            "deletes your home directory",
        ),
        (
            Language::JavaScript,
            "require('child_process').execSync('cat ~/.ssh/id_rsa')",
            "read_secret",
            "reads your SSH keys",
        ),
        (
            Language::Python,
            "import subprocess; subprocess.run(['rm', '-rf', 'x'], cwd='/home/me')",
            "delete",
            "deletes a path outside the workspace",
        ),
        (
            Language::Python,
            "import subprocess, sys; subprocess.run(['rm', '-rf', sys.argv[1]])",
            "delete",
            "deletes a path only known when it runs",
        ),
        (
            Language::Python,
            "import os, sys; os.chdir(sys.argv[1]); os.system('cat .ssh/id_rsa')",
            "read_secret",
            "reads your SSH keys",
        ),
    ] {
        let lines = targets(language, code, &paths);
        let all: Vec<_> = lines
            .iter()
            .map(|line| found(line, shell_of(&paths), &paths))
            .collect();
        let finds = all
            .iter()
            .flatten()
            .any(|(name, said)| *name == rule && said == reason);
        assert!(finds, "{code}: {lines:?}: {all:?}");
    }
}

#[test]
fn a_safe_target_never_makes_the_code_safe() {
    for (language, code) in [
        (Language::Python, "import os\nos.system('true')\nimport x"),
        (
            Language::Python,
            "import subprocess\nsubprocess.run(['true'])",
        ),
        (
            Language::JavaScript,
            "require('child_process').execSync('ls'); require('lodash')",
        ),
    ] {
        let paths = posix();
        let assessment = script::judge(language, code, &paths);
        // Every program is safe to the shell guard…
        for line in targets(language, code, &paths) {
            assert!(
                shell::classify(&line, shell_of(&paths), &paths).is_safe(),
                "{line}"
            );
        }
        // …and the code is not: it is not read whole.
        assert!(
            assessment
                .findings()
                .iter()
                .any(|finding| finding.rule == script::Rule::Unknown),
            "{code}: {assessment:?}"
        );
    }
}

#[test]
fn a_target_for_cmd_or_a_batch_file_is_the_line_cmd_reads() {
    // cmd, and a batch file, read the words joined as Windows joins them:
    // `C:\Users\me,x` is two names to `rd`, and the shell guard's cmd
    // reading of the target finds the delete of the home directory. Quoted
    // as a word for another program, it would be one name outside the
    // workspace.
    let paths = windows();
    for code in [
        r"import subprocess; subprocess.run(['cmd', '/c', 'rd', '/s', '/q', 'C:\\Users\\me,x'])",
        r"import subprocess; subprocess.run(['C:\\x\\clean.BAT', 'C:\\Users\\me,x'])",
    ] {
        let lines = targets(Language::Python, code, &paths);
        assert_eq!(lines.len(), 1, "{code}: {lines:?}");
        assert!(!lines[0].contains('"'), "{code}: {lines:?}");
    }
    let code =
        r"import subprocess; subprocess.run(['cmd', '/c', 'rd', '/s', '/q', 'C:\\Users\\me,x'])";
    let lines = targets(Language::Python, code, &paths);
    let reads = found(&lines[0], shell_of(&paths), &paths);
    assert!(
        reads
            .iter()
            .any(|(rule, reason)| *rule == "delete" && reason == "deletes your home directory"),
        "{lines:?}: {reads:?}"
    );
}
