//! Files a tool runs on its own (`.vscode/tasks.json`, `.envrc`, `.husky/*`,
//! `.github/workflows/*`...): a line that writes one, at any depth in a
//! workspace folder and however it is spelled, is `overwrite` with "a file a
//! tool runs on its own"; a line that reads one, or deletes one, is safe; and
//! the files that only run when someone asks (`Makefile`, `justfile`,
//! `package.json`) stay safe.
//!
//! The lines and their answers are in `tests/cases/startup.cases`; here are
//! the lines made for every place on the list (each writer, read and delete
//! of each, in every shell) and the target a finding names.

mod common;

use common::{check, check_effect, classify, posix, windows};
use milo_guards_shell::{Effect, Reach, Rule, Shell};

/// Every place on the list, as a file or something below a folder, and at
/// depth.
const PLACES: &[&str] = &[
    ".vscode/settings.json",
    "proj.code-workspace",
    "a/b/proj2.code-workspace",
    "mise.toml",
    ".mise.toml",
    "mise.local.toml",
    ".mise.local.toml",
    ".zed/tasks.json",
    ".gitpod.yml",
    ".gitea/workflows/ci.yml",
    ".forgejo/workflows/ci.yml",
    ".woodpecker.yml",
    ".woodpecker/build.yml",
    ".githooks/pre-commit",
    ".githooks",
    ".cursor/hooks.json",
    ".windsurf/hooks.json",
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".gemini/settings.json",
    ".codex/config.toml",
    ".roo/mcp.json",
    ".amazonq/mcp.json",
    ".kiro/settings/mcp.json",
    ".kiro/hooks/x.kiro.hook",
    ".continue/mcpServers/x.yaml",
    ".vscode/tasks.json",
    ".vscode/launch.json",
    ".vscode/mcp.json",
    ".cursor/mcp.json",
    ".mcp.json",
    ".idea/runConfigurations/Build.xml",
    ".envrc",
    ".husky/pre-commit",
    ".husky/_/husky.sh",
    ".pre-commit-config.yaml",
    "lefthook.yml",
    ".lefthook.yml",
    "lefthook-local.yml",
    ".github/workflows/ci.yml",
    ".github/workflows/deep/er/x.yml",
    ".github/actions/setup/action.yml",
    ".gitlab-ci.yml",
    ".circleci/config.yml",
    ".buildkite/pipeline.yml",
    ".travis.yml",
    ".drone.yml",
    "Jenkinsfile",
    "azure-pipelines.yml",
    "bitbucket-pipelines.yml",
    ".devcontainer/devcontainer.json",
    ".devcontainer/Dockerfile",
    ".devcontainer.json",
    "src/.envrc",
    "a/b/c/.vscode/tasks.json",
    "packages/app/.github/workflows/ci.yml",
    "vendor/x/.husky/pre-commit",
];

/// What only runs when someone asks, and near misses of the names.
const EVERYDAY: &[&str] = &[
    "Makefile",
    "justfile",
    "package.json",
    "Cargo.toml",
    "scripts/build.sh",
    ".cargo/config.toml",
    ".env",
    ".envrcx",
    "x.envrc",
    ".envrc.bak",
    "envrc",
    "tasks.json",
    ".vscode/extensions.json",
    ".vscodex/tasks.json",
    "vscode/tasks.json",
    ".cursor/rules/x.mdc",
    ".idea/workspace.xml",
    ".husky-old/pre-commit",
    ".pre-commit-hooks.yaml",
    "lefthook.yml.bak",
    "my-lefthook.yml",
    ".github/dependabot.yml",
    ".github/ISSUE_TEMPLATE/bug.md",
    ".github/workflows-old/ci.yml",
    ".githubx/workflows/ci.yml",
    ".gitlab/issue_templates/x.md",
    "Jenkinsfile.md",
    ".devcontainerx/x",
    "src/main.rs",
];

#[test]
fn every_case_holds() {
    common::cases::check("startup");
}

/// Lines that write `path` in a POSIX shell, each a way to write a file.
fn posix_writers(path: &str) -> Vec<String> {
    [
        "echo x > {}",
        "echo x >> {}",
        "echo x >| {}",
        "echo x &> {}",
        "echo x 2> {}",
        ": > {}",
        "> {}",
        "cat a > {}",
        "printf x | tee {}",
        "echo x | tee -a {}",
        "cp a {}",
        "cp -f a.txt {}",
        "install -m 755 a {}",
        "mv a {}",
        "ln -s a {}",
        "ln -sf a {}",
        "sed -i s/a/b/ {}",
        "sed -i '' -e s/a/b/ {}",
        "sed --in-place s/a/b/ {}",
        "perl -pi -e s/a/b/ {}",
        "touch {}",
        "truncate -s 0 {}",
        "dd if=a of={}",
        "curl -o {} https://x.example/f",
        "curl --output {} https://x.example/f",
        "wget -O {} https://x.example/f",
    ]
    .iter()
    .map(|line| line.replace("{}", path))
    .collect()
}

fn overwrites(lines: &[String]) -> Vec<(&str, Rule)> {
    lines
        .iter()
        .map(|line| (line.as_str(), Rule::Overwrite))
        .collect()
}

#[test]
fn every_writer_of_every_place_is_an_overwrite() {
    let lines: Vec<String> = PLACES.iter().flat_map(|p| posix_writers(p)).collect();
    check(Shell::Posix, &posix(), &[], &overwrites(&lines));
}

#[test]
fn a_read_or_a_delete_of_one_is_safe() {
    let mut lines = Vec::new();
    for place in PLACES {
        for line in [
            "cat {}",
            "head -n 3 {}",
            "less {}",
            "grep x {}",
            "diff a {}",
            "wc -l {}",
            "cp {} /tmp/x",
            "cp {} copy.txt",
            "rm {}",
            "rm -f {}",
            "rm -rf {}",
            "mv {} /tmp/x",
            "chmod +x {}",
            "echo x > /tmp/{}.out",
            "cat {} > out.txt",
            "grep x {} | wc -l",
            "sort {} | uniq > out.txt",
        ] {
            lines.push(line.replace("{}", place));
        }
    }
    let lines: Vec<&str> = lines.iter().map(String::as_str).collect();
    check(Shell::Posix, &posix(), &lines, &[]);
}

#[test]
fn the_files_that_only_run_when_asked_stay_safe() {
    let lines: Vec<String> = EVERYDAY.iter().flat_map(|p| posix_writers(p)).collect();
    let lines: Vec<&str> = lines.iter().map(String::as_str).collect();
    // `curl -o` and the like are not what is asked; the rows are about the
    // places, so a writer of an everyday name is safe.
    check(Shell::Posix, &posix(), &lines, &[]);
}

#[test]
fn cmd_writes_the_same_places_and_reads_them_safe() {
    let writers = |path: &str| -> Vec<String> {
        [
            "echo x > {}",
            "echo x >> {}",
            "type a > {}",
            "copy a {}",
            "copy /y a {}",
            "move a {}",
            "move /y a {}",
            "xcopy /y a {}",
            "type nul > {}",
        ]
        .iter()
        .map(|line| line.replace("{}", path))
        .collect()
    };
    let places: Vec<String> = PLACES.iter().map(|p| p.replace('/', "\\")).collect();
    let lines: Vec<String> = places.iter().flat_map(|p| writers(p)).collect();
    check(Shell::Cmd, &windows(), &[], &overwrites(&lines));
    let reads: Vec<String> = places
        .iter()
        .flat_map(|p| {
            [
                format!("type {p}"),
                format!("more {p}"),
                format!("findstr x {p}"),
                format!("copy {p} out.txt"),
                format!("copy {p} C:\\Windows\\Temp\\x"),
                format!("del {p}"),
                format!("del /q {p}"),
                format!("move {p} C:\\Windows\\Temp\\x"),
                format!("type {p} > out.txt"),
            ]
        })
        .collect();
    let reads: Vec<&str> = reads.iter().map(String::as_str).collect();
    check(Shell::Cmd, &windows(), &reads, &[]);
    let everyday: Vec<String> = EVERYDAY
        .iter()
        .flat_map(|p| writers(&p.replace('/', "\\")))
        .collect();
    let everyday: Vec<&str> = everyday.iter().map(String::as_str).collect();
    check(Shell::Cmd, &windows(), &everyday, &[]);
}

fn powershell_writers(path: &str) -> Vec<String> {
    [
        "echo x > {}",
        "echo x >> {}",
        "'x' | Out-File {}",
        "'x' | Out-File -FilePath {} -Append",
        "Set-Content {} x",
        "Set-Content -Path {} -Value x",
        "Set-Content -LiteralPath {} -Value x",
        "sc {} x",
        "Add-Content -Path {} -Value x",
        "ac {} x",
        "Clear-Content {}",
        "New-Item {}",
        "New-Item -Path {} -ItemType File",
        "ni {} -Force",
        "'x' | Tee-Object {}",
        "Copy-Item a {}",
        "Copy-Item -Path a -Destination {}",
        "cp a {} -Force",
        "Move-Item a {}",
        "mi a {}",
        "Invoke-WebRequest https://x.example/f -OutFile {}",
        "iwr https://x.example/f -OutFile {}",
    ]
    .iter()
    .map(|line| line.replace("{}", path))
    .collect()
}

#[test]
fn powershell_writes_the_same_places_and_reads_them_safe() {
    let places: Vec<String> = PLACES.iter().map(|p| p.replace('/', "\\")).collect();
    let lines: Vec<String> = places.iter().flat_map(|p| powershell_writers(p)).collect();
    check(Shell::PowerShell, &windows(), &[], &overwrites(&lines));
    let reads: Vec<String> = places
        .iter()
        .flat_map(|p| {
            [
                format!("Get-Content {p}"),
                format!("gc -Path {p} -TotalCount 3"),
                format!("cat {p}"),
                format!("Select-String x {p}"),
                format!("Get-Item {p}"),
                format!("Test-Path {p}"),
                format!("Copy-Item {p} out.txt"),
                format!("Copy-Item {p} C:\\Windows\\Temp\\x"),
                format!("Remove-Item {p}"),
                format!("Remove-Item -Recurse -Force {p}"),
                format!("rm {p}"),
                format!("Move-Item {p} C:\\Windows\\Temp\\x"),
                format!("Get-Content {p} | Set-Content out.txt"),
            ]
        })
        .collect();
    let reads: Vec<&str> = reads.iter().map(String::as_str).collect();
    check(Shell::PowerShell, &windows(), &reads, &[]);
    let everyday: Vec<String> = EVERYDAY
        .iter()
        .flat_map(|p| powershell_writers(&p.replace('/', "\\")))
        .collect();
    let everyday: Vec<&str> = everyday.iter().map(String::as_str).collect();
    check(Shell::PowerShell, &windows(), &everyday, &[]);
}

/// The path a finding names is the one the line wrote (its rule and reason
/// are a case).
#[test]
fn a_finding_names_the_path_as_written() {
    let found = classify("echo x > .Vscode/Tasks.json", Shell::Posix, &posix());
    let finding = &found.findings()[0];
    assert_eq!(finding.target.as_deref(), Some(".Vscode/Tasks.json"));
}

#[test]
fn reading_a_file_a_tool_runs_on_its_own_stays_in_the_workspace() {
    let lines: Vec<String> = PLACES
        .iter()
        .flat_map(|place| {
            [
                format!("cat {place}"),
                format!("grep -rn x {place}"),
                format!("head -n 3 {place}"),
                format!("diff {place} {place}"),
            ]
        })
        .collect();
    let lines: Vec<&str> = lines.iter().map(String::as_str).collect();
    check_effect(
        Shell::Posix,
        &posix(),
        Effect::ReadsOnly(Reach::Workspace),
        &lines,
    );
}
