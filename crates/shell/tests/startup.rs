//! Files a tool runs on its own (`.vscode/tasks.json`, `.envrc`, `.husky/*`,
//! `.github/workflows/*`...): a line that writes one, at any depth in a
//! workspace folder and however it is spelled, is `overwrite` with "a file a
//! tool runs on its own"; a line that reads one, or deletes one, is safe; and
//! the files that only run when someone asks (`Makefile`, `justfile`,
//! `package.json`) stay safe. Every spelling a review could try is a row.

mod common;

use common::{check, check_effect, classify, macos, posix, windows};
use milo_guards_shell::{Assessment, Effect, Paths, Protected, Rule, Shell};

const WORDS: &str = "a file a tool runs on its own";

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

fn reasons(line: &str, shell: Shell, paths: &Paths) -> Vec<String> {
    classify(line, shell, paths)
        .findings()
        .iter()
        .map(|finding| finding.reason.clone())
        .collect()
}

#[test]
fn every_writer_of_every_place_is_an_overwrite() {
    let lines: Vec<String> = PLACES.iter().flat_map(|p| posix_writers(p)).collect();
    check(Shell::Posix, &posix(), &[], &overwrites(&lines));
    // Said in the words of the place: `writes to`, and the verb of the line.
    for (line, reason) in [
        ("echo x > .envrc", "writes to a file a tool runs on its own"),
        (
            "tee .vscode/tasks.json",
            "writes to a file a tool runs on its own",
        ),
        ("cp a .envrc", "writes to a file a tool runs on its own"),
        (
            "sed -i s/a/b/ .github/workflows/ci.yml",
            "edits a file a tool runs on its own",
        ),
        ("touch .envrc", "creates a file a tool runs on its own"),
        (
            "truncate -s 0 .envrc",
            "truncates a file a tool runs on its own",
        ),
    ] {
        let got = reasons(line, Shell::Posix, &posix());
        assert_eq!(got, [reason], "{line}");
    }
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
fn spellings_of_one_are_one_file() {
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[
            // Quoted, escaped and expanded.
            ("echo x > '.envrc'", Rule::Overwrite),
            ("echo x > \".envrc\"", Rule::Overwrite),
            ("echo x > .en\"\"vrc", Rule::Overwrite),
            ("echo x > .e'n'vrc", Rule::Overwrite),
            ("echo x > .env\\rc", Rule::Overwrite),
            ("echo x > $'.envrc'", Rule::Overwrite),
            ("echo x > $'.\\x65nvrc'", Rule::Overwrite),
            ("echo x > $'\\056envrc'", Rule::Overwrite),
            ("echo x > ${EMPTY:-.envrc}", Rule::Overwrite),
            ("echo x > .vscode/\"tasks\".json", Rule::Overwrite),
            // Absolute, from home, from the working directory.
            ("echo x > /home/me/work/repo/.envrc", Rule::Overwrite),
            ("echo x > ~/work/repo/.envrc", Rule::Overwrite),
            ("echo x > $HOME/work/repo/.envrc", Rule::Overwrite),
            (
                "echo x > ${HOME}/work/repo/.vscode/tasks.json",
                Rule::Overwrite,
            ),
            ("echo x > ./.envrc", Rule::Overwrite),
            ("echo x > src/../.envrc", Rule::Overwrite),
            ("echo x > ../repo/.envrc", Rule::Overwrite),
            ("echo x > .//.envrc", Rule::Overwrite),
            ("echo x > .vscode//tasks.json", Rule::Overwrite),
            ("echo x > .vscode/./tasks.json", Rule::Overwrite),
            ("echo x > .vscode/x/../tasks.json", Rule::Overwrite),
            (
                "echo x > /home/me/work/./repo/.vscode/../.envrc",
                Rule::Overwrite,
            ),
            // Without case.
            ("echo x > .ENVRC", Rule::Overwrite),
            ("echo x > .VSCode/Tasks.JSON", Rule::Overwrite),
            ("echo x > .GitHub/Workflows/CI.yml", Rule::Overwrite),
            ("echo x > JENKINSFILE", Rule::Overwrite),
            ("echo x > lefthoo\u{212A}.yml", Rule::Overwrite),
            // A `cd` moves where a relative path is.
            ("cd .vscode && echo x > tasks.json", Rule::Overwrite),
            ("cd .github/workflows; echo x > ci.yml", Rule::Overwrite),
            ("cd .github && cp a workflows/ci.yml", Rule::Overwrite),
            ("cd .husky; sed -i s/a/b/ pre-commit", Rule::Overwrite),
            ("cd src && echo x > .envrc", Rule::Overwrite),
            (
                "cd /home/me/work/repo/.vscode && tee launch.json",
                Rule::Overwrite,
            ),
            // In a subshell, a group, a pipeline, a loop and a function.
            ("(echo x > .envrc)", Rule::Overwrite),
            ("{ echo x > .envrc; }", Rule::Overwrite),
            ("true && echo x > .envrc", Rule::Overwrite),
            ("cat a | tee .envrc", Rule::Overwrite),
            ("for f in a b; do echo x > .envrc; done", Rule::Overwrite),
            ("f() { echo x > .envrc; }; f", Rule::Overwrite),
            ("sh -c 'echo x > .envrc'", Rule::Overwrite),
            ("bash -c \"echo x > .vscode/tasks.json\"", Rule::Overwrite),
            ("cat <<'EOF' > .envrc\nx\nEOF", Rule::Overwrite),
            ("sudo tee .envrc", Rule::Overwrite),
            // Several at once.
            ("cp a b .husky/", Rule::Overwrite),
            ("tee a.txt .envrc", Rule::Overwrite),
        ],
    );
}

#[test]
fn a_mac_reads_its_links_and_its_fold() {
    check(
        Shell::Posix,
        &macos(),
        &[],
        &[
            ("echo x > .envrc", Rule::Overwrite),
            ("echo x > .ENVRC", Rule::Overwrite),
            ("echo x > .VSCODE/TASKS.JSON", Rule::Overwrite),
            ("echo x > /Users/me/dev/repo/.envrc", Rule::Overwrite),
            (
                "echo x > ~/dev/repo/.github/workflows/ci.yml",
                Rule::Overwrite,
            ),
            (
                "echo x > /System/Volumes/Data/Users/me/dev/repo/.envrc",
                Rule::Overwrite,
            ),
            (
                "echo x > '/Volumes/Macintosh HD/Users/me/dev/repo/.vscode/tasks.json'",
                Rule::Overwrite,
            ),
            (
                "echo x > '/Volumes/Macintosh HD - Data/Users/me/dev/repo/.husky/pre-commit'",
                Rule::Overwrite,
            ),
            (
                "echo x > ../../../../System/Volumes/Data/Users/me/dev/repo/.envrc",
                Rule::Overwrite,
            ),
            ("echo x > .v\u{17F}code/tasks.json", Rule::Overwrite),
            ("sed -i '' s/a/b/ .envrc", Rule::Overwrite),
            ("cp a .GitHub/Workflows/x.yml", Rule::Overwrite),
        ],
    );
    check(
        Shell::Posix,
        &macos(),
        &["cat .envrc", "rm .envrc", "echo x > Makefile"],
        &[],
    );
}

#[test]
fn a_write_beyond_the_workspace_keeps_its_own_words() {
    let paths = posix();
    for (line, reason) in [
        (
            "echo x > /home/me/other/.envrc",
            "writes to a file outside the workspace",
        ),
        (
            "echo x > ~/.vscode/tasks.json",
            "writes to a file outside the workspace",
        ),
        ("echo x > /etc/.envrc", "writes to a system folder"),
        ("echo x > .git/.envrc", "writes to the repository's history"),
        ("echo x > ~/.ssh/.envrc", "writes to your SSH keys"),
        ("echo x > ~/.bashrc", "writes to a shell startup file"),
    ] {
        let got = reasons(line, Shell::Posix, &paths);
        assert_eq!(got, [reason], "{line}");
    }
    // A temporary file is the agent's own.
    check(
        Shell::Posix,
        &paths,
        &[
            "echo x > /tmp/x/.envrc",
            "echo x > /tmp/.vscode/tasks.json",
            "cp a /var/tmp/x/.github/workflows/ci.yml",
            "echo x > $TMPDIR/.envrc",
        ],
        &[],
    );
}

#[test]
fn a_protected_path_and_the_history_keep_their_words() {
    let paths = posix().with_protected([Protected::folder(
        "/home/me/work/repo/.github",
        "the agent's rules",
    )]);
    assert_eq!(
        reasons("echo x > .github/workflows/ci.yml", Shell::Posix, &paths),
        ["writes to the agent's rules"]
    );
    assert_eq!(
        reasons("echo x > .vscode/tasks.json", Shell::Posix, &paths),
        ["writes to a file a tool runs on its own"]
    );
}

#[test]
fn a_file_lands_at_its_own_name_in_a_folder() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "cp a.txt .vscode/",
            "cp a.txt .husky-old/",
            "cp -r a .vscode-x",
            "cp lefthook.yml.bak sub/",
            "cp .envrc /tmp/",
            "mv Makefile sub/",
            "cp *.md docs/",
            "cp *.yaml conf/",
            "cp *.yml deploy/",
            "mv *.json dist/",
            "cp 'x*/.env' sub/",
        ],
        &[
            ("cp lefthook.yml sub/", Rule::Overwrite),
            ("cp a/lefthook.yml sub/", Rule::Overwrite),
            ("cp a/.envrc sub/", Rule::Overwrite),
            ("cp a/.envrc .", Rule::Overwrite),
            ("cp a/.envrc ./", Rule::Overwrite),
            ("cp a/tasks.json .vscode/", Rule::Overwrite),
            ("cp -t .vscode a/tasks.json", Rule::Overwrite),
            ("cp a/ci.yml .github/workflows/", Rule::Overwrite),
            ("cp a/pre-commit .husky", Rule::Overwrite),
            ("mv a/.envrc sub/", Rule::Overwrite),
            ("mv x/Jenkinsfile .", Rule::Overwrite),
            ("install a/.envrc sub/", Rule::Overwrite),
            ("ln -s a/.envrc sub/", Rule::Overwrite),
            ("ln -sf a/Jenkinsfile sub/", Rule::Overwrite),
            ("cp a/.envrc a/lefthook.yml sub/", Rule::Overwrite),
            ("cp .envrc .vscode/tasks.json sub/", Rule::Overwrite),
        ],
    );
}

#[test]
fn a_recursive_copy_can_replace_what_is_below() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "cp -r src dist",
            "cp -r src dist/",
            "cp -R src dist",
            "cp -a src build",
            "cp -r a/. src",
            "cp -r a .vscode-x",
            "cp -r a .githubx",
            "cp -r a .config",
            "rsync -a src/ dist/",
            "cp -r ~/.config dist/",
            "cp -r x /tmp/.github",
        ],
        &[
            ("cp -r a .github", Rule::Overwrite),
            ("cp -r a .github/", Rule::Overwrite),
            ("cp -r a/. .github", Rule::Overwrite),
            ("cp -R a .vscode", Rule::Overwrite),
            ("cp -a a .idea", Rule::Overwrite),
            ("cp -a a .cursor", Rule::Overwrite),
            ("cp -r a sub/.github", Rule::Overwrite),
            ("cp -r a .GitHub", Rule::Overwrite),
            ("cp -r a src/../.vscode", Rule::Overwrite),
            ("cp -r a ~/work/repo/.github", Rule::Overwrite),
            ("cp -r a .github/workflows", Rule::Overwrite),
            ("cp -r a .husky", Rule::Overwrite),
            ("cp --recursive a .github", Rule::Overwrite),
            ("cp -rt .github a", Rule::Overwrite),
            ("cp -r .github sub/", Rule::Overwrite),
            ("cp -r .vscode sub/", Rule::Overwrite),
            ("cp -r a/.github .", Rule::Overwrite),
            ("cp -r a/.github/ sub/", Rule::Overwrite),
            ("rsync -a a/ .github/", Rule::Overwrite),
            ("rsync -a a .vscode", Rule::Overwrite),
        ],
    );
}

#[test]
fn a_pattern_that_can_pick_one_is_one() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "sed -i s/a/b/ src/*.rs",
            "sed -i s/a/b/ *.md",
            "sed -i s/a/b/ *.json",
            "sed -i s/a/b/ src/*",
            "tee src/*",
            "echo x > src/*.txt",
            "sed -i s/a/b/ .vscode/e*",
            "sed -i s/a/b/ .github/*.md",
            "sed -i s/a/b/ lefthook.y",
            "sed -i s/a/b/ Makefile*",
            "sed -i s/a/b/ package.*",
        ],
        &[
            ("sed -i s/a/b/ .github/workflows/*", Rule::Overwrite),
            ("sed -i s/a/b/ .github/workflows/*.yml", Rule::Overwrite),
            ("echo x > .github/workflows/*", Rule::Overwrite),
            ("tee .husky/*", Rule::Overwrite),
            ("sed -i s/a/b/ .vscode/*.json", Rule::Overwrite),
            ("sed -i s/a/b/ .vscode/*", Rule::Overwrite),
            ("sed -i s/a/b/ .vscode/t*", Rule::Overwrite),
            ("sed -i s/a/b/ .vscode/?asks.json", Rule::Overwrite),
            ("sed -i s/a/b/ .vscode/[t]asks.json", Rule::Overwrite),
            ("sed -i s/a/b/ .github/*/ci.yml", Rule::Overwrite),
            ("sed -i s/a/b/ src/.vscode/*.json", Rule::Overwrite),
            ("sed -i s/a/b/ */.vscode/tasks.json", Rule::Overwrite),
            ("sed -i s/a/b/ *.yml", Rule::Overwrite),
            ("sed -i s/a/b/ lefthook.*", Rule::Overwrite),
            ("sed -i s/a/b/ Jenkins*", Rule::Overwrite),
            ("sed -i s/a/b/ */Jenkinsfile", Rule::Overwrite),
            ("sed -i s/a/b/ **/Jenkinsfile", Rule::Overwrite),
            ("cp a .vscode/*", Rule::Overwrite),
            ("cp a .github/workflows/*", Rule::Overwrite),
            // A wildcard that matches a leading dot where the shell says so.
            (
                "shopt -s dotglob; sed -i s/a/b/ */tasks.json",
                Rule::Overwrite,
            ),
            ("shopt -s dotglob; sed -i s/a/b/ *.json", Rule::Overwrite),
            ("shopt -s dotglob; tee .v*/launch.json", Rule::Overwrite),
            ("sed -i s/a/b/ .e*", Rule::Overwrite),
            ("sed -i s/a/b/ .?nvrc", Rule::Overwrite),
            ("echo x > .env*", Rule::Overwrite),
            ("echo x > .*/mcp.json", Rule::Overwrite),
            // A `..` after a wildcard part still climbs.
            ("sed -i s/a/b/ src/*/../../.envrc", Rule::Overwrite),
        ],
    );
}

#[test]
fn what_is_known_only_when_it_runs_is_risky_as_before() {
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[
            ("echo x > $F", Rule::Overwrite),
            ("echo x > \"$DIR/.envrc\"", Rule::Overwrite),
            ("echo x > $(pwd)/.envrc", Rule::Overwrite),
            ("echo x > ~root/.envrc", Rule::Overwrite),
            ("echo x > {.envrc,x}", Rule::Overwrite),
        ],
    );
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

#[test]
fn cmd_reads_every_spelling_windows_resolves_to_one_name() {
    check(
        Shell::Cmd,
        &windows(),
        &[
            "echo x > VSCODE~1\\EXTENS~1.JSO",
            "echo x > PROGRA~1\\x",
            "echo x > ENVRCX~1",
            "del VSCODE~1\\TASKS~1.JSO",
            "type VSCODE~1\\TASKS~1.JSO",
        ],
        &[
            ("echo x > .ENVRC", Rule::Overwrite),
            ("echo x > .Envrc.", Rule::Overwrite),
            ("echo x > .envrc.", Rule::Overwrite),
            ("echo x > .vscode/tasks.json", Rule::Overwrite),
            ("echo x > .vscode\\\\tasks.json", Rule::Overwrite),
            ("echo x > .VSCODE\\TASKS.JSON", Rule::Overwrite),
            ("echo x > .vscode.\\tasks.json", Rule::Overwrite),
            ("echo x > C:\\Users\\me\\dev\\repo\\.envrc", Rule::Overwrite),
            ("echo x > c:\\users\\ME\\dev\\repo\\.ENVRC", Rule::Overwrite),
            ("echo x > C:/Users/me/dev/repo/.envrc", Rule::Overwrite),
            ("echo x > \\Users\\me\\dev\\repo\\.envrc", Rule::Overwrite),
            (
                "echo x > \\\\?\\C:\\Users\\me\\dev\\repo\\.envrc",
                Rule::Overwrite,
            ),
            ("echo x > %USERPROFILE%\\dev\\repo\\.envrc", Rule::Overwrite),
            ("echo x > ~\\dev\\repo\\.envrc", Rule::Overwrite),
            ("echo x > C:.envrc", Rule::Overwrite),
            ("echo x > VSCODE~1\\TASKS~1.JSO", Rule::Overwrite),
            ("echo x > VSCODE~1\\tasks.json", Rule::Overwrite),
            ("echo x > .vscode\\TASKS~1.JSO", Rule::Overwrite),
            ("echo x > ENVRC~1", Rule::Overwrite),
            ("echo x > GITHUB~1\\WORKFL~1\\ci.yml", Rule::Overwrite),
            ("echo x > GITHUB~1\\workflows\\ci.yml", Rule::Overwrite),
            ("echo x > HUSKY~1\\pre-commit", Rule::Overwrite),
            ("echo x > GITLAB~1.YML", Rule::Overwrite),
            ("echo x > LEFTHO~1.YML", Rule::Overwrite),
            ("echo x > JENKIN~1", Rule::Overwrite),
            ("echo x > DEVCON~1\\devcontainer.json", Rule::Overwrite),
            ("echo x > VS1A2B~1\\tasks.json", Rule::Overwrite),
            ("echo x > src\\ENVRC~1", Rule::Overwrite),
            ("cd .vscode & echo x > tasks.json", Rule::Overwrite),
            ("cd .github\\workflows && copy a ci.yml", Rule::Overwrite),
            (
                "cd /d C:\\Users\\me\\dev\\repo\\.vscode && echo x > tasks.json",
                Rule::Overwrite,
            ),
            ("echo x>.envrc", Rule::Overwrite),
            ("echo x > .en^vrc", Rule::Overwrite),
            ("echo x > .vscode\\tasks.json 2>&1", Rule::Overwrite),
            ("cmd /c \"echo x > .envrc\"", Rule::Overwrite),
        ],
    );
}

#[test]
fn cmd_recursive_copies_and_patterns() {
    check(
        Shell::Cmd,
        &windows(),
        &[
            "xcopy /s /y a dist",
            "robocopy a dist /E",
            "copy a dist\\",
            "xcopy a .githubx\\ /s",
        ],
        &[
            ("xcopy /s /y a .github", Rule::Overwrite),
            ("xcopy /e /y a .vscode\\", Rule::Overwrite),
            ("robocopy a .github /E", Rule::Overwrite),
            ("robocopy a GITHUB~1 /E", Rule::Overwrite),
            ("xcopy /s a sub\\.github", Rule::Overwrite),
            ("copy a .vscode\\*", Rule::Overwrite),
            ("copy a .github\\workflows\\*.yml", Rule::Overwrite),
            ("copy lefthook.yml sub\\", Rule::Overwrite),
            ("copy a\\.envrc sub\\", Rule::Overwrite),
            ("copy a\\tasks.json .vscode\\", Rule::Overwrite),
            ("copy a\\ci.yml .github\\workflows\\", Rule::Overwrite),
            ("copy a *.yml", Rule::Overwrite),
            ("echo x > *.json", Rule::Overwrite),
        ],
    );
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

#[test]
fn powershell_reads_every_spelling_windows_resolves_to_one_name() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Set-Content VSCODE~1\\EXTENS~1.JSO x",
            "Set-Content PROGRA~1\\x x",
            "Set-Content ENVRCX~1 x",
            "Set-Content .envrcx x",
        ],
        &[
            ("Set-Content .ENVRC x", Rule::Overwrite),
            ("Set-Content .envrc. x", Rule::Overwrite),
            ("Set-Content '.envrc ' x", Rule::Overwrite),
            ("Set-Content .vscode/tasks.json x", Rule::Overwrite),
            ("Set-Content .VSCODE\\TASKS.JSON x", Rule::Overwrite),
            ("Set-Content C:\\Users\\me\\dev\\repo\\.envrc x", Rule::Overwrite),
            ("Set-Content c:\\users\\ME\\dev\\repo\\.ENVRC x", Rule::Overwrite),
            ("Set-Content C:/Users/me/dev/repo/.envrc x", Rule::Overwrite),
            ("Set-Content \\\\?\\C:\\Users\\me\\dev\\repo\\.envrc x", Rule::Overwrite),
            ("Set-Content ~\\dev\\repo\\.envrc x", Rule::Overwrite),
            ("Set-Content $HOME\\dev\\repo\\.envrc x", Rule::Overwrite),
            ("Set-Content $env:USERPROFILE\\dev\\repo\\.envrc x", Rule::Overwrite),
            ("Set-Content C:.envrc x", Rule::Overwrite),
            ("Set-Content VSCODE~1\\TASKS~1.JSO x", Rule::Overwrite),
            ("Set-Content VSCODE~1\\tasks.json x", Rule::Overwrite),
            ("Set-Content ENVRC~1 x", Rule::Overwrite),
            ("Set-Content GITHUB~1\\WORKFL~1\\ci.yml x", Rule::Overwrite),
            ("Set-Content HUSKY~1\\pre-commit x", Rule::Overwrite),
            ("Set-Content JENKIN~1 x", Rule::Overwrite),
            ("Set-Content VS1A2B~1\\tasks.json x", Rule::Overwrite),
            ("Set-Content .en`vrc x", Rule::Overwrite),
            ("Set-Content FileSystem::.envrc x", Rule::Overwrite),
            (
                "Set-Content Microsoft.PowerShell.Core\\FileSystem::C:\\Users\\me\\dev\\repo\\.envrc x",
                Rule::Overwrite,
            ),
            ("Set-Location .vscode; Set-Content tasks.json x", Rule::Overwrite),
            ("cd .github\\workflows; Out-File ci.yml", Rule::Overwrite),
            ("Push-Location .husky; Set-Content pre-commit x", Rule::Overwrite),
            ("& { Set-Content .envrc x }", Rule::Overwrite),
            ("pwsh -Command \"Set-Content .envrc x\"", Rule::Overwrite),
            (
                "powershell -NoProfile -Command \"'x' | Out-File .vscode\\tasks.json\"",
                Rule::Overwrite,
            ),
        ],
    );
}

#[test]
fn powershell_recursive_copies_and_patterns() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Copy-Item -Recurse a dist",
            "Copy-Item -Recurse a .githubx",
            "Set-Content src\\*.rs x",
            "Set-Content *.md x",
            "Set-Content src\\* x",
        ],
        &[
            ("Copy-Item -Recurse a .github", Rule::Overwrite),
            ("Copy-Item -Recurse a .vscode\\", Rule::Overwrite),
            ("Copy-Item -Recurse a GITHUB~1", Rule::Overwrite),
            ("Copy-Item -Recurse a sub\\.github", Rule::Overwrite),
            ("Copy-Item -Recurse .vscode sub\\", Rule::Overwrite),
            ("Copy-Item lefthook.yml sub\\", Rule::Overwrite),
            ("Copy-Item a\\.envrc sub\\", Rule::Overwrite),
            ("Copy-Item a\\tasks.json .vscode\\", Rule::Overwrite),
            ("Copy-Item a .vscode\\*", Rule::Overwrite),
            ("Set-Content .github\\workflows\\*.yml x", Rule::Overwrite),
            ("Set-Content .husky\\* x", Rule::Overwrite),
            ("Set-Content *.yml x", Rule::Overwrite),
            ("Set-Content *\\tasks.json x", Rule::Overwrite),
            ("Set-Content *.json x", Rule::Overwrite),
            ("Set-Content .e* x", Rule::Overwrite),
        ],
    );
}

#[test]
fn a_finding_names_the_path_as_written() {
    let paths = posix();
    let found: Assessment = classify("echo x > .Vscode/Tasks.json", Shell::Posix, &paths);
    let finding = &found.findings()[0];
    assert_eq!(finding.rule, Rule::Overwrite);
    assert_eq!(finding.reason, format!("writes to {WORDS}"));
    assert_eq!(finding.target.as_deref(), Some(".Vscode/Tasks.json"));
}

/// A destination that may be a file as well as a folder is judged as the
/// name it is: `cp .envrc .envrc.bak` is an everyday backup, and which of the
/// two a name is cannot be read. A folder that is one for certain (a trailing
/// separator, `.`, `..`, `-t`, several sources) is read as one.
#[test]
fn a_destination_that_may_be_a_file_is_not_read_as_a_folder() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "cp .envrc .envrc.bak",
            "cp .envrc backup",
            "cp -r .vscode backup",
            "cp a/lefthook.yml sub",
            "mv a/.envrc sub",
            "mv .vscode/tasks.json old-tasks",
            "ln -s a/.envrc link",
        ],
        &[
            ("cp a/.envrc sub/", Rule::Overwrite),
            ("cp a/.envrc sub/.", Rule::Overwrite),
            ("cp a/.envrc ..", Rule::Overwrite),
            ("cp -t sub a/.envrc", Rule::Overwrite),
            ("cp --target-directory=sub a/.envrc", Rule::Overwrite),
            ("cp -rt .vscode a", Rule::Overwrite),
            ("cp -t .vscode a/tasks.json", Rule::Overwrite),
            ("mv -t .vscode a/tasks.json", Rule::Overwrite),
            ("cp a/.envrc b/Jenkinsfile sub", Rule::Overwrite),
            ("mv a/.envrc a/other sub", Rule::Overwrite),
        ],
    );
}

/// Reading one only reads; writing one changes.
#[test]
fn the_effect_of_a_line_that_reads_one_is_reads_only() {
    check_effect(
        Shell::Posix,
        &posix(),
        Effect::ReadsOnly,
        &[
            "cat .envrc",
            "cat .vscode/tasks.json",
            "grep x .github/workflows/*",
            "head -n 3 .husky/pre-commit",
            "wc -l lefthook.yml",
            "diff .envrc .envrc.bak",
            "ls -la .github/workflows",
            "git diff -- .github/workflows/ci.yml",
        ],
    );
    check_effect(
        Shell::Posix,
        &posix(),
        Effect::Changes,
        &[
            "echo x > .envrc",
            "tee .vscode/tasks.json",
            "cp a .github/workflows/ci.yml",
            "sed -i s/a/b/ .husky/pre-commit",
            "cp -r a .github",
            "cat .envrc > .envrc.new",
        ],
    );
    check_effect(
        Shell::Cmd,
        &windows(),
        Effect::ReadsOnly,
        &[
            "type .envrc",
            "type .vscode\\tasks.json",
            "findstr x .github\\workflows\\ci.yml",
        ],
    );
    check_effect(
        Shell::PowerShell,
        &windows(),
        Effect::ReadsOnly,
        &[
            "Get-Content .envrc",
            "Select-String x .github\\workflows\\ci.yml",
        ],
    );
}

#[test]
fn more_ways_to_write_one() {
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[
            ("exec 3> .envrc", Rule::Overwrite),
            ("exec 3>>.vscode/tasks.json", Rule::Overwrite),
            ("echo x 1> .envrc", Rule::Overwrite),
            ("echo x >.envrc", Rule::Overwrite),
            ("echo x>.envrc", Rule::Overwrite),
            ("rsync a .envrc", Rule::Overwrite),
            ("rsync -a a/ .github/workflows/", Rule::Overwrite),
            ("rsync a b/Jenkinsfile", Rule::Overwrite),
            ("awk '{print}' a > .envrc", Rule::Overwrite),
            ("rm .envrc && echo x > .envrc", Rule::Overwrite),
            ("if true; then echo x > .envrc; fi", Rule::Overwrite),
            (
                "while read l; do echo $l >> .envrc; done < a",
                Rule::Overwrite,
            ),
            ("xargs -I{} cp {} .envrc < list", Rule::Overwrite),
            ("echo x | sudo -u me tee .envrc", Rule::Overwrite),
            ("env X=1 tee .envrc", Rule::Overwrite),
            ("command tee .envrc", Rule::Overwrite),
            ("nohup tee .envrc", Rule::Overwrite),
            ("time sh -c 'echo x > .envrc'", Rule::Overwrite),
        ],
    );
}

/// An empty folder is no code: making the folder a place is not a finding
/// (`mkdir -p .github/workflows` comes before every workflow), and what is
/// written into it is.
#[test]
fn making_a_folder_is_not_a_write_of_one() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "mkdir .github/workflows",
            "mkdir -p .github/workflows",
            "mkdir -p .husky",
            "mkdir .vscode",
            "mkdir -p .devcontainer",
            "mkdir -p .idea/runConfigurations",
            "mkdir -p src/.github/workflows",
            "mkdir -p .GitHub/Workflows",
            "mkdir -m 755 .husky",
        ],
        &[
            ("touch .envrc", Rule::Overwrite),
            ("touch .husky/pre-commit", Rule::Overwrite),
            ("mkfifo .envrc", Rule::Overwrite),
            (
                "mkdir -p .github/workflows && echo x > .github/workflows/ci.yml",
                Rule::Overwrite,
            ),
            ("mkdir -p /home/me/other/.husky", Rule::Overwrite),
        ],
    );
    check(
        Shell::Cmd,
        &windows(),
        &[
            "md .github\\workflows",
            "md .husky",
            "md GITHUB~1\\WORKFL~1",
            "md src\\.devcontainer",
        ],
        &[(
            "md .github\\workflows & echo x > .github\\workflows\\ci.yml",
            Rule::Overwrite,
        )],
    );
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "New-Item -ItemType Directory .github\\workflows",
            "New-Item -ItemType Directory -Path .husky -Force",
            "ni -ItemType Directory .github\\workflows",
            "New-Item -Path .devcontainer -ItemType Directory",
            "New-Item -ItemType dir .vscode",
        ],
        &[
            ("New-Item .envrc", Rule::Overwrite),
            (
                "New-Item -ItemType File .github\\workflows\\ci.yml",
                Rule::Overwrite,
            ),
            ("New-Item -ItemType File .husky", Rule::Overwrite),
        ],
    );
}

fn agent_windows() -> Paths {
    windows().with_protected([Protected::folder(
        r"C:\Users\me\dev\repo\.agent",
        "the agent's settings",
    )])
}

fn agent_posix() -> Paths {
    posix().with_protected([Protected::folder(
        "/home/me/work/repo/.agent",
        "the agent's settings",
    )])
}

/// A rename lands the file at the new name, in the source's folder: what a
/// `Move-Item` and an `mv` find, a rename finds too.
#[test]
fn powershell_renames_and_links_write_the_new_name() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Rename-Item a b",
            "Rename-Item old.txt new.txt",
            "Rename-Item -Path a.txt -NewName b.txt",
            "ren a.txt b.txt",
            "rni a.txt b.txt",
            "Rename-Item README.md Readme.md",
            "Rename-Item .vscode\\old.json other.json",
            "Rename-Item .vscode\\old.json extensions.json",
            "Rename-Item sub\\a .envrcx",
            "Rename-Item .envrc old.txt",
            "Rename-Item -Path .husky -NewName old-husky",
            "New-Item -Path .vscode -Name extensions.json",
            "New-Item -ItemType SymbolicLink -Path link -Value target",
            "New-Item -ItemType Directory -Path .github -Name workflows",
            "New-Item -ItemType Directory -Name .husky",
            "New-Item -Type Directory .githooks",
        ],
        &[
            ("Rename-Item a .envrc", Rule::Overwrite),
            ("Rename-Item -Path a -NewName .envrc", Rule::Overwrite),
            (
                "Rename-Item -LiteralPath a -NewName .envrc",
                Rule::Overwrite,
            ),
            ("Rename-Item -NewName .envrc -Path a", Rule::Overwrite),
            ("Rename-Item -Path:a -NewName:.envrc", Rule::Overwrite),
            ("ren a .envrc", Rule::Overwrite),
            ("rni a .envrc", Rule::Overwrite),
            ("REN a .ENVRC", Rule::Overwrite),
            ("Rename-Item a .envrc.", Rule::Overwrite),
            ("Rename-Item a ENVRC~1", Rule::Overwrite),
            ("Rename-Item a '.envrc '", Rule::Overwrite),
            ("Rename-Item sub\\a .envrc", Rule::Overwrite),
            (
                "Rename-Item C:\\Users\\me\\dev\\repo\\sub\\a .envrc",
                Rule::Overwrite,
            ),
            ("Rename-Item .vscode\\old.json tasks.json", Rule::Overwrite),
            ("Rename-Item .vscode\\old.json TASKS~1.JSO", Rule::Overwrite),
            (
                "Rename-Item .vscode\\old.json settings.json",
                Rule::Overwrite,
            ),
            (
                "Rename-Item .github\\workflows\\a.txt ci.yml",
                Rule::Overwrite,
            ),
            ("Rename-Item .github\\a workflows", Rule::Overwrite),
            ("Rename-Item old .husky", Rule::Overwrite),
            ("Rename-Item old Jenkinsfile", Rule::Overwrite),
            ("Rename-Item old proj.code-workspace", Rule::Overwrite),
            ("Rename-Item old mise.toml", Rule::Overwrite),
            (
                "Get-ChildItem *.txt | Rename-Item -NewName .envrc",
                Rule::Overwrite,
            ),
            // A name or a folder only known when it runs.
            ("Rename-Item a $name", Rule::Overwrite),
            ("Rename-Item $path .envrc", Rule::Overwrite),
            (
                "Get-ChildItem | Rename-Item -NewName { $_.Name + 'x' }",
                Rule::Overwrite,
            ),
            // Links.
            (
                "New-Item -ItemType SymbolicLink -Path .envrc -Value a",
                Rule::Overwrite,
            ),
            (
                "New-Item -ItemType HardLink -Path .envrc -Value a",
                Rule::Overwrite,
            ),
            (
                "New-Item -ItemType Junction -Path .husky -Value x",
                Rule::Overwrite,
            ),
            (
                "New-Item -Type SymbolicLink -Path .vscode\\tasks.json -Value a",
                Rule::Overwrite,
            ),
            ("ni -Type SymbolicLink .envrc -Value a", Rule::Overwrite),
            ("ni -ItemType SymbolicLink .envrc -Value a", Rule::Overwrite),
            (
                "New-Item -ItemType SymbolicLink -Name .envrc -Value a",
                Rule::Overwrite,
            ),
            (
                "New-Item -ItemType SymbolicLink -Path l -Value C:\\Users\\me\\.ssh",
                Rule::Overwrite,
            ),
            // `-Name` in the folder `-Path` names.
            ("New-Item -Path .vscode -Name tasks.json", Rule::Overwrite),
            ("New-Item -Name .envrc", Rule::Overwrite),
            (
                "New-Item -Path . -Name .envrc -ItemType File",
                Rule::Overwrite,
            ),
            (
                "New-Item -ItemType File -Path .github\\workflows -Name ci.yml",
                Rule::Overwrite,
            ),
            (
                "New-Item -Path .github\\workflows\\ -Name ci.yml",
                Rule::Overwrite,
            ),
            (
                "New-Item -Path GITHUB~1\\workflows -Name ci.yml",
                Rule::Overwrite,
            ),
        ],
    );
}

#[test]
fn cmd_renames_and_links_write_the_new_name() {
    check(
        Shell::Cmd,
        &windows(),
        &[
            "ren a b",
            "ren a.txt b.txt",
            "rename a.txt b.txt",
            "ren sub\\a .envrcx",
            "ren .vscode\\old.json extensions.json",
            "ren .envrc old.txt",
            "ren .husky old-husky",
            "mklink link target",
            "mklink /d link target",
            "mklink /h link target",
            "mklink /j link target",
        ],
        &[
            ("ren a .envrc", Rule::Overwrite),
            ("rename a .envrc", Rule::Overwrite),
            ("REN a .ENVRC", Rule::Overwrite),
            ("ren a .envrc.", Rule::Overwrite),
            ("ren a ENVRC~1", Rule::Overwrite),
            ("ren sub\\a .envrc", Rule::Overwrite),
            (
                "ren C:\\Users\\me\\dev\\repo\\sub\\a .envrc",
                Rule::Overwrite,
            ),
            ("ren .vscode\\old.json tasks.json", Rule::Overwrite),
            ("ren .vscode\\old.json settings.json", Rule::Overwrite),
            ("ren .github\\workflows\\a.txt ci.yml", Rule::Overwrite),
            ("ren old .husky", Rule::Overwrite),
            ("ren old Jenkinsfile", Rule::Overwrite),
            ("ren old %NAME%", Rule::Overwrite),
            ("ren %OLD% .envrc", Rule::Overwrite),
            ("cd .vscode & ren old.json tasks.json", Rule::Overwrite),
            ("mklink .envrc a", Rule::Overwrite),
            ("mklink /h .envrc a", Rule::Overwrite),
            ("mklink /H .envrc a", Rule::Overwrite),
            ("mklink /d .github\\workflows x", Rule::Overwrite),
            ("mklink /D .husky x", Rule::Overwrite),
            ("mklink /j .husky x", Rule::Overwrite),
            ("mklink /d /j .husky x", Rule::Overwrite),
            ("mklink .vscode\\tasks.json a", Rule::Overwrite),
            ("mklink /h .vscode/tasks.json a", Rule::Overwrite),
            ("mklink ENVRC~1 a", Rule::Overwrite),
            ("mklink /d link C:\\Users\\me\\.ssh", Rule::Overwrite),
            (
                "mklink /h link C:\\Users\\me\\.ssh\\id_rsa",
                Rule::Overwrite,
            ),
        ],
    );
}

#[test]
fn a_posix_rename_writes_the_new_name() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "rename .htm .html *.htm",
            "rename -n a b f",
            "rename -v old new old.txt",
            "rename -vn old new old.txt",
            "rename --verbose --no-act old new old.txt",
            "rename -o old new old.txt",
            "rename -s old new old.txt",
            "rename -i old new old.txt",
            "rename --no-overwrite --symlink --interactive old new old.txt",
            "rename old .envrcx old",
            "rename -- old new old",
            "rename -a o x old",
            "rename .htm .html a.htm b.htm",
            "ln -s a b",
            "ln a b",
        ],
        &[
            ("rename old .envrc old", Rule::Overwrite),
            ("rename -v old .envrc old", Rule::Overwrite),
            ("rename -a old .envrc old", Rule::Overwrite),
            ("rename --all old .envrc old", Rule::Overwrite),
            ("rename -vn old .envrc old", Rule::Overwrite),
            ("rename -- old .envrc old", Rule::Overwrite),
            ("rename old .envrc sub/old", Rule::Overwrite),
            ("rename old tasks.json .vscode/old", Rule::Overwrite),
            ("rename old .ENVRC old", Rule::Overwrite),
            ("rename old ci.yml .github/workflows/old", Rule::Overwrite),
            ("rename old .envrc a b old", Rule::Overwrite),
            // A `TO` only known when it runs, and a file too.
            ("rename old $NEW old", Rule::Overwrite),
            ("rename $FROM .envrc old", Rule::Overwrite),
            ("rename old .envrc $F", Rule::Overwrite),
            // An option that is not read changes what the new name is: an
            // option that takes the last one (`-l X Jenkinsfile X.d/X`).
            ("rename -l X Jenkinsfile X.d/X", Rule::Overwrite),
            ("rename -l X Jenkinsfile X.d/X", Rule::Unknown),
            ("rename -x old .envrc old", Rule::Overwrite),
            ("rename -x old .envrc old", Rule::Unknown),
            ("rename -V old .envrc old", Rule::Unknown),
            ("rename --last old .envrc old", Rule::Overwrite),
            ("rename --last old .envrc old", Rule::Unknown),
            ("rename -vx old new old.txt", Rule::Unknown),
            ("rename --verbose=1 old new old.txt", Rule::Unknown),
            ("rename --nopath old .envrc a/old", Rule::Overwrite),
            ("rename -d old .envrc a/old", Rule::Unknown),
            // Perl's `rename` takes an expression, which is code the guard
            // does not read: it is never worked out to a new name.
            ("rename 's/a/b/' x", Rule::Unknown),
            ("rename 's/a/b/' x", Rule::Overwrite),
            ("rename 's/x/@{[system q(rm -rf ~)]}/' x", Rule::Unknown),
            ("rename 's/x/@{[system q(rm -rf ~)]}/' x", Rule::Overwrite),
            ("rename 's/^tmp$/.envrc/' tmp", Rule::Unknown),
            ("rename 's/^tmp$/.envrc/' tmp", Rule::Overwrite),
            ("rename 's/old/.envrc/' sub/old", Rule::Overwrite),
            ("rename 's/x\\.txt$/.envrc/' x.txt", Rule::Overwrite),
            ("rename 's/a/.vscode\\/tasks.json/' a", Rule::Overwrite),
            ("rename 's|a|.vscode/tasks.json|' a", Rule::Overwrite),
            ("rename 's/\\.htm$/.html/' *.htm", Rule::Unknown),
            ("rename 's/ /_/g' *", Rule::Unknown),
            ("rename 's/foo/bar/' *", Rule::Unknown),
            ("rename 's/(.*)/$1/' a", Rule::Unknown),
            ("rename 's/a/b/i' x", Rule::Unknown),
            ("rename 's/a/b/e' x", Rule::Unknown),
            ("rename 'y/a-z/A-Z/' x", Rule::Unknown),
            ("rename 's/a+/.envrc/' a", Rule::Overwrite),
            ("rename 's/a/b/' $F", Rule::Overwrite),
            ("rename '$_ .= q(x)' a", Rule::Unknown),
            ("rename 'lc' a", Rule::Unknown),
            ("rename old new", Rule::Unknown),
            ("rename old new", Rule::Overwrite),
            ("rename -e 's/a/.envrc/' a", Rule::Unknown),
            ("rename -e 's/a/.envrc/' a", Rule::Overwrite),
            ("rename -e 's/a/b/' -e 's/b/.envrc/' a", Rule::Overwrite),
            ("rename --expr='s/a/.envrc/' a", Rule::Unknown),
            ("rename --expr='s/a/.envrc/' a", Rule::Overwrite),
            ("rename -n 's/a/.envrc/' a", Rule::Unknown),
            ("rename -n 's/a/.envrc/' a", Rule::Overwrite),
            ("rename -d 's/^x/.envrc/' a/x", Rule::Unknown),
            ("rename -d 's/^x/.envrc/' a/x", Rule::Overwrite),
            ("rename --nopath 's/^x/.envrc/' a/x", Rule::Unknown),
            ("rename --nopath 's/^x/.envrc/' a/x", Rule::Overwrite),
            ("rename -v 's/a/.envrc/g' a", Rule::Unknown),
            ("rename 's/^old/.git/' old/x", Rule::Overwrite),
            // Links without `-f`.
            ("ln a .envrc", Rule::Overwrite),
            ("ln -s a .envrc", Rule::Overwrite),
            ("ln -sr a .envrc", Rule::Overwrite),
            ("ln -T a .envrc", Rule::Overwrite),
            ("ln -s a .husky/pre-commit", Rule::Overwrite),
            ("ln -s a .github/workflows/ci.yml", Rule::Overwrite),
            ("ln -sf a .envrc", Rule::Overwrite),
            ("ln -sfn a .husky", Rule::Overwrite),
            ("ln -s a sub/.envrc", Rule::Overwrite),
        ],
    );
}

/// The same hole for the caller's own files: a rename or a link onto a
/// protected name is a write of it.
#[test]
fn a_rename_or_a_link_onto_a_protected_name_is_a_write_of_it() {
    check(
        Shell::PowerShell,
        &agent_windows(),
        &["Rename-Item a b", "ren a .agentx", "New-Item -Name .agentx"],
        &[
            ("Rename-Item a .agent", Rule::Overwrite),
            ("Rename-Item a .AGENT", Rule::Overwrite),
            ("Rename-Item -Path a -NewName .agent", Rule::Overwrite),
            ("ren a .agent", Rule::Overwrite),
            ("rni a AGENT~1", Rule::Overwrite),
            ("Rename-Item .\\a .agent", Rule::Overwrite),
            (
                "New-Item -ItemType SymbolicLink -Path .agent -Value a",
                Rule::Overwrite,
            ),
            (
                "New-Item -Name .agent -ItemType Junction -Value x",
                Rule::Overwrite,
            ),
            ("New-Item -Path .agent -Name rules", Rule::Overwrite),
            // What is renamed away is a delete of it, as `mv` is.
            ("Rename-Item .agent old", Rule::Delete),
            ("ren .agent old", Rule::Delete),
        ],
    );
    check(
        Shell::Cmd,
        &agent_windows(),
        &["ren a b", "ren a .agentx", "mklink link target"],
        &[
            ("ren a .agent", Rule::Overwrite),
            ("rename a .AGENT", Rule::Overwrite),
            ("ren a AGENT~1", Rule::Overwrite),
            ("ren .\\a .agent", Rule::Overwrite),
            ("mklink .agent a", Rule::Overwrite),
            ("mklink /d .agent a", Rule::Overwrite),
            ("mklink /j .agent\\rules a", Rule::Overwrite),
            ("ren .agent old", Rule::Delete),
        ],
    );
    check(
        Shell::Posix,
        &agent_posix(),
        &["rename old new old", "ln -s a b"],
        &[
            ("rename old .agent old", Rule::Overwrite),
            ("rename 's/^old$/.agent/' old", Rule::Overwrite),
            // What is renamed away is a delete of it, as `mv` is.
            ("rename .agent b .agent", Rule::Delete),
            ("rename 's/agent/b/' .agent", Rule::Delete),
            ("rename -x .agent b .agent", Rule::Delete),
            ("rename .agent b .agent/rules", Rule::Delete),
            ("ln -s a .agent", Rule::Overwrite),
            ("ln a .agent/rules", Rule::Overwrite),
            ("ln -sf a .AGENT", Rule::Overwrite),
        ],
    );
}
