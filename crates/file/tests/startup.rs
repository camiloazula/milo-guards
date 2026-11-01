//! Files a tool runs on its own (`.vscode/tasks.json`, `.envrc`, `.husky/*`,
//! `.github/workflows/*`...): a write to one, at any depth in a workspace
//! folder and however it is spelled, is `write_sensitive`; a read is safe;
//! and the files that only run when someone asks (`Makefile`, `justfile`,
//! `package.json`) stay safe. Every spelling a review could try is a row.

mod common;

use common::{exactly, macos, posix, risky, safe, windows};
use milo_guards_file::{judge, Access, Paths, Protected, Rule};

const WORDS: &str = "writes to a file a tool runs on its own";

/// Every place on the list, written as a file or as something below a folder.
const PLACES: &[&str] = &[
    ".vscode/settings.json",
    "proj.code-workspace",
    "a/b/My Project.code-workspace",
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
    ".idea/runConfigurations",
    ".idea/runConfigurations/Build.xml",
    ".envrc",
    ".husky",
    ".husky/pre-commit",
    ".husky/_/husky.sh",
    ".pre-commit-config.yaml",
    "lefthook.yml",
    "lefthook.yaml",
    ".lefthook.yml",
    ".lefthook.yaml",
    "lefthook-local.yml",
    ".lefthook-local.yml",
    ".github/workflows",
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
    ".devcontainer",
    ".devcontainer/devcontainer.json",
    ".devcontainer/Dockerfile",
    ".devcontainer/features/x/install.sh",
    ".devcontainer.json",
    // At any depth below a workspace folder, as a `.git` is.
    "src/.envrc",
    "a/b/c/.vscode/tasks.json",
    "packages/app/.github/workflows/ci.yml",
    "vendor/x/.husky/pre-commit",
    "docs/Jenkinsfile",
];

/// Files that run only when someone asks, and near misses of the names.
const EVERYDAY: &[&str] = &[
    "Makefile",
    "justfile",
    "package.json",
    "Cargo.toml",
    "build.rs",
    "scripts/build.sh",
    ".cargo/config.toml",
    ".env",
    ".envrcx",
    "x.envrc",
    ".envrc.bak",
    ".env/rc",
    "envrc",
    "tasks.json",
    "launch.json",
    "mcp.json",
    ".vscode/extensions.json",
    ".vscode/tasks.json.bak",
    ".vscodex/tasks.json",
    "vscode/tasks.json",
    ".vscode/x/tasks.json.d",
    ".cursor/rules/x.mdc",
    ".cursor/mcp.json.bak",
    ".idea/workspace.xml",
    ".idea/runConfigurationsx/x.xml",
    ".husky-old/pre-commit",
    ".huskyx",
    ".pre-commit-hooks.yaml",
    "lefthook.yml.bak",
    "my-lefthook.yml",
    "lefthook",
    ".github/dependabot.yml",
    ".github/ISSUE_TEMPLATE/bug.md",
    ".github/workflows-old/ci.yml",
    ".githubx/workflows/ci.yml",
    ".github/hooks/x",
    ".gitlab/issue_templates/x.md",
    ".gitlab-ci.yml.bak",
    "Jenkinsfile.md",
    ".devcontainerx/x",
    ".devcontainer.jsonx",
    "src/main.rs",
    "src/.gitignore",
];

fn writes<'a>(places: &[&'a str]) -> Vec<(&'a str, Rule)> {
    places
        .iter()
        .map(|place| (*place, Rule::WriteSensitive))
        .collect()
}

#[test]
fn a_write_to_a_file_a_tool_runs_on_its_own_is_a_finding() {
    risky(Access::Write, &posix(), &writes(PLACES));
    for place in PLACES {
        let found = judge(Access::Write, place, &posix());
        assert_eq!(found.findings().len(), 1, "{place}: {found:?}");
        assert_eq!(found.findings()[0].reason, WORDS, "{place}");
        assert_eq!(
            found.findings()[0].target.as_deref(),
            Some(*place),
            "{place}"
        );
    }
}

#[test]
fn a_read_of_one_stays_safe() {
    for paths in [posix(), macos(), windows()] {
        safe(Access::Read, &paths, PLACES);
    }
}

#[test]
fn the_files_that_only_run_when_asked_stay_safe() {
    for paths in [posix(), macos(), windows()] {
        safe(Access::Write, &paths, EVERYDAY);
        safe(Access::Read, &paths, EVERYDAY);
    }
}

#[test]
fn spellings_of_one_are_one_file() {
    risky(
        Access::Write,
        &posix(),
        &[
            // Absolute, from home, from the working directory.
            ("/home/me/work/repo/.envrc", Rule::WriteSensitive),
            ("~/work/repo/.envrc", Rule::WriteSensitive),
            ("~/work/repo/.vscode/tasks.json", Rule::WriteSensitive),
            ("./.envrc", Rule::WriteSensitive),
            ("src/../.envrc", Rule::WriteSensitive),
            ("../repo/.envrc", Rule::WriteSensitive),
            ("/home/me/work/./repo/.envrc", Rule::WriteSensitive),
            // Doubled and dotted separators, `..` inside the name's folder.
            (".//.envrc", Rule::WriteSensitive),
            (".vscode//tasks.json", Rule::WriteSensitive),
            (".vscode/./tasks.json", Rule::WriteSensitive),
            (".vscode/x/../tasks.json", Rule::WriteSensitive),
            (".github//workflows//ci.yml", Rule::WriteSensitive),
            (".github/workflows/", Rule::WriteSensitive),
            (".husky/", Rule::WriteSensitive),
            (".husky/.", Rule::WriteSensitive),
            (".github/x/../workflows/ci.yml", Rule::WriteSensitive),
            // Without case: a Mac and Windows ignore it.
            (".ENVRC", Rule::WriteSensitive),
            (".Envrc", Rule::WriteSensitive),
            (".VSCode/Tasks.JSON", Rule::WriteSensitive),
            (".GitHub/Workflows/CI.yml", Rule::WriteSensitive),
            (".HUSKY/pre-commit", Rule::WriteSensitive),
            ("JENKINSFILE", Rule::WriteSensitive),
            ("LeftHook.YML", Rule::WriteSensitive),
            (".PRE-COMMIT-CONFIG.YAML", Rule::WriteSensitive),
            (".Devcontainer/devcontainer.json", Rule::WriteSensitive),
            // The widest fold, as a Mac's file system reads it: the Kelvin
            // sign U+212A is a `k`.
            ("lefthoo\u{212A}.yml", Rule::WriteSensitive),
            ("src/.ENVRC", Rule::WriteSensitive),
        ],
    );
}

#[test]
fn a_mac_reads_the_same_names_by_its_links_and_its_fold() {
    let paths = macos();
    risky(
        Access::Write,
        &paths,
        &[
            ("/Users/me/dev/repo/.envrc", Rule::WriteSensitive),
            (
                "/Users/me/dev/repo/.vscode/tasks.json",
                Rule::WriteSensitive,
            ),
            (".ENVRC", Rule::WriteSensitive),
            (".VSCODE/TASKS.JSON", Rule::WriteSensitive),
            (".GITHUB/WORKFLOWS/ci.yml", Rule::WriteSensitive),
            (
                "/System/Volumes/Data/Users/me/dev/repo/.envrc",
                Rule::WriteSensitive,
            ),
            (
                "/Volumes/Macintosh HD/Users/me/dev/repo/.vscode/tasks.json",
                Rule::WriteSensitive,
            ),
            (
                "/Volumes/Macintosh HD - Data/Users/me/dev/repo/.husky/pre-commit",
                Rule::WriteSensitive,
            ),
            (
                "../../../../System/Volumes/Data/Users/me/dev/repo/.envrc",
                Rule::WriteSensitive,
            ),
            ("~/dev/repo/.envrc", Rule::WriteSensitive),
            // The long s is an `s` there.
            (".vſcode/tasks.json", Rule::WriteSensitive),
            ("Jenkinſfile", Rule::WriteSensitive),
        ],
    );
}

#[test]
fn windows_reads_every_spelling_it_resolves_to_one_name() {
    risky(Access::Write, &windows(), &writes(PLACES));
    let backslashed: Vec<String> = PLACES
        .iter()
        .map(|place| place.replace('/', "\\"))
        .collect();
    let rows: Vec<(&str, Rule)> = backslashed
        .iter()
        .map(|place| (place.as_str(), Rule::WriteSensitive))
        .collect();
    risky(Access::Write, &windows(), &rows);
    let paths = windows();
    risky(
        Access::Write,
        &paths,
        &[
            // Drive, case, separators, long path.
            (r"C:\Users\me\dev\repo\.envrc", Rule::WriteSensitive),
            (r"c:\users\ME\dev\repo\.ENVRC", Rule::WriteSensitive),
            ("C:/Users/me/dev/repo/.envrc", Rule::WriteSensitive),
            (r"\Users\me\dev\repo\.envrc", Rule::WriteSensitive),
            (r"\\?\C:\Users\me\dev\repo\.envrc", Rule::WriteSensitive),
            (
                r"//?/C:/Users/me/dev/repo/.vscode/tasks.json",
                Rule::WriteSensitive,
            ),
            (r"~\dev\repo\.envrc", Rule::WriteSensitive),
            ("C:.envrc", Rule::WriteSensitive),
            (r"c:.vscode\tasks.json", Rule::WriteSensitive),
            // Mixed and doubled separators, dots.
            (r".vscode/tasks.json", Rule::WriteSensitive),
            (r".vscode\/tasks.json", Rule::WriteSensitive),
            (r".vscode\\tasks.json", Rule::WriteSensitive),
            (r".vscode\.\tasks.json", Rule::WriteSensitive),
            (r".vscode\x\..\tasks.json", Rule::WriteSensitive),
            (r"src\..\.envrc", Rule::WriteSensitive),
            (r".github\workflows\", Rule::WriteSensitive),
            // Trailing dots and spaces a name loses on Windows.
            (".envrc.", Rule::WriteSensitive),
            (".envrc ", Rule::WriteSensitive),
            (".envrc. .", Rule::WriteSensitive),
            (r".vscode.\tasks.json", Rule::WriteSensitive),
            (r".vscode\tasks.json.", Rule::WriteSensitive),
            (r".vscode\tasks.json ", Rule::WriteSensitive),
            (r".github.\workflows.\ci.yml", Rule::WriteSensitive),
            // Case.
            (r".VSCODE\TASKS.JSON", Rule::WriteSensitive),
            (r".GitHub\Workflows\CI.yml", Rule::WriteSensitive),
            ("JENKINSFILE", Rule::WriteSensitive),
            // 8.3 short names, whole or in part.
            (r"VSCODE~1\TASKS~1.JSO", Rule::WriteSensitive),
            (r"VSCODE~1\tasks.json", Rule::WriteSensitive),
            (r".vscode\TASKS~1.JSO", Rule::WriteSensitive),
            (r"vscode~1\launch~1.jso", Rule::WriteSensitive),
            (r"VSCODE~1\MCP~1.JSO", Rule::WriteSensitive),
            (r"VSCODE~1\MCP.JSON", Rule::WriteSensitive),
            ("ENVRC~1", Rule::WriteSensitive),
            ("envrc~1", Rule::WriteSensitive),
            (r"GITHUB~1\WORKFL~1\ci.yml", Rule::WriteSensitive),
            (r"GITHUB~1\workflows\ci.yml", Rule::WriteSensitive),
            (r"GITHUB~1\ACTIONS\x\action.yml", Rule::WriteSensitive),
            (r"GITHUB~1\ACTION~1\x\action.yml", Rule::WriteSensitive),
            (r"HUSKY~1\pre-commit", Rule::WriteSensitive),
            ("PRE-CO~1.YAM", Rule::WriteSensitive),
            ("GITLAB~1.YML", Rule::WriteSensitive),
            ("LEFTHO~1.YML", Rule::WriteSensitive),
            ("JENKIN~1", Rule::WriteSensitive),
            ("AZURE-~1.YML", Rule::WriteSensitive),
            (r"DEVCON~1\devcontainer.json", Rule::WriteSensitive),
            ("DEVCON~1.JSO", Rule::WriteSensitive),
            (r"CIRCLE~1\config.yml", Rule::WriteSensitive),
            // The form a name hashes to once short names collide.
            (r"VS1A2B~1\tasks.json", Rule::WriteSensitive),
            ("EN1A2B~1", Rule::WriteSensitive),
            // Beside the repository's history and under another folder.
            (r"src\ENVRC~1", Rule::WriteSensitive),
            (
                r"packages\app\GITHUB~1\workflows\ci.yml",
                Rule::WriteSensitive,
            ),
        ],
    );
}

#[test]
fn windows_keeps_the_everyday_names_safe() {
    let paths = windows();
    safe(
        Access::Write,
        &paths,
        &[
            r"VSCODE~1\EXTENS~1.JSO",
            r".vscode\extensions.json",
            r"GITHUB~1\ISSUE_~1\bug.md",
            r"GITHUB~1\DEPEND~1.YML",
            r"GITHUB~1\workflows-old\x",
            "ENVRCX~1",
            "MAKEFI~1",
            "PACKAG~1.JSO",
            "JUSTFI~1",
            r"src\main.rs",
            r".github\hooks\x",
            r"C:\Users\me\dev\repo\Makefile",
            r"C:\Users\me\dev\repo\package.json",
            r"\\?\C:\Users\me\dev\repo\justfile",
        ],
    );
    // A short name of another kind of name is a plain name.
    safe(
        Access::Write,
        &paths,
        &[r"PROGRA~1\x", "VSCODE~X", "ENVRC~"],
    );
}

#[test]
fn what_windows_cannot_read_to_a_name_stays_unreadable() {
    exactly(
        Access::Write,
        &windows(),
        &[
            (r".vscode\tasks.json::$DATA", &[Rule::Unreadable]),
            (r".envrc:stream", &[Rule::Unreadable]),
            (r".github\workflows\x \ci.yml", &[Rule::Unreadable]),
            (r"D:.envrc", &[Rule::Unreadable]),
        ],
    );
}

#[test]
fn only_the_workspaces_own_paths_are_found() {
    let paths = posix();
    exactly(
        Access::Write,
        &paths,
        &[
            // Beyond the workspace the place already says so, and nothing is
            // added to it.
            ("/home/me/other/.envrc", &[Rule::WriteOutside]),
            ("/home/me/.vscode/tasks.json", &[Rule::WriteOutside]),
            // `~` is also a folder named `~` in the working directory, which
            // is the workspace's own, and that reading is judged too.
            ("~/.envrc", &[Rule::WriteOutside, Rule::WriteSensitive]),
            ("/etc/.envrc", &[Rule::WriteOutside]),
            (
                "/home/me/work/.github/workflows/ci.yml",
                &[Rule::WriteOutside],
            ),
            // A temporary file is the agent's own.
            ("/tmp/x/.envrc", &[]),
            ("/tmp/.vscode/tasks.json", &[]),
            ("/var/tmp/x/.github/workflows/ci.yml", &[]),
            // The repository's history, a hook and a key keep their words.
            (".git/.envrc", &[Rule::WriteSensitive]),
            ("vendor/x/.git/hooks/.envrc", &[Rule::WriteSensitive]),
        ],
    );
    for (path, reason) in [
        (".git/.envrc", "writes to the repository's history"),
        (
            "vendor/x/.git/hooks/pre-commit",
            "writes to a git hook, which runs code",
        ),
    ] {
        let found = judge(Access::Write, path, &paths);
        assert_eq!(found.findings().len(), 1, "{path}: {found:?}");
        assert_eq!(found.findings()[0].reason, reason, "{path}");
    }
}

#[test]
fn a_protected_path_keeps_its_own_words() {
    let paths = posix().with_protected([
        Protected::file(
            "/home/me/work/repo/.vscode/tasks.json",
            "the agent's settings",
        ),
        Protected::folder("/home/me/work/repo/.github/workflows", "the agent's rules"),
    ]);
    exactly(
        Access::Write,
        &paths,
        &[
            (".vscode/tasks.json", &[Rule::WriteProtected]),
            (".github/workflows/ci.yml", &[Rule::WriteProtected]),
            // Not protected: one finding of its own.
            (".vscode/launch.json", &[Rule::WriteSensitive]),
            (".github/actions/x/action.yml", &[Rule::WriteSensitive]),
        ],
    );
    let found = judge(Access::Write, ".github/workflows/ci.yml", &paths);
    assert_eq!(found.findings()[0].reason, "writes to the agent's rules");
}

#[test]
fn a_write_in_a_workspace_that_is_the_home_directory_is_found_too() {
    let paths = Paths::new("/home/me", "/home/me", ["/home/me"]);
    exactly(
        Access::Write,
        &paths,
        &[
            (".envrc", &[Rule::WriteSensitive]),
            ("proj/.vscode/tasks.json", &[Rule::WriteSensitive]),
            ("~/proj/.github/workflows/ci.yml", &[Rule::WriteSensitive]),
            // What the home directory holds keeps its own words.
            (".bashrc", &[Rule::WriteSensitive]),
            (".ssh/id_rsa", &[Rule::WriteSensitive]),
            ("proj/Makefile", &[]),
        ],
    );
    let found = judge(Access::Write, ".bashrc", &paths);
    assert_eq!(found.findings()[0].reason, "writes to a shell startup file");
}

#[test]
fn a_bracket_class_inside_the_workspace_is_read_as_a_pattern() {
    risky(
        Access::Write,
        &posix(),
        &[
            // A class that can pick one of the places is one.
            (".vscode/[t]asks.json", Rule::WriteSensitive),
            ("[.]vscode/tasks.json", Rule::WriteSensitive),
            (".github/workflows/[a-z].yml", Rule::WriteSensitive),
        ],
    );
    safe(
        Access::Write,
        &posix(),
        &["app/[id]/page.tsx", "src/routes/[slug]/+page.svelte"],
    );
}

#[test]
fn a_share_or_a_device_is_not_the_workspaces_own() {
    exactly(
        Access::Write,
        &windows(),
        &[
            (
                r"\\srv\share\.envrc",
                &[Rule::WriteOutside, Rule::NetworkShare],
            ),
            (r"\\.\C:\Users\me\dev\repo\.envrc", &[Rule::WriteOutside]),
            (
                r"\\?\GLOBALROOT\Device\x\.envrc",
                &[Rule::WriteOutside, Rule::NetworkShare],
            ),
        ],
    );
    // A workspace on a share: its own paths are found, and the share is the
    // caller's own.
    let paths = Paths::new(r"\\srv\share\repo", r"C:\Users\me", [r"\\srv\share\repo"]);
    exactly(
        Access::Write,
        &paths,
        &[
            (r"\\srv\share\repo\.envrc", &[Rule::WriteSensitive]),
            (
                r"//srv/share/repo/.vscode/tasks.json",
                &[Rule::WriteSensitive],
            ),
            (
                r"\\?\UNC\srv\share\repo\.github\workflows\ci.yml",
                &[Rule::WriteSensitive],
            ),
            (r".github\workflows\ci.yml", &[Rule::WriteSensitive]),
            (r"\\srv\share\repo\Makefile", &[]),
        ],
    );
}
