//! Paths the caller protects, in every shell. A protected path is its own
//! whatever the line does to it: a delete, a write or a permission change of
//! it is a finding, a read is not. It wins over the workspace it is in, a
//! folder that holds one cannot go whole, a copy, move or link into its
//! folder by its name replaces it, names compare without case, and only a
//! protected folder has something below its name. One test for each set of
//! protected paths, with a table for each shell.

mod common;

use common::{check, classify, macos, posix, windows};
use milo_guards_shell::{Paths, Protected, Rule, Shell};

const W: &str = "the agent's settings";

/// The first finding of each row's line is the row's rule, with the row's
/// reason; the rows that are not are named together.
fn first_findings(shell: Shell, paths: &Paths, rows: &[(&str, Rule, &str)]) {
    findings_are(shell, paths, rows, 1);
}

/// Some finding of each row's line is the row's rule, with the row's reason;
/// the rows that are not are named together.
fn some_findings(shell: Shell, paths: &Paths, rows: &[(&str, Rule, &str)]) {
    findings_are(shell, paths, rows, usize::MAX);
}

/// One of the first `first` findings of each row's line is the row's rule,
/// with the row's reason.
fn findings_are(shell: Shell, paths: &Paths, rows: &[(&str, Rule, &str)], first: usize) {
    let wrong: Vec<String> = rows
        .iter()
        .filter_map(|(line, rule, reason)| {
            let assessment = classify(line, shell, paths);
            let found = assessment
                .findings()
                .iter()
                .take(first)
                .any(|finding| finding.rule == *rule && finding.reason == *reason);
            (!found).then(|| {
                format!(
                    "{line}: wanted {rule:?} \"{reason}\", got {:?}",
                    assessment.findings()
                )
            })
        })
        .collect();
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// A folder in the home directory.
fn home_folder() -> Paths {
    posix().with_protected([Protected::folder("/home/me/.agent", W)])
}

/// The same folder, spelled with a trailing slash.
fn home_folder_with_a_slash() -> Paths {
    posix().with_protected([Protected::folder("/home/me/.agent/", W)])
}

/// A folder and a file in the workspace.
fn workspace_folder_and_file() -> Paths {
    posix().with_protected([
        Protected::folder("/home/me/work/repo/.agent", W),
        Protected::file("/home/me/work/repo/conf/app/x.yaml", W),
    ])
}

/// A folder and a file at the top of the workspace.
fn workspace_folder_and_settings() -> Paths {
    posix().with_protected([
        Protected::folder("/home/me/work/repo/.agent", W),
        Protected::file("/home/me/work/repo/settings.yaml", W),
    ])
}

/// A folder in the workspace.
fn workspace_folder() -> Paths {
    posix().with_protected([Protected::folder("/home/me/work/repo/.agent", W)])
}

/// A file two folders down in the workspace.
fn workspace_file() -> Paths {
    posix().with_protected([Protected::file("/home/me/work/repo/conf/app/x.yaml", W)])
}

/// A folder at the top of the workspace.
fn workspace_cfg() -> Paths {
    posix().with_protected([Protected::folder("/home/me/work/repo/cfg", W)])
}

/// A file two folders down and a folder at the top of the workspace.
fn workspace_file_and_cfg() -> Paths {
    posix().with_protected([
        Protected::file("/home/me/work/repo/conf/app/x.yaml", W),
        Protected::folder("/home/me/work/repo/cfg", W),
    ])
}

/// The folder at the top of the workspace, marked as a file.
fn cfg_marked_as_a_file() -> Paths {
    posix().with_protected([Protected::file("/home/me/work/repo/cfg", W)])
}

/// The file two folders down, marked as a folder.
fn file_marked_as_a_folder() -> Paths {
    posix().with_protected([Protected::folder("/home/me/work/repo/conf/app/x.yaml", W)])
}

/// A file in a temporary folder.
fn temporary_file() -> Paths {
    posix().with_protected([Protected::file("/tmp/state/x", W)])
}

/// A file and a folder in a temporary folder.
fn temporary_file_and_folder() -> Paths {
    posix().with_protected([
        Protected::file("/tmp/state/x", W),
        Protected::folder("/tmp/st", W),
    ])
}

/// A folder in the workspace on a Mac.
fn mac_folder() -> Paths {
    macos().with_protected([Protected::folder("/Users/me/dev/repo/.agent", W)])
}

/// A file two folders down in the workspace on a Mac.
fn mac_file() -> Paths {
    macos().with_protected([Protected::file("/Users/me/dev/repo/conf/app/x.yaml", W)])
}

/// A folder in the home directory and one in the workspace on Windows.
fn windows_home_and_workspace_folders() -> Paths {
    windows().with_protected([
        Protected::folder(r"C:\Users\me\.agent", W),
        Protected::folder(r"C:\Users\me\dev\repo\.agent", W),
    ])
}

/// A folder and a file in the workspace on Windows.
fn windows_folder_and_file() -> Paths {
    windows().with_protected([
        Protected::folder(r"C:\Users\me\dev\repo\.agent", W),
        Protected::file(r"C:\Users\me\dev\repo\conf\app\x.yaml", W),
    ])
}

/// A file two folders down in the workspace on Windows.
fn windows_file() -> Paths {
    windows().with_protected([Protected::file(r"C:\Users\me\dev\repo\conf\app\x.yaml", W)])
}

/// A folder on a share.
fn share_folder() -> Paths {
    windows().with_protected([Protected::folder(r"\\srv\share\.agent", W)])
}

/// A delete, a write or a permission change of a protected folder in the
/// home directory is a finding, however the line spells it, and a read is
/// not; the finding says so in the caller's words, and a pattern that picks
/// it says so, not that it is the home directory.
#[test]
fn a_protected_folder_in_the_home_directory() {
    let paths = home_folder();
    check(
        Shell::Posix,
        &paths,
        &[
            "cat ~/.agent/config.yaml",
            "ls -la ~/.agent",
            "grep -rn model ~/.agent/rules",
            "cp ~/.agent/config.yaml backup.yaml",
            "cd ~/.agent && ls",
            "rm -rf target",
            "echo x > notes.md",
            "sed -n s/a/b/p ~/.agent/rules",
        ],
        &[
            ("rm -rf ~/.agent", Rule::Delete),
            ("rm ~/.agent/config.yaml", Rule::Delete),
            ("rm -rf $HOME/.agent", Rule::Delete),
            ("rm -rf /home/me/.agent/rules", Rule::Delete),
            ("rm ~/.agent/*.yaml", Rule::Delete),
            ("cd ~/.agent && rm config.yaml", Rule::Delete),
            ("mv ~/.agent/config.yaml /tmp/x", Rule::Delete),
            ("find ~/.agent -delete", Rule::Delete),
            ("ls ~/.agent/*.yaml | xargs rm", Rule::Delete),
            ("echo x > ~/.agent/config.yaml", Rule::Overwrite),
            ("echo x >> ~/.agent/rules", Rule::Overwrite),
            ("sed -i s/a/b/ ~/.agent/rules", Rule::Overwrite),
            ("cp notes.md ~/.agent/config.yaml", Rule::Overwrite),
            ("mv notes.md ~/.agent/rules", Rule::Overwrite),
            ("tee ~/.agent/rules < notes.md", Rule::Overwrite),
            ("chmod 777 ~/.agent/config.yaml", Rule::Permissions),
            // Other spellings of the folder.
            ("rm ~/.agent/", Rule::Delete),
            ("rm -rf ~/.agent/.", Rule::Delete),
            ("rm -rf ~//.agent", Rule::Delete),
            ("rm -rf ~/./.agent", Rule::Delete),
            ("rm -rf ~/x/../.agent", Rule::Delete),
            ("rm -rf ~/.a*", Rule::Delete),
            ("rm -rf ~/.agen?", Rule::Delete),
            ("rm -rf ~/.agent*", Rule::Delete),
            ("rm -rf /home/me/../me/.agent", Rule::Delete),
            ("rm -rf $HOME/.agent/", Rule::Delete),
            ("rm -rf ${HOME}/.agent", Rule::Delete),
            ("rm -rf ~me/.agent", Rule::Delete),
            ("rm -rf ~", Rule::Delete),
            ("rm -rf ~/*", Rule::Delete),
        ],
    );
    // A finding of each says so in the caller's words.
    some_findings(
        Shell::Posix,
        &paths,
        &[
            (
                "rm ~/.agent/config.yaml",
                Rule::Delete,
                "deletes the agent's settings",
            ),
            (
                "rm -rf ~/.agent",
                Rule::Delete,
                "deletes the agent's settings",
            ),
            (
                "mv ~/.agent/rules /tmp/x",
                Rule::Delete,
                "moves the agent's settings",
            ),
            (
                "echo x > ~/.agent/config.yaml",
                Rule::Overwrite,
                "writes to the agent's settings",
            ),
            (
                "sed -i s/a/b/ ~/.agent/rules",
                Rule::Overwrite,
                "edits the agent's settings",
            ),
            (
                "chmod 777 ~/.agent/rules",
                Rule::Permissions,
                "changes permissions of the agent's settings",
            ),
        ],
    );
    first_findings(
        Shell::Posix,
        &paths,
        &[
            // A sibling of the protected folder is not it.
            (
                "rm ~/.agent-old/x",
                Rule::Delete,
                "deletes a path outside the workspace",
            ),
            // A pattern that picks it.
            (
                "rm -rf ~/.agent*",
                Rule::Delete,
                "deletes the agent's settings",
            ),
            ("rm -rf ~/.a*", Rule::Delete, "deletes the agent's settings"),
            (
                "rm -rf ~/.agent/",
                Rule::Delete,
                "deletes the agent's settings",
            ),
            ("rm -rf ~", Rule::Delete, "deletes your home directory"),
        ],
    );
}

#[test]
fn a_protected_folder_spelled_with_a_trailing_slash() {
    check(
        Shell::Posix,
        &home_folder_with_a_slash(),
        &[],
        &[
            ("rm ~/.agent/x", Rule::Delete),
            ("rm ~/.agentx", Rule::Delete),
        ],
    );
}

/// A protected path inside the workspace is protected, not inside it; the
/// rest of the workspace stays the agent's own.
#[test]
fn a_protected_path_in_the_workspace_wins_over_the_workspace() {
    check(
        Shell::Posix,
        &workspace_folder_and_settings(),
        &[
            "rm src/main.rs",
            "rm -rf target",
            "rm -f *.log",
            "rm src/set*",
            "echo x > src/settings.yaml",
            "sed -i s/a/b/ src/lib.rs",
            "cat .agent/rules",
            "cd src && rm -f ../target/x.o",
        ],
        &[
            ("rm .agent/rules", Rule::Delete),
            ("rm -rf .agent", Rule::Delete),
            ("rm -rf ./src/../.agent", Rule::Delete),
            ("rm settings.yaml", Rule::Delete),
            ("rm set*", Rule::Delete),
            ("rm *.yaml", Rule::Delete),
            ("cd .agent && rm rules", Rule::Delete),
            ("cd src && rm ../.agent/rules", Rule::Delete),
            ("echo x > .agent/rules", Rule::Overwrite),
            ("echo x > settings.yaml", Rule::Overwrite),
            ("sed -i s/a/b/ .agent/rules", Rule::Overwrite),
            ("chmod 600 .agent/rules", Rule::Permissions),
            // The workspace itself is still a finding.
            ("rm -rf *", Rule::Delete),
        ],
    );
}

/// A folder and a file in the workspace, in every spelling, and the folders
/// that hold them.
#[test]
fn a_protected_folder_and_file_in_the_workspace() {
    check(
        Shell::Posix,
        &workspace_folder_and_file(),
        &["rm .agentx/rules", "rm *.rs", "rm src/*.rs", "rm -rf src/*"],
        &[
            ("rm -rf .AGENT/rules", Rule::Delete),
            ("rm -rf .Agent", Rule::Delete),
            ("rm -rf ./.agent/", Rule::Delete),
            ("rm -rf .agent/.", Rule::Delete),
            ("rm -rf conf", Rule::Delete),
            ("rm -rf conf/app", Rule::Delete),
            ("mv conf /tmp/x", Rule::Delete),
            ("rm -rf **/x.yaml", Rule::Delete),
            ("rm conf/**/x.yaml", Rule::Delete),
            ("rm -rf c*", Rule::Delete),
            ("rm */*/x.yaml", Rule::Delete),
            ("rm conf/*/x.yaml", Rule::Delete),
            ("shopt -s dotglob; rm -rf .ag*", Rule::Delete),
            ("shopt -s dotglob; rm -rf *gent", Rule::Delete),
            ("cd conf && rm -rf app", Rule::Delete),
            ("cd conf/app && rm *", Rule::Delete),
            ("cd .agent && rm *", Rule::Delete),
            ("cd .agent && rm -rf ./*", Rule::Delete),
            ("rm .agent/*", Rule::Delete),
            ("rm -rf ./.agent/*", Rule::Delete),
            ("echo x > .agent/new", Rule::Overwrite),
            ("rm .agen[t]/rules", Rule::Delete),
            ("rm .agent/../.agent/rules", Rule::Delete),
            ("rm -rf .", Rule::Delete),
            ("rm -rf *", Rule::Delete),
        ],
    );
}

/// Case and near names of a protected folder in the workspace.
#[test]
fn a_protected_folder_in_the_workspace_and_names_near_it() {
    check(
        Shell::Posix,
        &workspace_folder(),
        &[
            "rm -rf .Agents",
            "rm -rf .AGENTS/x",
            "rm -rf .agent2",
            "rm -rf src/.agent",
            "rm -rf **/rules",
            "rm -rf **/*.rs",
        ],
        &[
            ("rm -rf /HOME/ME/work/repo/.agent", Rule::Delete),
            ("rm -rf **/.agent", Rule::Delete),
        ],
    );
}

/// A folder that holds a protected file is protected when it would be
/// harmless, so the whole folder cannot go; a write into it, and work beside
/// the protected file, stay the agent's own. A copy, move or link into the
/// file's folder by its name replaces it, and so can a recursive copy or
/// mirror into a folder that holds it; a copy elsewhere, or under another
/// name, does not. Only a folder has something below its name.
#[test]
fn a_protected_file_in_the_workspace() {
    let paths = workspace_file();
    check(
        Shell::Posix,
        &paths,
        &[
            "touch conf/new.txt",
            "rm conf/other.txt",
            "rm -rf src",
            "rm conf/app/y.yaml",
            "cp a.txt conf/",
            "cp a.txt conf/app",
            "mkdir -p conf/app",
            "echo x > conf/new.txt",
            "cat conf/app/x.yaml",
            "ls conf",
            "cd conf && ls",
            "cd conf && touch new.txt",
            "rm -f *.log conf/*.log",
            "rm -rf conf/o*",
            "rm -rf **/y.yaml",
            "rm -rf **/*.rs",
            "rm **/*.pyc",
            "rm -rf src/**/z",
            // A copy elsewhere, or under another name.
            "cp a.txt conf/app/",
            "cp a.txt conf",
            "cp new/y.yaml conf/app",
            "cp -t conf/app y.yaml",
            "cp *.txt conf/app/",
            "cp *.yaml conf/",
            "install -m 644 a.txt conf/app/",
            "mv a.txt conf/app/",
            "ln -s other/y.yaml conf/app/",
            "cp -r src/. dist/",
            "cp -r src dist",
            "cp -a src dist/",
            "rsync -a src/ dist/",
            "cp $f conf/",
            "cp -r a.txt src/",
            "cp -r src conf2",
            "cp -r src conf/app/new",
            r"find . -name '*.o' -exec cp {} dist/ \;",
            // A recursive copy into a folder that holds no protected path.
            "cp -r other/. dist",
            "cp -r a.txt conf/other",
            "rsync -a src/ conf/other/",
            "rsync src/ conf/",
            "cp -r conf/other conf/new",
        ],
        &[
            ("rm -rf conf", Rule::Delete),
            ("rm -rf conf/", Rule::Delete),
            ("rm -rf ./conf/app", Rule::Delete),
            ("rm -rf conf/app", Rule::Delete),
            ("rm conf/app/x.yaml", Rule::Delete),
            ("cd conf && rm -rf app", Rule::Delete),
            ("cd conf/app && rm x.yaml", Rule::Delete),
            ("mv conf /tmp/x", Rule::Delete),
            ("mv conf/app /tmp/x", Rule::Delete),
            ("rm -rf c*", Rule::Delete),
            ("rm -rf conf/a*", Rule::Delete),
            ("rm -rf **/x.yaml", Rule::Delete),
            ("rm conf/**/x.yaml", Rule::Delete),
            ("rm -rf conf/**", Rule::Delete),
            ("rm -rf */*/x.yaml", Rule::Delete),
            ("find conf -delete", Rule::Delete),
            ("ls conf | xargs rm -rf", Rule::Delete),
            ("echo x > conf/app/x.yaml", Rule::Overwrite),
            ("cp a.txt conf/app/x.yaml", Rule::Overwrite),
            ("cp a.txt conf/app/x*", Rule::Overwrite),
            ("chmod -R 777 conf", Rule::Permissions),
            // A copy, move or link into its folder by its name.
            ("cp x.yaml conf/app/", Rule::Overwrite),
            ("cp x.yaml conf/app", Rule::Overwrite),
            ("cp new/x.yaml conf/app", Rule::Overwrite),
            ("cp ./new/x.yaml conf/app/", Rule::Overwrite),
            ("cp -t conf/app x.yaml", Rule::Overwrite),
            ("cp --target-directory=conf/app x.yaml", Rule::Overwrite),
            ("install x.yaml conf/app/", Rule::Overwrite),
            ("install -m 600 x.yaml conf/app", Rule::Overwrite),
            ("mv x.yaml conf/app/", Rule::Overwrite),
            ("mv new/x.yaml conf/app", Rule::Overwrite),
            ("cp *.yaml conf/app/", Rule::Overwrite),
            ("cp x.* conf/app/", Rule::Overwrite),
            ("cp * conf/app/", Rule::Overwrite),
            ("cp $f conf/app/", Rule::Overwrite),
            ("ln -sf other/x.yaml conf/app/", Rule::Overwrite),
            ("ln -s other/x.yaml conf/app", Rule::Overwrite),
            ("cd conf && cp ../x.yaml app/", Rule::Overwrite),
            ("cp -f a.txt x.yaml conf/app", Rule::Overwrite),
            ("cp -- x.yaml conf/app/", Rule::Overwrite),
            ("cp --target-directory conf/app x.yaml", Rule::Overwrite),
            ("cp -tconf/app x.yaml", Rule::Overwrite),
            ("mv -t conf/app x.yaml", Rule::Overwrite),
            ("mv --target-directory=conf/app x.yaml", Rule::Overwrite),
            ("cp x.yaml y.yaml conf/app/", Rule::Overwrite),
            ("cp y.yaml x.yaml conf/app/", Rule::Overwrite),
            ("ln -s ../x.yaml conf/app/", Rule::Overwrite),
            ("ln -s -t conf/app x.yaml", Rule::Overwrite),
            ("install -D x.yaml conf/app/x.yaml", Rule::Overwrite),
            ("install -t conf/app x.yaml", Rule::Overwrite),
            ("install -m 644 x.yaml conf/app/", Rule::Overwrite),
            ("cp ../x.yaml ./conf/app/", Rule::Overwrite),
            ("cp x.yaml conf//app/", Rule::Overwrite),
            ("cp x.yaml ./conf/./app", Rule::Overwrite),
            ("cp X.YAML conf/app/", Rule::Overwrite),
            ("cp x.yaml CONF/APP/", Rule::Overwrite),
            ("cp x.yaml conf/app/.", Rule::Overwrite),
            ("cp x.yaml conf/app/./", Rule::Overwrite),
            ("cp x.yaml conf/app/../app", Rule::Overwrite),
            ("cp -f x.yaml conf/app/", Rule::Overwrite),
            ("cat x.yaml | tee conf/app/x.yaml", Rule::Overwrite),
            ("ls *.yaml | xargs cp -t conf/app", Rule::Overwrite),
            (
                r"find . -name x.yaml -exec cp {} conf/app/ \;",
                Rule::Overwrite,
            ),
            (
                r"find . -name x.yaml -execdir cp {} conf/app/ \;",
                Rule::Overwrite,
            ),
            (
                r"find . -name x.yaml -ok cp {} conf/app/ \;",
                Rule::Overwrite,
            ),
            ("ls | xargs -I{} cp {} conf/app/", Rule::Overwrite),
            ("cp $(ls *.yaml) conf/app/", Rule::Overwrite),
            // A recursive copy or mirror into a folder that holds it.
            ("cp -r other/. conf", Rule::Overwrite),
            ("cp -R app conf/", Rule::Overwrite),
            ("cp -a app conf", Rule::Overwrite),
            ("cp -R other/ conf/", Rule::Overwrite),
            ("cp --recursive other conf", Rule::Overwrite),
            ("cp -r other conf/app", Rule::Overwrite),
            ("rsync -a src/ conf/", Rule::Overwrite),
            ("rsync -r src conf", Rule::Overwrite),
            ("rsync -avz src/ conf/app/", Rule::Overwrite),
            ("rsync -r src/ conf", Rule::Overwrite),
            ("rsync -av --progress src/ conf/", Rule::Overwrite),
            ("cp --recursive app conf", Rule::Overwrite),
            ("cp -rf app conf", Rule::Overwrite),
            ("cp -fR app conf", Rule::Overwrite),
            ("cp -dR app conf", Rule::Overwrite),
            ("rsync -rlpt src/ conf/", Rule::Overwrite),
            ("rsync --recursive src/ conf/", Rule::Overwrite),
            ("rsync -a src conf/", Rule::Overwrite),
            ("cp -r src/* conf/", Rule::Overwrite),
            ("cp -R src/app conf", Rule::Overwrite),
            // Mirroring is the delete rule's own: it keeps its words.
            ("rsync -a --delete src/ conf/", Rule::Delete),
        ],
    );
    // The reason of a folder that holds it is the caller's words.
    for line in ["rm -rf conf", "rm -rf c*", "mv conf /tmp/x"] {
        let assessment = classify(line, Shell::Posix, &paths);
        assert!(
            assessment
                .findings()
                .iter()
                .any(|finding| finding.reason.ends_with("the agent's settings")),
            "{line}: {:?}",
            assessment.findings()
        );
    }
    // A copy onto it is one finding.
    let assessment = classify("cp x.yaml conf/app/", Shell::Posix, &paths);
    assert_eq!(assessment.findings().len(), 1);
    first_findings(
        Shell::Posix,
        &paths,
        &[
            (
                "cp x.yaml conf/app/",
                Rule::Overwrite,
                "writes to the agent's settings",
            ),
            // A verdict that is already risky keeps its own words.
            ("rm -rf .", Rule::Delete, "deletes the whole workspace"),
            ("rm -rf *", Rule::Delete, "deletes the whole workspace"),
            ("rm -rf ~", Rule::Delete, "deletes your home directory"),
            (
                "rm -rf /home/me/work",
                Rule::Delete,
                "deletes a folder holding the workspace",
            ),
            (
                "cp -r src ~",
                Rule::Overwrite,
                "writes to your home directory",
            ),
        ],
    );
}

/// A protected folder lets a pattern go below its name.
#[test]
fn a_protected_folder_lets_a_pattern_go_below_its_name() {
    check(
        Shell::Posix,
        &workspace_cfg(),
        &[
            "rm -rf src/**/z",
            "rm -rf src",
            "rm -rf src/**",
            "cp a cfgx/",
        ],
        &[
            ("rm -rf **/rules", Rule::Delete),
            ("rm **/*.yaml", Rule::Delete),
            ("rm -rf **/*.rs", Rule::Delete),
            ("rm -rf cfg", Rule::Delete),
            ("rm cfg/rules", Rule::Delete),
            ("rm -rf **/y.yaml", Rule::Delete),
            ("cp rules cfg/", Rule::Overwrite),
            ("cp -r src cfg", Rule::Overwrite),
        ],
    );
}

/// A file and a folder: copies, patterns and what stays safe beside them,
/// and a pattern part below each.
#[test]
fn a_protected_file_beside_a_protected_folder() {
    check(
        Shell::Posix,
        &workspace_file_and_cfg(),
        &[
            "mv app conf/",
            "cp a.txt conf/",
            "touch conf/new.txt",
            "mkdir -p conf/app",
            "rm -rf src/**",
            "rm -rf src",
            "rm conf/other.txt",
            "rm conf/*.txt",
            "rm -rf cfgx",
            "rm -rf .Agents",
        ],
        &[
            ("cp -r other/ conf/", Rule::Overwrite),
            ("cp -R app conf/", Rule::Overwrite),
            ("cp -a app conf", Rule::Overwrite),
            ("cp -r other/. conf", Rule::Overwrite),
            ("cp -R other/ cfg", Rule::Overwrite),
            ("cp -r x cfg", Rule::Overwrite),
            ("rsync -a src/ conf/", Rule::Overwrite),
            ("rsync -a --delete src/ conf/", Rule::Delete),
            ("rsync -a --delete src/ conf/", Rule::Overwrite),
            ("chmod 755 conf", Rule::Permissions),
            ("chmod -R 777 conf", Rule::Permissions),
            ("rm -rf **/rules", Rule::Delete),
            ("rm -rf cfg/**/x", Rule::Delete),
            ("rm **/x.yaml", Rule::Delete),
            ("rm -rf **", Rule::Delete),
            ("rm -rf conf/**", Rule::Delete),
            ("rm **/*.yaml", Rule::Delete),
            ("rm -rf **/app", Rule::Delete),
            ("rm -rf **/*.rs", Rule::Delete),
            ("rm -rf c**", Rule::Delete),
            ("rm -rf .", Rule::Delete),
            ("rm conf/*", Rule::Delete),
            ("rm -rf CONF", Rule::Delete),
            ("rm -rf Cfg", Rule::Delete),
            // A pattern part below a protected file or folder.
            ("rm -rf **/y.yaml", Rule::Delete),
            ("rm -rf **/x.yaml", Rule::Delete),
            ("rm -rf conf", Rule::Delete),
            ("rm conf/*/x.yaml", Rule::Delete),
            ("rm conf/app/*", Rule::Delete),
            ("rm */app/x.yaml", Rule::Delete),
            ("rm -rf cfg/*", Rule::Delete),
            ("rm -rf c*/rules", Rule::Delete),
            ("rm -rf */rules", Rule::Delete),
            ("rm cfg/**/x", Rule::Delete),
            ("rm -rf ?fg", Rule::Delete),
        ],
    );
}

/// A folder marked as a file opens patterns below its name.
#[test]
fn a_folder_marked_as_a_file() {
    check(
        Shell::Posix,
        &cfg_marked_as_a_file(),
        &["rm -rf c*/rules", "rm -rf **/rules", "rm -rf */rules"],
        &[
            ("rm -rf cfg/*", Rule::Delete),
            ("rm cfg/rules", Rule::Delete),
            ("cp rules cfg/", Rule::Overwrite),
            ("cp -r src/. cfg", Rule::Overwrite),
            ("rm -rf c*", Rule::Delete),
        ],
    );
}

/// A file marked as a folder only adds noise.
#[test]
fn a_file_marked_as_a_folder() {
    check(
        Shell::Posix,
        &file_marked_as_a_folder(),
        &["rm src/*.rs", "rm -rf src"],
        &[("rm -rf **/y.yaml", Rule::Delete)],
    );
}

/// A protected path in a temporary folder is not a temporary file, and a
/// pattern that picks it is not either.
#[test]
fn a_protected_path_in_a_temporary_folder_is_protected() {
    check(
        Shell::Posix,
        &temporary_file(),
        &[
            "rm /tmp/other",
            "rm /tmp/state/y",
            "rm /tmp/state/y*",
            "rm /tmp/*.log",
        ],
        &[
            ("rm /tmp/state/x", Rule::Delete),
            ("rm /tmp/state/*", Rule::Delete),
            ("rm /tmp/state/x*", Rule::Delete),
            ("rm -rf /tmp/state", Rule::Delete),
            ("rm /tmp/*/x", Rule::Delete),
            ("echo x > /tmp/state/x", Rule::Overwrite),
        ],
    );
    check(
        Shell::Posix,
        &temporary_file_and_folder(),
        &[],
        &[
            ("rm /tmp/state/*", Rule::Delete),
            ("rm /tmp/state/x*", Rule::Delete),
            ("rm /tmp/*/x", Rule::Delete),
            ("rm /tmp/s*", Rule::Delete),
            ("rm /tmp/st/*", Rule::Delete),
            ("rm /tmp/st*", Rule::Delete),
            ("rm /tmp/*", Rule::Delete),
        ],
    );
}

/// Names compare without case on every host, a macOS file system included,
/// and so does the place a copy lands.
#[test]
fn a_protected_path_is_the_same_whatever_its_case() {
    check(
        Shell::Posix,
        &mac_folder(),
        &["rm -rf .agents", "cat .AGENT/rules", "rm src/main.rs"],
        &[
            ("rm -rf .AGENT", Rule::Delete),
            ("rm .Agent/rules", Rule::Delete),
            ("rm -rf .agent", Rule::Delete),
            ("echo x > .AGENT/rules", Rule::Overwrite),
            ("rm -rf .AGE*", Rule::Delete),
        ],
    );
    check(
        Shell::Posix,
        &mac_file(),
        &[],
        &[
            ("cp X.yaml conf/app/", Rule::Overwrite),
            ("cp x.YAML Conf/App", Rule::Overwrite),
        ],
    );
}

/// A Windows spelling of a protected path resolves the same way, in every
/// shell, and without regard to case.
#[test]
fn a_protected_path_is_a_finding_on_windows_too() {
    let paths = windows_home_and_workspace_folders();
    check(
        Shell::PowerShell,
        &paths,
        &[
            r"Get-Content C:\Users\me\.agent\config.yaml",
            r"Get-ChildItem C:\Users\me\.agent",
            "Remove-Item src\\main.rs",
            "Remove-Item -Recurse -Force target",
        ],
        &[
            (r"Remove-Item C:\Users\me\.agent\config.yaml", Rule::Delete),
            (
                r"Remove-Item -Recurse -Force C:\Users\me\.agent",
                Rule::Delete,
            ),
            (r"Remove-Item c:\users\ME\.AGENT\config.yaml", Rule::Delete),
            (r"Remove-Item C:/Users/me/.agent/config.yaml", Rule::Delete),
            (r"Remove-Item $HOME\.agent\config.yaml", Rule::Delete),
            (r"Remove-Item .agent\rules", Rule::Delete),
            (r"Remove-Item C:\Users\me\.agent\*", Rule::Delete),
            (r"'x' > C:\Users\me\.agent\config.yaml", Rule::Overwrite),
            (r"Set-Content .agent\rules -Value x", Rule::Overwrite),
        ],
    );
    check(
        Shell::Cmd,
        &paths,
        &[
            r"type C:\Users\me\.agent\config.yaml",
            r"dir C:\Users\me\.agent",
            r"del src\main.rs",
        ],
        &[
            (r"del C:\Users\me\.agent\config.yaml", Rule::Delete),
            (r"del C:\USERS\me\.Agent\config.yaml", Rule::Delete),
            (r"rd /s /q C:\Users\me\.agent", Rule::Delete),
            (r"del .agent\rules", Rule::Delete),
            (r"echo x > C:\Users\me\.agent\config.yaml", Rule::Overwrite),
            (
                r"copy x.txt C:\Users\me\.agent\config.yaml",
                Rule::Overwrite,
            ),
        ],
    );
    first_findings(
        Shell::PowerShell,
        &paths,
        &[(
            r"Remove-Item C:\Users\me\.agent\config.yaml",
            Rule::Delete,
            "deletes the agent's settings",
        )],
    );
}

/// The 8.3 short name of a protected name is the protected name, other
/// Windows spellings resolve to it, a folder holding a protected path cannot
/// be deleted whole, and a recursive copy or mirror into one can replace it.
#[test]
fn a_windows_spelling_of_a_protected_folder_or_a_folder_holding_a_file() {
    let paths = windows_folder_and_file();
    check(
        Shell::PowerShell,
        &paths,
        &[
            r"Remove-Item AGEN~1\rules",
            r"Remove-Item OTHER~1\rules",
            r"Remove-Item conf\other.txt",
            r"Remove-Item src -Recurse",
            r"Copy-Item a.txt conf\",
            r"New-Item -ItemType Directory conf\app",
            "Remove-Item *.rs",
        ],
        &[
            (r"Remove-Item AGENT~1\rules", Rule::Delete),
            (r"Remove-Item -Recurse agent~1", Rule::Delete),
            (r"Remove-Item -Recurse conf", Rule::Delete),
            (r"Remove-Item -Recurse conf\app", Rule::Delete),
            (r"Remove-Item -Recurse c*", Rule::Delete),
            (r"Remove-Item conf\app\x.yaml", Rule::Delete),
            (r"Remove-Item -Recurse AGENT~*", Rule::Delete),
            (r"'x' > AGENT~1\rules", Rule::Overwrite),
            (r"Remove-Item .agent.\rules", Rule::Delete),
            (r"Remove-Item .agent\\rules", Rule::Delete),
            (r"Remove-Item .\.AGENT\", Rule::Delete),
            (r"Remove-Item \Users\me\dev\repo\.agent\rules", Rule::Delete),
            (r"Remove-Item C:.agent\rules", Rule::Delete),
            ("Remove-Item *", Rule::Delete),
            ("Remove-Item .a*", Rule::Delete),
            ("Remove-Item .agent ", Rule::Delete),
            (r"Remove-Item '.agent '\x", Rule::Unreadable),
            (r"Remove-Item '.agent '\x", Rule::Delete),
            // Recursive copies and mirrors.
            ("Copy-Item -Recurse -Force src conf", Rule::Overwrite),
            (r"Copy-Item -Recurse src\* conf", Rule::Overwrite),
            ("robocopy src conf /MIR", Rule::Delete),
            ("robocopy src conf /MIR", Rule::Overwrite),
            ("robocopy src conf /E", Rule::Overwrite),
        ],
    );
    check(
        Shell::Cmd,
        &paths,
        &[
            r"del AGEN~1\rules",
            r"del conf\other.txt",
            r"copy a.txt conf\",
            "del *.rs",
        ],
        &[
            (r"del AGENT~1\rules", Rule::Delete),
            (r"rd /s /q conf", Rule::Delete),
            (r"rd /s /q AGENT~1", Rule::Delete),
            (r"echo x > AGENT~1\rules", Rule::Overwrite),
            (r"del .agent\rules", Rule::Delete),
            ("xcopy /s /y src conf", Rule::Overwrite),
        ],
    );
}

/// A copy or move into the folder of a protected file by its name replaces
/// it, in every shell and every spelling of the cmdlet and its parameters; a
/// recursive copy into a folder holding one can.
#[test]
fn a_windows_copy_into_a_protected_files_folder_is_a_finding() {
    let paths = windows_file();
    check(
        Shell::PowerShell,
        &paths,
        &[
            r"Copy-Item a.txt conf\app",
            r"Copy-Item y.yaml conf\app\",
            r"Move-Item a.txt conf\app",
            r"Copy-Item -Recurse src dist",
            r"Copy-Item -Recurse -Force src conf\other",
            r"Copy-Item *.txt conf\app",
            r"Copy-Item a.txt,b.txt conf\app",
            r"Move-Item -Path a.txt,b.txt -Destination conf\app",
            "Copy-Item x.yaml SETTIN~1",
            "Copy-Item a.txt b.txt",
            "Copy-Item src -Destination dist -Recurse",
            r"Copy-Item a.txt conf\app -ErrorAction Stop",
            r"Copy-Item a.txt conf\app -ea 0",
        ],
        &[
            (r"Copy-Item x.yaml conf\app", Rule::Overwrite),
            (r"Copy-Item x.yaml conf\app\", Rule::Overwrite),
            (
                r"Copy-Item -Path new\x.yaml -Destination conf\app",
                Rule::Overwrite,
            ),
            (r"Move-Item x.yaml conf\app", Rule::Overwrite),
            (r"Copy-Item *.yaml conf\app", Rule::Overwrite),
            (r"Copy-Item -Recurse -Force src conf", Rule::Overwrite),
            (r"Copy-Item -Recurse src conf\app", Rule::Overwrite),
            (r"Copy-Item -Recurse app conf", Rule::Overwrite),
            // A comma list of sources.
            (r"Copy-Item y.yaml,x.yaml conf\app", Rule::Overwrite),
            (r"Copy-Item x.yaml, y.yaml conf\app", Rule::Overwrite),
            (r"Copy-Item x.yaml,y.yaml conf\app\", Rule::Overwrite),
            (r"Move-Item y,x.yaml conf\app", Rule::Overwrite),
            (r"Copy-Item -Path y.yaml,x.yaml conf\app", Rule::Overwrite),
            (
                r"Copy-Item -Path a,x.yaml -Destination conf\app",
                Rule::Overwrite,
            ),
            // Every spelling of the parameters.
            (r"Copy-Item x.yaml -Destination conf\app", Rule::Overwrite),
            (
                r"Copy-Item -Path x.yaml -Destination conf\app\",
                Rule::Overwrite,
            ),
            (r"Copy-Item -LiteralPath x.yaml conf\app", Rule::Overwrite),
            (
                r"Copy-Item -Destination conf\app -Path x.yaml",
                Rule::Overwrite,
            ),
            (r"Copy-Item -Destination conf\app x.yaml", Rule::Overwrite),
            (r"Copy-Item X.YAML CONF\APP", Rule::Overwrite),
            ("Copy-Item -Recurse src conf", Rule::Overwrite),
            ("Copy-Item -r src conf", Rule::Overwrite),
            (r"cp x.yaml conf\app", Rule::Overwrite),
            (r"Copy-Item x.yaml,y.yaml conf\app", Rule::Overwrite),
            (
                r"Copy-Item -Path x.yaml,y.yaml -Destination conf\app",
                Rule::Overwrite,
            ),
            (r"Remove-Item y.txt,conf\app\x.yaml", Rule::Delete),
            (r"Move-Item y,x.yaml conf\app", Rule::Delete),
            (r"Copy-Item -Path y.yaml x.yaml conf\app", Rule::Overwrite),
            (
                r"Copy-Item -LiteralPath y.yaml,x.yaml -Destination conf\app",
                Rule::Overwrite,
            ),
            (
                r"'x.yaml' | Copy-Item -Destination conf\app",
                Rule::Overwrite,
            ),
            (
                r"Get-ChildItem *.yaml | Copy-Item -Destination conf\app",
                Rule::Overwrite,
            ),
            (r"gci src | cpi -Destination conf\app", Rule::Overwrite),
            (r"cp y.yaml,x.yaml conf\app", Rule::Overwrite),
            (r"copy x.yaml conf\app", Rule::Overwrite),
            (r"cpi x.yaml conf\app", Rule::Overwrite),
            (r"mv x.yaml conf\app", Rule::Overwrite),
            (r"move x.yaml conf\app", Rule::Overwrite),
            (r"mi x.yaml conf\app", Rule::Overwrite),
            (r"Copy-Item @('y','x.yaml') conf\app", Rule::Overwrite),
            (r"Copy-Item $files conf\app", Rule::Overwrite),
            (
                r"Copy-Item (Get-ChildItem *.yaml) conf\app",
                Rule::Overwrite,
            ),
            (
                r"Copy-Item x.yaml conf\app -ErrorAction SilentlyContinue",
                Rule::Overwrite,
            ),
            (r"Copy-Item x.yaml conf\app -ea 0", Rule::Overwrite),
            (
                r"Copy-Item -Path x.yaml conf\app -ErrorAction Stop",
                Rule::Overwrite,
            ),
            (r"Copy-Item x.yaml conf\app -Force", Rule::Overwrite),
            (r"Copy-Item -Force x.yaml conf\app", Rule::Overwrite),
            (r"Copy-Item x.yaml conf\app -Recurse", Rule::Overwrite),
            (r"Copy-Item x.yaml conf\app -WhatIf:$false", Rule::Overwrite),
            (r"Copy-Item x.yaml conf\app -OutVariable o", Rule::Overwrite),
            (
                r"Copy-Item x.yaml conf\app -wa 0 -ev e -iv i -pv p -ob 1 -infa 0 -proga 0",
                Rule::Overwrite,
            ),
            (
                r"Move-Item conf\app\x.yaml C:\tmp -ErrorAction Stop",
                Rule::Delete,
            ),
            (
                r"Move-Item conf\app\x.yaml C:\tmp -ErrorAction Stop",
                Rule::Overwrite,
            ),
            (r"Move-Item conf C:\tmp -ea 0", Rule::Delete),
            (r"Move-Item conf C:\tmp -ea 0", Rule::Overwrite),
            (r"Copy-Item -Destination:conf\app x.yaml", Rule::Overwrite),
            (
                r"Copy-Item x.yaml -Destination conf\app -Container",
                Rule::Overwrite,
            ),
            ("Get-ChildItem conf | Remove-Item -Recurse", Rule::Delete),
            ("'conf' | Remove-Item -Recurse", Rule::Delete),
            (r"Get-ChildItem C:\Windows | Remove-Item", Rule::Delete),
            (r"Remove-Item C:\Windows\x,y", Rule::Delete),
        ],
    );
    check(
        Shell::Cmd,
        &paths,
        &[
            r"copy a.txt conf\app",
            r"copy a.txt,b.txt conf\app",
            r"copy /b a.txt+b.txt conf\app",
            r"move /y a.txt conf\app",
            r"xcopy /y a.txt conf\app",
            r"robocopy src dist /E",
            r"robocopy src conf\other /E",
            r"xcopy /s /y src dist",
            "robocopy src conf x.yaml",
            "robocopy src conf",
            "robocopy src dist",
            r"copy a.txt+b.txt conf\app",
        ],
        &[
            (r"copy /y x.yaml conf\app", Rule::Overwrite),
            (r"copy y.yaml,x.yaml conf\app", Rule::Overwrite),
            (r"copy /b y.yaml+x.yaml conf\app", Rule::Overwrite),
            (r"copy x.yaml+y.yaml conf\app\", Rule::Overwrite),
            (r"copy x.yaml conf\app\", Rule::Overwrite),
            (r"move /y x.yaml conf\app", Rule::Overwrite),
            (r"xcopy /y x.yaml conf\app", Rule::Overwrite),
            (r"xcopy /s /y src conf", Rule::Overwrite),
            (r"xcopy /e src conf\app", Rule::Overwrite),
            (r"robocopy src conf /E", Rule::Overwrite),
            (r"robocopy src conf\app /S", Rule::Overwrite),
            (r"robocopy src conf\app x.yaml", Rule::Overwrite),
            (r"robocopy src conf\app", Rule::Overwrite),
            ("xcopy /s src conf", Rule::Overwrite),
            (r"xcopy x.yaml conf\app", Rule::Overwrite),
            (r"copy y.yaml+x.yaml conf\app", Rule::Overwrite),
            (r"copy /b y.yaml + x.yaml conf\app", Rule::Overwrite),
        ],
    );
}

/// A protected folder on a share, in other spellings of the share.
#[test]
fn a_protected_folder_on_a_share() {
    check(
        Shell::PowerShell,
        &share_folder(),
        &[],
        &[
            (r"Remove-Item \\SRV\Share\.agent\x", Rule::Delete),
            ("Remove-Item //srv/share/.agent/x", Rule::Delete),
        ],
    );
}

/// Nothing changes without protected paths: the same lines are as they were,
/// with the guard's own words.
#[test]
fn without_protected_paths_nothing_changes() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "rm *.rs",
            "rm -rf conf",
            "cp x.yaml conf/app/",
            "cp -r src conf",
        ],
        &[],
    );
    first_findings(
        Shell::Posix,
        &posix(),
        &[(
            "rm ~/.agent/config.yaml",
            Rule::Delete,
            "deletes a path outside the workspace",
        )],
    );
}
