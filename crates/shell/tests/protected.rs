//! Every probe the reviews of the protected-paths change ran, kept as a row so
//! a later fix cannot reopen one. A row's verdict is what the review said it
//! must be: a finding with the rule shown, or safe. Unpacking an archive and
//! writers the guard does not know are not rows.

mod common;

use common::{check, macos, posix, windows};
use milo_guards_shell::{Paths, Protected, Rule, Shell};

const W: &str = "the agent's settings";

fn home() -> Paths {
    posix().with_protected([Protected::folder("/home/me/.agent", W)])
}

fn slash() -> Paths {
    posix().with_protected([Protected::folder("/home/me/.agent/", W)])
}

fn ws() -> Paths {
    posix().with_protected([
        Protected::folder("/home/me/work/repo/.agent", W),
        Protected::file("/home/me/work/repo/conf/app/x.yaml", W),
    ])
}

fn tmp() -> Paths {
    posix().with_protected([
        Protected::file("/tmp/state/x", W),
        Protected::folder("/tmp/st", W),
    ])
}

fn mac() -> Paths {
    macos().with_protected([Protected::folder("/Users/me/dev/repo/.agent", W)])
}

fn macfile() -> Paths {
    macos().with_protected([Protected::file("/Users/me/dev/repo/conf/app/x.yaml", W)])
}

fn win() -> Paths {
    windows().with_protected([
        Protected::folder(r"C:\Users\me\dev\repo\.agent", W),
        Protected::file(r"C:\Users\me\dev\repo\conf\app\x.yaml", W),
    ])
}

fn unc() -> Paths {
    windows().with_protected([Protected::folder(r"\\srv\share\.agent", W)])
}

fn conf() -> Paths {
    posix().with_protected([
        Protected::file("/home/me/work/repo/conf/app/x.yaml", W),
        Protected::folder("/home/me/work/repo/cfg", W),
    ])
}

fn agent() -> Paths {
    posix().with_protected([Protected::folder("/home/me/work/repo/.agent", W)])
}

fn none() -> Paths {
    posix()
}

fn file() -> Paths {
    posix().with_protected([Protected::file("/home/me/work/repo/conf/app/x.yaml", W)])
}

fn cfg() -> Paths {
    posix().with_protected([Protected::folder("/home/me/work/repo/cfg", W)])
}

fn winfile() -> Paths {
    windows().with_protected([Protected::file(r"C:\Users\me\dev\repo\conf\app\x.yaml", W)])
}

fn cfgfile() -> Paths {
    posix().with_protected([Protected::file("/home/me/work/repo/cfg", W)])
}

fn filefolder() -> Paths {
    posix().with_protected([Protected::folder("/home/me/work/repo/conf/app/x.yaml", W)])
}

/// Round 1: spellings of a protected folder in the home directory.
#[test]
fn home_agent_folder() {
    check(
        Shell::Posix,
        &home(),
        &[],
        &[
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
}

/// A protected path spelled with a trailing slash.
#[test]
fn protected_path_spelled_with_a_trailing_slash() {
    check(
        Shell::Posix,
        &slash(),
        &[],
        &[
            ("rm ~/.agent/x", Rule::Delete),
            ("rm ~/.agentx", Rule::Delete),
        ],
    );
}

/// Round 1 and 2: a protected folder and file inside the workspace.
#[test]
fn workspace_folder_and_file() {
    check(
        Shell::Posix,
        &ws(),
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

/// Round 1: protected paths in a temporary folder.
#[test]
fn temporary_folder() {
    check(
        Shell::Posix,
        &tmp(),
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

/// Round 1: names compare without case on a macOS host.
#[test]
fn macos_case() {
    check(
        Shell::Posix,
        &mac(),
        &[],
        &[
            ("rm -rf .AGENT", Rule::Delete),
            ("rm .Agent/rules", Rule::Delete),
        ],
    );
}

/// Round 3: case in a copy's landing path.
#[test]
fn macos_case_of_a_copy() {
    check(
        Shell::Posix,
        &macfile(),
        &[],
        &[
            ("cp X.yaml conf/app/", Rule::Overwrite),
            ("cp x.YAML Conf/App", Rule::Overwrite),
        ],
    );
}

/// Round 1: Windows spellings in PowerShell.
#[test]
fn windows_powershell_spellings() {
    check(
        Shell::PowerShell,
        &win(),
        &["Remove-Item *.rs"],
        &[
            (r"Remove-Item AGENT~1\rules", Rule::Delete),
            (r"Remove-Item .agent.\rules", Rule::Delete),
            (r"Remove-Item .agent\\rules", Rule::Delete),
            (r"Remove-Item .\.AGENT\", Rule::Delete),
            (r"Remove-Item \Users\me\dev\repo\.agent\rules", Rule::Delete),
            (r"Remove-Item C:.agent\rules", Rule::Delete),
            ("Remove-Item *", Rule::Delete),
            ("Remove-Item .a*", Rule::Delete),
            ("Remove-Item -Recurse conf", Rule::Delete),
            ("Remove-Item .agent ", Rule::Delete),
            (r"Remove-Item '.agent '\x", Rule::Unreadable),
            (r"Remove-Item '.agent '\x", Rule::Delete),
        ],
    );
}

/// Round 1: Windows spellings in cmd.
#[test]
fn windows_cmd_spellings() {
    check(
        Shell::Cmd,
        &win(),
        &["del *.rs"],
        &[
            (r"del AGENT~1\rules", Rule::Delete),
            (r"del .agent\rules", Rule::Delete),
            ("rd /s /q conf", Rule::Delete),
        ],
    );
}

/// Round 1: a protected folder on a share.
#[test]
fn unc_share() {
    check(
        Shell::PowerShell,
        &unc(),
        &[],
        &[
            (r"Remove-Item \\SRV\Share\.agent\x", Rule::Delete),
            ("Remove-Item //srv/share/.agent/x", Rule::Delete),
        ],
    );
}

/// Round 1 and 2: copies, patterns and what stays safe.
#[test]
fn copies_and_patterns_beside_a_folder_and_a_file() {
    check(
        Shell::Posix,
        &conf(),
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
        ],
    );
}

/// Round 2: recursive copies and mirrors on Windows.
#[test]
fn windows_recursive_copies() {
    check(
        Shell::PowerShell,
        &win(),
        &[],
        &[
            ("Copy-Item -Recurse -Force src conf", Rule::Overwrite),
            (r"Copy-Item -Recurse src\* conf", Rule::Overwrite),
            ("robocopy src conf /MIR", Rule::Delete),
            ("robocopy src conf /MIR", Rule::Overwrite),
            ("robocopy src conf /E", Rule::Overwrite),
        ],
    );
}

/// Round 2: xcopy of a tree.
#[test]
fn windows_xcopy() {
    check(
        Shell::Cmd,
        &win(),
        &[],
        &[("xcopy /s /y src conf", Rule::Overwrite)],
    );
}

/// Round 1: case and near names of a protected folder.
#[test]
fn case_of_a_protected_folder() {
    check(
        Shell::Posix,
        &agent(),
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

/// Nothing changes without protected paths.
#[test]
fn without_protected_paths() {
    check(
        Shell::Posix,
        &none(),
        &[
            "rm *.rs",
            "rm -rf conf",
            "cp x.yaml conf/app/",
            "cp -r src conf",
        ],
        &[],
    );
}

/// Round 2 and 3: a copy, move or link into the protected file's folder.
#[test]
fn copy_into_the_files_folder() {
    check(
        Shell::Posix,
        &file(),
        &[
            "rm -rf **/y.yaml",
            "rm -rf **/*.rs",
            "cp a.txt conf/app",
            "cp -r src dist",
            "touch conf/new.txt",
            "rsync -a src/ dist/",
            "cp -r src conf2",
            "cp a.txt conf/",
            "mv a.txt conf/app/",
            "cp -r src conf/app/new",
            r"find . -name '*.o' -exec cp {} dist/ \;",
        ],
        &[
            ("cp x.yaml conf/app/", Rule::Overwrite),
            ("cp new/x.yaml conf/app", Rule::Overwrite),
            ("cp -t conf/app x.yaml", Rule::Overwrite),
            ("install x.yaml conf/app/", Rule::Overwrite),
            ("mv x.yaml conf/app/", Rule::Overwrite),
            ("cp *.yaml conf/app/", Rule::Overwrite),
            ("ln -sf other/x.yaml conf/app/", Rule::Overwrite),
            ("cp -- x.yaml conf/app/", Rule::Overwrite),
            ("cp --target-directory=conf/app x.yaml", Rule::Overwrite),
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
            ("cd conf && cp ../x.yaml app/", Rule::Overwrite),
            ("cp -f x.yaml conf/app/", Rule::Overwrite),
            ("cp -r other/. conf", Rule::Overwrite),
            ("cp -R app conf/", Rule::Overwrite),
            ("cp -a app conf", Rule::Overwrite),
            ("cp -R other/ conf/", Rule::Overwrite),
            ("rsync -a src/ conf/", Rule::Overwrite),
            ("rsync -r src/ conf", Rule::Overwrite),
            ("rsync -av --progress src/ conf/", Rule::Overwrite),
            ("cp --recursive app conf", Rule::Overwrite),
            ("cp -rf app conf", Rule::Overwrite),
            ("cp -fR app conf", Rule::Overwrite),
            ("cp -dR app conf", Rule::Overwrite),
            ("rsync -rlpt src/ conf/", Rule::Overwrite),
            ("rsync --recursive src/ conf/", Rule::Overwrite),
            ("rsync -a src conf/", Rule::Overwrite),
            ("cp * conf/app/", Rule::Overwrite),
            ("cp $f conf/app/", Rule::Overwrite),
            ("cat x.yaml | tee conf/app/x.yaml", Rule::Overwrite),
            ("cp -r src/* conf/", Rule::Overwrite),
            ("cp -R src/app conf", Rule::Overwrite),
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
        ],
    );
}

/// Round 3: a protected folder lets a pattern go below its name.
#[test]
fn a_protected_folder_in_posix_patterns() {
    check(
        Shell::Posix,
        &cfg(),
        &["rm -rf src/**", "cp a cfgx/"],
        &[
            ("rm -rf **/y.yaml", Rule::Delete),
            ("rm -rf **/*.rs", Rule::Delete),
            ("cp rules cfg/", Rule::Overwrite),
            ("cp -r src cfg", Rule::Overwrite),
        ],
    );
}

/// Round 3 and 4: Copy-Item and Move-Item in every spelling.
#[test]
fn windows_powershell_copies() {
    check(
        Shell::PowerShell,
        &winfile(),
        &[
            r"Copy-Item a.txt conf\app",
            "Copy-Item x.yaml SETTIN~1",
            "Copy-Item a.txt b.txt",
            "Copy-Item src -Destination dist -Recurse",
            r"Copy-Item a.txt conf\app -ErrorAction Stop",
            r"Copy-Item a.txt conf\app -ea 0",
        ],
        &[
            (r"Copy-Item x.yaml conf\app", Rule::Overwrite),
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
            (r"Move-Item x.yaml conf\app", Rule::Overwrite),
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
            (r"Copy-Item y.yaml,x.yaml conf\app", Rule::Overwrite),
            (r"Copy-Item x.yaml, y.yaml conf\app", Rule::Overwrite),
            (r"Move-Item y,x.yaml conf\app", Rule::Delete),
            (r"Move-Item y,x.yaml conf\app", Rule::Overwrite),
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
}

/// Round 3 and 4: cmd copy, move, xcopy and robocopy.
#[test]
fn windows_cmd_copies() {
    check(
        Shell::Cmd,
        &winfile(),
        &[
            "robocopy src conf x.yaml",
            "robocopy src conf",
            r"copy a.txt conf\app",
            "robocopy src dist",
            r"copy a.txt+b.txt conf\app",
        ],
        &[
            (r"copy /y x.yaml conf\app", Rule::Overwrite),
            (r"move /y x.yaml conf\app", Rule::Overwrite),
            ("xcopy /s src conf", Rule::Overwrite),
            (r"xcopy x.yaml conf\app", Rule::Overwrite),
            ("robocopy src conf /E", Rule::Overwrite),
            (r"copy y.yaml+x.yaml conf\app", Rule::Overwrite),
            (r"copy /b y.yaml + x.yaml conf\app", Rule::Overwrite),
        ],
    );
}

/// Round 3 and 4: a pattern part below a protected file or folder.
#[test]
fn pattern_kinds() {
    check(
        Shell::Posix,
        &conf(),
        &[],
        &[
            ("rm -rf **/y.yaml", Rule::Delete),
            ("rm -rf **/*.rs", Rule::Delete),
            ("rm -rf **/x.yaml", Rule::Delete),
            ("rm -rf conf", Rule::Delete),
            ("rm -rf conf/**", Rule::Delete),
            ("rm conf/*/x.yaml", Rule::Delete),
            ("rm conf/app/*", Rule::Delete),
            ("rm */app/x.yaml", Rule::Delete),
            ("rm -rf **/rules", Rule::Delete),
            ("rm -rf cfg/*", Rule::Delete),
            ("rm -rf c*/rules", Rule::Delete),
            ("rm -rf */rules", Rule::Delete),
            ("rm cfg/**/x", Rule::Delete),
            ("rm -rf ?fg", Rule::Delete),
        ],
    );
}

/// Round 4: a folder marked as a file opens patterns below its name.
#[test]
fn a_folder_marked_as_a_file() {
    check(
        Shell::Posix,
        &cfgfile(),
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

/// Round 4: a file marked as a folder only adds noise.
#[test]
fn a_file_marked_as_a_folder() {
    check(
        Shell::Posix,
        &filefolder(),
        &["rm src/*.rs", "rm -rf src"],
        &[("rm -rf **/y.yaml", Rule::Delete)],
    );
}
