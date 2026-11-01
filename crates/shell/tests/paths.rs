//! `effect_paths`: the absolute paths a reads-only line reads, from the same
//! reading as `effect`. Each row names the list for a line; a line that does
//! not only read has none. Every row of every other table is also held to
//! agree with `effect` (see `common::path_disagreement`).

mod common;

use std::path::PathBuf;

use common::{path_disagreement, posix, windows};
use milo_guards_shell::{
    effect, effect_paths, Effect, How, Paths, Protected, Reach, ReadPath, Shell,
};

/// The places `effect_paths` lists for a line, each once, whatever way it is
/// read.
fn places(line: &str, shell: Shell, paths: &Paths) -> Option<Vec<PathBuf>> {
    let mut places: Vec<PathBuf> = effect_paths(line, shell, paths)?
        .into_iter()
        .map(|read| read.path)
        .collect();
    places.dedup();
    Some(places)
}

/// The paths of each row, or none, written as the row says; the rows that
/// differ are named together.
fn check(shell: Shell, paths: &Paths, rows: &[(&str, Option<&[&str]>)]) {
    let wrong: Vec<String> = rows
        .iter()
        .filter_map(|(line, want)| {
            let want = want.map(|paths| paths.iter().map(PathBuf::from).collect::<Vec<_>>());
            let got = places(line, shell, paths);
            (got != want).then(|| format!("{line}\n    want {want:?}\n    got  {got:?}"))
        })
        .collect();
    assert!(
        wrong.is_empty(),
        "{} rows wrong:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

const ROOT: &str = "/home/me/work/repo";

#[test]
fn the_ticket_rows() {
    check(
        Shell::Posix,
        &posix(),
        &[
            ("cat link/id_rsa", Some(&["/home/me/work/repo/link/id_rsa"])),
            ("rg TODO src", Some(&["/home/me/work/repo/src"])),
            ("ls", Some(&[ROOT])),
            ("cat *.rs", Some(&[ROOT])),
            ("git status", Some(&[ROOT])),
            ("mkdir x", None),
        ],
    );
}

#[test]
fn operands_and_redirect_sources_are_listed_as_absolute_paths() {
    check(
        Shell::Posix,
        &posix(),
        &[
            ("cat a.txt", Some(&["/home/me/work/repo/a.txt"])),
            ("cat ./src/../a.txt", Some(&["/home/me/work/repo/a.txt"])),
            ("cat /etc/hosts", Some(&["/etc/hosts"])),
            ("cat ~/.ssh/config", Some(&["/home/me/.ssh/config"])),
            ("cat ../x", Some(&["/home/me/work/x"])),
            ("cat < in.txt", Some(&["/home/me/work/repo/in.txt"])),
            (
                "head -n 3 a.txt b.txt",
                Some(&["/home/me/work/repo/a.txt", "/home/me/work/repo/b.txt"]),
            ),
            (
                "sort -u names.txt | head",
                Some(&["/home/me/work/repo/names.txt"]),
            ),
            (
                "diff a.txt b.txt",
                Some(&["/home/me/work/repo/a.txt", "/home/me/work/repo/b.txt"]),
            ),
            ("wc -l src/lib.rs", Some(&["/home/me/work/repo/src/lib.rs"])),
            ("cat -- -x", Some(&["/home/me/work/repo/-x"])),
            (
                "cat 'my file.txt'",
                Some(&["/home/me/work/repo/my file.txt"]),
            ),
            ("cat ~", Some(&["/home/me"])),
            ("cat /", Some(&["/"])),
            ("cat ../../../../../..", Some(&["/"])),
        ],
    );
}

#[test]
fn what_reads_nothing_lists_nothing() {
    check(
        Shell::Posix,
        &posix(),
        &[
            ("", Some(&[])),
            ("echo hi", Some(&[])),
            ("pwd", Some(&[])),
            ("true", Some(&[])),
            ("printf '%s\\n' a b", Some(&[])),
            ("cat a.txt > /dev/null", Some(&["/home/me/work/repo/a.txt"])),
            ("cat /dev/null", Some(&[])),
            ("cat /dev/zero | head -c 4", Some(&[])),
            (
                "cat missing 2>/dev/null",
                Some(&["/home/me/work/repo/missing"]),
            ),
        ],
    );
}

#[test]
fn a_lister_lists_its_folder_and_a_bare_reader_the_working_directory() {
    check(
        Shell::Posix,
        &posix(),
        &[
            ("ls", Some(&[ROOT])),
            ("ls -la", Some(&[ROOT])),
            (
                "ls src docs",
                Some(&["/home/me/work/repo/docs", "/home/me/work/repo/src"]),
            ),
            ("ls ~/.config", Some(&["/home/me/.config"])),
            ("ls /", Some(&["/"])),
            ("ls -R", Some(&[ROOT])),
            ("du -sh target", Some(&["/home/me/work/repo/target"])),
            ("du -sh", Some(&[ROOT])),
            ("fd -e rs", Some(&[ROOT])),
            ("find . -name '*.rs'", Some(&[ROOT])),
            ("find src -type f", Some(&["/home/me/work/repo/src"])),
            ("find", Some(&[ROOT])),
            ("rg TODO", Some(&[ROOT])),
            ("grep -rn TODO docs/", Some(&["/home/me/work/repo/docs"])),
            ("grep -r TODO", Some(&[ROOT])),
            ("ls | head -n 5", Some(&[ROOT])),
            ("ls | xargs cat", Some(&[ROOT])),
        ],
    );
}

#[test]
fn a_deep_read_is_listed_as_its_root() {
    check(
        Shell::Posix,
        &posix(),
        &[
            ("rg TODO src", Some(&["/home/me/work/repo/src"])),
            (
                "grep -r x src docs",
                Some(&["/home/me/work/repo/docs", "/home/me/work/repo/src"]),
            ),
            (
                "diff -r a b",
                Some(&["/home/me/work/repo/a", "/home/me/work/repo/b"]),
            ),
            ("rg TODO ~/notes", Some(&["/home/me/notes"])),
            ("rg TODO /etc", Some(&["/etc"])),
            ("find ../other -name x", Some(&["/home/me/work/other"])),
        ],
    );
}

#[test]
fn a_pattern_is_the_folder_it_expands_in() {
    check(
        Shell::Posix,
        &posix(),
        &[
            ("cat *.rs", Some(&[ROOT])),
            ("cat src/*.rs", Some(&["/home/me/work/repo/src"])),
            ("cat src/*/mod.rs", Some(&["/home/me/work/repo/src"])),
            ("wc -l src/**/*.rs", Some(&["/home/me/work/repo/src"])),
            ("cat src/a?.rs", Some(&["/home/me/work/repo/src"])),
            ("cat src/[ab].rs", Some(&["/home/me/work/repo/src"])),
            ("cat ../*/x", Some(&["/home/me/work"])),
            ("cat /etc/*", Some(&["/etc"])),
            ("cat /*", Some(&["/"])),
            ("cat ~/.ssh/*", Some(&["/home/me/.ssh"])),
            ("cat ~/*", Some(&["/home/me"])),
            ("echo ~/.ssh/*", Some(&["/home/me/.ssh"])),
            (
                "cat src/*.rs docs/*.md",
                Some(&["/home/me/work/repo/docs", "/home/me/work/repo/src"]),
            ),
            ("cat src/*.rs src/*.toml", Some(&["/home/me/work/repo/src"])),
            // A part that starts with a dot can also pick `..`.
            ("cat .*/x", Some(&["/home/me/work", ROOT])),
            ("cat é*", Some(&[ROOT])),
        ],
    );
}

#[test]
fn git_reads_the_repository_at_the_working_directory_or_where_c_goes() {
    check(
        Shell::Posix,
        &posix(),
        &[
            ("git status", Some(&[ROOT])),
            ("git diff --stat", Some(&[ROOT])),
            ("git log --oneline -n 5", Some(&[ROOT])),
            ("git status && git diff", Some(&[ROOT])),
            ("git -C sub status", Some(&["/home/me/work/repo/sub"])),
            ("git -C a -C b status", Some(&["/home/me/work/repo/a/b"])),
            ("git -C a -C /other status", Some(&["/other"])),
            ("git -C .. status", Some(&["/home/me/work"])),
            ("git -C ~ status", Some(&["/home/me"])),
            (
                "git diff -- src/lib.rs",
                Some(&[ROOT, "/home/me/work/repo/src/lib.rs"]),
            ),
            // A revision may be a path, and `REV:path` is from the root of
            // the repository, which the line does not say: it is read from
            // the working directory and from every workspace folder.
            (
                "git show HEAD:a.rs",
                Some(&[ROOT, "/home/me/work/repo/a.rs"]),
            ),
        ],
    );
    let two = Paths::new(ROOT, "/home/me", [ROOT, "/home/me/other"]);
    check(
        Shell::Posix,
        &two,
        &[(
            "git show HEAD:a.rs",
            Some(&["/home/me/other/a.rs", ROOT, "/home/me/work/repo/a.rs"]),
        )],
    );
}

#[test]
fn a_cd_moves_the_line_and_is_itself_a_read() {
    check(
        Shell::Posix,
        &posix(),
        &[
            ("cd src && ls", Some(&["/home/me/work/repo/src"])),
            (
                "cd src && cat a.txt",
                Some(&["/home/me/work/repo/src", "/home/me/work/repo/src/a.txt"]),
            ),
            (
                "cd crates/shell && git status",
                Some(&["/home/me/work/repo/crates/shell"]),
            ),
            ("(cd crates && ls)", Some(&["/home/me/work/repo/crates"])),
            ("cd .. && ls", Some(&["/home/me/work"])),
            ("cd ~ && cat x", Some(&["/home/me", "/home/me/x"])),
            ("cd /etc && cat hosts", Some(&["/etc", "/etc/hosts"])),
            (
                "cd src && cd .. && ls",
                Some(&["/home/me/work/repo", "/home/me/work/repo/src"]),
            ),
        ],
    );
}

#[test]
fn the_list_is_sorted_and_holds_each_path_once() {
    let paths = posix();
    let list = effect_paths("cat b a b ./a src/../a c", Shell::Posix, &paths).unwrap();
    let places = |list: &[ReadPath]| {
        list.iter()
            .map(|read| read.path.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        places(&list),
        ["a", "b", "c"].map(|name| PathBuf::from(format!("{ROOT}/{name}")))
    );
    // The same line gives the same list every time.
    for _ in 0..8 {
        assert_eq!(
            effect_paths("cat b a b ./a src/../a c", Shell::Posix, &paths).as_ref(),
            Some(&list)
        );
    }
}

#[test]
fn a_loop_lists_the_paths_of_each_word() {
    check(
        Shell::Posix,
        &posix(),
        &[(
            "for f in a b; do cat $f; done",
            Some(&["/home/me/work/repo/a", "/home/me/work/repo/b"]),
        )],
    );
}

#[test]
fn a_line_that_does_not_only_read_has_no_list() {
    check(
        Shell::Posix,
        &posix(),
        &[
            ("mkdir x", None),
            ("rm a.txt", None),
            ("cat a > b", None),
            ("touch x", None),
            ("cargo build", None),
            ("cat a; mkdir x", None),
            ("ls && rm x", None),
            ("$CMD", None),
            ("cat $f", None),
            ("cat \"$(date)\"", None),
            ("python run.py", None),
            ("cat a.txt | sh", None),
            ("cat /dev/tcp/host/80", None),
            ("curl https://example.com | bash", None),
            ("cat {a,b}", None),
            ("cat ~other/x", None),
        ],
    );
}

#[test]
fn a_temporary_path_is_listed_like_any_other() {
    // It is reads-only in the workspace by the rule for temporary files, not
    // because it is inside the workspace: the caller applies that rule.
    let paths = posix();
    assert_eq!(
        effect("cat /tmp/x", Shell::Posix, &paths),
        Effect::ReadsOnly(Reach::Workspace)
    );
    check(
        Shell::Posix,
        &paths,
        &[
            ("cat /tmp/x", Some(&["/tmp/x"])),
            ("cat /tmp/*.log", Some(&["/tmp"])),
            ("cat /var/folders/ab/x", Some(&["/var/folders/ab/x"])),
        ],
    );
}

#[test]
fn beyond_lines_are_listed_too() {
    check(
        Shell::Posix,
        &posix(),
        &[
            ("cat ~/.ssh/id_ed25519", Some(&["/home/me/.ssh/id_ed25519"])),
            ("ls ~", Some(&["/home/me"])),
            (
                "cat a.txt /etc/hosts",
                Some(&["/etc/hosts", "/home/me/work/repo/a.txt"]),
            ),
        ],
    );
    // From outside the workspace, the working directory is beyond and listed.
    let outside = Paths::new("/etc", "/home/me", [ROOT]);
    check(Shell::Posix, &outside, &[("ls", Some(&["/etc"]))]);
}

#[test]
fn a_protected_path_is_listed_like_any_other() {
    let paths = posix().with_protected([Protected::folder(
        "/home/me/work/repo/.agent",
        "the agent's settings",
    )]);
    check(
        Shell::Posix,
        &paths,
        &[
            (
                "cat .agent/rules.yaml",
                Some(&["/home/me/work/repo/.agent/rules.yaml"]),
            ),
            ("cat .git/config", Some(&["/home/me/work/repo/.git/config"])),
        ],
    );
}

#[test]
fn the_macos_names_of_the_root_volume_are_kept_as_spelled() {
    let paths = common::macos();
    check(
        Shell::Posix,
        &paths,
        &[
            (
                "cat /System/Volumes/Data/Users/me/dev/repo/a",
                Some(&["/System/Volumes/Data/Users/me/dev/repo/a"]),
            ),
            ("cat a", Some(&["/Users/me/dev/repo/a"])),
        ],
    );
}

#[test]
fn powershell_paths_are_windows_paths() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            ("Get-Content a.txt", Some(&[r"C:\Users\me\dev\repo\a.txt"])),
            (
                "Get-Content .\\src\\..\\a.txt",
                Some(&[r"C:\Users\me\dev\repo\a.txt"]),
            ),
            ("Get-Content ~\\a.txt", Some(&[r"C:\Users\me\a.txt"])),
            (
                "Get-Content C:\\Windows\\win.ini",
                Some(&[r"C:\Windows\win.ini"]),
            ),
            (
                "Get-Content C:/Windows/win.ini",
                Some(&[r"C:\Windows\win.ini"]),
            ),
            (
                "Get-Content src\\*.rs",
                Some(&[r"C:\Users\me\dev\repo\src"]),
            ),
            ("Get-Content *.rs", Some(&[r"C:\Users\me\dev\repo"])),
            ("Get-Content C:\\*", Some(&[r"C:\"])),
            ("Get-Content C:*", Some(&[r"C:\Users\me\dev\repo"])),
            ("Get-Content C:x\\*", Some(&[r"C:\Users\me\dev\repo\x"])),
            (
                "Get-Content FileSystem::C:\\Users\\me\\dev\\repo\\x",
                Some(&[r"C:\Users\me\dev\repo\x"]),
            ),
            ("Get-Content FileSystem::C:\\*", Some(&[r"C:\"])),
            (
                "Get-Content \\\\?\\C:\\Users\\me\\dev\\repo\\y",
                Some(&[r"C:\Users\me\dev\repo\y"]),
            ),
            ("Get-ChildItem", Some(&[r"C:\Users\me\dev\repo"])),
            ("Get-ChildItem src", Some(&[r"C:\Users\me\dev\repo\src"])),
            (
                "Get-ChildItem -Recurse src",
                Some(&[r"C:\Users\me\dev\repo\src"]),
            ),
            ("gci -Rec", Some(&[r"C:\Users\me\dev\repo"])),
            (
                "Select-String -Path src\\*.rs -Pattern TODO",
                Some(&[r"C:\Users\me\dev\repo\src"]),
            ),
            ("git status", Some(&[r"C:\Users\me\dev\repo"])),
            ("git -C sub status", Some(&[r"C:\Users\me\dev\repo\sub"])),
            (
                "Get-Content a.txt | Select-Object -First 3",
                Some(&[r"C:\Users\me\dev\repo\a.txt"]),
            ),
            // Not a place on a disk: no path.
            ("Get-Content $null", Some(&[])),
            ("Get-Content HKLM:\\Software", Some(&[])),
            ("Get-Content Env:Path", Some(&[])),
            ("Get-Content D:x", Some(&[])),
            ("Write-Output hi", Some(&[])),
            // Not only a read: no list.
            ("Remove-Item a.txt", None),
            ("Set-Content a.txt hi", None),
            ("Get-Content a.txt > b.txt", None),
            ("Get-Content \\\\server\\share\\x", None),
            ("Get-Content $p", None),
        ],
    );
}

#[test]
fn cmd_paths_are_windows_paths() {
    check(
        Shell::Cmd,
        &windows(),
        &[
            ("type a.txt", Some(&[r"C:\Users\me\dev\repo\a.txt"])),
            ("type ..\\x", Some(&[r"C:\Users\me\dev\x"])),
            ("type C:\\Windows\\win.ini", Some(&[r"C:\Windows\win.ini"])),
            ("type ~\\a", Some(&[r"C:\Users\me\a"])),
            ("type \\Windows\\win.ini", Some(&[r"C:\Windows\win.ini"])),
            ("dir", Some(&[r"C:\Users\me\dev\repo"])),
            ("dir src", Some(&[r"C:\Users\me\dev\repo\src"])),
            ("dir /s src", Some(&[r"C:\Users\me\dev\repo\src"])),
            ("findstr foo *.rs", Some(&[r"C:\Users\me\dev\repo"])),
            (
                "findstr foo src\\*.rs",
                Some(&[r"C:\Users\me\dev\repo\src"]),
            ),
            ("type *.txt", Some(&[r"C:\Users\me\dev\repo"])),
            ("type nul", Some(&[])),
            ("git status", Some(&[r"C:\Users\me\dev\repo"])),
            (
                "type \\\\?\\C:\\Users\\me\\dev\\repo\\y",
                Some(&[r"C:\Users\me\dev\repo\y"]),
            ),
            ("type D:x", Some(&[])),
            ("del a.txt", None),
            ("type \\\\server\\share\\x", None),
        ],
    );
}

#[test]
fn a_workspace_that_is_the_home_folder_lists_what_is_read_there() {
    let home = Paths::new("/home/me", "/home/me", ["/home/me"]);
    check(
        Shell::Posix,
        &home,
        &[
            ("ls", Some(&["/home/me"])),
            ("cat .ssh/config", Some(&["/home/me/.ssh/config"])),
        ],
    );
}

#[test]
fn every_extra_row_agrees_with_effect() {
    // The tables go through `common::path_disagreement` already; these are
    // the lines that mix shells' habits and the spellings of paths.
    let rows = [
        "cat a b *.rs src/*.rs",
        "cd src && rg TODO .. | head",
        "git -C a log -p -- b c",
        "sudo cat /etc/hosts",
        "env LANG=C ls",
        "find . -name '*.log' -exec cat {} +",
        "mkdir x && cat x",
        "cat /*",
        "cat \"\"",
        "echo \"/usr/*\"",
        "ls ~root",
        "cat a >&2",
    ];
    let wrong: Vec<String> = rows
        .iter()
        .filter_map(|line| path_disagreement(Shell::Posix, &posix(), line))
        .collect();
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
fn exact(path: &str) -> ReadPath {
    ReadPath {
        path: PathBuf::from(path),
        how: How::Exact,
    }
}

fn glob(path: &str, rest: &str) -> ReadPath {
    ReadPath {
        path: PathBuf::from(path),
        how: How::Glob(rest.to_string()),
    }
}

fn walk(path: &str, follows_links: bool) -> ReadPath {
    ReadPath {
        path: PathBuf::from(path),
        how: How::Tree { follows_links },
    }
}

/// How each line is read: exact paths, patterns as a folder and the rest,
/// and walks, with whether they open what they find through links.
#[test]
fn each_entry_says_how_it_is_read() {
    let rows: &[(&str, &[ReadPath])] = &[
        ("cat a.txt", &[exact("/home/me/work/repo/a.txt")]),
        ("cat < in.txt", &[exact("/home/me/work/repo/in.txt")]),
        ("ls src", &[exact("/home/me/work/repo/src")]),
        ("ls", &[exact(ROOT)]),
        ("cd src && ls", &[exact("/home/me/work/repo/src")]),
        // A pattern: the folder it expands in, and the rest.
        ("cat *.rs", &[glob(ROOT, "*.rs")]),
        ("cat src/*.rs", &[glob("/home/me/work/repo/src", "*.rs")]),
        (
            "cat src/*/x.rs",
            &[glob("/home/me/work/repo/src", "*/x.rs")],
        ),
        (
            "cat src/**/x.rs",
            &[glob("/home/me/work/repo/src", "**/x.rs")],
        ),
        ("cat ../*/x", &[glob("/home/me/work", "*/x")]),
        ("cat /*", &[glob("/", "*")]),
        ("cat ~/.ssh/*", &[glob("/home/me/.ssh", "*")]),
        ("echo ~/.ssh/*", &[glob("/home/me/.ssh", "*")]),
        ("cat src/a?.rs", &[glob("/home/me/work/repo/src", "a?.rs")]),
        (
            "cat src/[ab].rs",
            &[glob("/home/me/work/repo/src", "[ab].rs")],
        ),
        (
            "cat src/*.rs docs/*.md",
            &[
                glob("/home/me/work/repo/docs", "*.md"),
                glob("/home/me/work/repo/src", "*.rs"),
            ],
        ),
        ("for f in *.rs; do cat \"$f\"; done", &[glob(ROOT, "*.rs")]),
        (
            "for d in a b; do ls $d/*; done",
            &[
                glob("/home/me/work/repo/a", "*"),
                glob("/home/me/work/repo/b", "*"),
            ],
        ),
        // A walk that stays out of links.
        ("rg TODO src", &[walk("/home/me/work/repo/src", false)]),
        ("rg TODO", &[walk(ROOT, false)]),
        ("grep -r x src", &[walk("/home/me/work/repo/src", false)]),
        ("find src -name x", &[walk("/home/me/work/repo/src", false)]),
        ("find . -name '*.rs'", &[walk(ROOT, false)]),
        ("ls -R", &[walk(ROOT, false)]),
        ("ls -R src", &[walk("/home/me/work/repo/src", false)]),
        ("fd -e rs", &[walk(ROOT, false)]),
        ("du -sh target", &[walk("/home/me/work/repo/target", false)]),
        ("git status", &[walk(ROOT, false)]),
        (
            "git -C a -C b log",
            &[walk("/home/me/work/repo/a/b", false)],
        ),
        // A walk that opens what it finds through links.
        ("grep -R x src", &[walk("/home/me/work/repo/src", true)]),
        ("grep -rR x src", &[walk("/home/me/work/repo/src", true)]),
        (
            "grep --dereference-recursive x src",
            &[walk("/home/me/work/repo/src", true)],
        ),
        ("rg -L x src", &[walk("/home/me/work/repo/src", true)]),
        ("rg --follow x src", &[walk("/home/me/work/repo/src", true)]),
        ("rg -nL x src", &[walk("/home/me/work/repo/src", true)]),
        ("fd -L x src", &[walk("/home/me/work/repo/src", true)]),
        ("find -L src", &[walk("/home/me/work/repo/src", true)]),
        ("find src -follow", &[walk("/home/me/work/repo/src", true)]),
        (
            "find src -exec cat {} +",
            &[walk("/home/me/work/repo/src", true)],
        ),
        (
            r"find src -execdir cat {} \;",
            &[walk("/home/me/work/repo/src", true)],
        ),
        (
            "diff -r a b",
            &[
                walk("/home/me/work/repo/a", true),
                walk("/home/me/work/repo/b", true),
            ],
        ),
        // What a lister hands to a program that opens the names.
        (
            "ls src | xargs cat",
            &[walk("/home/me/work/repo/src", true)],
        ),
        ("ls | xargs cat", &[walk(ROOT, true)]),
        ("ls | sort | xargs cat", &[walk(ROOT, true)]),
        ("git ls-files | xargs cat", &[walk(ROOT, true)]),
        ("fd -e rs | xargs cat", &[walk(ROOT, true)]),
        (
            "find src -name '*.rs' | xargs cat",
            &[walk("/home/me/work/repo/src", true)],
        ),
        (
            "find src -print0 | xargs -0 grep x",
            &[walk("/home/me/work/repo/src", true)],
        ),
        (
            "ls src/* | xargs cat",
            &[walk("/home/me/work/repo/src", true)],
        ),
        // A lister whose names nothing opens is only read.
        ("ls src | head -n 5", &[exact("/home/me/work/repo/src")]),
        ("ls src | wc -l", &[exact("/home/me/work/repo/src")]),
        // The same folder read two ways keeps the stronger.
        (
            "cat src; rg x src",
            &[walk("/home/me/work/repo/src", false)],
        ),
        (
            "rg x src; grep -R y src",
            &[walk("/home/me/work/repo/src", true)],
        ),
        (
            "rg x src; ls src | xargs cat",
            &[walk("/home/me/work/repo/src", true)],
        ),
    ];
    let wrong: Vec<String> = rows
        .iter()
        .filter_map(|(line, want)| {
            let got = effect_paths(line, Shell::Posix, &posix());
            (got.as_deref() != Some(*want))
                .then(|| format!("{line}\n    want {want:?}\n    got  {got:?}"))
        })
        .collect();
    assert!(
        wrong.is_empty(),
        "{} rows wrong:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// The rest of a pattern is what is written after its fixed folder, as
/// written, so the caller expands the same pattern: a leading dot is part of
/// it when the pattern starts at the working directory.
#[test]
fn a_leading_dot_stays_in_the_rest_of_a_pattern() {
    let src = "/home/me/work/repo/src";
    let rows: &[(&str, &[ReadPath])] = &[
        ("cat .a*/x", &[glob(ROOT, ".a*/x")]),
        ("cat .??/x", &[glob(ROOT, ".??/x")]),
        ("cat .*", &[exact("/home/me/work"), glob(ROOT, ".*")]),
        ("ls .*", &[exact("/home/me/work"), glob(ROOT, ".*")]),
        ("cat .[a-z]*/x", &[glob(ROOT, ".[a-z]*/x")]),
        ("cat ./*.rs", &[glob(ROOT, "*.rs")]),
        ("cat ./.*", &[exact("/home/me/work"), glob(ROOT, ".*")]),
        ("cat a.*", &[glob(ROOT, "a.*")]),
        ("cat src/.*rc", &[glob(src, ".*rc")]),
        ("cat src/.[a-z]*/x", &[glob(src, ".[a-z]*/x")]),
        (
            "cat x/.*",
            &[exact(ROOT), glob("/home/me/work/repo/x", ".*")],
        ),
        ("cat ~/.*rc", &[glob("/home/me", ".*rc")]),
        (
            "cat ../.*",
            &[exact("/home/me"), glob("/home/me/work", ".*")],
        ),
        ("cat /.*", &[exact("/"), glob("/", ".*")]),
        (
            "cat src/*.rs lib/*.rs",
            &[glob("/home/me/work/repo/lib", "*.rs"), glob(src, "*.rs")],
        ),
        ("cat ?x/y", &[glob(ROOT, "?x/y")]),
        ("cat src/[ab]/x", &[glob(src, "[ab]/x")]),
    ];
    let wrong: Vec<String> = rows
        .iter()
        .filter_map(|(line, want)| {
            let got = effect_paths(line, Shell::Posix, &posix());
            (got.as_deref() != Some(*want))
                .then(|| format!("{line}\n    want {want:?}\n    got  {got:?}"))
        })
        .collect();
    assert!(
        wrong.is_empty(),
        "{} rows wrong:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
    // The folder and the rest, put together, are the pattern as written.
    for line in [
        "cat .a*/x",
        "cat .*",
        "cat src/.*rc",
        "cat a.*",
        "cat src/*/x.rs",
    ] {
        let pattern = line.strip_prefix("cat ").unwrap();
        let reads = effect_paths(line, Shell::Posix, &posix()).unwrap();
        let joined = reads.iter().any(|read| match &read.how {
            How::Glob(rest) => {
                let folder = read.path.to_string_lossy();
                let whole = format!("{folder}/{rest}");
                whole == format!("{ROOT}/{pattern}")
            }
            _ => false,
        });
        assert!(joined, "{line}: {reads:?}");
    }
    // The same in PowerShell and cmd.
    let win = windows();
    let root = r"C:\Users\me\dev\repo";
    assert_eq!(
        effect_paths("Get-Content .a*\\x", Shell::PowerShell, &win),
        Some(vec![glob(root, ".a*\\x")])
    );
    assert_eq!(
        effect_paths("type .*", Shell::Cmd, &win)
            .unwrap()
            .into_iter()
            .filter(|read| matches!(read.how, How::Glob(_)))
            .collect::<Vec<_>>(),
        vec![glob(root, ".*")]
    );
}

/// A walker stays out of links only when every flag it is given is one its
/// own list says does not change that: any other flag, an abbreviation
/// included, and any reader that is not listed, follows them.
#[test]
fn a_walk_stays_out_of_links_only_with_flags_known_not_to_follow_them() {
    let src = "/home/me/work/repo/src";
    let rows: &[(&str, bool)] = &[
        // Stays out.
        ("ls -R src", false),
        ("ls -laR src", false),
        ("ls -R -a src", false),
        ("ls --recursive src", false),
        ("ls --recursive --all --color=never src", false),
        ("du -sh src", false),
        ("du -a src", false),
        ("du -d 2 src", false),
        ("du --max-depth=2 src", false),
        ("du -P src", false),
        ("grep -r x src", false),
        ("grep -rn x src", false),
        ("grep -rniI x src", false),
        ("grep -rn --include='*.rs' x src", false),
        ("grep -r -e x -e y src", false),
        ("grep -rA3 x src", false),
        ("grep -rO x src", false),
        ("grep -rp x src", false),
        ("grep -r -- -L src", false),
        ("grep --recursive x src", false),
        ("rg x src", false),
        ("rg -n --no-heading x src", false),
        ("rg -g '*.rs' x src", false),
        ("rg -A3 -i x src", false),
        ("rg --glob=*.rs --hidden x src", false),
        ("rg -t rust x src", false),
        ("fd x src", false),
        ("fd -e rs -H x src", false),
        ("fd -t f x src", false),
        ("find src", false),
        ("find src -name x -type f", false),
        ("find src -name x -type f -print0", false),
        ("find -H src", false),
        ("find src -maxdepth 2 -mtime -3", false),
        ("git status", false),
        ("git log -p --stat", false),
        // Follows: a flag that opens through links.
        ("ls -RL src", true),
        ("ls -LR src", true),
        ("ls -R -L src", true),
        ("ls --dereference -R src", true),
        ("ls -RH src", true),
        ("ls -R --dereference-command-line src", true),
        ("du -L src", true),
        ("du -aL src", true),
        ("du --dereference src", true),
        ("du -H src", true),
        ("grep -R x src", true),
        ("grep -rS x src", true),
        ("grep -r -S x src", true),
        ("grep --dereference-recursive x src", true),
        ("rg -L x src", true),
        ("rg -uL x src", true),
        ("rg --follow x src", true),
        ("fd -L x src", true),
        ("fd -HL x src", true),
        ("fd --follow x src", true),
        ("find -L src", true),
        ("find src -follow", true),
        ("find src -name x -follow", true),
        ("find src -xtype l", true),
        ("find src -exec cat {} +", true),
        (r"find src -execdir cat {} ;", true),
        (r"find src -ok cat {} ;", true),
        // Follows: any other flag, and an abbreviation.
        ("ls -R --recurs src", true),
        ("ls -R --colo src", true),
        ("ls -R -Z src", true),
        ("du --max src", true),
        ("grep -r --recurs x src", true),
        ("grep -r --binary x src", true),
        ("grep -r -X x src", true),
        ("rg --max-c 3 x src", true),
        ("rg --no-follow x src", true),
        ("rg --some-new-flag x src", true),
        ("fd --max-d 2 x src", true),
        ("find src -fstype ext4", true),
        ("find src -newerct x", true),
        ("git diff --no-index a b", true),
        // Follows: a reader the guard does not know to stay out of links.
        ("diff -r a b", true),
        ("diff -r --no-dereference a b", true),
    ];
    let wrong: Vec<String> = rows
        .iter()
        .filter_map(|(line, follows)| {
            let got = effect_paths(line, Shell::Posix, &posix());
            // The walk is the one root the row names; a row's other reads
            // do not matter, only whether any walk follows links.
            let follows_any = got.as_ref().map(|reads| {
                reads.iter().any(|read| {
                    read.how
                        == How::Tree {
                            follows_links: true,
                        }
                })
            });
            let walks = got.as_ref().is_some_and(|reads| {
                reads
                    .iter()
                    .any(|read| matches!(read.how, How::Tree { .. }))
            });
            (follows_any != Some(*follows) || !walks)
                .then(|| format!("{line}\n    want follows_links {follows}\n    got  {got:?}"))
        })
        .collect();
    let _ = src;
    assert!(
        wrong.is_empty(),
        "{} rows wrong:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

#[test]
fn powershell_and_cmd_walks_are_taken_to_follow_links() {
    let win = windows();
    let root = r"C:\Users\me\dev\repo";
    for (shell, line, want) in [
        (
            Shell::PowerShell,
            "Get-ChildItem -Recurse src",
            vec![walk(&format!(r"{root}\src"), true)],
        ),
        (Shell::PowerShell, "gci -Rec", vec![walk(root, true)]),
        (
            Shell::PowerShell,
            "Get-ChildItem src",
            vec![exact(&format!(r"{root}\src"))],
        ),
        (
            Shell::PowerShell,
            "Get-ChildItem src | Get-Content",
            vec![walk(&format!(r"{root}\src"), true)],
        ),
        (
            Shell::PowerShell,
            "Get-Content src\\*.rs",
            vec![glob(&format!(r"{root}\src"), "*.rs")],
        ),
        (
            Shell::PowerShell,
            "Get-Content C:\\*",
            vec![glob(r"C:\", "*")],
        ),
        (Shell::PowerShell, "Get-Content C:*", vec![glob("C:", "*")]),
        (
            Shell::Cmd,
            "dir /s src",
            vec![walk(&format!(r"{root}\src"), true)],
        ),
        (
            Shell::Cmd,
            "findstr foo src\\*.rs",
            vec![glob(&format!(r"{root}\src"), "*.rs")],
        ),
        (
            Shell::Cmd,
            "type a.txt",
            vec![exact(&format!(r"{root}\a.txt"))],
        ),
    ] {
        let got = effect_paths(line, shell, &win);
        // `C:*` on the drive of the working directory is its working directory.
        let want = if line == "Get-Content C:*" {
            vec![glob(root, "*")]
        } else {
            want
        };
        assert_eq!(got, Some(want), "{line}");
    }
}

#[test]
fn a_long_path_and_a_provider_prefix_are_not_patterns() {
    let win = windows();
    let root = r"C:\Users\me\dev\repo";
    for line in [
        r"Get-Content \\?\C:\Users\me\dev\repo\x",
        r"Get-Content FileSystem::\\?\C:\Users\me\dev\repo\x",
        r"Get-Content FileSystem::C:\Users\me\dev\repo\x",
        r"Get-Content Microsoft.PowerShell.Core\FileSystem::\\?\C:\Users\me\dev\repo\x",
    ] {
        assert_eq!(
            effect_paths(line, Shell::PowerShell, &win),
            Some(vec![exact(&format!(r"{root}\x"))]),
            "{line}"
        );
    }
    // A pattern behind either is still one.
    assert_eq!(
        effect_paths(
            r"Get-Content \\?\C:\Users\me\dev\repo\*.rs",
            Shell::PowerShell,
            &win
        ),
        Some(vec![glob(root, "*.rs")])
    );
    assert_eq!(
        effect_paths(
            r"Get-Content FileSystem::\\?\C:\Users\me\dev\repo\*.rs",
            Shell::PowerShell,
            &win
        ),
        Some(vec![glob(root, "*.rs")])
    );
}

/// The caller's side of the contract, with the disk played by a table of
/// links and files (the guard itself does no I/O, and neither do its tests): a
/// link in the workspace that points out of it reads as `Workspace` by
/// spelling, and checking each entry as the docs say finds where it really
/// goes. Every way of reading is covered: exact, a pattern the shell expands
/// across a link, a walk that follows links, and names a lister hands on.
#[test]
fn a_link_that_leaves_the_workspace_is_found_by_checking_each_entry() {
    const LINKS: [(&str, &str); 3] = [
        ("/home/me/work/repo/link", "/home/me/.ssh"),
        ("/home/me/work/repo/src/a", "/home/me"),
        ("/home/me/work/repo/a.rs", "/home/me/.ssh/id_rsa"),
    ];
    // Every name on the disk, as spelled (links included).
    const FILES: [&str; 8] = [
        "/home/me/work/repo/a.rs",
        "/home/me/work/repo/b.rs",
        "/home/me/work/repo/src/a",
        "/home/me/work/repo/src/a/x.rs",
        "/home/me/work/repo/src/b",
        "/home/me/work/repo/src/b/x.rs",
        "/home/me/work/repo/link",
        "/home/me/work/repo/link/id_rsa",
    ];

    /// Where `path` really is: each link on the way is followed, and the
    /// names below one that does not exist are put back.
    fn resolve(path: &str) -> String {
        let mut at = String::new();
        for name in path.split('/').filter(|name| !name.is_empty()) {
            at = format!("{at}/{name}");
            if let Some((_, to)) = LINKS.iter().find(|(from, _)| *from == at) {
                at = (*to).to_string();
            }
        }
        at
    }
    let inside = |real: &str| real == ROOT || real.starts_with(&format!("{ROOT}/"));
    /// Whether `name` matches one part of a pattern with `*` in it.
    fn part(pattern: &str, name: &str) -> bool {
        match pattern.split_once('*') {
            Some((head, tail)) => {
                name.len() >= head.len() + tail.len()
                    && name.starts_with(head)
                    && name.ends_with(tail)
            }
            None => pattern == name,
        }
    }
    /// The names a pattern picks: the folder, then the parts of the rest.
    fn expand(folder: &str, rest: &str) -> Vec<String> {
        let mut found = vec![folder.to_string()];
        for pattern in rest.split('/') {
            found = FILES
                .iter()
                .map(|file| (*file).to_string())
                .filter(|file| {
                    found.iter().any(|from| {
                        file.strip_prefix(&format!("{from}/"))
                            .is_some_and(|name| part(pattern, name))
                    })
                })
                .collect();
        }
        found
    }

    let paths = posix();
    let leaves = |line: &str| {
        effect_paths(line, Shell::Posix, &paths)
            .unwrap()
            .iter()
            .any(|read| {
                let path = read.path.to_string_lossy();
                match &read.how {
                    How::Exact
                    | How::Tree {
                        follows_links: false,
                    } => !inside(&resolve(&path)),
                    How::Glob(rest) => {
                        !inside(&resolve(&path))
                            || expand(&path, rest)
                                .iter()
                                .any(|name| !inside(&resolve(name)))
                    }
                    How::Tree {
                        follows_links: true,
                    } => true,
                }
            })
    };
    // Judged by spelling, all of them stay in the workspace; on the disk,
    // each reads what a link points at.
    for line in [
        "cat link/id_rsa",
        "ls link",
        "rg TODO link",
        "cat link/*",
        "cd link && ls",
        "cat src/../link/id_rsa",
        "cat *.rs",
        "cat src/*/x.rs",
        "for f in *.rs; do cat \"$f\"; done",
        "ls src | xargs cat",
        "git ls-files | xargs cat",
        "find src -exec cat {} +",
        "grep -R x src",
        "rg -L x src",
        "rg --follow x src",
        "find -L src",
    ] {
        assert_eq!(
            effect(line, Shell::Posix, &paths),
            Effect::ReadsOnly(Reach::Workspace),
            "{line}"
        );
        assert!(leaves(line), "{line}");
    }
    // What is in the workspace stays in it.
    for line in [
        "cat src/b/x.rs",
        "cat b.rs",
        "cat src/b/*.rs",
        "ls",
        "rg TODO src/b",
        "grep -r x src/b",
        "find src/b -name x",
        "git status",
        "ls -R src/b",
    ] {
        assert!(!leaves(line), "{line}");
    }
    assert_eq!(
        resolve("/home/me/work/repo/link/id_rsa"),
        "/home/me/.ssh/id_rsa"
    );
}
