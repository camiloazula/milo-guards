//! Everyday commands stay safe through the front door: what an agent runs all
//! day in a POSIX shell, in PowerShell and in cmd needs no one to ask. Each
//! line is also held to the shell guard's own agreement checks: its `effect`,
//! `explain` and `effect_paths` agree with `classify`.

#![cfg(feature = "shell")]

#[path = "../../shell/tests/common/mod.rs"]
mod common;

use milo_guards_core::testing;
use milo_local_guards::shell::{self, Shell};
use milo_local_guards::Paths;

/// Every line is safe through `milo_local_guards::shell`, and agrees with
/// the shell guard's other answers; the lines that do not are named together.
fn stays_safe(kind: Shell, paths: &Paths, lines: &[&str]) {
    let wrong = common::disagreements(kind, paths, lines.iter().copied());
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    testing::check(lines, &[], |line| shell::classify(line, kind, paths));
}

#[test]
fn everyday_posix_lines_are_safe() {
    stays_safe(
        Shell::Posix,
        &common::posix(),
        &[
            "",
            "ls -la",
            "cargo build && cargo test -- --nocapture",
            "git status; git diff HEAD~1 | less",
            "git commit -m 'undo reset --hard and rm -rf /'",
            "echo \"rm -rf /\"",
            "grep -rn 'rm -rf' docs/",
            "rm build.log",
            "rm -rf target",
            "rm -rf ./node_modules dist/*",
            "rm -r -f -- target",
            "\\rm -fr target/debug",
            "rm -rf /tmp/scratch-test-123",
            "rm -f *.log",
            "sed -i 's/a/b/' src/lib.rs",
            "sed -i '' -e 's/a/b/' README.md",
            "sed -n 's/a/b/p' ~/.zshrc",
            "find src -type f | xargs --max-args 10 rm -f",
            "git push --dry-run",
            "git clean -n -d",
            "git switch main",
            "mkdir -p target/out",
            "touch src/new.rs",
            "mkdir -p /tmp/scratch",
            "and cargo test",
            "perl -pi -e 's/a/b/' src/lib.rs",
            "perl -i.bak -pe 's/foo/bar/g' README.md",
            "perl -pi -e 's/a/b/; tr/x/y/' src/a.rs src/b.rs",
            "perl -pi -e 's|/usr/bin|/opt/bin|g' scripts/run.sh",
            "rm -f */*.o",
            "rm -f **/*.log",
            "rm c:foo",
            "git config --get core.pager",
            "git config core.editor",
            "git config --unset core.pager",
            "bash -o pipefail scripts/test.sh",
            "curl -fsSLo data.json https://x.example/d.json && jq . data.json",
            "cat <<'EOF' > notes.md\ndon't\nEOF",
            "find . -path './src/*.tmp' -delete",
            "python3 -E script.py",
            "ruby -E utf-8 script.rb",
            "perl -pi.bak script.pl",
            "cp -r ~/.config dist/",
            "ln -s src/lib.rs target/link",
            "find . -name '*.pyc' -delete",
            "find . -name '*.log' -exec rm {} +",
            "git config user.name 'A'",
            "git -c user.name=A commit -m x",
            "flock /tmp/l cargo build",
            "taskset 1 cargo test",
            "screen -dm cargo watch",
            "git switch -c feature",
            "crontab -l",
            "rm -rf src/*/target",
            "awk '{print $1}' data.txt",
            "awk -F, '$2 > 5 || $3 == \"x\" {print $1}' data.csv",
            "awk '{print > \"/dev/stderr\"}' data.txt",
            "rsync -avz -e 'ssh -p 22' build/ server:/srv/app",
            "echo hi # a note \\\nls",
            "rm -f -- *.tmp src/*.bak",
            "rm -rf \"$TMPDIR/scratch\"",
            "find . -name '*.o' -exec rm {} \\;",
            "find src -type f | xargs rm -f",
            "mv old.rs new.rs",
            "cp -r assets/ dist/assets",
            "cp report.txt /tmp/",
            "echo hi > out.txt 2>&1",
            "cargo test 2>/dev/null >> log.txt",
            "make > /dev/null",
            "tee -a build.log < input",
            "dd if=/dev/zero of=./disk.img bs=1M count=10",
            "chmod +x scripts/run.sh",
            "chmod -R 755 .",
            "chmod -x tool.sh",
            "git checkout -b feature",
            "git checkout main",
            "git reset --soft HEAD~1",
            "git clean -n",
            "git branch -d merged-branch",
            "git push -u origin feature",
            "git stash pop",
            "git restore --staged src/lib.rs",
            "git -C ../other status",
            "kill 4242",
            "kill -9 4242",
            "timeout 5 cargo test",
            "env RUST_LOG=debug cargo run",
            "nice -n 10 make",
            "bash scripts/test.sh",
            "bash -c 'cargo fmt && cargo clippy'",
            "sh -c \"echo $HOME\"",
            "python3 -m json.tool data.json",
            "python3 script.py",
            "curl -fsSL https://example.com/x.json -o data.json",
            "curl https://example.com | jq .",
            "command -v rm",
            "for f in *.txt; do wc -l \"$f\"; done",
            "if [ -d target ]; then rm -rf target; fi",
            "(cd crates && cargo check)",
            "echo $(git rev-parse HEAD)",
            "cat <<'EOF' > notes.md\nhello\nEOF",
            "fdisk -l",
            "systemctl status nginx",
            "shutdown -c",
        ],
    );
}

#[test]
fn everyday_powershell_lines_are_safe() {
    stays_safe(
        Shell::PowerShell,
        &common::windows(),
        &[
            "Get-ChildItem -Recurse",
            "cargo build; cargo test",
            "git status && git diff",
            "Remove-Item -Recurse -Force .\\target",
            "rm -r -fo target",
            "Remove-Item -Path:\"$env:TEMP\\scratch\" -Recurse",
            "Get-ChildItem -Path .\\out -Filter *.tmp | Remove-Item -Force",
            "Get-ChildItem *.log | ForEach-Object { Remove-Item $_.FullName }",
            "Copy-Item src\\a.txt dist\\a.txt",
            "Move-Item old.txt new.txt",
            "Set-Content -Path notes.txt -Value hi",
            "\"x\" | Out-File log.txt",
            "cargo test > out.txt 2>&1",
            "cargo test > $null",
            "Invoke-WebRequest https://example.com/x.json -OutFile data.json",
            "git push -u origin feature",
            "pwsh -NoProfile -Command \"cargo fmt\"",
            "pwsh -Version",
            "Write-Output 'Remove-Item -Recurse C:\\'",
            "[Math]::Round(1.5)",
            "$sw = [Diagnostics.Stopwatch]::StartNew(); $sw.Start()",
            "$name.Replace('a', 'b')",
            "ni -ItemType File notes.txt",
        ],
    );
}

#[test]
fn everyday_cmd_lines_are_safe() {
    stays_safe(
        Shell::Cmd,
        &common::windows(),
        &[
            "dir /b",
            "cargo build && cargo test",
            "rmdir /s/q build",
            "rd C:\\empty-folder-cmd-refuses-to-delete-unless-empty",
            "del /f /q build\\*.obj",
            "del /s /q %TEMP%\\scratch",
            "copy a.txt b.txt",
            "echo hi > out.txt 2>&1",
            "cargo test 2>nul",
            "if exist build (rd /s /q build) else echo none",
            "for %%f in (*.tmp) do echo %%f",
            "git status | findstr modified",
            "start \"\" notepad notes.txt",
            "shutdown /a",
            "rem build & deploy",
            "cd.. & dir",
            "cd src & del /q *.obj",
        ],
    );
}
