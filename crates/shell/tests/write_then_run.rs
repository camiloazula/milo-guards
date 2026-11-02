//! A script the line writes and then runs is `unknown`: the line writes it,
//! so what it does is not in the line. However it is run (handed to a POSIX
//! shell, run as the program itself by its path, with `powershell -File`,
//! `pwsh -File` or `Invoke-Command -FilePath`, by cmd's look in the working
//! folder before `PATH`), and however it is written (by a redirect, a
//! download, a copy, a write cmdlet's named or positional path). Where the
//! name the line writes cannot be read for sure (a pattern, an operand that
//! may be a list, a name only known when it runs, more patterns than the
//! guard reads), a run that may be of that file is not safe either. The work
//! for each run is bounded whatever the line writes.

mod common;

use std::time::Duration;

use common::{check, classify, posix, took, windows};
use milo_guards_shell::{Rule, Shell};

#[test]
fn a_file_the_line_writes_and_runs_by_its_path_is_a_script_nobody_can_read() {
    check(
        Shell::Posix,
        &posix(),
        &[
            // Nothing written first: a program by its path is only a program.
            "./gradlew build",
            "./x.sh",
            "x/run",
            "/usr/local/bin/tool --help",
            "./gradlew build > build.log",
            "./gradlew build 2>/dev/null",
            "echo hi > out.txt; ./gradlew build",
            "make > build.log; ./a.out",
            "./configure > config.log; make; ./a.out",
            "cargo build 2> err.log; ./target/debug/app",
            "npm test > out.log; ./node_modules/.bin/jest",
            // A download of something else, an unpacked archive.
            "curl -o x.tar.gz https://x.example/x.tar.gz; ./configure",
            "tar xzf x.tar.gz; ./x/configure",
            // A bare name is looked up in PATH, not in the folder.
            "echo 'rm -rf ~' > x.sh; x.sh",
            // A different file than the one written.
            "echo 'rm -rf ~' > y.sh; ./x.sh",
            "echo 'rm -rf ~' > x.sh; ./sub/x.sh",
            "echo 'rm -rf ~' > x.sh; ../x.sh",
            "echo 'rm -rf ~' > x.sh; /tmp/x.sh",
            "echo 'rm -rf ~' > x.sh; ~/x.sh",
            "cd sub; echo 'rm -rf ~' > x.sh; cd ..; ./x.sh",
            // Run from a folder that cannot be placed, with nothing written.
            "cd \"$(git rev-parse --show-toplevel)\" && ./gradlew build",
        ],
        &[
            ("echo 'rm -rf ~' > x.sh; ./x.sh", Rule::Unknown),
            (
                "curl -o run https://x.example/r; chmod +x run; ./run",
                Rule::Unknown,
            ),
            // Every way the file is written.
            (
                "curl -fsSLo run https://x.example/r && chmod +x run && ./run",
                Rule::Unknown,
            ),
            (
                "wget -O run https://x.example/r; chmod +x run; ./run",
                Rule::Unknown,
            ),
            (
                "curl -O https://x.example/install.sh; ./install.sh",
                Rule::Unknown,
            ),
            ("printf 'rm -rf ~' > x.sh; ./x.sh", Rule::Unknown),
            ("echo 'rm -rf ~' | tee x.sh; ./x.sh", Rule::Unknown),
            ("cp evil x.sh; ./x.sh", Rule::Unknown),
            ("echo 'rm -rf ~' >> x.sh; ./x.sh", Rule::Unknown),
            // Every way the path is written.
            ("echo hi > x/run; x/run", Rule::Unknown),
            ("echo hi > sub/x.sh; sub/x.sh", Rule::Unknown),
            ("echo hi > sub/x.sh; ./sub/x.sh", Rule::Unknown),
            ("echo hi > sub/x.sh; ./sub/../sub/x.sh", Rule::Unknown),
            ("echo hi > ./x.sh; ./x.sh", Rule::Unknown),
            ("echo hi > x.sh; ././x.sh", Rule::Unknown),
            ("echo hi > x.sh; ./x.sh arg --flag", Rule::Unknown),
            ("echo hi > /tmp/x; /tmp/x", Rule::Unknown),
            (
                "curl -fsSL -o /tmp/i https://x.example/i; /tmp/i",
                Rule::Unknown,
            ),
            ("echo hi > ~/x.sh; ~/x.sh", Rule::Unknown),
            ("echo hi > \"$HOME/x.sh\"; \"$HOME/x.sh\"", Rule::Unknown),
            ("echo hi > /home/me/work/repo/x.sh; ./x.sh", Rule::Unknown),
            // Where the line is when it runs.
            ("cd sub; echo hi > x.sh; ./x.sh", Rule::Unknown),
            ("echo hi > sub/x.sh; cd sub; ./x.sh", Rule::Unknown),
            ("echo hi > x.sh; cd sub; ../x.sh", Rule::Unknown),
            // The program wrapped or nested.
            ("echo hi > x.sh; sudo ./x.sh", Rule::Unknown),
            ("echo hi > x.sh; env FOO=1 ./x.sh", Rule::Unknown),
            ("echo hi > x.sh; nohup ./x.sh", Rule::Unknown),
            ("echo hi > x.sh; time ./x.sh", Rule::Unknown),
            ("echo hi > x.sh; exec ./x.sh", Rule::Unknown),
            ("echo hi > x.sh; command ./x.sh", Rule::Unknown),
            ("echo hi > x.sh; xargs ./x.sh", Rule::Unknown),
            ("echo hi > x.sh; find . -exec ./x.sh {} \\;", Rule::Unknown),
            ("echo hi > x.sh; bash -c './x.sh'", Rule::Unknown),
            ("echo hi > x.sh; sh -c \"./x.sh\"", Rule::Unknown),
            ("echo hi > x.sh; ./x.sh | cat", Rule::Unknown),
            ("echo hi > x.sh; ./x.sh &", Rule::Unknown),
            ("echo hi > x.sh; ./x.sh > /dev/null", Rule::Unknown),
            ("echo hi > x.sh; (./x.sh)", Rule::Unknown),
            ("echo hi > x.sh; { ./x.sh; }", Rule::Unknown),
            ("echo hi > x.sh; true && ./x.sh", Rule::Unknown),
            ("echo hi > x.sh; if true; then ./x.sh; fi", Rule::Unknown),
            (
                "echo hi > x.sh; for i in 1 2; do ./x.sh; done",
                Rule::Unknown,
            ),
            // Run before it is written: a loop, a function, a trap.
            ("./x.sh; echo hi > x.sh", Rule::Unknown),
            ("f() { ./x.sh; }; echo hi > x.sh; f", Rule::Unknown),
            ("trap './x.sh' EXIT; echo 'rm -rf ~' > x.sh", Rule::Unknown),
            ("trap ./x.sh EXIT; echo 'rm -rf ~' > x.sh", Rule::Unknown),
            (
                "trap \"./x.sh\" EXIT; printf 'rm -rf ~' > x.sh",
                Rule::Unknown,
            ),
            (
                "trap './x.sh' EXIT; curl -o x.sh https://x.example/x",
                Rule::Unknown,
            ),
            // From a folder that cannot be placed, with a file written.
            ("cd $DIR && echo hi > i.sh && ./i.sh", Rule::Unknown),
            ("echo hi > i.sh; cd $DIR; ./i.sh", Rule::Unknown),
            ("cd $DIR; echo hi | tee i.sh; ./i.sh", Rule::Unknown),
        ],
    );
    check(
        Shell::PowerShell,
        &windows(),
        &[
            ".\\gradlew.bat build",
            ".\\gradlew.bat build > build.log",
            "'x' > out.txt; .\\gradlew.bat build",
            // A bare name is not looked up in the folder.
            "Set-Content -Path x.ps1 -Value x; x.ps1",
            "Set-Content -Path x.ps1 -Value x; .\\y.ps1",
            "cd $env:X; .\\run.ps1",
        ],
        &[
            ("'x' > x.ps1; .\\x.ps1", Rule::Unknown),
            ("'x' > x.ps1; & .\\x.ps1", Rule::Unknown),
            ("'x' > x.ps1; . .\\x.ps1", Rule::Unknown),
            ("'x' > x.ps1; & ./x.ps1", Rule::Unknown),
            ("Set-Content -Path x.ps1 -Value x; .\\x.ps1", Rule::Unknown),
            ("Set-Content -Path x.ps1 -Value x; & .\\x.ps1", Rule::Unknown),
            // Windows file names are not case sensitive.
            ("Set-Content -Path x.ps1 -Value x; .\\X.PS1", Rule::Unknown),
            // A name with no extension runs the file with one: `.ps1`
            // first, then the executable extensions.
            ("Set-Content -Path x.ps1 -Value x; .\\x", Rule::Unknown),
            ("'x' > x.ps1; .\\x", Rule::Unknown),
            (
                "Invoke-WebRequest https://x.example/i.ps1 -OutFile i.ps1; .\\i",
                Rule::Unknown,
            ),
            ("Set-Content -Path x.bat -Value x; .\\x", Rule::Unknown),
            ("Set-Content -Path x.bat -Value x; & .\\x.bat", Rule::Unknown),
            (
                "Invoke-WebRequest https://x.example/i.ps1 -OutFile i.ps1; .\\i.ps1",
                Rule::Unknown,
            ),
            (
                "Invoke-WebRequest https://x.example/i.ps1 -OutFile i.ps1; C:\\Users\\me\\dev\\repo\\i.ps1",
                Rule::Unknown,
            ),
            ("cd $env:X; 'x' > i.ps1; .\\i.ps1", Rule::Unknown),
        ],
    );
}

/// cmd looks in the working folder before `PATH`, so a bare name is the file
/// the line wrote when it names one, and a name with no extension runs the
/// file with one of the executable extensions.
#[test]
fn a_cmd_program_the_line_writes_is_a_script_nobody_can_read() {
    check(
        Shell::Cmd,
        &windows(),
        &[
            "gradlew.bat build",
            "gradlew build > build.log",
            "echo hi > out.txt & gradlew.bat build",
            "echo hi > out.txt & dir",
            "echo hi > out.txt & echo done",
            "echo hi > out.txt & del out.txt",
            "echo del x > b.bat & a.bat",
        ],
        &[
            ("echo del x > a.bat & a.bat", Rule::Unknown),
            ("echo del x > a.bat & a", Rule::Unknown),
            ("echo del x > a.cmd & a", Rule::Unknown),
            ("echo del x > a.exe & a", Rule::Unknown),
            ("echo del x > A.BAT & a.bat", Rule::Unknown),
            ("echo del x > a.bat && call a.bat", Rule::Unknown),
            ("echo del x > a.bat && start a.bat", Rule::Unknown),
            ("echo del x > a.bat && cmd /c a.bat", Rule::Unknown),
            (
                "curl -o i.bat https://x.example/i.bat & i.bat",
                Rule::Unknown,
            ),
        ],
    );
}

/// A script the line writes and then runs with `powershell -File` (or `pwsh
/// -File`, `Invoke-Command -FilePath`) is the same script as one run by its
/// path or handed to a POSIX shell.
#[test]
fn a_script_the_line_writes_and_runs_with_file_is_a_script_nobody_can_read() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            // Nothing written first: a script is only a script.
            "powershell -File scripts\\build.ps1",
            "powershell -File .\\scripts\\build.ps1",
            "powershell -NoProfile -ExecutionPolicy Bypass -File build.ps1 -Verbose",
            "pwsh -File build.ps1",
            "pwsh build.ps1",
            "pwsh -NoProfile -File C:\\tools\\setup.ps1",
            "& .\\build.ps1",
            ".\\build.ps1",
            ". .\\profile.ps1",
            "Invoke-Command -FilePath scripts\\build.ps1",
            "powershell -WorkingDirectory sub -File i.ps1",
            "powershell -File",
            // Something else written first.
            "'x' > out.txt; powershell -File build.ps1",
            "'x' > out.txt; & .\\build.ps1",
            "cargo build > build.log; powershell -File build.ps1",
            "Invoke-WebRequest https://x.example/x.json -OutFile data.json; pwsh -File build.ps1",
            // A different file than the one written.
            "'x' > j.ps1; powershell -File i.ps1",
            "'x' > sub\\i.ps1; powershell -File i.ps1",
            "'x' > i.ps1; powershell -File sub\\i.ps1",
            "'x' > i.ps1; pwsh -File ..\\i.ps1",
            "Set-Location sub; 'x' > i.ps1; Set-Location ..; powershell -File i.ps1",
            "'x' > i.ps1; Invoke-Command -FilePath other.ps1",
            // The script is not a file the line names.
            "'x' > i.ps1; powershell -Command ls",
            "'x' > i.ps1; pwsh -c ls",
            "'x' > i.ps1; Invoke-Command -ScriptBlock { ls }",
            // Run from a folder that cannot be placed, with nothing written.
            "Set-Location $d; powershell -File i.ps1",
        ],
        &[
            // The download is an unknown script, as the POSIX forms are;
            // only a pipe into a shell is a `RunDownloaded`.
            ("'x' > i.ps1; powershell -File i.ps1", Rule::Unknown),
            (
                "Invoke-WebRequest https://x.example/a.ps1 -OutFile i.ps1; powershell -File i.ps1",
                Rule::Unknown,
            ),
            ("'x' > i.ps1; pwsh -File i.ps1", Rule::Unknown),
            (
                "Invoke-WebRequest https://x.example/a.ps1 -OutFile i.ps1; pwsh -File i.ps1",
                Rule::Unknown,
            ),
            (
                "iwr https://x.example/a.ps1 -OutFile i.ps1; powershell -File i.ps1",
                Rule::Unknown,
            ),
            ("'x' > i.ps1; & .\\i.ps1", Rule::Unknown),
            (
                "iwr https://x.example/a.ps1 -OutFile i.ps1; & .\\i.ps1",
                Rule::Unknown,
            ),
            ("'x' > i.ps1; .\\i.ps1", Rule::Unknown),
            (
                "iwr https://x.example/a.ps1 -OutFile i.ps1; .\\i.ps1",
                Rule::Unknown,
            ),
            // Every way the file is written.
            ("Set-Content -Path i.ps1 -Value x; powershell -File i.ps1", Rule::Unknown),
            ("'x' | Out-File -FilePath i.ps1; pwsh -File i.ps1", Rule::Unknown),
            ("Add-Content -Path i.ps1 -Value x; pwsh -File i.ps1", Rule::Unknown),
            ("Copy-Item -Path a.ps1 -Destination i.ps1; pwsh -File i.ps1", Rule::Unknown),
            ("'x' >> i.ps1; powershell -File i.ps1", Rule::Unknown),
            // Every way the parameter is spelled.
            ("'x' > i.ps1; powershell -f i.ps1", Rule::Unknown),
            ("'x' > i.ps1; powershell -fi i.ps1", Rule::Unknown),
            ("'x' > i.ps1; powershell -FILE i.ps1", Rule::Unknown),
            ("'x' > i.ps1; powershell /File i.ps1", Rule::Unknown),
            ("'x' > i.ps1; powershell -File:i.ps1", Rule::Unknown),
            ("'x' > i.ps1; powershell -File i.ps1 a b", Rule::Unknown),
            ("'x' > i.ps1; powershell -File \"i.ps1\"", Rule::Unknown),
            ("'x' > i.ps1; powershell -File 'i.ps1'", Rule::Unknown),
            // After the options that take a value.
            ("'x' > i.ps1; powershell -NoProfile -File i.ps1", Rule::Unknown),
            (
                "'x' > i.ps1; powershell -ExecutionPolicy Bypass -File i.ps1",
                Rule::Unknown,
            ),
            ("'x' > i.ps1; powershell -Version 5 -File i.ps1", Rule::Unknown),
            (
                "'x' > i.ps1; powershell -WindowStyle Hidden -File i.ps1",
                Rule::Unknown,
            ),
            (
                "'x' > i.ps1; pwsh -NoProfile -NonInteractive -File i.ps1",
                Rule::Unknown,
            ),
            // The first word that is not a parameter is the file for `pwsh`.
            ("'x' > i.ps1; pwsh i.ps1", Rule::Unknown),
            ("'x' > i.ps1; pwsh -NoProfile i.ps1", Rule::Unknown),
            ("'x' > i.ps1; powershell i.ps1", Rule::Unknown),
            // Every way the path is written.
            ("'x' > i.ps1; powershell -File .\\i.ps1", Rule::Unknown),
            ("'x' > i.ps1; powershell -File ./i.ps1", Rule::Unknown),
            ("'x' > i.ps1; powershell -File I.PS1", Rule::Unknown),
            (
                "'x' > i.ps1; powershell -File C:\\Users\\me\\dev\\repo\\i.ps1",
                Rule::Unknown,
            ),
            ("'x' > sub\\i.ps1; powershell -File sub\\i.ps1", Rule::Unknown),
            ("'x' > sub\\i.ps1; Set-Location sub; pwsh -File i.ps1", Rule::Unknown),
            ("Set-Location sub; 'x' > i.ps1; pwsh -File i.ps1", Rule::Unknown),
            ("'x' > i.ps1; powershell.exe -File i.ps1", Rule::Unknown),
            ("'x' > i.ps1; pwsh.exe -File i.ps1", Rule::Unknown),
            // A name with no extension: PowerShell tries `.ps1` first.
            ("'x' > i.ps1; powershell -File i", Rule::Unknown),
            ("'x' > i; powershell -File i", Rule::Unknown),
            // The program wrapped or nested.
            ("'x' > i.ps1; & powershell -File i.ps1", Rule::Unknown),
            ("'x' > i.ps1; cmd /c powershell -File i.ps1", Rule::Unknown),
            (
                "'x' > i.ps1; powershell -Command \"powershell -File i.ps1\"",
                Rule::Unknown,
            ),
            (
                "'x' > i.ps1; pwsh -NoProfile -Command \"& { pwsh -File i.ps1 }\"",
                Rule::Unknown,
            ),
            ("'x' > i.ps1; & { pwsh -File i.ps1 }", Rule::Unknown),
            (
                "'x' > i.ps1; Get-ChildItem | ForEach-Object { pwsh -File i.ps1 }",
                Rule::Unknown,
            ),
            ("'x' > i.ps1; powershell -File i.ps1 | Out-Null", Rule::Unknown),
            ("'x' > i.ps1; if ($?) { powershell -File i.ps1 }", Rule::Unknown),
            // Run before it is written: a script block that runs later.
            (
                "Register-EngineEvent PowerShell.Exiting -Action { powershell -File i.ps1 }; 'x' > i.ps1",
                Rule::Unknown,
            ),
            // `Invoke-Command -FilePath` runs the file.
            ("'x' > i.ps1; Invoke-Command -FilePath i.ps1", Rule::Unknown),
            ("'x' > i.ps1; icm -FilePath .\\i.ps1", Rule::Unknown),
            (
                "'x' > i.ps1; Invoke-Command -ComputerName server -FilePath i.ps1",
                Rule::Unknown,
            ),
            // The file cannot be placed, or is read from a folder the line
            // gives, with a file written.
            ("Set-Location $d; 'x' > i.ps1; powershell -File i.ps1", Rule::Unknown),
            ("'x' > i.ps1; Set-Location $d; powershell -File i.ps1", Rule::Unknown),
            ("'x' > i.ps1; powershell -File $f", Rule::Unknown),
            ("'x' > sub\\i.ps1; powershell -WorkingDirectory sub -File i.ps1", Rule::Unknown),
            ("'x' > i.ps1; powershell -wd sub -File i.ps1", Rule::Unknown),
            ("'x' > i.ps1; pwsh -WorkingDirectory sub i.ps1", Rule::Unknown),
        ],
    );
    // `pwsh` is also run from a POSIX shell, where a file is a path with `/`.
    check(
        Shell::Posix,
        &posix(),
        &[
            "pwsh -File scripts/build.ps1",
            "pwsh build.ps1",
            "pwsh -NoProfile -Command ls",
            "pwsh -c ls",
            "pwsh -Version",
            "echo x > j.ps1; pwsh -File i.ps1",
            "cd sub; echo x > i.ps1; cd ..; pwsh -File i.ps1",
        ],
        &[
            ("echo x > i.ps1; pwsh -File i.ps1", Rule::Unknown),
            ("echo x > i.ps1; pwsh -File ./i.ps1", Rule::Unknown),
            ("echo x > i.ps1; pwsh i.ps1", Rule::Unknown),
            ("echo x > i.ps1; pwsh -NoProfile -File i.ps1", Rule::Unknown),
            (
                "curl -fsSLo i.ps1 https://x.example/a.ps1 && pwsh -File i.ps1",
                Rule::Unknown,
            ),
            ("echo x > i.ps1; sudo pwsh -File i.ps1", Rule::Unknown),
            ("echo x > i.ps1; env FOO=1 pwsh -File i.ps1", Rule::Unknown),
            ("echo x > i.ps1; bash -c 'pwsh -File i.ps1'", Rule::Unknown),
        ],
    );
}

/// The finding says the line runs a script it writes, and names the script
/// as the line wrote it.
#[test]
fn the_finding_names_the_script_and_says_why() {
    for (shell, line, script) in [
        (Shell::Posix, "echo 'rm -rf ~' > x.sh; ./x.sh", "./x.sh"),
        (Shell::Posix, "echo hi > x/run; x/run", "x/run"),
        (Shell::Posix, "echo hi > /tmp/x; /tmp/x", "/tmp/x"),
        (Shell::Posix, "echo hi > x.sh; sudo ./x.sh", "./x.sh"),
        (
            Shell::PowerShell,
            "'x' > i.ps1; powershell -File i.ps1",
            "i.ps1",
        ),
        (
            Shell::PowerShell,
            "'x' > i.ps1; pwsh -NoProfile -File .\\i.ps1",
            ".\\i.ps1",
        ),
        (Shell::PowerShell, "'x' > i.ps1; pwsh i.ps1", "i.ps1"),
        (
            Shell::PowerShell,
            "'x' > i.ps1; powershell -File:i.ps1",
            "i.ps1",
        ),
        (
            Shell::PowerShell,
            "'x' > i.ps1; Invoke-Command -FilePath i.ps1",
            "i.ps1",
        ),
        (
            Shell::PowerShell,
            "'x' > i.ps1; & powershell -f i.ps1",
            "i.ps1",
        ),
    ] {
        let paths = if shell == Shell::Posix {
            posix()
        } else {
            windows()
        };
        let assessment = classify(line, shell, &paths);
        assert!(
            assessment.findings().iter().any(|finding| {
                finding.rule == Rule::Unknown
                    && finding.reason == "runs a script the same line writes"
                    && finding.target.as_deref() == Some(script)
            }),
            "{line}: {:?}",
            assessment.findings()
        );
    }
}

/// A script written to a file named by position (`Set-Content i.ps1 x`,
/// `'x' | Out-File i.ps1`, `New-Item i.ps1 -Value x`) and then run is the
/// same script as one written with `-Path` or `-FilePath`.
#[test]
fn a_script_written_to_a_positional_path_and_then_run_is_unknown() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            // Reading what was written is not running it.
            "Set-Content notes.txt x; Get-Content notes.txt",
            "Set-Content i.ps1 x; Get-Content i.ps1",
            // Nothing is run, or what is run is not what was written.
            "Set-Content out.txt x",
            "Set-Content i.ps1 x",
            "Set-Content i.ps1 x; .\\j.ps1",
            "Set-Content i.ps1 x; powershell -File j.ps1",
            "Set-Content sub\\i.ps1 x; .\\i.ps1",
            "Set-Content i.ps1 x; .\\sub\\i.ps1",
            "New-Item i.ps1 -Value x",
            "'x' | Out-File i.ps1",
            "New-Item -ItemType Directory build; .\\i.ps1",
            "Copy-Item a.ps1 b.ps1; .\\a.ps1",
        ],
        &[
            ("Set-Content i.ps1 x; powershell -File i.ps1", Rule::Unknown),
            ("Set-Content i.ps1 x; .\\i.ps1", Rule::Unknown),
            ("Add-Content i.ps1 x; pwsh -File i.ps1", Rule::Unknown),
            ("'x' | Out-File i.ps1; pwsh -File i.ps1", Rule::Unknown),
            ("New-Item i.ps1 -Value x; .\\i.ps1", Rule::Unknown),
            // The same with the file named.
            ("New-Item -Path i.ps1 -Value x; .\\i.ps1", Rule::Unknown),
            // The aliases.
            ("sc i.ps1 x; .\\i.ps1", Rule::Unknown),
            ("ac i.ps1 x; .\\i.ps1", Rule::Unknown),
            ("ni i.ps1 -Value x; .\\i.ps1", Rule::Unknown),
            ("'x' | tee i.ps1; .\\i.ps1", Rule::Unknown),
            ("'x' | Tee-Object i.ps1; .\\i.ps1", Rule::Unknown),
            // Every way the file is run.
            ("Set-Content i.ps1 x; & .\\i.ps1", Rule::Unknown),
            ("Set-Content i.ps1 x; . .\\i.ps1", Rule::Unknown),
            ("Set-Content i.ps1 x; .\\i", Rule::Unknown),
            ("Set-Content i.bat x; .\\i", Rule::Unknown),
            ("Set-Content i.ps1 x; pwsh i.ps1", Rule::Unknown),
            (
                "Set-Content i.ps1 x; Invoke-Command -FilePath i.ps1",
                Rule::Unknown,
            ),
            // However the file is spelled.
            ("Set-Content ./i.ps1 x; .\\i.ps1", Rule::Unknown),
            ("Set-Content I.PS1 x; .\\i.ps1", Rule::Unknown),
            ("Set-Content 'i.ps1' x; .\\i.ps1", Rule::Unknown),
            ("Set-Content \"i.ps1\" x; .\\i.ps1", Rule::Unknown),
            ("Set-Content .\\sub\\i.ps1 x; .\\sub\\i.ps1", Rule::Unknown),
            (
                "Set-Content sub\\i.ps1 x; sub\\..\\sub\\i.ps1",
                Rule::Unknown,
            ),
            ("cd sub; Set-Content i.ps1 x; .\\i.ps1", Rule::Unknown),
            // After parameters, whatever they take.
            ("Set-Content -Value x i.ps1; .\\i.ps1", Rule::Unknown),
            (
                "Set-Content -Encoding utf8 i.ps1 x; .\\i.ps1",
                Rule::Unknown,
            ),
            ("Set-Content -NoNewline i.ps1 x; .\\i.ps1", Rule::Unknown),
            ("Set-Content -Force i.ps1 x; .\\i.ps1", Rule::Unknown),
            ("Set-Content -Foo i.ps1 x; .\\i.ps1", Rule::Unknown),
            ("Set-Content -Foo x i.ps1; .\\i.ps1", Rule::Unknown),
            (
                "Out-File i.ps1 -InputObject x; pwsh -File i.ps1",
                Rule::Unknown,
            ),
            (
                "'x' | Out-File -Append i.ps1; pwsh -File i.ps1",
                Rule::Unknown,
            ),
            (
                "'x' | Out-File -Width 80 i.ps1; pwsh -File i.ps1",
                Rule::Unknown,
            ),
            (
                "'x' | Out-File -Encoding utf8 i.ps1; pwsh -File i.ps1",
                Rule::Unknown,
            ),
            ("Add-Content -Path:i.ps1 x; .\\i.ps1", Rule::Unknown),
            // `New-Item` names its file in the folder.
            ("New-Item -Name i.ps1 -Value x; .\\i.ps1", Rule::Unknown),
            (
                "New-Item -Path . -Name i.ps1 -Value x; .\\i.ps1",
                Rule::Unknown,
            ),
            (
                "New-Item -Path sub -Name i.ps1 -Value x; .\\sub\\i.ps1",
                Rule::Unknown,
            ),
            (
                "New-Item sub -Name i.ps1 -Value x; .\\sub\\i.ps1",
                Rule::Unknown,
            ),
            ("New-Item -ItemType File i.ps1; .\\i.ps1", Rule::Unknown),
            // A copy or a move by position writes its destination.
            ("Copy-Item a.ps1 i.ps1; .\\i.ps1", Rule::Unknown),
            ("Move-Item a.ps1 i.ps1; .\\i.ps1", Rule::Unknown),
            ("Copy-Item a.ps1 sub; .\\sub\\a.ps1", Rule::Unknown),
            ("Copy-Item -Path a.ps1 i.ps1; .\\i.ps1", Rule::Unknown),
            (
                "Copy-Item -Destination i.ps1 a.ps1; .\\i.ps1",
                Rule::Unknown,
            ),
        ],
    );
    check(
        Shell::Posix,
        &posix(),
        &[
            "Set-Content x.sh 'x'; bash y.sh",
            "Set-Content x.sh 'x'",
            "echo x | tee x.sh",
            "cp -r src/* dest/; bash build.sh",
            "echo x | tee *.log; bash build.sh",
        ],
        &[
            ("Set-Content x.sh 'x'; bash x.sh", Rule::Unknown),
            ("Set-Content x.sh 'x'; sh ./x.sh", Rule::Unknown),
            ("Add-Content x.sh 'x'; bash x.sh", Rule::Unknown),
            ("echo x | tee x.sh; bash x.sh", Rule::Unknown),
            ("echo x | tee *.sh; bash x.sh", Rule::Unknown),
            ("echo x | tee sub/*.sh; bash sub/x.sh", Rule::Unknown),
            ("cp -r src/* dest/; bash dest/x.sh", Rule::Unknown),
        ],
    );
}

/// A list of paths reaches the guard as separate words, so a file after the
/// first may be one of them, and the same word may only be a value.
#[test]
fn every_readable_operand_of_a_write_may_be_the_file() {
    check(
        Shell::PowerShell,
        &windows(),
        &["Set-Content a.ps1,b.ps1 x; .\\c.ps1"],
        &[
            ("Set-Content a.ps1,b.ps1 x; .\\b.ps1", Rule::Unknown),
            (
                "Set-Content -Path a.ps1,b.ps1 -Value x; .\\b.ps1",
                Rule::Unknown,
            ),
            ("Out-File a.ps1,b.ps1; .\\b.ps1", Rule::Unknown),
            ("New-Item a.ps1,b.ps1 -Value x; .\\b.ps1", Rule::Unknown),
            (
                "New-Item -Name a.ps1,b.ps1 -Value x; .\\b.ps1",
                Rule::Unknown,
            ),
            (
                "New-Item -Path sub -Name a.ps1,b.ps1; .\\sub\\b.ps1",
                Rule::Unknown,
            ),
            // The value is read as a file too: it is not told from one.
            ("Set-Content notes.txt x.ps1; .\\x.ps1", Rule::Unknown),
        ],
    );
}

/// A pattern writes every file it matches, in its folder.
#[test]
fn a_pattern_written_to_may_be_the_script_that_is_run() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Set-Content *.txt x; .\\i.ps1",
            "Set-Content *.ps1 x; .\\sub\\i.ps1",
            "Set-Content sub\\*.ps1 x; .\\i.ps1",
            "Set-Content *.ps1 x",
            "Copy-Item src\\* dest\\; .\\build.ps1",
        ],
        &[
            ("Set-Content *.ps1 x; .\\i.ps1", Rule::Unknown),
            ("Set-Content -Path *.ps1 -Value x; .\\i.ps1", Rule::Unknown),
            ("Set-Content i*.ps1 x; .\\I1.PS1", Rule::Unknown),
            ("Set-Content ?.ps1 x; .\\i.ps1", Rule::Unknown),
            ("Set-Content sub\\*.ps1 x; .\\sub\\i.ps1", Rule::Unknown),
            ("Set-Content *.ps1 x; pwsh -File i.ps1", Rule::Unknown),
            ("Set-Content *.ps1 x; .\\i", Rule::Unknown),
            ("Copy-Item src\\* dest\\; .\\dest\\x.ps1", Rule::Unknown),
        ],
    );
}

/// A name only known when it runs, after the first in a list or as the
/// value, is a file that cannot be placed: the line writes any file.
#[test]
fn a_later_name_only_known_when_the_line_runs_may_be_the_script_that_is_run() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            // Nothing is run, or the name is not of a write cmdlet's file.
            "Set-Content notes.txt,$x y",
            "Set-Content notes.txt $x",
            "Set-Content -Path notes.txt -Value $x",
            "Set-Content -Path notes.txt -Value $x; Get-Content notes.txt",
            "Get-Content notes.txt,$x; .\\i.ps1",
            "Write-Output notes.txt,$x; .\\i.ps1",
            "Set-Content -Path notes.txt -Value $x; Get-Process",
            // The value is named: it is not a file.
            "Set-Content -Path notes.txt -Value $x; .\\i.ps1",
            "Set-Content notes.txt -Value $x; .\\i.ps1",
            "New-Item -Path a.txt -Value $x; .\\i.ps1",
        ],
        &[
            ("Set-Content notes.txt,$x y; .\\i.ps1", Rule::Unknown),
            (
                "Set-Content -Path notes.txt,$x -Value y; .\\i.ps1",
                Rule::Unknown,
            ),
            ("Add-Content a.txt,$x y; .\\i.ps1", Rule::Unknown),
            ("New-Item -Path a.txt,$x -Value y; .\\i.ps1", Rule::Unknown),
            // The value is not told from a name in a list.
            ("Set-Content notes.txt $x; .\\i.ps1", Rule::Unknown),
            ("Set-Content a.txt,b.txt $x; .\\i.ps1", Rule::Unknown),
            ("'x' | Out-File a.txt,$x; .\\i.ps1", Rule::Unknown),
            ("'x' | Tee-Object a.txt,$x; .\\i.ps1", Rule::Unknown),
            ("New-Item a.txt,$x -Value y; .\\i.ps1", Rule::Unknown),
            ("New-Item -Name a.txt,$x; .\\i.ps1", Rule::Unknown),
            // A name of a part: a string or an expression.
            ("Set-Content a.txt,\"$d\\x\" y; .\\i.ps1", Rule::Unknown),
            (
                "Set-Content a.txt,(Join-Path $d x) y; .\\i.ps1",
                Rule::Unknown,
            ),
            // Whatever runs it, and wherever it is.
            (
                "Set-Content notes.txt,$x y; powershell -File j.ps1",
                Rule::Unknown,
            ),
            ("Set-Content notes.txt,$x y; .\\sub\\j.ps1", Rule::Unknown),
            ("Set-Content notes.txt,$x y; .\\j", Rule::Unknown),
            ("Set-Content notes.txt,$x y; pwsh j.ps1", Rule::Unknown),
            ("sc notes.txt,$x y; .\\i.ps1", Rule::Unknown),
            ("ac notes.txt,$x y; .\\i.ps1", Rule::Unknown),
            ("ni a.txt,$x -Value y; .\\i.ps1", Rule::Unknown),
        ],
    );
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[("Set-Content a.txt,$x y; bash b.sh", Rule::Unknown)],
    );
}

/// `New-Item` makes each path with each name; past a few dozen files a line
/// is read as making any file.
#[test]
fn a_new_item_of_very_many_files_makes_any_file() {
    let names = |count: usize| {
        (0..count)
            .map(|number| format!("n{number}"))
            .collect::<Vec<_>>()
            .join(",")
    };
    let few = format!("New-Item -Path a -Name {}; .\\i.ps1", names(30));
    let many = format!("New-Item -Path a -Name {}; .\\i.ps1", names(70));
    check(
        Shell::PowerShell,
        &windows(),
        &[&few],
        &[
            (&many, Rule::Unknown),
            ("New-Item -Path a -Name n1,n2; .\\a\\n2", Rule::Unknown),
        ],
    );
}

/// A name only known when it runs is written by a line that is not safe, so
/// the line is not judged only by its run.
#[test]
fn a_file_named_when_the_line_runs_is_not_safe_to_write_and_run() {
    check(
        Shell::PowerShell,
        &windows(),
        &[],
        &[
            ("Set-Content $f x; .\\i.ps1", Rule::Overwrite),
            ("Add-Content $f x; .\\i.ps1", Rule::Overwrite),
            ("'x' | Out-File $f; .\\i.ps1", Rule::Overwrite),
            ("'x' | Tee-Object $f; .\\i.ps1", Rule::Overwrite),
            ("New-Item $f -Value x; .\\i.ps1", Rule::Overwrite),
            ("New-Item -Name $n -Value x; .\\i.ps1", Rule::Overwrite),
            (
                "New-Item -Path $d -Name i.ps1 -Value x; .\\i.ps1",
                Rule::Overwrite,
            ),
            ("Copy-Item a.ps1 $f; .\\i.ps1", Rule::Overwrite),
            (
                "Set-Content (Join-Path $d i.ps1) x; .\\i.ps1",
                Rule::Overwrite,
            ),
            ("Set-Content \"$d\\i.ps1\" x; .\\i.ps1", Rule::Overwrite),
        ],
    );
}

/// The same pattern again is one pattern, a few distinct ones are each read,
/// and a line that writes by more than the guard reads, or by a pattern too
/// long to match cheaply, writes any file.
#[test]
fn a_line_that_writes_by_too_many_patterns_writes_any_file() {
    // Distinct patterns, none of which a `.sh` script's name matches.
    let writes = |count: usize| {
        (0..count)
            .map(|number| format!("echo x > *{number}.log; "))
            .collect::<Vec<_>>()
            .concat()
    };
    let repeated = "echo x > *.log; ".repeat(100);
    let few = format!("{}bash b.sh", writes(8));
    let many = format!("{}bash b.sh", writes(9));
    let many_before = format!("bash b.sh; {}", writes(9));
    let long_name = format!("echo x > *{}; bash b.sh", "a".repeat(64));
    let short_name = format!("echo x > *{}; bash b.sh", "a".repeat(60));
    let long_script = format!("echo x > *.log; bash {}", "a".repeat(300));
    let repeated_run = format!("{repeated}bash b.sh");
    check(
        Shell::Posix,
        &posix(),
        &[
            &repeated_run,
            &few,
            &short_name,
            "echo x > *.log; bash b.sh",
        ],
        &[
            (&many, Rule::Unknown),
            (&many_before, Rule::Unknown),
            (&long_name, Rule::Unknown),
            (&long_script, Rule::Unknown),
            ("echo x > *.log; bash b.log", Rule::Unknown),
        ],
    );
    // The same in PowerShell, whose runs are also read with each extension.
    let writes = |count: usize| {
        (0..count)
            .map(|number| format!("sc *{number}.log x; "))
            .collect::<Vec<_>>()
            .concat()
    };
    let few = format!("{}.\\b", writes(8));
    let many = format!("{}.\\b", writes(9));
    let repeated_run = format!("{}.\\b", "sc *.log x; ".repeat(100));
    check(
        Shell::PowerShell,
        &windows(),
        &[&repeated_run, &few, "sc *.log x; .\\b"],
        &[(&many, Rule::Unknown), ("sc *.b* x; .\\b", Rule::Unknown)],
    );
}

/// Each run on a line costs a bounded amount whatever the line writes, so a
/// long line that writes by patterns and runs scripts is read in time. When
/// each run was matched against every pattern, with each extension, a line of
/// 24 KB took seconds in an optimized build and minutes in a debug one.
#[test]
#[cfg_attr(
    coverage,
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn many_pattern_writes_and_many_runs_are_read_in_time() {
    // A line of this length, whatever it holds, is read in about a tenth of
    // a second in an optimized build, and a debug build takes ten times
    // that; a write by a pattern costs the guard more than a write by a name
    // whatever the runs are (about 0.1 ms in an optimized build).
    const SIZE: usize = 24 * 1024;
    const LIMIT: Duration = if cfg!(debug_assertions) {
        Duration::from_secs(8)
    } else {
        Duration::from_secs(1)
    };
    let fit = |unit: &str, head: &str, tail: &str| {
        let count = (SIZE - head.len() - tail.len()) / unit.len();
        format!("{head}{}{tail}", unit.repeat(count))
    };
    // A write and a run, each `#` in them the number of the pair: distinct
    // patterns, written out one after another.
    let numbered = |write: &str, run: &str| {
        let mut line = String::new();
        let mut number = 0;
        loop {
            let next = format!("{write}{run}").replace('#', &number.to_string());
            if line.len() + next.len() > SIZE {
                return line;
            }
            line += &next;
            number += 1;
        }
    };
    let star_name = format!("{}b", "a*".repeat(28));
    let lines = [
        (
            Shell::PowerShell,
            "a pattern and a run, repeated",
            fit("sc *a x;.\\b;", "", ""),
        ),
        (
            Shell::PowerShell,
            "a pattern that backtracks",
            fit(
                &format!("sc *a*a*a*a*a*a*a*b x;.\\{};", "a".repeat(40)),
                "",
                "",
            ),
        ),
        (
            Shell::PowerShell,
            "a pattern and a run of a script",
            fit("sc *a x;.\\b.ps1;", "", ""),
        ),
        (
            Shell::PowerShell,
            "distinct patterns, each before a run",
            numbered("sc *a# x;", ".\\b;"),
        ),
        (
            Shell::PowerShell,
            "patterns that backtrack, distinct",
            numbered(
                &format!("sc *{star_name}# x;"),
                ".\\aaaaaaaaaaaaaaaaaaaaaaaa;",
            ),
        ),
        (
            Shell::PowerShell,
            "a name only known when it runs, repeated",
            fit("sc a.txt,$x y;.\\b;", "", ""),
        ),
        (
            Shell::PowerShell,
            "a pattern and a run of a long name",
            format!("sc *a x;.\\{}", "a".repeat(SIZE - 20)),
        ),
        (
            Shell::PowerShell,
            "a long pattern and a run of a long name",
            format!(
                "sc *{} x;.\\{}",
                "a*".repeat(SIZE / 8),
                "a".repeat(SIZE / 2)
            ),
        ),
        (
            Shell::Posix,
            "tee a pattern, repeated",
            fit("tee *a;./b;", "", ""),
        ),
        (
            Shell::Posix,
            "a redirect to a pattern, repeated",
            fit("echo x > *a; bash b;", "", ""),
        ),
        (
            Shell::Posix,
            "distinct patterns, each before a run",
            numbered("echo x > *a#;", " bash b;"),
        ),
    ];
    for (shell, what, line) in &lines {
        assert!(line.len() <= SIZE, "{what}: {}", line.len());
        let paths = if *shell == Shell::Posix {
            posix()
        } else {
            windows()
        };
        let elapsed = took(line, *shell, &paths);
        assert!(elapsed < LIMIT, "{what} in {shell:?}: {elapsed:?}");
    }
}
