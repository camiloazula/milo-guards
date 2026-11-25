//! No line runs and no line reads: bash only parses what it is given.
//!
//! Each line here is a canary: harmless, and written so that it leaves a
//! file in a folder of the test's own if bash runs it, whether through a
//! builtin (`echo ran > FILE`, which an empty `PATH` cannot stop) or by
//! starting a program by its absolute path (`/usr/bin/touch FILE`), which
//! would also be a child process other than the shell. They sit in every place
//! a line can hide code: after `;`, `&&` and a line break, in a command
//! substitution, a here-document, an `eval` string, a function, a trap, an
//! alias, a sourced file, a process substitution, a prompt, a background job.
//! What the tests show is that none of those files appears, after every line
//! and again after a pause long enough for a background job to have written,
//! and that bash accepts every canary, so it read each. That holds with
//! bash's restricted mode (`-r`) and again without it, so `-n` alone is shown
//! to hold: restricted mode refuses a redirect and a program named with a
//! slash, and would stop most canaries by itself.
//!
//! A shell that only parses also opens nothing a line names: zsh's no-exec
//! mode opens the file of a `$(< FILE)`, which is why zsh is not one of the
//! shells. So each line that reads a file (`$(< FILE)` in an argument and in
//! an assignment, backticks, a here-string, an input redirect) is given a
//! file that does not exist, one that does, and a FIFO: bash must name no
//! missing file, give the same answer for all three, and not block on the
//! FIFO, which an open for reading would until it was killed. It must also
//! look up no program or builtin, answer the same for `! cmd` as for `cmd`,
//! and refuse a list left unfinished at the end of the text.
//!
//! The layers of the room are held one by one in `tests/room.rs`, and the
//! startup files and the parent's environment in `tests/startup.rs`. A shell
//! that is not installed is skipped, with a note.

#![allow(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::disallowed_macros,
    clippy::unwrap_used,
    reason = "the test makes its own folders, looks for the shells and says which it skips; a helper of a test fails it as the test does"
)]

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use std::ffi::OsString;

use grammar_check::check::{self, Options, Status};
use grammar_check::powershell::{self, Parsed};
use grammar_check::room::{self, Failure, Finished, Room};
use grammar_check::shells::{self, Kind, Verdict, BASH_NO_EXEC, BASH_STARTUP};

/// bash's arguments without its restricted mode: what is left is `-n`.
fn without_restricted() -> Vec<OsString> {
    BASH_STARTUP
        .iter()
        .chain(BASH_NO_EXEC.iter().filter(|flag| **flag != "-r"))
        .map(OsString::from)
        .collect()
}

/// Start bash on `line` as the tool does, and again without `-r`: both must
/// end the same way, and the first is given back.
fn twice(path: &Path, room: &Room, line: &str) -> Result<Finished, Failure> {
    let first = room.start(&shells::bash_parse(path, line));
    let mut plain = shells::bash_parse(path, line);
    plain.args = without_restricted();
    let second = room.start(&plain);
    assert_eq!(
        first.as_ref().map(|f| (f.code, f.stderr.is_empty())),
        second.as_ref().map(|f| (f.code, f.stderr.is_empty())),
        "{line:?}: bash answers otherwise without -r"
    );
    first
}

/// What bash says of `line`, as the tool and without `-r`, which must agree.
fn verdict(path: &Path, room: &Room, line: &str) -> Result<Verdict, Failure> {
    let finished = twice(path, room, line)?;
    shells::verdict_of(finished.code, &String::from_utf8_lossy(&finished.stderr))
        .map_err(Failure::Start)
}

/// A folder of the test's own, made new: canaries, a sourced file, rooms.
struct Scratch {
    root: PathBuf,
}

impl Scratch {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!("grammar-check-test-{name}-{}", room::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("canaries")).unwrap();
        Self { root }
    }

    fn canaries(&self) -> PathBuf {
        self.root.join("canaries")
    }

    /// Every canary file there is.
    fn fired(&self) -> Vec<String> {
        let mut fired: Vec<String> = fs::read_dir(self.canaries())
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        fired.sort();
        fired
    }

    /// Three files a line may name: one that does not exist, one that does,
    /// and a FIFO, which blocks whoever opens it to read (`None` where
    /// `mkfifo` is not installed).
    fn read_targets(&self) -> (PathBuf, PathBuf, Option<PathBuf>) {
        let reads = self.root.join("reads");
        fs::create_dir_all(&reads).unwrap();
        let missing = reads.join("missing");
        let present = reads.join("present");
        fs::write(&present, "data\n").unwrap();
        let fifo = reads.join("fifo");
        let made = room::make_fifo(&fifo);
        if !made {
            eprintln!("mkfifo is not installed: the FIFO reads are skipped");
        }
        (missing, present, made.then_some(fifo))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn shell(kind: Kind) -> Option<PathBuf> {
    let found = shells::on_path(kind.name(), std::env::var_os("PATH").as_deref());
    if found.is_none() {
        eprintln!("{} is not installed: its canaries are skipped", kind.name());
    }
    found
}

/// The POSIX canaries, each writing to a file of its name in `c`, with
/// `sourced` a file that writes one when it is sourced.
fn posix_canaries(c: &Path, sourced: &Path) -> Vec<(&'static str, String)> {
    let c = c.display();
    let sourced = sourced.display();
    vec![
        ("plain", format!("echo ran > {c}/plain")),
        ("program", format!("/usr/bin/touch {c}/program")),
        ("sh", format!("/bin/sh -c 'echo ran > {c}/sh'")),
        ("exec", format!("exec /usr/bin/touch {c}/exec")),
        ("semicolon", format!("true; echo ran > {c}/semicolon")),
        ("and", format!("true && echo ran > {c}/and")),
        ("or", format!("false || echo ran > {c}/or")),
        ("newline", format!("true\necho ran > {c}/newline")),
        (
            "substitution",
            format!("echo $(echo ran > {c}/substitution)"),
        ),
        ("backticks", format!("echo `echo ran > {c}/backticks`")),
        ("arithmetic", format!(": $(( $(echo 1 > {c}/arithmetic) ))")),
        ("default", format!(": ${{x:=$(echo ran > {c}/default)}}")),
        (
            "here-document",
            format!("cat <<EOF\n$(echo ran > {c}/heredoc)\nEOF"),
        ),
        (
            "here-document read",
            format!("read x <<EOF\n$(/usr/bin/touch {c}/heredoc_read)\nEOF\necho $x"),
        ),
        (
            "here-string",
            format!("cat <<< $(echo ran > {c}/herestring)"),
        ),
        ("eval", format!("eval 'echo ran > {c}/eval'")),
        (
            "eval of a variable",
            format!("x='echo ran > {c}/eval_variable'; eval \"$x\""),
        ),
        ("function", format!("f() {{ echo ran > {c}/function; }}; f")),
        (
            "function on its lines",
            format!("f()\n{{\n  /usr/bin/touch {c}/function_lines\n}}\nf"),
        ),
        ("trap", format!("trap 'echo ran > {c}/trap' EXIT")),
        (
            "trap on error",
            format!("trap 'echo ran > {c}/trap_err' ERR; false"),
        ),
        ("alias", format!("alias c='echo ran > {c}/alias'\nc")),
        (
            "alias expanded",
            format!("shopt -s expand_aliases\nalias c='echo ran > {c}/alias_expanded'\nc"),
        ),
        ("source", format!("source {sourced}")),
        ("dot", format!(". {sourced}")),
        (
            "process substitution",
            format!("cat <(echo ran > {c}/procsub)"),
        ),
        (
            "process substitution out",
            format!("echo x > >(read y; echo ran > {c}/procsub_out)"),
        ),
        ("prompt", format!("PS1='$(echo ran > {c}/ps1)'")),
        (
            "prompt command",
            format!("PROMPT_COMMAND='echo ran > {c}/prompt_command'"),
        ),
        (
            "trace prompt",
            format!("PS4='$(echo ran > {c}/ps4)'; set -x; true"),
        ),
        (
            "background",
            format!("(/bin/sleep 1; echo ran > {c}/background) &"),
        ),
        ("command", format!("command echo ran > {c}/command")),
        ("builtin", format!("builtin echo ran > {c}/builtin")),
        ("home", "echo ran > ~/home_canary".to_string()),
        ("working folder", "echo ran > working_canary".to_string()),
    ]
}

#[test]
fn no_bash_canary_runs() {
    let Some(path) = shell(Kind::Bash) else {
        return;
    };
    let scratch = Scratch::new("bash");
    let sourced = scratch.root.join("sourced");
    fs::write(
        &sourced,
        format!("echo ran > {}/sourced\n", scratch.canaries().display()),
    )
    .unwrap();
    let room = Room::new(&scratch.root.join("room")).unwrap();
    let version = shells::bash_version(&path, &room).unwrap();
    assert!(!version.is_empty());
    for (name, line) in posix_canaries(&scratch.canaries(), &sourced) {
        let verdict = verdict(&path, &room, &line).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        // bash read it: every canary is a line it accepts.
        assert_eq!(verdict, Verdict::Accepts, "{name}");
    }
    // A canary before an error: bash read the whole text, to the error on
    // its last line, and ran none of it.
    let line = format!(
        "echo ran > {}/before_error\nfi",
        scratch.canaries().display()
    );
    match verdict(&path, &room, &line).unwrap() {
        Verdict::Rejects(error) => assert!(error.contains("line 2"), "{error}"),
        Verdict::Accepts => panic!("bash accepts a stray `fi`"),
    }
    assert_eq!(scratch.fired(), [] as [String; 0]);
    // A background job would have written by now.
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(scratch.fired(), [] as [String; 0]);
}

/// The lines that read the file `file`, each as bash writes it.
fn bash_reads(file: &Path) -> Vec<String> {
    let file = file.display();
    vec![
        format!("echo $(< {file})"),
        format!("x=$(< {file})"),
        format!("echo `< {file}`"),
        format!("x=`< {file}`"),
        format!("cat <<< $(< {file})"),
        format!("cat <<< \"$(< {file})\""),
        format!("cat < {file}"),
        format!("read x < {file}"),
        format!("while read x; do echo $x; done < {file}"),
        format!("echo $(< ~/{})", "no_such_file_in_home"),
    ]
}

#[test]
fn bash_opens_no_file_a_line_names() {
    let Some(path) = shell(Kind::Bash) else {
        return;
    };
    let scratch = Scratch::new("bash-reads");
    let (missing, present, fifo) = scratch.read_targets();
    let room = Room::new(&scratch.root.join("room")).unwrap();
    for ((on_missing, on_present), on_fifo) in bash_reads(&missing)
        .into_iter()
        .zip(bash_reads(&present))
        .zip(
            fifo.iter()
                .flat_map(|fifo| bash_reads(fifo))
                .map(Some)
                .chain(std::iter::repeat(None)),
        )
    {
        let finished =
            twice(&path, &room, &on_missing).unwrap_or_else(|e| panic!("{on_missing}: {e:?}"));
        let said = String::from_utf8_lossy(&finished.stderr);
        assert!(
            !said.contains("No such file") && !said.contains("no such file"),
            "bash looked for the file of {on_missing:?}: {said}"
        );
        assert_eq!((finished.code, said.trim()), (Some(0), ""), "{on_missing}");
        let answer = verdict(&path, &room, &on_missing).unwrap();
        assert_eq!(
            verdict(&path, &room, &on_present).unwrap(),
            answer,
            "{on_present}: the same answer whether the file exists or not"
        );
        if let Some(on_fifo) = on_fifo {
            // An open of the FIFO would block until bash was killed, which
            // is no answer.
            assert_eq!(verdict(&path, &room, &on_fifo), Ok(answer), "{on_fifo}");
        }
    }
}

#[test]
fn bash_looks_nothing_up_and_its_status_is_its_parse() {
    let Some(path) = shell(Kind::Bash) else {
        return;
    };
    let scratch = Scratch::new("bash-status");
    let room = Room::new(&scratch.root.join("room")).unwrap();
    // A program or a builtin that does not exist: nothing is looked up, so
    // nothing is said.
    for line in [
        "builtin no_such_builtin",
        "command no_such_program",
        "no_such_program",
        "enable no_such_builtin",
        "type no_such_program",
        "hash no_such_program",
        "echo ${x:?no such value}",
        "echo no_such_match_*",
        "! true",
        "! false",
        "! no_such_program",
    ] {
        let finished = twice(&path, &room, line).unwrap();
        assert_eq!(
            (
                finished.code,
                String::from_utf8_lossy(&finished.stderr).trim()
            ),
            (Some(0), ""),
            "{line}"
        );
    }
    // A list left unfinished at the end of the text is refused.
    for line in [
        "echo &&",
        "echo ||",
        "echo |",
        "echo (",
        "if true; then",
        "for x in a; do",
        "echo \"open",
    ] {
        assert!(
            matches!(verdict(&path, &room, line), Ok(Verdict::Rejects(_))),
            "{line}"
        );
    }
}

#[test]
fn a_long_line_bash_refuses_has_an_answer() {
    let Some(path) = shell(Kind::Bash) else {
        return;
    };
    let scratch = Scratch::new("long");
    let room = Room::new(&scratch.root.join("room")).unwrap();
    // bash repeats a refused line in its error, far past what is kept of it:
    // the rest is read and dropped, and bash ends as it would.
    let line = format!(
        "echo ran > {}/long {} )",
        scratch.canaries().display(),
        "x".repeat(200_000)
    );
    assert!(matches!(
        verdict(&path, &room, &line),
        Ok(Verdict::Rejects(_))
    ));
    assert_eq!(scratch.fired(), [] as [String; 0]);
}

#[test]
fn no_powershell_canary_runs_or_reads() {
    let Some(path) = shell(Kind::Pwsh) else {
        return;
    };
    let scratch = Scratch::new("powershell");
    let c = scratch.canaries();
    let c = c.display();
    let canaries = [
        format!("Set-Content -Path '{c}/set' -Value ran"),
        format!("'ran' > '{c}/redirect'"),
        format!("New-Item -ItemType File -Path '{c}/new'"),
        format!("Get-Item x; New-Item -Path '{c}/semicolon'"),
        format!("Get-Item x\nNew-Item -Path '{c}/newline'"),
        format!("$(New-Item -Path '{c}/subexpression')"),
        format!("& {{ New-Item -Path '{c}/block' }}"),
        format!("Invoke-Expression \"New-Item -Path '{c}/iex'\""),
        format!("[IO.File]::WriteAllText('{c}/dotnet', 'ran')"),
        format!("function prompt {{ New-Item -Path '{c}/prompt' }}; prompt"),
        format!("function f {{ New-Item -Path '{c}/function' }}\nf"),
        format!("Start-Process -FilePath /usr/bin/touch -ArgumentList '{c}/start'"),
        format!("/usr/bin/touch '{c}/native'"),
        format!("@\"\n$(New-Item -Path '{c}/herestring')\n\"@"),
        format!("trap {{ New-Item -Path '{c}/trap' }}; throw 'x'"),
        format!("Start-Job {{ New-Item -Path '{c}/job' }}"),
        format!("Set-Alias c New-Item; c -Path '{c}/alias'"),
    ];
    let error = format!("New-Item -Path '{c}/before_error'; {{");
    let mut lines: Vec<&str> = canaries.iter().map(String::as_str).collect();
    lines.push(&error);
    let room = Room::new(&scratch.root.join("room")).unwrap();
    let (version, answers) = powershell::parse_batch(&path, &room, &lines).unwrap();
    assert!(!version.is_empty());
    assert_eq!(answers.len(), lines.len());
    // The parser read each: every canary is accepted, into its commands, and
    // the last is refused.
    for (line, answer) in lines.iter().zip(&answers).take(canaries.len()) {
        assert!(matches!(answer, Parsed::Accepts(_)), "{line}: {answer:?}");
    }
    assert!(matches!(answers.last(), Some(Parsed::Rejects(..))));
    let Parsed::Accepts(first) = &answers[0] else {
        unreachable!()
    };
    assert_eq!(
        first[0].words[0],
        powershell::Word::Value("Set-Content".into())
    );
    // A line the parser acts on is never handed to it.
    assert!(matches!(
        powershell::parse_batch(&path, &room, &[&format!("using module '{c}/x.psm1'")]),
        Err(Failure::Start(_))
    ));
    // Lines that read a file: the same answers whether it is missing, there
    // or a FIFO, which an open would block on until pwsh was killed.
    let (missing, present, fifo) = scratch.read_targets();
    let reads = |file: &Path| {
        let f = file.display();
        vec![
            format!("Get-Content '{f}'"),
            format!("$x = $(Get-Content '{f}')"),
            format!("Write-Output \"$(Get-Content '{f}')\""),
            format!("@\"\n$(Get-Content '{f}')\n\"@"),
            format!("Get-Content '{f}' | Write-Output"),
            format!("[IO.File]::ReadAllText('{f}')"),
            format!("${{{f}}}"),
        ]
    };
    let answers_for = |file: &Path| {
        let lines = reads(file);
        let lines: Vec<&str> = lines.iter().map(String::as_str).collect();
        powershell::parse_batch(&path, &room, &lines).unwrap().1
    };
    let on_missing = answers_for(&missing);
    let shape = |answers: &[Parsed]| -> Vec<bool> {
        answers
            .iter()
            .map(|a| matches!(a, Parsed::Accepts(_)))
            .collect()
    };
    assert_eq!(shape(&answers_for(&present)), shape(&on_missing));
    if let Some(fifo) = fifo {
        assert_eq!(shape(&answers_for(&fifo)), shape(&on_missing));
    }
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(scratch.fired(), [] as [String; 0]);
}

#[test]
fn a_run_prints_every_difference_and_holds_the_known_list() {
    let scratch = Scratch::new("run");
    let cases = scratch.root.join("cases");
    fs::create_dir(&cases).unwrap();
    let c = scratch.canaries();
    let c = c.display();
    fs::write(
        cases.join("canaries.cases"),
        format!(
            "posix safe | echo ran > {c}/accepted\nposix safe | echo ran > {c}/refused; )\n\
             posix safe | do echo ran > {c}/reserved\n\
             powershell safe | Set-Content -Path '{c}/ps' -Value ran\ncmd safe | echo ran > {c}/cmd\n"
        ),
    )
    .unwrap();
    let known = scratch.root.join("known.cases");
    // An entry for a line that does not differ is stale where its shell ran.
    fs::write(
        &known,
        format!("bash grammar_rejects reason=\"never\" | echo ran > {c}/accepted\n"),
    )
    .unwrap();
    let options = Options {
        root: scratch.root.clone(),
        cases: vec![cases],
        known,
        scratch: scratch.root.join("run"),
        shells: Kind::ALL
            .into_iter()
            .map(|kind| {
                // PowerShell's half is held by its canaries alone, below,
                // until it has been read on a maintainer's machine.
                let status = match kind {
                    Kind::Pwsh => Status::Off,
                    _ => shell(kind).map_or(Status::NotInstalled, Status::At),
                };
                (kind, status)
            })
            .collect(),
        required: Vec::new(),
        generated: 20,
        private: false,
        entries: true,
        jobs: 2,
        // The lines are canaries.
        unsandboxed: true,
    };
    let outcome = check::run(&options);
    let report = &outcome.report;
    assert!(
        report.contains(
            "lines: 3 POSIX from the case files and 20 generated; 1 PowerShell from the case files and"
        ),
        "{report}"
    );
    assert!(report.contains("cmd: not compared"), "{report}");
    assert!(report.contains("zsh is not asked"), "{report}");
    assert!(report.contains("result: "), "{report}");
    if shell(Kind::Bash).is_some() {
        assert!(report.contains("stale known entries"), "{report}");
        // Every line had an answer: none was lost to a limit or a crash.
        assert!(report.contains(" 0 lines with no answer:"), "{report}");
        // The new difference, as an entry with its version and no reason.
        assert!(report.contains("NEW"), "{report}");
        assert!(report.contains("bash shell_rejects versions="), "{report}");
        assert!(report.contains("reason=\"\" | do echo ran"), "{report}");
        assert_eq!(outcome.code, 1, "{report}");
    } else {
        assert!(report.contains("bash: skipped: not installed"), "{report}");
    }
    assert!(
        report.contains("pwsh: not run: off unless --with pwsh"),
        "{report}"
    );
    assert_eq!(check::run(&options), outcome, "the same report every time");
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(scratch.fired(), [] as [String; 0]);
    // The run's own folders are gone.
    assert_eq!(fs::read_dir(scratch.root.join("run")).unwrap().count(), 0);
}

#[test]
fn refused_inputs_end_the_run_before_any_shell() {
    let scratch = Scratch::new("refused");
    let cases = scratch.root.join("cases");
    fs::create_dir(&cases).unwrap();
    fs::write(cases.join("bad.cases"), "posix safe |  x\n").unwrap();
    let known = scratch.root.join("known.cases");
    fs::write(&known, "").unwrap();
    let options = Options {
        root: scratch.root.clone(),
        cases: vec![cases.clone()],
        known: known.clone(),
        scratch: scratch.root.join("run"),
        shells: Vec::new(),
        required: Vec::new(),
        generated: 0,
        private: false,
        entries: false,
        jobs: 1,
        unsandboxed: true,
    };
    let outcome = check::run(&options);
    assert_eq!(outcome.code, 2, "{}", outcome.report);
    assert!(outcome.report.contains("bad.cases:1"), "{}", outcome.report);
    fs::write(cases.join("bad.cases"), "posix safe | x\n").unwrap();
    fs::write(&known, "bash split reason=r | x\n").unwrap();
    let outcome = check::run(&options);
    assert_eq!(outcome.code, 2, "{}", outcome.report);
    assert!(
        outcome.report.contains("a split is never kept here"),
        "{}",
        outcome.report
    );
    // A shell the run requires and does not have refuses the run.
    let required = Options {
        shells: vec![
            (Kind::Bash, Status::NotInstalled),
            (Kind::Pwsh, Status::Off),
        ],
        required: vec![Kind::Bash],
        ..options
    };
    let outcome = check::run(&required);
    assert_eq!(outcome.code, 2, "{}", outcome.report);
    assert!(
        outcome.report.contains("bash is required"),
        "{}",
        outcome.report
    );
    // On macOS, outside the sandbox of `just grammars`, no shell is started
    // unless the run says so; under it, or elsewhere, the run goes on.
    let Some(bash) = shell(Kind::Bash) else {
        return;
    };
    let guarded = Options {
        shells: vec![(Kind::Bash, Status::At(bash)), (Kind::Pwsh, Status::Off)],
        required: Vec::new(),
        unsandboxed: false,
        ..required
    };
    let outcome = check::run(&guarded);
    let refused = outcome.report.contains("only under the sandbox");
    assert_eq!(refused, room::unsandboxed_on_macos(), "{}", outcome.report);
}
