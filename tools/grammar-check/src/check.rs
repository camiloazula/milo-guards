//! One run of the check: the lines, the shells found, every parse, every
//! difference beside the known list, and the report.

#![allow(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "the tool reads its inputs and makes the folders its shells run in"
)]

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::thread;

use milo_guards_shell::testing::Grammar;

use crate::cases;
use crate::compare::{self, Found, Kind as Difference};
use crate::guard::{self, Reading};
use crate::known::{self, Entry};
use crate::lines::{self, Family, Line};
use crate::powershell::{self, Parsed};
use crate::room::{Failure, Room};
use crate::shells::{self, Kind, Verdict};

/// Whether a shell is compared against, and where it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    /// It is installed there and is asked.
    At(PathBuf),
    /// It is not on `PATH`.
    NotInstalled,
    /// It is left out: `--without`, or PowerShell without `--with pwsh`.
    Off,
}

/// What a run reads and where it starts its shells.
#[derive(Debug, Clone)]
pub struct Options {
    /// The repository's root: places are named from it.
    pub root: PathBuf,
    /// The folders whose `*.cases` are read.
    pub cases: Vec<PathBuf>,
    /// The known list.
    pub known: PathBuf,
    /// The folder the run's own folder is made in.
    pub scratch: PathBuf,
    /// Each shell, and whether it is asked.
    pub shells: Vec<(Kind, Status)>,
    /// The shells that must be asked: a run without one is refused, not
    /// passed (`--require bash`, as CI's job runs it).
    pub required: Vec<Kind>,
    /// How many lines of each family to generate.
    pub generated: usize,
    /// Whether to print the lines of what is reported privately: split
    /// differences, and lines the guard does not read whole and answers
    /// safe (never in CI).
    pub private: bool,
    /// Whether to print each new difference as an entry of the known list,
    /// its versions filled in and its reason left to write.
    pub entries: bool,
    /// How many shells run at once.
    pub jobs: usize,
    /// Whether a shell may be started on macOS outside the sandbox of
    /// `just grammars` (`--unsandboxed`, which the recipe never passes).
    pub unsandboxed: bool,
}

/// What a run printed, and how it ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// The report.
    pub report: String,
    /// The exit code: 0 when every difference on a line of the case files is
    /// known, every entry still is one, every line has an answer and nothing
    /// private was found; 1 when not; 2 when the inputs are refused or a
    /// required shell is not there; 3 when the run stopped because something
    /// happened that a parse never does.
    pub code: i32,
}

/// A shell that ran, with its answer for every line it was given.
struct Ran {
    kind: Kind,
    path: PathBuf,
    version: String,
    /// The answer for each line of its family, by its index in the lines;
    /// `None` for a line it was not given.
    answers: Vec<Option<Answer>>,
    /// The lines left out (PowerShell's parser acts on them).
    left_out: usize,
}

#[derive(Debug, Clone)]
enum Answer {
    Posix(Verdict),
    PowerShell(Parsed),
    None(String),
}

/// One task of a worker.
enum Task {
    Posix { shell: usize, line: usize },
    Batch { shell: usize, lines: Vec<usize> },
}

/// Run the check.
pub fn run(options: &Options) -> Outcome {
    let mut report = String::new();
    let _ = writeln!(
        report,
        "grammar-check: the shell guard's grammars beside the real shells, for every POSIX and \
         PowerShell line of the case files and of a generated set. No line is run: bash only \
         parses it (-n), PowerShell only hands it to its parser. zsh is not asked: its -n still \
         expands words."
    );
    for kind in &options.required {
        if !options
            .shells
            .iter()
            .any(|(k, status)| k == kind && matches!(status, Status::At(_)))
        {
            let _ = writeln!(
                report,
                "refused: {} is required and is not run",
                kind.name()
            );
            return Outcome { report, code: 2 };
        }
    }
    let asks = options
        .shells
        .iter()
        .any(|(_, status)| matches!(status, Status::At(_)));
    if asks && !options.unsandboxed && crate::room::unsandboxed_on_macos() {
        let _ = writeln!(
            report,
            "refused: on macOS a shell is started only under the sandbox of `just grammars`, and \
             this process can read /Users: run `just grammars`, or pass --unsandboxed"
        );
        return Outcome { report, code: 2 };
    }
    let (lines, entries, with_nul) = match inputs(options) {
        Ok(input) => input,
        Err(why) => {
            let _ = writeln!(report, "refused:\n{}", why.join("\n"));
            return Outcome { report, code: 2 };
        }
    };
    let _ = writeln!(report, "{}", line_counts(&lines));
    if with_nul > 0 {
        let _ = writeln!(
            report,
            "{with_nul} lines left out: they hold a NUL, which cannot be handed to a shell as text"
        );
    }
    let run_dir = match make_run_dir(&options.scratch) {
        Ok(dir) => dir,
        Err(why) => {
            let _ = writeln!(report, "refused: {why}");
            return Outcome { report, code: 2 };
        }
    };
    let ran = match parse_everything(options, &run_dir, &lines, &mut report) {
        Ok(ran) => ran,
        Err(stop) => {
            let _ = writeln!(
                report,
                "STOPPED: {stop}\nThe run's folder is kept as it was: {}",
                run_dir.display()
            );
            return Outcome { report, code: 3 };
        }
    };
    let _ = fs::remove_dir_all(&run_dir);
    let _ = writeln!(
        report,
        "cmd: not compared: cmd.exe has no way to parse a line without running it"
    );
    let readings = read_with_guard(&lines, options.jobs);
    let failed = differences(options, &lines, &readings, &ran, &entries, &mut report);
    Outcome {
        report,
        code: i32::from(failed),
    }
}

/// The lines (without those that hold a NUL, counted), and the known list,
/// or why they are refused.
fn inputs(options: &Options) -> Result<(Vec<Line>, Vec<Entry>, usize), Vec<String>> {
    let folders: Vec<&Path> = options.cases.iter().map(PathBuf::as_path).collect();
    let mut lines = lines::from_cases(&options.root, &folders)?;
    let made = lines::generated(&lines, options.generated);
    lines.extend(made);
    let before = lines.len();
    lines.retain(|line| !line.text.contains('\0'));
    let with_nul = before - lines.len();
    let shown = options
        .known
        .strip_prefix(&options.root)
        .unwrap_or(&options.known)
        .display()
        .to_string();
    let source = fs::read_to_string(&options.known)
        .map_err(|e| vec![format!("cannot read the known list {shown}: {e}")])?;
    let entries = known::parse(&shown, &source)?;
    Ok((lines, entries, with_nul))
}

fn line_counts(lines: &[Line]) -> String {
    let count = |family: Family, generated: bool| {
        lines
            .iter()
            .filter(|line| line.family == family && line.generated() == generated)
            .count()
    };
    format!(
        "lines: {} POSIX from the case files and {} generated; {} PowerShell from the case files and {} generated",
        count(Family::Posix, false),
        count(Family::Posix, true),
        count(Family::PowerShell, false),
        count(Family::PowerShell, true),
    )
}

/// A folder of this run's own in `scratch`, made new.
fn make_run_dir(scratch: &Path) -> Result<PathBuf, String> {
    fs::create_dir_all(scratch).map_err(|e| format!("cannot make {}: {e}", scratch.display()))?;
    let id = crate::room::id();
    for n in 0..1000 {
        let dir = scratch.join(format!("grammar-check-{id}-{n}"));
        if fs::create_dir(&dir).is_ok() {
            return Ok(dir);
        }
    }
    Err(format!(
        "cannot make a folder of its own in {}",
        scratch.display()
    ))
}

/// Find each shell's version and parse every line of its family with it.
fn parse_everything(
    options: &Options,
    run_dir: &Path,
    lines: &[Line],
    report: &mut String,
) -> Result<Vec<Ran>, String> {
    let probe =
        Room::new(&run_dir.join("probe")).map_err(|e| format!("cannot make a room: {e}"))?;
    let mut ran = Vec::new();
    for (kind, status) in &options.shells {
        let path = match status {
            Status::At(path) => path,
            Status::NotInstalled => {
                let _ = writeln!(report, "{}: skipped: not installed", kind.name());
                continue;
            }
            Status::Off => {
                let why = if *kind == Kind::Pwsh {
                    "off unless --with pwsh: PowerShell's half has not been proven yet"
                } else {
                    "left out (--without)"
                };
                let _ = writeln!(report, "{}: not run: {why}", kind.name());
                continue;
            }
        };
        let version = if kind.posix() {
            match shells::bash_version(path, &probe) {
                Ok(version) => version,
                Err(Failure::Stop(why)) => return Err(why),
                Err(other) => {
                    let _ = writeln!(report, "{}: skipped: {other:?}", kind.name());
                    continue;
                }
            }
        } else {
            // PowerShell says its version with its answers.
            String::new()
        };
        ran.push(Ran {
            kind: *kind,
            path: path.clone(),
            version,
            answers: vec![None; lines.len()],
            left_out: 0,
        });
    }
    let mut tasks = Vec::new();
    for (shell, one) in ran.iter_mut().enumerate() {
        if one.kind.posix() {
            for (index, line) in lines.iter().enumerate() {
                if line.family == Family::Posix {
                    tasks.push(Task::Posix { shell, line: index });
                }
            }
        } else {
            let (given, left): (Vec<usize>, Vec<usize>) = (0..lines.len())
                .filter(|&index| lines[index].family == Family::PowerShell)
                .partition(|&index| !powershell::acted_on(&lines[index].text));
            one.left_out = left.len();
            for chunk in given.chunks(powershell::BATCH) {
                tasks.push(Task::Batch {
                    shell,
                    lines: chunk.to_vec(),
                });
            }
        }
    }
    let shells: Vec<(Kind, PathBuf)> = ran.iter().map(|one| (one.kind, one.path.clone())).collect();
    let results = run_tasks(options.jobs, run_dir, &tasks, &shells, lines)?;
    for (task, result) in tasks.iter().zip(results) {
        match (task, result) {
            (Task::Posix { shell, line }, TaskResult::Posix(answer)) => {
                ran[*shell].answers[*line] = Some(answer);
            }
            (
                Task::Batch {
                    shell,
                    lines: given,
                },
                TaskResult::Batch(version, answers),
            ) => {
                if !version.is_empty() {
                    ran[*shell].version = version;
                }
                for (index, answer) in given.iter().zip(answers) {
                    ran[*shell].answers[*index] = Some(answer);
                }
            }
            _ => {}
        }
    }
    for one in &ran {
        let given = one.answers.iter().filter(|answer| answer.is_some()).count();
        let version = if one.version.is_empty() {
            "(no answer)"
        } else {
            &one.version
        };
        let how = if one.kind.posix() {
            "in no-exec mode"
        } else {
            "with its parser"
        };
        let _ = write!(
            report,
            "{} {version} at {}: parsed {given} lines {how}",
            one.kind.name(),
            one.path.display()
        );
        if one.left_out > 0 {
            let _ = write!(
                report,
                "; {} left out, which may hold a word or a type its parser acts on (using, \
                 configuration, DSC resources, requires, an assembly)",
                one.left_out
            );
        }
        report.push('\n');
    }
    Ok(ran)
}

enum TaskResult {
    Posix(Answer),
    Batch(String, Vec<Answer>),
    Pending,
}

/// Run every task on `jobs` workers, each in a room of its own; stop them
/// all at the first [`Failure::Stop`].
fn run_tasks(
    jobs: usize,
    run_dir: &Path,
    tasks: &[Task],
    shells: &[(Kind, PathBuf)],
    lines: &[Line],
) -> Result<Vec<TaskResult>, String> {
    let next = AtomicUsize::new(0);
    let stopped = AtomicBool::new(false);
    let stop: Mutex<Option<String>> = Mutex::new(None);
    let results: Mutex<Vec<TaskResult>> =
        Mutex::new(tasks.iter().map(|_| TaskResult::Pending).collect());
    thread::scope(|scope| {
        for worker in 0..jobs.max(1) {
            let (next, stopped, stop, results) = (&next, &stopped, &stop, &results);
            scope.spawn(move || {
                let room = match Room::new(&run_dir.join(format!("room-{worker}"))) {
                    Ok(room) => room,
                    Err(e) => {
                        stopped.store(true, Ordering::SeqCst);
                        set(stop, format!("cannot make a room: {e}"));
                        return;
                    }
                };
                while !stopped.load(Ordering::SeqCst) {
                    let index = next.fetch_add(1, Ordering::SeqCst);
                    let Some(task) = tasks.get(index) else {
                        return;
                    };
                    match one_task(&room, task, shells, lines) {
                        Ok(result) => {
                            if let Ok(mut results) = results.lock() {
                                results[index] = result;
                            }
                        }
                        Err(why) => {
                            stopped.store(true, Ordering::SeqCst);
                            set(stop, why);
                            return;
                        }
                    }
                }
            });
        }
    });
    if let Some(why) = stop.into_inner().ok().flatten() {
        return Err(why);
    }
    results
        .into_inner()
        .map_err(|_| "a worker failed".to_string())
}

fn set(stop: &Mutex<Option<String>>, why: String) {
    if let Ok(mut stop) = stop.lock() {
        stop.get_or_insert(why);
    }
}

/// One task in `room`: its answers, or why the run must stop.
fn one_task(
    room: &Room,
    task: &Task,
    shells: &[(Kind, PathBuf)],
    lines: &[Line],
) -> Result<TaskResult, String> {
    match task {
        Task::Posix { shell, line } => {
            let (_, path) = &shells[*shell];
            let text = &lines[*line].text;
            match shells::parse_bash(path, room, text) {
                Ok(verdict) => Ok(TaskResult::Posix(Answer::Posix(verdict))),
                Err(Failure::Stop(why)) => Err(format!("{why} (line {})", cases::encode(text))),
                Err(other) => Ok(TaskResult::Posix(Answer::None(no_answer(&other)))),
            }
        }
        Task::Batch {
            shell,
            lines: given,
        } => {
            let (_, path) = &shells[*shell];
            let texts: Vec<&str> = given
                .iter()
                .map(|&index| lines[index].text.as_str())
                .collect();
            match powershell::parse_each(path, room, &texts) {
                Ok((version, answers)) => Ok(TaskResult::Batch(
                    version,
                    answers
                        .into_iter()
                        .map(|answer| answer.map_or_else(Answer::None, Answer::PowerShell))
                        .collect(),
                )),
                Err(Failure::Stop(why)) => Err(why),
                Err(other) => Ok(TaskResult::Batch(
                    String::new(),
                    texts
                        .iter()
                        .map(|_| Answer::None(no_answer(&other)))
                        .collect(),
                )),
            }
        }
    }
}

fn no_answer(failure: &Failure) -> String {
    match failure {
        Failure::TimedOut => "ran past its time and was killed".to_string(),
        Failure::Start(why) | Failure::Stop(why) => why.clone(),
    }
}

/// The guard's reading of every line, on `jobs` threads.
fn read_with_guard(lines: &[Line], jobs: usize) -> Vec<Reading> {
    let chunk = lines.len().div_ceil(jobs.max(1)).max(1);
    thread::scope(|scope| {
        let handles: Vec<_> = lines
            .chunks(chunk)
            .map(|part| {
                scope.spawn(move || {
                    part.iter()
                        .map(|line| guard::read(&line.text, line.family))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|handle| handle.join().unwrap_or_default())
            .collect()
    })
}

/// One difference found.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Shown {
    shell: Kind,
    found: Found,
    line: String,
    index: usize,
}

/// Every difference, beside the known list, into `report`; whether the run
/// fails.
fn differences(
    options: &Options,
    lines: &[Line],
    readings: &[Reading],
    ran: &[Ran],
    entries: &[Entry],
    report: &mut String,
) -> bool {
    let mut found = BTreeSet::new();
    let mut unanswered = BTreeSet::new();
    for one in ran {
        for (index, answer) in one.answers.iter().enumerate() {
            let Some(answer) = answer else { continue };
            let reading = &readings[index];
            let difference = match answer {
                Answer::Posix(verdict) => compare::posix(reading, verdict),
                Answer::PowerShell(parsed) => compare::powershell(reading, parsed),
                Answer::None(why) => {
                    unanswered.insert((one.kind, lines[index].text.clone(), why.clone()));
                    None
                }
            };
            if let Some(found_one) = difference {
                found.insert(Shown {
                    shell: one.kind,
                    found: found_one,
                    line: lines[index].text.clone(),
                    index,
                });
            }
        }
    }
    let version = |kind: Kind| {
        ran.iter()
            .find(|one| one.kind == kind)
            .map_or("", |one| one.version.as_str())
    };
    let known_at = |shown: &Shown| {
        entries.iter().position(|entry| {
            entry.matches(
                shown.shell,
                version(shown.shell),
                shown.found.kind,
                &shown.line,
            )
        })
    };
    let mut used = vec![false; entries.len()];
    let mut new: Vec<&Shown> = Vec::new();
    let mut splits: Vec<(Kind, usize)> = Vec::new();
    let mut public = String::new();
    let mut generated = String::new();
    for shown in &found {
        let private = shown.found.kind == Difference::Split;
        let known = known_at(shown);
        if let Some(at) = known {
            used[at] = true;
        }
        let from_cases = !lines[shown.index].generated();
        if private {
            match splits.iter_mut().find(|(kind, _)| *kind == shown.shell) {
                Some((_, count)) => *count += 1,
                None => splits.push((shown.shell, 1)),
            }
            if !options.private {
                continue;
            }
        } else if known.is_none() && from_cases {
            new.push(shown);
        }
        let out = if from_cases {
            &mut public
        } else {
            &mut generated
        };
        let _ = writeln!(
            out,
            "{} {} {} | {}",
            shown.shell.name(),
            version(shown.shell),
            shown.found.kind.name(),
            cases::encode(&shown.line)
        );
        let _ = writeln!(out, "  {}", shown.found.kind.says());
        let _ = writeln!(out, "  shell: {}", shown.found.shell);
        let _ = writeln!(out, "  guard: {}", shown.found.guard);
        if private && readings[shown.index].safe {
            let _ = writeln!(
                out,
                "  the guard answers safe: see whether the shell's reading is risky"
            );
        }
        let _ = writeln!(out, "  from: {}", places(&lines[shown.index].from));
        match known {
            Some(at) => {
                let _ = writeln!(out, "  known ({}): {}", entries[at].at, entries[at].reason);
            }
            None if from_cases && !private => {
                let _ = writeln!(out, "  NEW");
            }
            None => {}
        }
    }
    let _ = writeln!(report, "\ndifferences on lines of the case files:");
    report.push_str(if public.is_empty() { "none\n" } else { &public });
    let _ = writeln!(
        report,
        "\ndifferences on generated lines (not kept on the known list, and no reason to fail):"
    );
    report.push_str(if generated.is_empty() {
        "none\n"
    } else {
        &generated
    });
    if options.private {
        for (kind, count) in &splits {
            let _ = writeln!(
                report,
                "\n{} {}: {count} split differences, above: report them privately as SECURITY.md says",
                kind.name(),
                version(*kind),
            );
        }
    }
    // A line the grammar does not read whole must never be answered safe:
    // that is the premise of every `grammar_rejects` entry.
    let unread_safe: Vec<&Line> = lines
        .iter()
        .zip(readings)
        .filter(|(_, reading)| reading.grammar != Grammar::Whole && reading.safe)
        .map(|(line, _)| line)
        .collect();
    if options.private && !unread_safe.is_empty() {
        let _ = writeln!(
            report,
            "\n{} lines the guard does not read whole and answers safe: report them privately \
             as SECURITY.md says",
            unread_safe.len()
        );
        for line in &unread_safe {
            let _ = writeln!(report, "  {}", cases::encode(&line.text));
        }
    }
    // An entry is stale when its shell ran at a version it holds for and no
    // difference matched it.
    let stale: Vec<&Entry> = entries
        .iter()
        .zip(&used)
        .filter(|(entry, used)| {
            !**used
                && ran
                    .iter()
                    .any(|one| one.kind == entry.shell && entry.versions.holds(&one.version))
        })
        .map(|(entry, _)| entry)
        .collect();
    if !stale.is_empty() {
        let _ = writeln!(report, "\nstale known entries (no such difference here):");
        for entry in &stale {
            let _ = writeln!(
                report,
                "{}: {} {} | {}",
                entry.at,
                entry.shell.name(),
                entry.kind.name(),
                cases::encode(&entry.line)
            );
        }
    }
    if !unanswered.is_empty() {
        let _ = writeln!(report, "\nno answer:");
        for (kind, line, why) in &unanswered {
            let _ = writeln!(report, "{} | {}: {why}", kind.name(), cases::encode(line));
        }
    }
    if options.entries && !new.is_empty() {
        let _ = writeln!(
            report,
            "\nthe new differences as entries of the known list (write each reason):"
        );
        for shown in &new {
            let _ = writeln!(
                report,
                "{} {} versions={} reason=\"\" | {}",
                shown.shell.name(),
                shown.found.kind.name(),
                major_minor(version(shown.shell)),
                cases::encode(&shown.line)
            );
        }
    }
    let _ = writeln!(report, "\nsummary:");
    for one in ran {
        let mine: Vec<&Shown> = found
            .iter()
            .filter(|shown| shown.shell == one.kind && shown.found.kind != Difference::Split)
            .filter(|shown| !lines[shown.index].generated())
            .collect();
        let known = mine
            .iter()
            .filter(|shown| known_at(shown).is_some())
            .count();
        let generated_count = found
            .iter()
            .filter(|shown| shown.shell == one.kind && lines[shown.index].generated())
            .filter(|shown| shown.found.kind != Difference::Split)
            .count();
        let _ = writeln!(
            report,
            "{} {}: {} differences on lines of the case files, {known} known, {} new; {generated_count} on generated lines",
            one.kind.name(),
            one.version,
            mine.len(),
            mine.len() - known
        );
    }
    let split_count: usize = splits.iter().map(|(_, count)| count).sum();
    // What is reported privately is never told apart, counted or shown
    // without `--private`: only that there is something.
    let private = split_count > 0 || !unread_safe.is_empty();
    let failed = !new.is_empty() || !stale.is_empty() || !unanswered.is_empty() || private;
    let mut result = format!(
        "result: {} new differences, {} stale entries, {} lines with no answer",
        new.len(),
        stale.len(),
        unanswered.len(),
    );
    if options.private {
        let _ = write!(
            result,
            ", {split_count} split differences, {} lines not read whole and answered safe",
            unread_safe.len()
        );
    } else if private {
        result.push_str(
            ", and something to report privately: run with --private on a machine of your \
             own, and report it as SECURITY.md says",
        );
    }
    let _ = writeln!(
        report,
        "{result}: {}",
        if failed { "FAILS" } else { "passes" }
    );
    failed
}

/// `5.2` of `5.2.21`.
fn major_minor(version: &str) -> String {
    version.split('.').take(2).collect::<Vec<_>>().join(".")
}

/// Where a line comes from, the first few places.
fn places(from: &[String]) -> String {
    const SHOWN: usize = 3;
    let mut text = from
        .iter()
        .take(SHOWN)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    if from.len() > SHOWN {
        let _ = write!(text, " and {} more", from.len() - SHOWN);
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_from_many_places_names_the_first_few() {
        let from: Vec<String> = (1..=5).map(|n| format!("a.cases:{n}")).collect();
        assert_eq!(places(&from), "a.cases:1, a.cases:2, a.cases:3 and 2 more");
        assert_eq!(places(&from[..1]), "a.cases:1");
    }

    #[test]
    fn an_entry_names_the_major_and_minor_version() {
        assert_eq!(major_minor("5.2.21"), "5.2");
        assert_eq!(major_minor("3.2"), "3.2");
    }
}
