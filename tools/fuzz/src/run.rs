//! Seeding a target and running it: the one place this tool writes files
//! and starts a process, cargo-fuzz, which builds the target and runs it
//! under `libFuzzer`.
//!
//! A run keeps what `libFuzzer` prints in a log of its own and prints none
//! of it: when it finds an input that breaks a promise, it prints the input
//! (as bytes and as text) and the panic, which names it. What it found is a
//! security report (SECURITY.md), so the run says only that it found
//! something and where it kept it, with the log beside it; `--private`
//! prints the log too, for a run on a machine of your own. What the build
//! prints is shown as it goes: it holds no input.

#![allow(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::disallowed_macros,
    reason = "this is the tool's one place that writes files and starts a process"
)]

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The code the runner ends with: named here, the one file of the tool that
/// names a process.
pub use std::process::ExitCode;

use crate::promises::Target;
use crate::seeds;

/// What `libFuzzer` is told for every run: no input may take more than
/// five seconds or two gigabytes, and its final counts are printed (to the
/// log), so the run can say how far it went.
pub const LIMITS: [&str; 3] = ["-rss_limit_mb=2048", "-timeout=5", "-print_final_stats=1"];

/// What `libFuzzer` is told for a run that keeps going past what it finds:
/// one job forked at a time, which a crash, a hang or a run out of memory
/// does not stop, so a run of its time keeps every input it found.
pub const KEEP_GOING: [&str; 4] = [
    "-fork=1",
    "-ignore_crashes=1",
    "-ignore_timeouts=1",
    "-ignore_ooms=1",
];

/// How a run goes: which target, for how long, where its files go,
/// whether it stops at what it finds, and whether the log is printed.
#[derive(Debug, Clone)]
pub struct Options {
    /// The target.
    pub target: Target,
    /// How long it runs, in seconds.
    pub seconds: u64,
    /// Where its seeds, its corpus and what it finds go, each in a folder
    /// named by the target: `seeds/`, `corpus/` and `found/`.
    pub out: PathBuf,
    /// Whether it runs its whole time, past what it finds ([`KEEP_GOING`]),
    /// or stops at the first.
    pub keep_going: bool,
    /// Whether the log is printed when the run finds something.
    pub private: bool,
}

/// What a run came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// It ran its time and found nothing.
    Clean(Counts),
    /// It found an input that breaks a promise, a hang or a crash: these
    /// files in `found/`, with the log.
    Found(Counts, Vec<PathBuf>),
}

/// How far a run went, as `libFuzzer`'s last status line and final counts
/// say: none of it is an input.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Counts {
    /// The inputs it ran.
    pub executions: Option<u64>,
    /// The edges of the code it reached (`cov:`).
    pub coverage: Option<u64>,
    /// The features of that coverage it told apart (`ft:`).
    pub features: Option<u64>,
    /// The inputs its corpus kept (`corp:`).
    pub corpus: Option<u64>,
}

/// The repository's root, two folders above this package.
pub fn root() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    root.canonicalize().unwrap_or(root)
}

/// This package's folder, where cargo-fuzz is run.
fn package() -> PathBuf {
    root().join("tools/fuzz")
}

/// The nightly the targets are built with: the channel of this package's
/// `rust-toolchain.toml`.
pub fn nightly() -> Result<String, String> {
    let file = package().join("rust-toolchain.toml");
    let text =
        fs::read_to_string(&file).map_err(|e| format!("cannot read {}: {e}", file.display()))?;
    text.lines()
        .filter_map(|line| line.trim().strip_prefix("channel"))
        .filter_map(|rest| rest.trim_start().strip_prefix('='))
        .map(|value| value.trim().trim_matches('"').to_string())
        .next()
        .ok_or_else(|| format!("{} names no channel", file.display()))
}

/// Write the seeds of `target` into `folder`, emptied first: one file for
/// each distinct input, named by its place. How many were written.
pub fn write_seeds(target: Target, folder: &Path) -> Result<usize, String> {
    let all = seeds::read(&root())?;
    if folder.exists() {
        fs::remove_dir_all(folder)
            .map_err(|e| format!("cannot empty {}: {e}", folder.display()))?;
    }
    fs::create_dir_all(folder).map_err(|e| format!("cannot make {}: {e}", folder.display()))?;
    let mut written = std::collections::BTreeSet::new();
    for seed in all.iter().filter(|seed| seed.target == target) {
        let bytes = seed.bytes();
        if written.insert(bytes.clone()) {
            let file = folder.join(format!("{:06}", written.len()));
            fs::write(&file, bytes).map_err(|e| format!("cannot write {}: {e}", file.display()))?;
        }
    }
    Ok(written.len())
}

/// `cargo fuzz` with the nightly, run in this package, with nothing of the
/// cargo that runs this tool: the nightly is named, never picked by where
/// it runs from or by what started it.
fn cargo_fuzz(nightly: &str) -> Command {
    let mut command = Command::new("cargo");
    command
        .current_dir(package())
        .env("RUSTUP_TOOLCHAIN", nightly)
        .env_remove("CARGO")
        .env_remove("RUSTC")
        .env_remove("RUSTDOC")
        .arg("fuzz");
    command
}

/// Seed `options.target`, build it and run it for its time.
pub fn run(options: &Options) -> Result<Outcome, String> {
    let name = options.target.name();
    let seeds = options.out.join("seeds").join(name);
    let corpus = options.out.join("corpus").join(name);
    let found = options.out.join("found").join(name);
    let count = write_seeds(options.target, &seeds)?;
    println!("{name}: {count} seeds from the case files");
    for folder in [&corpus, &found] {
        fs::create_dir_all(folder).map_err(|e| format!("cannot make {}: {e}", folder.display()))?;
    }
    // What an earlier run found is not this run's.
    for file in kept(&found)? {
        fs::remove_file(&file).map_err(|e| format!("cannot remove {}: {e}", file.display()))?;
    }
    let nightly = nightly()?;
    let built = cargo_fuzz(&nightly)
        .args(["build", "--fuzz-dir", ".", name])
        .status()
        .map_err(|e| format!("cannot start cargo fuzz with {nightly}: {e}"))?;
    if !built.success() {
        return Err(format!("cargo fuzz could not build {name} with {nightly}"));
    }
    let log = found.join("log.txt");
    let output = File::create(&log).map_err(|e| format!("cannot write {}: {e}", log.display()))?;
    let errors = output
        .try_clone()
        .map_err(|e| format!("cannot write {}: {e}", log.display()))?;
    let mut prefix = found.clone().into_os_string();
    prefix.push("/");
    let mut artifacts = std::ffi::OsString::from("-artifact_prefix=");
    artifacts.push(prefix);
    println!(
        "{name}: running for {} s, what libFuzzer prints kept in {}",
        options.seconds,
        log.display()
    );
    let status = cargo_fuzz(&nightly)
        .args(["run", "--fuzz-dir", ".", name])
        .arg(&corpus)
        .arg(&seeds)
        .arg("--")
        .arg(format!("-max_total_time={}", options.seconds))
        .args(LIMITS)
        .args(if options.keep_going {
            &KEEP_GOING[..]
        } else {
            &[]
        })
        .arg(artifacts)
        .stdin(Stdio::null())
        .stdout(output)
        .stderr(errors)
        .status()
        .map_err(|e| format!("cannot start cargo fuzz with {nightly}: {e}"))?;
    let text = fs::read(&log).map_err(|e| format!("cannot read {}: {e}", log.display()))?;
    let text = String::from_utf8_lossy(&text);
    let inputs = kept(&found)?;
    if status.success() && inputs.is_empty() {
        return Ok(Outcome::Clean(counts(&text)));
    }
    if options.private {
        println!("{text}");
    }
    Ok(Outcome::Found(counts(&text), inputs))
}

/// The files a run left in `found`, but its log, sorted.
fn kept(found: &Path) -> Result<Vec<PathBuf>, String> {
    let entries =
        fs::read_dir(found).map_err(|e| format!("cannot list {}: {e}", found.display()))?;
    let mut files: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.file_name().is_some_and(|name| name != "log.txt"))
        .collect();
    files.sort();
    Ok(files)
}

/// The counts in what `libFuzzer` printed: its last status line (`#N ...
/// cov: C ft: F corp: K/...`) and its final count of the inputs it ran.
pub fn counts(log: &str) -> Counts {
    let field = |line: &str, key: &str| {
        let mut words = line.split_whitespace();
        words.find(|word| *word == key)?;
        words.next()?.split('/').next()?.parse::<u64>().ok()
    };
    let mut counts = Counts::default();
    for line in log.lines() {
        // `#N` alone, or `#N:` in a run that forks its jobs.
        if let Some(rest) = line.strip_prefix('#') {
            if let Some(runs) = rest
                .split_whitespace()
                .next()
                .and_then(|n| n.trim_end_matches(':').parse().ok())
            {
                counts.executions = Some(runs);
                counts.coverage = field(line, "cov:").or(counts.coverage);
                counts.features = field(line, "ft:").or(counts.features);
                counts.corpus = field(line, "corp:").or(counts.corpus);
            }
        }
        if let Some(units) = line
            .strip_prefix("stat::number_of_executed_units:")
            .and_then(|n| n.trim().parse().ok())
        {
            counts.executions = Some(units);
        }
    }
    counts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_counts_are_read_from_the_last_status_and_the_final_stats() {
        let log = "INFO: Seed: 1\n#2\tINITED cov: 10 ft: 20 corp: 5/1Kb exec/s: 0 rss: 40Mb\n\
                   #4096\tpulse  cov: 12 ft: 25 corp: 6/2Kb lim: 40 exec/s: 2048 rss: 41Mb\n\
                   #9000\tDONE   cov: 15 ft: 31 corp: 9/3Kb lim: 40 exec/s: 3000 rss: 42Mb\n\
                   Done 9000 runs in 3 second(s)\nstat::number_of_executed_units: 9001\n";
        assert_eq!(
            counts(log),
            Counts {
                executions: Some(9001),
                coverage: Some(15),
                features: Some(31),
                corpus: Some(9),
            }
        );
        assert_eq!(counts("nothing"), Counts::default());
        let forked = "#120: cov: 30 ft: 40 corp: 12 exec/s: 5 oom/timeout/crash: 0/0/1 time: 9s\n";
        assert_eq!(
            counts(forked),
            Counts {
                executions: Some(120),
                coverage: Some(30),
                features: Some(40),
                corpus: Some(12),
            }
        );
    }

    #[test]
    fn the_nightly_is_named_by_its_date() -> Result<(), String> {
        let nightly = nightly()?;
        let date = nightly.strip_prefix("nightly-").unwrap_or_default();
        assert_eq!(date.len(), 10, "{nightly}");
        Ok(())
    }
}
