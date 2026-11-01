//! The line as the rules saw it: [`explain`](crate::explain) and the types it
//! returns.

use std::fmt;

use crate::detect::Judged;
use crate::path::{self, Resolver};
use crate::unit::{self, Arg, Split, Unit};
use crate::{Assessment, Finding, Reading, Shell};

/// How an argument's value is known.
///
/// `#[non_exhaustive]`: a caller's `match` needs a fallback arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ArgKind {
    /// Its value is in the text: `target`, `~/x`, `"a b"`.
    Known,
    /// Only known when it runs: `$VAR`, `$(…)`, `%X%`.
    Unknown,
    /// Known except for the expansions in it: `"rm -rf $d"`.
    Template,
    /// What the previous stage of its pipeline hands it (`xargs`, `$_`).
    Input,
}

/// One argument of a unit, as written and as the rules read it.
///
/// `#[non_exhaustive]`: fields may be added.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ArgExplanation {
    /// The argument as written, quotes and all; a placeholder (`<input>`)
    /// for what a pipeline hands on.
    pub written: String,
    /// How its value is known.
    pub kind: ArgKind,
    /// Where it would land if read as a path, in the words of a reason
    /// (`your home directory`), from the folder the unit runs from. Every
    /// known argument that is not an option is placed, whether or not the
    /// program takes it as a path (`reset` in `git reset` lands inside the
    /// workspace); the rules decide which are paths. `None` for an option
    /// (`-rf`, `/s`), a value only known when it runs, and what a pipeline
    /// hands on.
    pub resolved: Option<String>,
}

/// Where a unit sits in a pipeline.
///
/// `#[non_exhaustive]`: fields may be added.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct PipelineStage {
    /// The pipeline's number in the line, from 1.
    pub pipeline: usize,
    /// The stage in it, from 0.
    pub index: usize,
}

/// One program the line runs, as the rules saw it.
///
/// `#[non_exhaustive]`: fields may be added.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UnitExplanation {
    /// The shell whose grammar read it.
    pub shell: Shell,
    /// How many shells deep the script it came from is nested: `0` for the
    /// line itself, one more for each `bash -c`, `eval` or `cmd /c`.
    pub depth: usize,
    /// The program as written, after its wrappers came off.
    pub program: String,
    /// The name the rules know the program by (`rm` for `/bin/RM`), when
    /// its value is known.
    pub key: Option<String>,
    /// The arguments, after the wrappers' own.
    pub args: Vec<ArgExplanation>,
    /// The wrappers taken off in front of the program, outermost first
    /// (`sudo`, `env`, `xargs`, `find`).
    pub wrappers: Vec<String>,
    /// The folder an earlier `cd` of the line moved to, as written, when one
    /// did: relative paths resolve from there.
    pub dir: Option<String>,
    /// Whether a wildcard in its arguments may match a leading dot.
    pub hidden: bool,
    /// Its place in a pipeline, when it is a stage of one.
    pub stage: Option<PipelineStage>,
    /// The findings this unit produced.
    pub findings: Vec<Finding>,
}

/// A write a redirect makes (`> file`, `>> file`), as the rules saw it.
///
/// `#[non_exhaustive]`: fields may be added.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RedirectExplanation {
    /// The shell whose grammar read it.
    pub shell: Shell,
    /// The target as written.
    pub target: String,
    /// Where it lands, in the words of a reason, from the folder the
    /// redirect runs from; `None` when the target is only known when it
    /// runs.
    pub resolved: Option<String>,
    /// As [`UnitExplanation::dir`].
    pub dir: Option<String>,
    /// The findings this write produced.
    pub findings: Vec<Finding>,
}

/// How the guard read a line: every unit as the rules saw it, and what each
/// found. Returned by [`explain`](crate::explain).
///
/// `Display` prints it as a short indented tree. `classify` takes its
/// answer from the same reading, so [`findings`](Self::findings) is what
/// `classify` reports.
///
/// `#[non_exhaustive]`: fields may be added.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Explanation {
    /// The line, as given.
    pub command: String,
    /// The shell that was said to run it.
    pub shell: Shell,
    /// Every program the line runs, in the order the split found them.
    pub units: Vec<UnitExplanation>,
    /// The writes the line's redirects make.
    pub redirects: Vec<RedirectExplanation>,
    /// What the line itself found, no unit of it: a part that cannot be
    /// read, a script or a program known only when it runs, a limit hit.
    pub line: Vec<Finding>,
    /// Every finding of the line, each once: what `classify` reports.
    findings: Vec<Finding>,
}

impl Explanation {
    /// Every finding of the line, each once, in the order `classify`
    /// reports them.
    #[must_use]
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// What `classify` answers for the line: safe when there is no finding.
    pub fn assessment(&self) -> Assessment {
        if self.findings.is_empty() {
            Assessment::Safe
        } else {
            Assessment::Risky(self.findings.clone())
        }
    }
}

/// The name of a shell in the tree.
const fn shell_name(shell: Shell) -> &'static str {
    match shell {
        Shell::Posix => "posix",
        Shell::PowerShell => "powershell",
        Shell::Cmd => "cmd",
    }
}

pub(crate) fn explanation(command: &str, shell: Shell, reading: &Reading) -> Explanation {
    let Reading {
        split,
        judged,
        resolver,
    } = reading;
    let Judged {
        found,
        line,
        units,
        writes,
    } = judged;
    Explanation {
        command: command.to_string(),
        shell,
        units: split
            .units
            .iter()
            .zip(units)
            .map(|(unit, findings)| of_unit(unit, findings, resolver))
            .collect(),
        redirects: redirects(split, writes, resolver),
        line: line.clone(),
        findings: found.clone(),
    }
}

fn redirects(
    split: &Split,
    writes: &[Vec<Finding>],
    resolver: &Resolver,
) -> Vec<RedirectExplanation> {
    split
        .writes
        .iter()
        .zip(writes)
        .map(|(write, findings)| RedirectExplanation {
            shell: write.shell,
            target: write.target.text().to_string(),
            resolved: resolved(
                &write.target,
                write.dir.as_ref(),
                write.shell,
                write.hidden,
                resolver,
                true,
            ),
            dir: write.dir.as_ref().map(|dir| dir.text().to_string()),
            findings: findings.clone(),
        })
        .collect()
}

/// Where `arg` lands, from `dir`, in words; `None` when it is not a value
/// the text gives.
fn resolved(
    arg: &Arg,
    dir: Option<&Arg>,
    shell: Shell,
    hidden: bool,
    resolver: &Resolver,
    into: bool,
) -> Option<String> {
    arg.known()?;
    let arg = path::within(dir, arg, shell);
    let place = if into {
        resolver.place_into(&arg, shell, hidden)
    } else {
        resolver.place(&arg, shell, hidden)
    };
    Some(place.words().to_string())
}

fn of_unit(unit: &Unit, findings: &[Finding], resolver: &Resolver) -> UnitExplanation {
    UnitExplanation {
        shell: unit.shell,
        depth: unit.depth,
        program: unit.program.text().to_string(),
        key: unit.key(),
        args: unit
            .args
            .iter()
            .map(|arg| ArgExplanation {
                written: arg.text().to_string(),
                kind: match arg {
                    Arg::Known(_) => ArgKind::Known,
                    Arg::Unknown(_) => ArgKind::Unknown,
                    Arg::Template { .. } => ArgKind::Template,
                    Arg::Input => ArgKind::Input,
                },
                resolved: arg
                    .known()
                    .filter(|text| !is_option(text, unit.shell))
                    .and_then(|_| {
                        resolved(
                            arg,
                            unit.dir.as_ref(),
                            unit.shell,
                            unit.hidden,
                            resolver,
                            false,
                        )
                    }),
            })
            .collect(),
        wrappers: unit.wrappers.clone(),
        dir: unit.dir.as_ref().map(|dir| dir.text().to_string()),
        hidden: unit.hidden,
        stage: unit.stage.map(|stage| PipelineStage {
            pipeline: stage.pipeline,
            index: stage.index,
        }),
        findings: findings.to_vec(),
    }
}

/// Whether `text` is an option, which is not read as a path: `-rf`, `--force`,
/// and for PowerShell and cmd `/s`.
fn is_option(text: &str, shell: Shell) -> bool {
    (text.len() > 1 && text.starts_with('-')) || (shell != Shell::Posix && unit::is_switch(text))
}

impl fmt::Display for Explanation {
    /// A short indented tree: the line, each unit with what it was read as
    /// and what it found, the redirects, and what the line found itself.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "line ({}): {}", shell_name(self.shell), self.command)?;
        match self.findings.len() {
            0 => writeln!(f, "verdict: safe")?,
            1 => writeln!(f, "verdict: risky, 1 finding")?,
            n => writeln!(f, "verdict: risky, {n} findings")?,
        }
        for (at, unit) in self.units.iter().enumerate() {
            unit.write(f, at + 1)?;
        }
        for redirect in &self.redirects {
            redirect.write(f)?;
        }
        if !self.line.is_empty() {
            writeln!(f, "line findings")?;
            for finding in &self.line {
                write_finding(f, "  ", finding)?;
            }
        }
        Ok(())
    }
}

impl UnitExplanation {
    fn write(&self, f: &mut fmt::Formatter<'_>, number: usize) -> fmt::Result {
        write!(f, "unit {number}: {}", self.program)?;
        if let Some(key) = self.key.as_deref().filter(|key| *key != self.program) {
            write!(f, " (read as {key})")?;
        }
        writeln!(f)?;
        write!(f, "  shell: {}", shell_name(self.shell))?;
        if self.depth > 0 {
            write!(f, ", nested {} deep", self.depth)?;
        }
        writeln!(f)?;
        if !self.wrappers.is_empty() {
            writeln!(f, "  wrappers: {}", self.wrappers.join(", "))?;
        }
        if let Some(stage) = self.stage {
            writeln!(f, "  pipeline {}, stage {}", stage.pipeline, stage.index)?;
        }
        if let Some(dir) = &self.dir {
            writeln!(f, "  runs from: {dir}")?;
        }
        if self.hidden {
            writeln!(f, "  wildcards match hidden names")?;
        }
        if !self.args.is_empty() {
            writeln!(f, "  args")?;
            for arg in &self.args {
                write!(f, "    {}", arg.written)?;
                match (&arg.resolved, arg.kind) {
                    (Some(place), _) => write!(f, " (as a path: {place})")?,
                    (None, ArgKind::Unknown) => write!(f, " (known only when it runs)")?,
                    (None, ArgKind::Template) => {
                        write!(f, " (partly known only when it runs)")?;
                    }
                    (None, ArgKind::Input) => write!(f, " (from the previous stage)")?,
                    (None, _) => {}
                }
                writeln!(f)?;
            }
        }
        write_findings(f, &self.findings)
    }
}

impl RedirectExplanation {
    fn write(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "redirect: writes to {}", self.target)?;
        if let Some(place) = &self.resolved {
            write!(f, " (as a path: {place})")?;
        }
        writeln!(f)?;
        write!(f, "  shell: {}", shell_name(self.shell))?;
        writeln!(f)?;
        if let Some(dir) = &self.dir {
            writeln!(f, "  runs from: {dir}")?;
        }
        write_findings(f, &self.findings)
    }
}

fn write_findings(f: &mut fmt::Formatter<'_>, findings: &[Finding]) -> fmt::Result {
    if findings.is_empty() {
        return writeln!(f, "  safe");
    }
    writeln!(f, "  findings")?;
    for finding in findings {
        write_finding(f, "    ", finding)?;
    }
    Ok(())
}

fn write_finding(f: &mut fmt::Formatter<'_>, indent: &str, finding: &Finding) -> fmt::Result {
    write!(f, "{indent}{}: {}", finding.rule.name(), finding.reason)?;
    if let Some(target) = &finding.target {
        write!(f, " ({target})")?;
    }
    writeln!(f)
}
