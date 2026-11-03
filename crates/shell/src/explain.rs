//! The line as the rules saw it: [`explain`](crate::explain) and the types it
//! returns.

use std::collections::HashMap;
use std::fmt;

use crate::detect::Judged;
use crate::path::{Access, Resolver};
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
    /// A known argument holds its value with the quotes taken off: `a b`
    /// for `'a b'`, `git reset --hard` for the script of `bash -c 'git reset
    /// --hard'`. An unknown or template argument keeps its source text
    /// (`"$X"`, quotes and all), since it has no value yet. For what a
    /// pipeline hands on it is a placeholder (`<input>`).
    pub written: String,
    /// How its value is known.
    pub kind: ArgKind,
    /// Where it would land if read as a path, in the words of a reason
    /// (`your home directory`), from the folder the unit runs from. Every
    /// known argument that is not an option is placed, whether or not the
    /// program takes it as a path (`reset` in `git reset` lands inside the
    /// workspace); the rules decide which are paths. `None` for an option
    /// (`-rf`, `/s`), a value only known when it runs, and what a pipeline
    /// hands on. In a POSIX shell nothing after the first `--` is an option:
    /// in `rm -- -rf`, `--` is not placed and `-rf` is.
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
    /// How many levels deep the script it came from is nested: `0` for the
    /// line itself, one more for each `bash -c`, `eval` or `cmd /c`, and one
    /// more for a part of the line that the grammar reads again (what follows
    /// the `&&` in cmd's `set X=1 && del y`, the stage after `--%` in
    /// PowerShell). It is the number the depth limit counts.
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
    // Arguments run from the same folder land in the same place: each word
    // is placed once for each folder (a runner read many ways hands
    // thousands of copies of a few words on, a loop runs one word in
    // thousands of units).
    let mut placed = Placed::new();
    Explanation {
        command: command.to_string(),
        shell,
        units: split
            .units
            .iter()
            .zip(units)
            .map(|(unit, findings)| of_unit(unit, findings, resolver, &mut placed))
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
            )
            .map(str::to_string),
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
) -> Option<&'static str> {
    arg.known()?;
    let place = if into {
        resolver.place_into(dir, arg, shell, hidden, Access::Item)
    } else {
        resolver.place(dir, arg, shell, hidden, Access::Item)
    };
    Some(place.words())
}

/// Where each word lands, by the folder it runs from, its shell, whether its
/// wildcards match hidden names, and its text. The folder is the whole
/// [`Arg`], not its text: `cd '$Y'` and `cd $Y` spell the same text, but one
/// is a folder the text names and the other one only known when it runs.
type Placed<'a> = HashMap<(Option<&'a Arg>, &'static str, bool, &'a str), Option<&'static str>>;

fn of_unit<'a>(
    unit: &'a Unit,
    findings: &[Finding],
    resolver: &Resolver,
    placed: &mut Placed<'a>,
) -> UnitExplanation {
    // In a POSIX shell the first `--` ends the options: what follows it is an
    // operand, whatever it starts with (`rm -- -rf` deletes a file `-rf`).
    let mut ended = false;
    let dir = unit.dir.as_ref();
    UnitExplanation {
        shell: unit.shell,
        depth: unit.depth,
        program: unit.program.text().to_string(),
        key: unit.key(),
        args: unit
            .args
            .iter()
            .map(|arg| {
                let option = !ended && arg.known().is_some_and(|text| is_option(text, unit.shell));
                ended |= unit.shell == Shell::Posix && arg.known() == Some("--");
                (arg, option)
            })
            .map(|(arg, option)| ArgExplanation {
                written: arg.text().to_string(),
                kind: match arg {
                    Arg::Known(_) => ArgKind::Known,
                    Arg::Unknown(_) => ArgKind::Unknown,
                    Arg::Template { .. } => ArgKind::Template,
                    Arg::Input => ArgKind::Input,
                    Arg::Null => ArgKind::Unknown,
                },
                resolved: arg
                    .known()
                    .filter(|_| !option)
                    .and_then(|text| {
                        *placed
                            .entry((dir, shell_name(unit.shell), unit.hidden, text))
                            .or_insert_with(|| {
                                resolved(
                                    arg,
                                    unit.dir.as_ref(),
                                    unit.shell,
                                    unit.hidden,
                                    resolver,
                                    false,
                                )
                            })
                    })
                    .map(str::to_string),
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

/// A text as the tree prints it: a control character (a newline, a tab, an
/// ESC), a line or paragraph separator and a format character (a
/// right-to-left override, a bidi isolate, a zero-width space) are written as
/// escapes (`\n`, `\u{1b}`, `\u{202e}`), so what the line holds can neither
/// pose as a line of the tree, nor reach a terminal as a sequence, nor show
/// its text in another order than it is read. The fields stay raw; only the
/// tree escapes.
struct Escaped<'a>(&'a str);

/// The format characters of Unicode 17.0 (general category `Cf`, from its
/// `DerivedGeneralCategory.txt`): they draw nothing, and the bidi controls
/// among them (U+202A to U+202E, U+2066 to U+2069) reorder the text around
/// them.
const FORMAT: [(char, char); 21] = [
    ('\u{00ad}', '\u{00ad}'),
    ('\u{0600}', '\u{0605}'),
    ('\u{061c}', '\u{061c}'),
    ('\u{06dd}', '\u{06dd}'),
    ('\u{070f}', '\u{070f}'),
    ('\u{0890}', '\u{0891}'),
    ('\u{08e2}', '\u{08e2}'),
    ('\u{180e}', '\u{180e}'),
    ('\u{200b}', '\u{200f}'),
    ('\u{202a}', '\u{202e}'),
    ('\u{2060}', '\u{2064}'),
    ('\u{2066}', '\u{206f}'),
    ('\u{feff}', '\u{feff}'),
    ('\u{fff9}', '\u{fffb}'),
    ('\u{110bd}', '\u{110bd}'),
    ('\u{110cd}', '\u{110cd}'),
    ('\u{13430}', '\u{1343f}'),
    ('\u{1bca0}', '\u{1bca3}'),
    ('\u{1d173}', '\u{1d17a}'),
    ('\u{e0001}', '\u{e0001}'),
    ('\u{e0020}', '\u{e007f}'),
];

/// Whether the tree writes `c` as an escape.
fn escaped(c: char) -> bool {
    if c.is_ascii() {
        return c.is_ascii_control();
    }
    c.is_control()
        || matches!(c, '\u{2028}' | '\u{2029}')
        || FORMAT.iter().any(|&(from, to)| (from..=to).contains(&c))
}

impl fmt::Display for Escaped<'_> {
    /// Printable ASCII is written as it is, and other text a run at a time
    /// between escapes: a tree can hold megabytes of nested script.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.bytes().all(|byte| matches!(byte, b' '..=b'~')) {
            return f.write_str(self.0);
        }
        let mut from = 0;
        for (at, c) in self.0.char_indices().filter(|&(_, c)| escaped(c)) {
            f.write_str(self.0.get(from..at).unwrap_or_default())?;
            write!(f, "{}", c.escape_debug())?;
            from = at + c.len_utf8();
        }
        f.write_str(self.0.get(from..).unwrap_or_default())
    }
}

impl fmt::Display for Explanation {
    /// A short indented tree: the line, each unit with what it was read as
    /// and what it found, the redirects, and what the line found itself.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "line ({}): {}",
            shell_name(self.shell),
            Escaped(&self.command)
        )?;
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
        write!(f, "unit {number}: {}", Escaped(&self.program))?;
        if let Some(key) = self.key.as_deref().filter(|key| *key != self.program) {
            write!(f, " (read as {})", Escaped(key))?;
        }
        writeln!(f)?;
        write!(f, "  shell: {}", shell_name(self.shell))?;
        if self.depth > 0 {
            write!(f, ", nested {} deep", self.depth)?;
        }
        writeln!(f)?;
        if !self.wrappers.is_empty() {
            write!(f, "  wrappers: ")?;
            for (at, wrapper) in self.wrappers.iter().enumerate() {
                if at > 0 {
                    write!(f, ", ")?;
                }
                write!(f, "{}", Escaped(wrapper))?;
            }
            writeln!(f)?;
        }
        if let Some(stage) = self.stage {
            writeln!(f, "  pipeline {}, stage {}", stage.pipeline, stage.index)?;
        }
        if let Some(dir) = &self.dir {
            writeln!(f, "  runs from: {}", Escaped(dir))?;
        }
        if self.hidden {
            writeln!(f, "  wildcards match hidden names")?;
        }
        if !self.args.is_empty() {
            writeln!(f, "  args")?;
            // A unit may hold thousands of arguments: each line is written
            // in pieces, with no formatting to parse.
            for arg in &self.args {
                f.write_str("    ")?;
                fmt::Display::fmt(&Escaped(&arg.written), f)?;
                match (&arg.resolved, arg.kind) {
                    (Some(place), _) => {
                        f.write_str(" (as a path: ")?;
                        fmt::Display::fmt(&Escaped(place), f)?;
                        f.write_str(")")?;
                    }
                    (None, ArgKind::Unknown) => f.write_str(" (known only when it runs)")?,
                    (None, ArgKind::Template) => {
                        f.write_str(" (partly known only when it runs)")?;
                    }
                    (None, ArgKind::Input) => f.write_str(" (from the previous stage)")?,
                    (None, _) => {}
                }
                f.write_str("\n")?;
            }
        }
        write_findings(f, &self.findings)
    }
}

impl RedirectExplanation {
    fn write(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "redirect: writes to {}", Escaped(&self.target))?;
        if let Some(place) = &self.resolved {
            write!(f, " (as a path: {})", Escaped(place))?;
        }
        writeln!(f)?;
        write!(f, "  shell: {}", shell_name(self.shell))?;
        writeln!(f)?;
        if let Some(dir) = &self.dir {
            writeln!(f, "  runs from: {}", Escaped(dir))?;
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
    write!(
        f,
        "{indent}{}: {}",
        finding.rule.name(),
        Escaped(&finding.reason)
    )?;
    if let Some(target) = &finding.target {
        write!(f, " ({})", Escaped(target))?;
    }
    writeln!(f)?;
    if let Some(instead) = &finding.instead {
        writeln!(f, "{indent}  instead: {}", Escaped(instead))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{escaped, Escaped, FORMAT};

    #[test]
    fn every_format_character_is_written_as_an_escape() {
        for &(from, to) in &FORMAT {
            for c in from..=to {
                assert!(escaped(c));
                let printed = Escaped(&c.to_string()).to_string();
                assert_eq!(printed, format!("\\u{{{:x}}}", u32::from(c)));
            }
        }
    }

    /// Written out here, not read from `FORMAT`, so a character the table
    /// lost is caught: every bidi control, and the format characters that
    /// most often hide in text.
    #[test]
    fn the_bidi_controls_and_common_invisible_characters_are_escapes() {
        let required = [
            '\u{202a}',
            '\u{202b}',
            '\u{202c}',
            '\u{202d}',
            '\u{202e}',
            '\u{2066}',
            '\u{2067}',
            '\u{2068}',
            '\u{2069}',
            '\u{00ad}',
            '\u{061c}',
            '\u{200b}',
            '\u{200c}',
            '\u{200d}',
            '\u{200e}',
            '\u{200f}',
            '\u{2060}',
            '\u{feff}',
            '\u{e0001}',
        ];
        for c in required {
            assert!(escaped(c), "{:x}", u32::from(c));
        }
    }

    #[test]
    fn other_text_is_written_as_it_is() {
        for text in ["rm -rf ~/x", "é", "日本", "a\u{301}", "\\", "'\""] {
            assert_eq!(Escaped(text).to_string(), text);
        }
    }
}
