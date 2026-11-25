//! PowerShell's own parser, asked about a batch of lines without running
//! one.
//!
//! PowerShell has no no-exec mode, but its parser is a .NET method,
//! `[System.Management.Automation.Language.Parser]::ParseInput`, which reads
//! a text into a tree and its errors and runs nothing. [`SNIPPET`] is the one
//! PowerShell script of the repository, and the one exception to "Rust
//! only" beside the release workflow's steps: PowerShell's parser is reached
//! from PowerShell (or from .NET, which would be a second language too). It
//! is the whole program `pwsh` is started with (`-NoProfile -NonInteractive
//! -Command`), embedded here, with no line in its text: the lines are data,
//! each encoded in base64 on a line of a file in the room, read with
//! `[IO.File]::ReadAllLines` and decoded, then handed to `ParseInput` and to
//! nothing else. What it prints is the parser's answer, encoded again.
//!
//! The parser does act on a few statements while it reads: `using module`
//! and `using assembly` load what they name, and a `configuration` (and its
//! `Import-DscResource`) loads DSC resources. A line that may hold one of
//! those words, in any case and in any spelling PowerShell folds to them, is
//! never handed to it ([`acted_on`]), and nor is one with a type literal
//! that may name an assembly (`[Type, Assembly]`), which the parser may try
//! to load to resolve it; the report counts them.
//!
//! This half has not run anywhere yet: `pwsh` is off unless `--with pwsh` is
//! given, and CI's job does not give it (`docs/design/shell.md`).

use crate::base64;
use crate::room::{Failure, Limits, Room, Start};

/// The PowerShell program: it reads the file `$env:GRAMMAR_CHECK_BATCH`, one
/// line of base64 (UTF-8) to a line to parse, and prints, after its version,
/// for each: `rejects OFFSET ERROR` (the first error's offset in UTF-16
/// units and its id, in base64), or `accepts` and one `command NESTED
/// WORD…` for each command of the tree (`NESTED` is `1` when it sits in a
/// script block inside the line, which runs only when something calls it),
/// then `end`. A word is `k` and the text of a parameter (`-Path:`), `s` and
/// the value of a string, each in base64, or `?` for anything else (a
/// variable, an expression, a number). An array of words (`a,b`) is its
/// words.
pub const SNIPPET: &str = r"
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0
$out = [Console]::Out
function Code([string] $text) {
    [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($text))
}
function Words($element) {
    if ($element -is [Management.Automation.Language.CommandParameterAst]) {
        $text = $element.Extent.Text
        if ($null -eq $element.Argument) {
            'k' + (Code $text)
        } else {
            $length = $element.Argument.Extent.StartOffset - $element.Extent.StartOffset
            if ($length -gt 0 -and $length -le $text.Length) {
                'k' + (Code ($text.Substring(0, $length).TrimEnd()))
            } else {
                '?'
            }
            Words $element.Argument
        }
    } elseif ($element -is [Management.Automation.Language.StringConstantExpressionAst]) {
        's' + (Code ($element.Value))
    } elseif ($element -is [Management.Automation.Language.ArrayLiteralAst]) {
        foreach ($item in $element.Elements) { Words $item }
    } else {
        '?'
    }
}
$out.WriteLine('version ' + $PSVersionTable.PSVersion.ToString())
foreach ($encoded in [IO.File]::ReadAllLines($env:GRAMMAR_CHECK_BATCH)) {
    $text = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encoded))
    $tokens = $null
    $errors = $null
    $tree = [Management.Automation.Language.Parser]::ParseInput($text, [ref] $tokens, [ref] $errors)
    if ($errors.Count -gt 0) {
        $out.WriteLine('rejects ' + $errors[0].Extent.StartOffset + ' ' + (Code ($errors[0].ErrorId)))
    } else {
        $out.WriteLine('accepts')
        $commands = $tree.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] }, $true)
        foreach ($command in $commands) {
            $block = $command.Parent
            while ($block -isnot [Management.Automation.Language.ScriptBlockAst]) { $block = $block.Parent }
            $nested = if ($null -eq $block.Parent) { '0' } else { '1' }
            $words = @(foreach ($element in $command.CommandElements) { Words $element })
            $out.WriteLine('command ' + $nested + ' ' + ($words -join ' '))
        }
    }
    $out.WriteLine('end')
}
$out.Flush()
";

/// The words PowerShell's parser acts on while it reads, upper case.
const ACTED_ON: [&str; 4] = ["USING", "CONFIGURATION", "DSCRESOURCE", "REQUIRES"];

/// Whether `line` may hold a word PowerShell's parser acts on while it reads
/// ([`ACTED_ON`]), in any case: each character is compared by its upper
/// case, as PowerShell compares a keyword (`ı` is `I`, `ſ` is `S`), with
/// the characters between letters PowerShell does not read in a word dropped
/// too, so no spelling of one gets through.
pub fn acted_on(line: &str) -> bool {
    let folded: String = line
        .chars()
        .flat_map(char::to_uppercase)
        .filter(|c| !is_invisible(*c))
        .collect();
    ACTED_ON.iter().any(|word| folded.contains(word)) || names_an_assembly(line)
}

/// Whether `line` may hold a type literal with an assembly beside the type
/// (`[System.Foo, Some.Assembly]`): a `[` with a `,` before its `]`. An index
/// with a comma (`$a[1,2]`) is left out too.
fn names_an_assembly(line: &str) -> bool {
    let mut open = 0usize;
    for c in line.chars() {
        match c {
            '[' => open += 1,
            ']' => open = open.saturating_sub(1),
            ',' if open > 0 => return true,
            _ => {}
        }
    }
    false
}

/// A character that shows nothing: a zero-width space, joiner or mark, a
/// soft hyphen.
fn is_invisible(c: char) -> bool {
    matches!(c, '\u{ad}' | '\u{200b}'..='\u{200f}' | '\u{2060}'..='\u{2064}' | '\u{feff}')
}

/// A word of a command, as the parser read it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Word {
    /// A parameter, as written (`-Recurse`, `-Path:`).
    Parameter(String),
    /// A string's value (`C:\x`, `a b` for `'a b'`).
    Value(String),
    /// Anything only known when it runs.
    Unknown,
}

/// One command of a line, as the parser read it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Command {
    /// Whether it sits in a script block inside the line (`{ rm x }`),
    /// which runs only when something calls the block.
    pub nested: bool,
    /// Its words, the command's name first.
    pub words: Vec<Word>,
}

/// What the parser said of one line.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Parsed {
    /// It read the line with no error, into these commands.
    Accepts(Vec<Command>),
    /// It found an error: its offset (UTF-16 units) and its id
    /// (`MissingEndCurlyBrace`).
    Rejects(usize, String),
}

/// The most lines handed to one `pwsh`: it takes about a second to start,
/// and a parse a fraction of a millisecond.
pub const BATCH: usize = 500;

/// Ask `pwsh` at `program`, in `room`, how its parser reads each of `lines`
/// (at most [`BATCH`], none of them [`acted_on`]); its version beside the
/// answers, in order.
pub fn parse_batch(
    program: &std::path::Path,
    room: &Room,
    lines: &[&str],
) -> Result<(String, Vec<Parsed>), Failure> {
    if let Some(line) = lines.iter().find(|line| acted_on(line)) {
        return Err(Failure::Start(format!(
            "a line PowerShell's parser acts on reached the batch: {line:?}"
        )));
    }
    let mut batch = String::new();
    for line in lines {
        batch.push_str(&base64::encode(line.as_bytes()));
        batch.push('\n');
    }
    let file = room.input().join("batch");
    write_batch(&file, &batch)?;
    let finished = room.start(&Start {
        program,
        args: [
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            SNIPPET,
        ]
        .map(std::ffi::OsString::from)
        .to_vec(),
        env: vec![
            ("GRAMMAR_CHECK_BATCH", file.as_os_str().to_os_string()),
            // Its own module path points at an empty folder (pwsh adds the
            // folders of the modules it ships with), and nothing is sent
            // anywhere.
            ("PSModulePath", room.bin().as_os_str().to_os_string()),
            ("POWERSHELL_TELEMETRY_OPTOUT", "1".into()),
            ("POWERSHELL_UPDATECHECK", "Off".into()),
            ("DOTNET_CLI_TELEMETRY_OPTOUT", "1".into()),
            ("DOTNET_NOLOGO", "1".into()),
        ],
        stdin: b"",
        home_stays_empty: false,
        silent: false,
        limits: Limits {
            patience: std::time::Duration::from_secs(120),
            output: 64 * 1024 * 1024,
        },
    })?;
    let printed = String::from_utf8_lossy(&finished.stdout);
    let answers = read_answers(&printed, lines.len()).map_err(|why| {
        let said = String::from_utf8_lossy(&finished.stderr);
        let said: Vec<&str> = said.lines().take(5).collect();
        Failure::Start(format!(
            "pwsh's answer cannot be read ({why}); it ended with {:?} and said: {}",
            finished.code,
            said.join(" / ")
        ))
    })?;
    Ok(answers)
}

/// What the parser said of each of `lines`, or why it said nothing of that
/// one, and its version: a batch that gives no answer is read again in two
/// halves, down to the one line, so one line that breaks it costs no other
/// line its answer. What stops the run stops it here too.
pub fn parse_each(
    program: &std::path::Path,
    room: &Room,
    lines: &[&str],
) -> Result<(String, Vec<Result<Parsed, String>>), Failure> {
    match parse_batch(program, room, lines) {
        Ok((version, answers)) => Ok((version, answers.into_iter().map(Ok).collect())),
        Err(Failure::Stop(why)) => Err(Failure::Stop(why)),
        Err(other) if lines.len() <= 1 => Ok((
            String::new(),
            vec![Err(match other {
                Failure::TimedOut => "ran past its time and was killed".to_string(),
                Failure::Start(why) | Failure::Stop(why) => why,
            })],
        )),
        Err(_) => {
            let (first, second) = lines.split_at(lines.len() / 2);
            let (version, mut answers) = parse_each(program, room, first)?;
            let (later, rest) = parse_each(program, room, second)?;
            answers.extend(rest);
            Ok((if version.is_empty() { later } else { version }, answers))
        }
    }
}

#[allow(
    clippy::disallowed_methods,
    reason = "the batch is handed to PowerShell as a file of the room"
)]
fn write_batch(file: &std::path::Path, batch: &str) -> Result<(), Failure> {
    std::fs::write(file, batch)
        .map_err(|e| Failure::Start(format!("cannot write {}: {e}", file.display())))
}

/// The version and the answers in what [`SNIPPET`] printed for `count`
/// lines.
pub fn read_answers(printed: &str, count: usize) -> Result<(String, Vec<Parsed>), String> {
    let mut lines = printed.lines();
    let version = lines
        .next()
        .and_then(|line| line.strip_prefix("version "))
        .ok_or("no version first")?
        .trim()
        .to_string();
    let mut answers = Vec::new();
    let mut current: Option<Parsed> = None;
    for line in lines {
        let (head, rest) = line.split_once(' ').unwrap_or((line, ""));
        match (head, &mut current) {
            ("accepts", None) => current = Some(Parsed::Accepts(Vec::new())),
            ("rejects", None) => {
                let (offset, id) = rest.split_once(' ').ok_or("a rejection without its id")?;
                let offset = offset
                    .parse()
                    .map_err(|_| "an offset that is not a number")?;
                current = Some(Parsed::Rejects(offset, decoded(id)?));
            }
            ("command", Some(Parsed::Accepts(commands))) => commands.push(command(rest)?),
            ("end", Some(_)) => answers.extend(current.take()),
            _ => return Err(format!("an unexpected line {line:?}")),
        }
    }
    if current.is_some() || answers.len() != count {
        return Err(format!("{} answers for {count} lines", answers.len()));
    }
    Ok((version, answers))
}

fn command(rest: &str) -> Result<Command, String> {
    let mut parts = rest.split(' ');
    let nested = match parts.next() {
        Some("0") => false,
        Some("1") => true,
        _ => return Err("a command without its nesting".to_string()),
    };
    let words = parts
        .filter(|part| !part.is_empty())
        .map(|part| {
            if part == "?" {
                Ok(Word::Unknown)
            } else if let Some(text) = part.strip_prefix('k') {
                decoded(text).map(Word::Parameter)
            } else if let Some(text) = part.strip_prefix('s') {
                decoded(text).map(Word::Value)
            } else {
                Err(format!("a word {part:?}"))
            }
        })
        .collect::<Result<_, _>>()?;
    Ok(Command { nested, words })
}

fn decoded(text: &str) -> Result<String, String> {
    let bytes = base64::decode(text).ok_or_else(|| format!("{text:?} is not base64"))?;
    String::from_utf8(bytes).map_err(|_| format!("{text:?} is not UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code(text: &str) -> String {
        base64::encode(text.as_bytes())
    }

    #[test]
    fn the_answers_are_read_in_order() {
        let printed = format!(
            "version 7.4.6\naccepts\ncommand 0 s{} k{} ? s{}\ncommand 1 s{}\nend\nrejects 12 {}\nend\naccepts\nend\n",
            code("Remove-Item"),
            code("-Path:"),
            code("C:\\x y"),
            code("rm"),
            code("MissingEndCurlyBrace"),
        );
        let (version, answers) = read_answers(&printed, 3).unwrap();
        assert_eq!(version, "7.4.6");
        assert_eq!(
            answers,
            [
                Parsed::Accepts(vec![
                    Command {
                        nested: false,
                        words: vec![
                            Word::Value("Remove-Item".into()),
                            Word::Parameter("-Path:".into()),
                            Word::Unknown,
                            Word::Value("C:\\x y".into()),
                        ],
                    },
                    Command {
                        nested: true,
                        words: vec![Word::Value("rm".into())],
                    },
                ]),
                Parsed::Rejects(12, "MissingEndCurlyBrace".into()),
                Parsed::Accepts(Vec::new()),
            ]
        );
    }

    #[test]
    fn an_answer_that_is_not_whole_is_refused() {
        for printed in [
            "",
            "accepts\nend\n",
            "version 7\naccepts\n",
            "version 7\naccepts\nend\naccepts\nend\n",
            "version 7\ncommand 0\nend\n",
            "version 7\naccepts\ncommand 2 ?\nend\n",
            "version 7\naccepts\ncommand 0 x\nend\n",
            "version 7\naccepts\ncommand 0 s!!\nend\n",
            "version 7\nrejects x y\nend\n",
            "version 7\nrejects 1\nend\n",
            "version 7\naccepts\ncommand 0 \u{e9}x\nend\n",
            "version 7\nsomething\n",
        ] {
            assert!(read_answers(printed, 1).is_err(), "{printed:?}");
        }
    }

    #[test]
    fn a_word_the_parser_acts_on_is_found_in_any_spelling() {
        for line in [
            "using module ./x.psm1",
            "UsInG assembly x.dll",
            "us\u{131}ng module x",
            "u\u{17f}ing module x",
            "us\u{200b}ing module x",
            "Configuration Web { Import-DscResource -ModuleName x }",
            "#requires -Modules x",
            "$x = 'confusing'",
        ] {
            assert!(acted_on(line), "{line}");
        }
        for line in [
            "[System.Text.Encoding, mscorlib]::UTF8",
            "$a[1,2]",
            "[Foo.Bar,Some.Assembly,Version=1.0.0.0]::new()",
        ] {
            assert!(acted_on(line), "{line}");
        }
        for line in [
            "Remove-Item x",
            "Get-ChildItem -Recurse | rm",
            "use x",
            "[int]::Parse('1'), 2",
        ] {
            assert!(!acted_on(line), "{line}");
        }
    }
}
