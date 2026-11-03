//! GNU `parallel`: a command, then the values it runs it with. Each job is a
//! line its shell runs: the command's words joined with spaces (with `-q`,
//! each word quoted), each value put, quoted, where a replacement string
//! stands (`{}`, `{.}`, `{1}`) or after the words when none does.

use super::{join, shell_word, Launch};
use crate::unit::{Arg, Reads, MAX_LEN};
use crate::Shell;

/// How many jobs the values of a line may make before it runs too many to
/// read one by one.
const MAX_JOBS: usize = 256;

/// How many sources of values (`:::`, `::::`, `-a`) a line may give before
/// it is not read: each job holds a value of each.
const MAX_SOURCES: usize = 32;

/// The longest replacement string (`-I`) read: a real one is a few bytes.
const MAX_REPLACE: usize = 64;

/// Why the jobs of a line are not read.
const UNREAD: &str = "runs commands built in a way that cannot be read";
const TOO_MANY: &str = "runs more commands than can be read one by one";
const TOO_LONG: &str = "runs commands too long to read";

/// The short options that take a value, as the next word or the rest of
/// the bundle.
const SHORT_VALUES: &str = "adEIjJLnNPSsW";

/// The short options that take none (`-l`, `-i` and `-e` take theirs only
/// attached).
const SHORT_FLAGS: &str = "0eghiklmpqrtuvxMTVX";

/// The long options that take a value.
const LONG_VALUES: &[&str] = &[
    "arg-file",
    "basefile",
    "bf",
    "block",
    "block-size",
    "compress-program",
    "ctagstring",
    "decompress-program",
    "delay",
    "delimiter",
    "env",
    "eof",
    "filter",
    "group-by",
    "halt",
    "halt-on-error",
    "id",
    "jobs",
    "joblog",
    "limit",
    "load",
    "max-args",
    "max-chars",
    "max-lines",
    "max-procs",
    "max-replace-args",
    "memfree",
    "memsuspend",
    "minversion",
    "nice",
    "profile",
    "recend",
    "recstart",
    "res",
    "results",
    "retries",
    "return",
    "semaphorename",
    "semaphoretimeout",
    "slf",
    "sql",
    "sqlandworker",
    "sqlmaster",
    "ssh",
    "sshdelay",
    "sshlogin",
    "sshloginfile",
    "st",
    "tagstring",
    "template",
    "tempdir",
    "termseq",
    "tf",
    "timeout",
    "tmpdir",
    "tmpl",
    "total-jobs",
    "transferfile",
    "trc",
    "trim",
    "wd",
    "workdir",
];

/// The long options that take none.
const LONG_FLAGS: &[&str] = &[
    "bar",
    "bg",
    "bibtex",
    "cat",
    "cf",
    "citation",
    "cleanup",
    "color",
    "color-failed",
    "colour",
    "compress",
    "ctag",
    "dry-run",
    "embed",
    "eta",
    "exit",
    "fg",
    "fifo",
    "files",
    "files0",
    "group",
    "help",
    "interactive",
    "joblog-append",
    "keep-order",
    "latest-line",
    "lb",
    "line-buffer",
    "linebuffer",
    "link",
    "ll",
    "no-notice",
    "no-run-if-empty",
    "nonall",
    "noswap",
    "null",
    "number-of-cores",
    "number-of-cpus",
    "number-of-sockets",
    "number-of-threads",
    "onall",
    "pipe",
    "pipe-part",
    "pipepart",
    "progress",
    "quote",
    "record-env",
    "regexp",
    "remove-rec-sep",
    "replace",
    "resume",
    "resume-failed",
    "retry-failed",
    "round",
    "round-robin",
    "rrs",
    "show-limits",
    "shuf",
    "silent",
    "skip-first-line",
    "spreadstdin",
    "tag",
    "tee",
    "tmux",
    "transfer",
    "tty",
    "ungroup",
    "unsafe",
    "use-cores-instead-of-cpus",
    "use-cpus-instead-of-cores",
    "use-sockets-instead-of-threads",
    "use-threads-instead-of-cores",
    "verbose",
    "version",
    "will-cite",
    "xapply",
    "xargs",
];

/// The options that change how a value is split, named or put in the
/// command, or what the separators are: what a job runs then is not read.
const LONG_UNREAD: &[&str] = &[
    "arg-file-sep",
    "arg-sep",
    "basenameextensionreplace",
    "basenamereplace",
    "bner",
    "bnr",
    "colsep",
    "csv",
    "dirnamereplace",
    "dr",
    "er",
    "extensionreplace",
    "hashbang",
    "header",
    "plus",
    "rpl",
    "seqreplace",
    "shebang",
    "shebang-wrap",
    "slotreplace",
];

/// The options that put more than one value, or values from several sources
/// in step, into one job: a job's numbered replacement string (`{2}`) then
/// names a value the guard does not pair.
const LONG_GROUPING: [&str; 7] = [
    "max-args",
    "max-replace-args",
    "max-lines",
    "xargs",
    "link",
    "xapply",
    "pipe",
];

/// One value a job is run with.
#[derive(Clone, PartialEq)]
enum Value {
    /// Known on the line.
    Known(String),
    /// Only known when it runs: its source text.
    Later(String),
    /// A line of the input, or of a file `-a` or `::::` names.
    Input,
}

/// What [`read_options`] finds before the command.
struct Options {
    /// Where the command starts.
    start: usize,
    /// The string replaced by the whole value (`-I`): `{}` by default.
    replace: String,
    /// `-q`: each word of the command is quoted, not read by the shell.
    quote: bool,
    /// Several values to a job, or sources read in step.
    grouping: bool,
    /// Sources named by `-a` (`--arg-file`).
    files: usize,
    /// `--trim`: the sides of each value whose spaces are taken off, `l`
    /// and `r` (`n`, none).
    trim: String,
}

/// `parallel`: its options, the command, and the values after `:::` (or
/// the files after `::::`), or, with neither, its input. With no command
/// each value is a line of its own. A line that runs too many jobs, or that
/// builds them in a way the guard does not follow (`--colsep`, a `{= … =}`
/// expression, an option it does not know), is not read.
pub(super) fn parallel(args: &[Arg]) -> Launch {
    let Some(options) = read_options(args) else {
        return Launch::Opaque(UNREAD);
    };
    let separator = args[options.start..]
        .iter()
        .position(|arg| arg.known().is_some_and(is_separator))
        .map_or(args.len(), |at| options.start + at);
    let command = &args[options.start..separator];
    let mut grouping = options.grouping;
    let mut sources: Vec<Vec<Value>> = vec![vec![Value::Input]; options.files];
    let mut at = separator;
    while let Some(arg) = args.get(at) {
        let separator = arg.known().unwrap_or_default();
        grouping |= separator.ends_with('+');
        let end = args[at + 1..]
            .iter()
            .position(|arg| arg.known().is_some_and(is_separator))
            .map_or(args.len(), |end| at + 1 + end);
        if separator.starts_with("::::") {
            sources.push(vec![Value::Input]);
        } else {
            sources.push(
                args[at + 1..end]
                    .iter()
                    .map(|word| {
                        word.known().map_or_else(
                            || Value::Later(word.text().to_string()),
                            |text| Value::Known(trimmed(text, &options.trim).to_string()),
                        )
                    })
                    .collect(),
            );
        }
        at = end;
    }
    if sources.is_empty() {
        sources.push(vec![Value::Input]);
    }
    if command.is_empty() {
        return values_as_lines(&sources);
    }
    if command.iter().any(|word| word.known().is_none()) {
        return Launch::Script(Shell::Posix, join(command));
    }
    let words: Vec<&str> = command.iter().filter_map(Arg::known).collect();
    let joined = [words.join(" ")];
    let joined = [joined[0].as_str()];
    // A command of plain words fed its input is `xargs`: what the input
    // holds is judged where it lands.
    if sources == [vec![Value::Input]] && plain(command, &options) {
        let replace = command
            .iter()
            .filter_map(Arg::known)
            .any(|word| word.contains(options.replace.as_str()))
            .then(|| options.replace.clone());
        return Launch::Input {
            start: options.start,
            replace,
        };
    }
    let Some(mut jobs) = jobs(&sources) else {
        return Launch::Opaque(TOO_MANY);
    };
    // The jobs run together: a command given every value at once is judged
    // too (`docker rm -f` of several containers).
    if jobs.len() > 1 {
        jobs.push(
            sources
                .iter()
                .map(|source| source.iter().collect())
                .collect(),
        );
    }
    // The jobs' lines are one script, which is not read past the longest
    // line: building them stops there.
    let script = |template: &[&str], quote: usize| {
        let mut lines: Vec<String> = Vec::new();
        let mut budget = MAX_LEN;
        for job in &jobs {
            let line = fill(template, quote, job, &options.replace, grouping, budget)?;
            if !lines.contains(&line) {
                budget = budget.checked_sub(line.len() + 1).ok_or(TOO_LONG)?;
                lines.push(line);
            }
        }
        Ok(Launch::Script(Shell::Posix, Arg::Known(lines.join("\n"))))
    };
    // The command's words as its shell gets them: with `-q` each word kept
    // whole, its values put in before it is quoted; otherwise joined with
    // spaces, so a word with a space in it splits. The guard also reads such
    // a word after the program kept whole, as `-q` would (`parallel sh -c
    // 'rm -rf {}'`), and the riskier reading counts. A program word kept
    // whole names no program, so it is read split in both.
    let readings = if options.quote {
        script(&words, 0).map(|kept| (kept, None))
    } else if words[1..].iter().all(|word| shell_word(word) == *word) {
        script(&joined, 1).map(|split| (split, None))
    } else {
        script(&joined, 1).and_then(|split| script(&words, 1).map(|kept| (split, Some(kept))))
    };
    match readings {
        Ok((first, None)) => first,
        Ok((first, Some(second))) => Launch::Either(Box::new(first), Box::new(second)),
        Err(reason) => Launch::Opaque(reason),
    }
}

/// With no command, each job's values are its line, run as they are; lines
/// read from the input are run as a shell runs its input.
fn values_as_lines(sources: &[Vec<Value>]) -> Launch {
    let Some(jobs) = jobs(sources) else {
        return Launch::Opaque(TOO_MANY);
    };
    let mut lines = Vec::new();
    let mut length = 0;
    for job in jobs {
        let mut words = Vec::new();
        for value in job.iter().flatten() {
            match value {
                Value::Known(text) => words.push(text.as_str()),
                Value::Later(text) => {
                    return Launch::Script(Shell::Posix, Arg::Unknown(text.clone()));
                }
                Value::Input => return Launch::Reads(Reads::Shell),
            }
        }
        let line = words.join(" ");
        length += line.len() + 1;
        if length > MAX_LEN {
            return Launch::Opaque(TOO_LONG);
        }
        lines.push(line);
    }
    Launch::Script(Shell::Posix, Arg::Known(lines.join("\n")))
}

/// Whether `text` starts a source of values: `:::` (the words after it),
/// `::::` (the files after it), and `:::+` and `::::+`, which read theirs in
/// step with the one before.
fn is_separator(text: &str) -> bool {
    matches!(text, ":::" | "::::" | ":::+" | "::::+")
}

/// Whether the command's words reach the shell as the same words: each is
/// known and plain, and the only replacement string is the whole value.
fn plain(command: &[Arg], options: &Options) -> bool {
    command.iter().enumerate().all(|(at, word)| {
        word.known().is_some_and(|text| {
            let rest = text.replace(options.replace.as_str(), "");
            !rest.contains(['{', '}'])
                && (options.quote
                    || (rest
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || "_./~:=@%+,-".contains(c))
                        && (at > 0 || !rest.contains('='))))
        })
    })
}

/// A job: for each source, the values it is given (one, or all of them for
/// the job that stands for every job at once).
type Job<'a> = Vec<Vec<&'a Value>>;

/// Every job: one value from each source, each source in turn. `None` past
/// [`MAX_JOBS`] or [`MAX_SOURCES`].
fn jobs(sources: &[Vec<Value>]) -> Option<Vec<Job<'_>>> {
    if sources.len() > MAX_SOURCES {
        return None;
    }
    let mut jobs: Vec<Job<'_>> = vec![Vec::new()];
    for source in sources {
        if jobs.len().checked_mul(source.len().max(1))? > MAX_JOBS {
            return None;
        }
        if source.len() <= 1 {
            for job in &mut jobs {
                job.push(source.iter().collect());
            }
            continue;
        }
        jobs = jobs
            .iter()
            .flat_map(|job| {
                source.iter().map(move |value| {
                    let mut next = job.clone();
                    next.push(vec![value]);
                    next
                })
            })
            .collect();
    }
    Some(jobs)
}

/// The line one job runs: the command's `words` with each replacement
/// string replaced by its values, quoted, or the values after them when
/// there is none. Each word from the one at `quote` on (every word with
/// `-q`) is one word of the line, its text quoted around the values; a word
/// before it is text the shell reads as it is. A value only known when it runs stands as `"$1"`, which the
/// shell's grammar reads as one. Why not, for a `{= … =}` expression, which
/// is Perl, for a numbered string when `grouping` pairs values the guard
/// does not, and for a line longer than `budget`.
fn fill(
    words: &[&str],
    quote: usize,
    job: &[Vec<&Value>],
    replace: &str,
    grouping: bool,
    budget: usize,
) -> Result<String, &'static str> {
    let values = |values: &[&Value], transform: &str| {
        values
            .iter()
            .map(|value| match value {
                Value::Known(text) => shell_word(&transformed(text, transform)),
                Value::Later(_) | Value::Input => "\"$1\"".to_string(),
            })
            .collect::<Vec<_>>()
            .join(" ")
    };
    let all = |transform: &str| {
        let every: Vec<&Value> = job.iter().flatten().copied().collect();
        values(&every, transform)
    };
    let mut line = String::with_capacity(budget.min(words.iter().map(|word| word.len() + 1).sum()));
    let mut replaced = false;
    for (index, word) in words.iter().enumerate() {
        if index > 0 {
            line.push(' ');
        }
        // The text of a word between its values, quoted when the word is.
        let quote = index >= quote;
        let mut text = String::new();
        let flush = |line: &mut String, text: &mut String| {
            if quote && !text.is_empty() {
                line.push_str(&shell_word(text));
            } else {
                line.push_str(text);
            }
            text.clear();
        };
        let mut rest = *word;
        if quote && rest.is_empty() {
            line.push_str("''");
        }
        while !rest.is_empty() {
            if line.len() + text.len() > budget {
                return Err(TOO_LONG);
            }
            if rest.starts_with("{=") {
                return Err(UNREAD);
            }
            if let Some(after) = rest.strip_prefix(replace) {
                flush(&mut line, &mut text);
                line.push_str(&all(""));
                replaced = true;
                rest = after;
                continue;
            }
            if let Some((number, transform, after)) = token(rest) {
                flush(&mut line, &mut text);
                match number {
                    Some(_) if grouping => return Err(UNREAD),
                    Some(number) => match job.get(number - 1) {
                        Some(given) if !given.is_empty() => {
                            line.push_str(&values(given, transform));
                        }
                        _ => line.push_str("''"),
                    },
                    None if matches!(transform, "#" | "%") => line.push('1'),
                    None => line.push_str(&all(transform)),
                }
                replaced = true;
                rest = after;
                continue;
            }
            let mut chars = rest.chars();
            text.extend(chars.next());
            rest = chars.as_str();
        }
        flush(&mut line, &mut text);
    }
    if !replaced {
        line.push(' ');
        line.push_str(&all(""));
    }
    if line.len() > budget {
        return Err(TOO_LONG);
    }
    Ok(line)
}

/// A replacement string at the start of `text` other than the whole value:
/// `{.}`, `{/}`, `{//}`, `{/.}`, `{#}`, `{%}`, and each with a source's
/// number in front (`{1}`, `{2.}`). Its number, its transform and the text
/// after it. Only the few bytes a transform takes are looked at past the
/// number, so a `{` that never closes costs no more than itself.
fn token(text: &str) -> Option<(Option<usize>, &str, &str)> {
    let inner = text.strip_prefix('{')?;
    let digits = inner.len() - inner.trim_start_matches(|c: char| c.is_ascii_digit()).len();
    let (number, rest) = inner.split_at(digits);
    let close = rest.bytes().take(3).position(|byte| byte == b'}')?;
    let (transform, after) = (&rest[..close], &rest[close + 1..]);
    let number = if number.is_empty() {
        None
    } else {
        Some(number.parse().ok().filter(|number| *number > 0)?)
    };
    match transform {
        "" if number.is_some() => Some((number, transform, after)),
        "." | "/" | "//" | "/." => Some((number, transform, after)),
        "#" | "%" if number.is_none() => Some((None, transform, after)),
        _ => None,
    }
}

/// A value with the spaces on the sides `--trim` names taken off.
fn trimmed<'a>(value: &'a str, sides: &str) -> &'a str {
    let value = if sides.contains('l') {
        value.trim_start_matches([' ', '\t'])
    } else {
        value
    };
    if sides.contains('r') {
        value.trim_end_matches([' ', '\t'])
    } else {
        value
    }
}

/// A value as a replacement string gives it: `{.}` without its extension,
/// `{/}` its last part, `{//}` its folder, `{/.}` its last part without the
/// extension.
fn transformed(value: &str, transform: &str) -> String {
    match transform {
        "." => without_extension(value).to_string(),
        "/" => basename(value).to_string(),
        "//" => dirname(value),
        "/." => without_extension(basename(value)).to_string(),
        _ => value.to_string(),
    }
}

/// `value` without the last `.` and what follows it in its last part.
fn without_extension(value: &str) -> &str {
    match value.rfind('.') {
        Some(dot) if !value[dot..].contains('/') => &value[..dot],
        _ => value,
    }
}

/// What follows the last `/` of `value`.
fn basename(value: &str) -> &str {
    value.rsplit('/').next().unwrap_or(value)
}

/// The folder `value` is in, as Perl's `dirname` gives it.
fn dirname(value: &str) -> String {
    let trimmed = value.trim_end_matches('/');
    if trimmed.is_empty() {
        return if value.is_empty() { "." } else { "/" }.to_string();
    }
    match trimmed.rfind('/') {
        None => ".".to_string(),
        Some(at) => {
            let folder = trimmed[..at].trim_end_matches('/');
            if folder.is_empty() { "/" } else { folder }.to_string()
        }
    }
}

/// The options before the command, read as `parallel` reads them: bundled
/// short letters, long options also by an unambiguous start of their name.
/// `None` for one that changes how jobs are built, or that it does not know.
fn read_options(args: &[Arg]) -> Option<Options> {
    let mut options = Options {
        start: args.len(),
        replace: "{}".to_string(),
        quote: false,
        grouping: false,
        files: 0,
        trim: String::new(),
    };
    let mut at = 0;
    while let Some(arg) = args.get(at) {
        let Some(text) = arg.known() else {
            options.start = at;
            return Some(options);
        };
        if text == "--" {
            options.start = at + 1;
            return Some(options);
        }
        if let Some(long) = text.strip_prefix("--") {
            let (name, value) = long
                .split_once('=')
                .map_or((long, None), |(name, value)| (name, Some(value)));
            let name = long_name(name)?;
            if LONG_UNREAD.contains(&name) {
                return None;
            }
            options.grouping |= LONG_GROUPING.contains(&name);
            options.quote |= name == "quote";
            options.files += usize::from(name == "arg-file");
            // `--replace` alone is `{}`; its own string only follows `=`.
            if name == "replace" {
                options.replace = replacement(value.unwrap_or("{}"))?;
            }
            if value.is_none() && LONG_VALUES.contains(&name) {
                at += 1;
                args.get(at)?;
            }
            if name == "trim" {
                let sides = value.map_or_else(|| args.get(at)?.known(), Some)?;
                if !sides.chars().all(|side| "nlr".contains(side)) {
                    return None;
                }
                options.trim = sides.to_string();
            }
            at += 1;
            continue;
        }
        if text.len() > 1 && text.starts_with('-') {
            let bundle = &text[1..];
            for (index, letter) in bundle.char_indices() {
                let rest = &bundle[index + letter.len_utf8()..];
                if SHORT_VALUES.contains(letter) {
                    let value = if rest.is_empty() {
                        at += 1;
                        args.get(at)?.clone()
                    } else {
                        Arg::Known(rest.to_string())
                    };
                    match letter {
                        'I' => options.replace = replacement(value.known()?)?,
                        'a' => options.files += 1,
                        'n' | 'N' | 'L' => options.grouping = true,
                        _ => {}
                    }
                    break;
                }
                if !SHORT_FLAGS.contains(letter) {
                    return None;
                }
                match letter {
                    'q' => options.quote = true,
                    'X' | 'm' => options.grouping = true,
                    // `-l` and `-i` take what follows them in the bundle.
                    'l' => {
                        options.grouping = true;
                        break;
                    }
                    'i' => {
                        if !rest.is_empty() {
                            options.replace = replacement(rest)?;
                        }
                        break;
                    }
                    'e' => break,
                    _ => {}
                }
            }
            at += 1;
            continue;
        }
        options.start = at;
        return Some(options);
    }
    Some(options)
}

/// The long option `name` stands for: its own name, or the one it is an
/// unambiguous start of. `--replace` is `-i`'s long name, read apart.
fn long_name(name: &str) -> Option<&'static str> {
    let every = || {
        LONG_VALUES
            .iter()
            .chain(LONG_FLAGS)
            .chain(LONG_UNREAD)
            .copied()
    };
    if let Some(exact) = every().find(|option| *option == name) {
        return Some(exact);
    }
    if name.is_empty() {
        return None;
    }
    let mut starts = every().filter(|option| option.starts_with(name));
    match (starts.next(), starts.next()) {
        (Some(only), None) => Some(only),
        _ => None,
    }
}

/// A replacement string an option names. `None` for an empty one, which
/// would stand everywhere, and for one longer than [`MAX_REPLACE`], which
/// would be looked for at every byte of the command.
fn replacement(text: &str) -> Option<String> {
    (!text.is_empty() && text.len() <= MAX_REPLACE).then(|| text.to_string())
}
