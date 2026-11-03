//! A small keyword reader over the text of a database statement: SQL, a
//! `MongoDB` script and Redis commands. It skips comments and string
//! literals and splits SQL on `;`. There is no grammar: it finds the few
//! words that destroy data and says what it could not read.

use std::collections::HashMap;

/// The SQL a client reads, with only the quoting that client has: where the
/// dialects differ in a way that would hide or show a statement, each one is
/// read as itself. A construct a dialect is not known to have is not read, so
/// what it would hide is read as code, never skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum Dialect {
    /// `psql`: `$tag$` and `E'…'` strings, block comments that nest, and
    /// backslash commands anywhere outside a string.
    Postgres,
    /// `sqlite3`: backtick and `[…]` identifiers, dot commands.
    Sqlite,
    /// `duckdb`: PostgreSQL's parser, so `$tag$` and `E'…'` strings, and
    /// dot commands. Block comments may nest, so a comment that holds `/*` is
    /// not read.
    DuckDb,
    /// `sqlcmd`: `[…]` identifiers and block comments that nest.
    SqlServer,
    /// `mysql`, `mariadb`: `#` comments, backslash escapes, backticks,
    /// `/*! … */` comments that run, `\g` and `\G`, `--` needing a space.
    MySql,
    /// `clickhouse-client`: `#` comments, block comments that nest, backslash
    /// escapes, backticks, `$tag$` strings, `\G`.
    ClickHouse,
    /// Cassandra's CQL: `//` comments and `$$` strings.
    Cql,
}

/// The dollar-quoted strings a dialect has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dollar {
    None,
    /// `$$ … $$` only.
    Plain,
    /// `$tag$ … $tag$`.
    Tagged,
}

/// Whether block comments nest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Nesting {
    No,
    Yes,
    /// Not known: a comment that holds a second `/*` cannot be read.
    Unsure,
}

/// How a string takes a backslash. A server setting the text can change
/// (`sql_mode` in MySQL, `standard_conforming_strings` in PostgreSQL) turns
/// the escape on or off, so a text is read with the rule the dialect has and
/// with the others it may have: what any of them shows counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Backslash {
    /// The dialect's own: `E'…'` in PostgreSQL, every string in MySQL.
    Dialect,
    /// None: MySQL's `NO_BACKSLASH_ESCAPES`.
    Never,
    /// In `'…'` strings and not in `"…"` identifiers: MySQL's `ANSI_QUOTES`,
    /// and PostgreSQL with `standard_conforming_strings` off.
    SingleQuotes,
}

impl Dialect {
    /// The other rules a string of this dialect may be read with.
    fn other_backslash(self) -> &'static [Backslash] {
        match self {
            Self::MySql => &[Backslash::Never, Backslash::SingleQuotes],
            Self::Postgres => &[Backslash::SingleQuotes],
            _ => &[],
        }
    }

    fn hash_comments(self) -> bool {
        matches!(self, Self::MySql | Self::ClickHouse)
    }

    fn dash_needs_space(self) -> bool {
        self == Self::MySql
    }

    fn backslash_escapes(self) -> bool {
        matches!(self, Self::MySql | Self::ClickHouse)
    }

    fn escape_strings(self) -> bool {
        matches!(self, Self::Postgres | Self::DuckDb)
    }

    fn backticks(self) -> bool {
        matches!(self, Self::Sqlite | Self::MySql | Self::ClickHouse)
    }

    fn brackets(self) -> bool {
        matches!(self, Self::Sqlite | Self::SqlServer)
    }

    fn dollar(self) -> Dollar {
        match self {
            Self::Postgres | Self::ClickHouse | Self::DuckDb => Dollar::Tagged,
            Self::Cql => Dollar::Plain,
            _ => Dollar::None,
        }
    }

    fn nesting(self) -> Nesting {
        match self {
            Self::Postgres | Self::SqlServer | Self::ClickHouse => Nesting::Yes,
            Self::DuckDb => Nesting::Unsure,
            _ => Nesting::No,
        }
    }

    fn dot_commands(self) -> bool {
        matches!(self, Self::Sqlite | Self::DuckDb)
    }

    /// Whether the shell skips an input line that starts with `#` when no
    /// statement is pending: `sqlite3`'s, and `duckdb`'s, which is derived
    /// from it.
    fn hash_lines(self) -> bool {
        matches!(self, Self::Sqlite | Self::DuckDb)
    }
}

/// A file a client command or a statement writes: `\o FILE`, `.output FILE`,
/// `COPY … TO 'FILE'`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Written {
    /// The name as the client is given it.
    pub(super) name: String,
    /// Whether it is a folder written into (`EXPORT DATABASE 'DIR'`).
    pub(super) folder: bool,
    /// Whether it is a copy of the database that replaces the file
    /// (`.backup`, `.save`).
    pub(super) database: bool,
}

/// A program a client runs, as the text shows it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) enum Program {
    /// A command line the system's shell runs (`\! ls`, `.shell ls`).
    Line(String),
    /// A program and its arguments, run with no shell (`runProgram('ls',
    /// '-l')`).
    Words(Vec<String>),
}

impl Program {
    /// The program as a reason's target shows it.
    pub(super) fn text(&self) -> String {
        match self {
            Self::Line(line) => line.clone(),
            Self::Words(words) => words.join(" "),
        }
    }
}

/// The most files written, and programs run, that one read keeps: past it
/// the text is read as running what the line does not show.
const MAX_ACTS: usize = 32;

/// What client commands and statements do beside the database: the files
/// they write and the programs they run, as the text shows them.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct Acts {
    pub(super) writes: Vec<Written>,
    pub(super) programs: Vec<Program>,
    /// It moves the client to another folder (`\cd`, `.cd`): a relative file
    /// it writes, and a program it runs, are somewhere the line does not
    /// say.
    pub(super) moves_folder: bool,
    /// It sets the environment of the programs it runs (`\setenv`).
    pub(super) environment: bool,
}

impl Acts {
    const NONE: Self = Self {
        writes: Vec::new(),
        programs: Vec::new(),
        moves_folder: false,
        environment: false,
    };

    /// Whether there is nothing to judge.
    pub(super) fn is_empty(&self) -> bool {
        self.writes.is_empty() && self.programs.is_empty()
    }
}

/// What a read of some statement text found.
#[allow(
    clippy::struct_excessive_bools,
    reason = "five independent findings, each read on its own"
)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct Reading {
    /// It drops, truncates or empties something.
    pub(super) destroys: bool,
    /// Part of it is only known when it runs, or cannot be read.
    pub(super) unreadable: bool,
    /// It runs a program of the machine the text does not show (`\!` alone,
    /// `COPY … PROGRAM`, `.read |cmd`, `.load`).
    pub(super) program: bool,
    /// It opens or attaches another database (`ATTACH`, `.open`), so the
    /// file the client was given is not the only one it can change.
    pub(super) moves: bool,
    /// It runs the statements of a file (`\i`, `.read`, `source`), which
    /// the line does not show.
    pub(super) unseen: bool,
    /// The files it writes and the programs it runs that the text shows.
    pub(super) acts: Acts,
}

impl Reading {
    pub(super) const UNREADABLE: Self = Self {
        destroys: false,
        unreadable: true,
        program: false,
        moves: false,
        unseen: false,
        acts: Acts::NONE,
    };

    /// Statements the line does not show: a file, or what a program the
    /// rule does not read hands the client.
    pub(super) const UNSEEN: Self = Self {
        destroys: false,
        unreadable: false,
        program: false,
        moves: false,
        unseen: true,
        acts: Acts::NONE,
    };

    pub(super) fn merge(&mut self, other: Self) {
        self.destroys |= other.destroys;
        self.unreadable |= other.unreadable;
        self.program |= other.program;
        self.moves |= other.moves;
        self.unseen |= other.unseen;
        self.add_acts(other.acts);
    }

    /// Keep the acts of `other` beside these, each once. Past [`MAX_ACTS`]
    /// of either, what is left is a program the line does not show.
    pub(super) fn add_acts(&mut self, other: Acts) {
        self.acts.moves_folder |= other.moves_folder;
        self.acts.environment |= other.environment;
        for write in other.writes {
            self.write(write);
        }
        for program in other.programs {
            self.run(program);
        }
    }

    /// Note a file it writes.
    fn write(&mut self, write: Written) {
        if self.acts.writes.contains(&write) {
            return;
        }
        if self.acts.writes.len() < MAX_ACTS {
            self.acts.writes.push(write);
        } else {
            self.program = true;
        }
    }

    /// Note a program it runs.
    fn run(&mut self, program: Program) {
        if self.acts.programs.contains(&program) {
            return;
        }
        if self.acts.programs.len() < MAX_ACTS {
            self.acts.programs.push(program);
        } else {
            self.program = true;
        }
    }
}

/// What a quoted string or identifier holds, for the few places where the
/// text of a string is read as more SQL.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Quote {
    /// The text inside the quotes, a doubled quote made one.
    body: String,
    /// Whether it is a `'…'` string, and not an identifier.
    string: bool,
    /// Whether a backslash in it escapes, so that `body` is not what it says.
    escapes: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    /// A bare word or number, in upper case.
    Word(String),
    /// A quoted string or identifier.
    Quoted(Quote),
    /// A `$$` string, with what is inside it.
    Dollar(String),
    /// An expansion of the shell, in text that came from a double-quoted
    /// word: its value is only known when it runs.
    Hole,
    /// A client command, as written: `\c db`, `.dump`, `\gexec`.
    Meta(String),
    Symbol(char),
}

/// Words that, before `DELETE` or `UPDATE`, show it is not a statement but
/// part of one: `DO UPDATE SET`, `FOR UPDATE`, `AFTER UPDATE`, `GRANT UPDATE`.
/// A `THEN` is one only in a `MERGE`, and an `ON` only when what follows the
/// verb is a referential action (see [`REFERENTIAL`]): `SET NOCOUNT ON DELETE
/// FROM t` is a statement.
const NOT_A_VERB_AFTER: [&str; 10] = [
    "DO", "KEY", "FOR", "OR", "AFTER", "BEFORE", "OF", "GRANT", "REVOKE", "DENY",
];

/// The words that follow `ON DELETE` or `ON UPDATE` when it is a rule of a
/// foreign key, a column or a rewrite rule, and not a statement: `ON DELETE
/// CASCADE`, `ON DELETE SET NULL`, `ON DELETE NO ACTION`, `ON UPDATE
/// RESTRICT`, `ON UPDATE CURRENT_TIMESTAMP`, `CREATE RULE r AS ON DELETE TO
/// t`.
const REFERENTIAL: [&str; 9] = [
    "CASCADE",
    "SET",
    "RESTRICT",
    "NO",
    "TO",
    "CURRENT_TIMESTAMP",
    "NOW",
    "LOCALTIME",
    "LOCALTIMESTAMP",
];

/// Words that end the part of a statement that can hold its `WHERE`: the
/// next statement of a batch with no `;` between.
const STARTS_A_STATEMENT: [&str; 11] = [
    "DELETE", "UPDATE", "INSERT", "DROP", "TRUNCATE", "ALTER", "CREATE", "SELECT", "EXEC",
    "EXECUTE", "PRINT",
];

/// Words after `DROP` that take away something other than data: `ALTER
/// COLUMN c DROP NOT NULL`, `DROP DEFAULT`, `DROP CONSTRAINT`. They are
/// reserved words, so no column has the name.
const DROPS_NO_DATA: [&str; 3] = ["NOT", "DEFAULT", "CONSTRAINT"];

/// The words after `DROP` that take away something other than data only in
/// `ALTER [COLUMN] c DROP IDENTITY` and `DROP EXPRESSION`: they are not
/// reserved, so `ALTER TABLE t DROP identity` drops a column of that name.
const DROPS_NO_DATA_OF_A_COLUMN: [&str; 2] = ["IDENTITY", "EXPRESSION"];

/// Whether `chars` holds a shell expansion (`$x`, `${x}`, `$(x)`, cmd's `%x%`)
/// starting at `at`, and where it ends.
fn hole_end(chars: &[char], at: usize) -> Option<usize> {
    let open = |start: usize, open: char, close: char| {
        let mut depth = 0usize;
        for (offset, c) in chars.get(start..)?.iter().enumerate() {
            if *c == open {
                depth += 1;
            } else if *c == close {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(start + offset + 1);
                }
            }
        }
        // Not closed: the rest is the expansion.
        Some(chars.len())
    };
    // cmd's `%name%` and `%1`.
    if chars.get(at) == Some(&'%') {
        let mut end = at + 1;
        while chars
            .get(end)
            .is_some_and(|c| c.is_alphanumeric() || *c == '_')
        {
            end += 1;
        }
        if end == at + 1 {
            return None;
        }
        return Some(end + usize::from(chars.get(end) == Some(&'%')));
    }
    match chars.get(at + 1)? {
        '(' => open(at + 1, '(', ')'),
        '{' => open(at + 1, '{', '}'),
        c if c.is_alphanumeric() || *c == '_' => {
            let mut end = at + 1;
            while chars
                .get(end)
                .is_some_and(|c| c.is_alphanumeric() || *c == '_')
            {
                end += 1;
            }
            Some(end)
        }
        '@' | '*' | '?' | '#' | '!' | '$' => Some(at + 2),
        _ => None,
    }
}

/// The index after the quote that closes the one at `at`, or `None` when it
/// is never closed. A doubled quote stays inside; with `escapes` a backslash
/// quotes the next character.
fn quoted(chars: &[char], at: usize, escapes: bool) -> Option<usize> {
    let quote = *chars.get(at)?;
    let mut i = at + 1;
    while let Some(&c) = chars.get(i) {
        if escapes && c == '\\' {
            i += 2;
        } else if c == quote {
            if chars.get(i + 1) == Some(&quote) {
                i += 2;
            } else {
                return Some(i + 1);
            }
        } else {
            i += 1;
        }
    }
    None
}

/// The index after the `]` that closes the `[` at `at` (`]]` stays inside),
/// or `None` when it is never closed.
fn bracketed(chars: &[char], at: usize) -> Option<usize> {
    let mut i = at + 1;
    while let Some(&c) = chars.get(i) {
        if c == ']' {
            if chars.get(i + 1) == Some(&']') {
                i += 2;
            } else {
                return Some(i + 1);
            }
        } else {
            i += 1;
        }
    }
    None
}

/// The index after the `psql` variable that starts at `at` (`:name`,
/// `:'name'`, `:"name"`): a quoted one runs to its closing quote, or to the
/// end when it has none.
fn psql_variable_end(chars: &[char], at: usize) -> usize {
    if let Some(&quote @ ('\'' | '"')) = chars.get(at + 1) {
        return chars
            .get(at + 2..)
            .and_then(|rest| rest.iter().position(|c| *c == quote))
            .map_or(chars.len(), |close| at + 2 + close + 1);
    }
    let mut end = at + 1;
    while chars.get(end).is_some_and(|c| is_word_char(*c)) {
        end += 1;
    }
    end
}

/// The index after the block comment that starts at `at`, or `None` when it
/// is never closed, or when whether it nests is not known and it holds a
/// second `/*`.
fn block_comment(chars: &[char], at: usize, nesting: Nesting) -> Option<usize> {
    let mut depth = 1usize;
    let mut i = at + 2;
    loop {
        match (chars.get(i), chars.get(i + 1)) {
            (Some('*'), Some('/')) => {
                depth -= 1;
                i += 2;
                if depth == 0 {
                    return Some(i);
                }
            }
            (Some('/'), Some('*')) if nesting != Nesting::No => {
                if nesting == Nesting::Unsure {
                    return None;
                }
                depth += 1;
                i += 2;
            }
            (Some(_), _) => i += 1,
            (None, _) => return None,
        }
    }
}

/// The quoted text that runs from `at` (its opening quote) to `end`, the
/// index after its closing one.
fn quote_of(chars: &[char], at: usize, end: usize, escapes: bool) -> Quote {
    let open = chars.get(at).copied().unwrap_or('\'');
    let close = if open == '[' { ']' } else { open };
    let inner: String = chars
        .get(at + 1..end.saturating_sub(1))
        .unwrap_or_default()
        .iter()
        .collect();
    Quote {
        body: inner.replace(&format!("{close}{close}"), &close.to_string()),
        string: open == '\'',
        escapes,
    }
}

fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// The line starting at `at`, and the index of its end.
fn line(chars: &[char], at: usize) -> (String, usize) {
    let end = chars
        .get(at..)
        .and_then(|rest| rest.iter().position(|c| *c == '\n'))
        .map_or(chars.len(), |offset| at + offset);
    (chars.get(at..end).unwrap_or_default().iter().collect(), end)
}

/// The `psql` backslash command that starts at `at`, and the index after it.
/// It ends at the end of its line, or at the next backslash outside a quote,
/// which starts the next command (or is `\\`, and the SQL goes on).
fn psql_command(chars: &[char], at: usize) -> (String, usize) {
    let mut i = at + 1;
    let mut quote: Option<char> = None;
    let (stop, end) = loop {
        let Some(&c) = chars.get(i) else {
            break (chars.len(), chars.len());
        };
        if c == '\n' {
            break (i, i);
        }
        match quote {
            Some('\'') if c == '\\' => {
                i += if chars.get(i + 1) == Some(&'\n') {
                    1
                } else {
                    2
                };
                continue;
            }
            Some(q) if c == q => quote = None,
            Some(_) => {}
            None if c == '\\' => break (i, i),
            None if matches!(c, '\'' | '"' | '`') => quote = Some(c),
            None => {}
        }
        i += 1;
    };
    (
        chars.get(at..stop).unwrap_or_default().iter().collect(),
        end,
    )
}

/// Where the tokens go on after a `mysql` command at `at` whose line ends at
/// `end`: after the first `;`, or the end of the line. The command is read to
/// the end of its line, and what follows a `;` is read as SQL too, so that
/// neither reading hides the other.
fn semicolon_or(chars: &[char], at: usize, end: usize) -> usize {
    chars
        .get(at..end)
        .and_then(|text| text.iter().position(|c| *c == ';'))
        .map_or(end, |offset| at + offset)
}

/// Whether the word at `at` is one of the `mysql` commands that run a
/// program or write a file: `system`, `pager` and `tee`, in any case.
fn mysql_command(chars: &[char], at: usize) -> bool {
    let rest = chars.get(at..).unwrap_or_default();
    let len = rest.iter().take_while(|c| is_word_char(**c)).count();
    let word: String = rest.iter().take(len).collect();
    matches!(
        word.to_ascii_lowercase().as_str(),
        "system" | "pager" | "tee"
    ) && rest.get(len).is_none_or(|c| c.is_whitespace() || *c == ';')
}

/// Whether only spaces and tabs stand between the start of the line and
/// `at`.
fn at_line_start(chars: &[char], at: usize) -> bool {
    let before = chars.get(..at).unwrap_or_default();
    let blank = before
        .iter()
        .rev()
        .take_while(|c| matches!(c, ' ' | '\t'))
        .count();
    blank == before.len() || before.get(before.len() - blank - 1) == Some(&'\n')
}

/// The `sqlcmd` command a line is, as the reader names it: `!!` and `:!!`
/// are `\!`, which runs the rest of the line; `:out`, `:error` and
/// `:perftrace` are themselves. `None` for any other line.
fn sqlcmd_command(text: &str) -> Option<String> {
    if let Some(rest) = text.strip_prefix(":!!").or_else(|| text.strip_prefix("!!")) {
        return Some(format!("\\!{rest}"));
    }
    let name = text
        .strip_prefix(':')?
        .split(char::is_whitespace)
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    matches!(name.as_str(), "out" | "error" | "perftrace").then(|| text.to_string())
}

/// Cut `text` into tokens. `None` when a string, a comment or a `$$` string
/// is never closed: the rest of the text could be anything. `holes` says the
/// text came from a double-quoted shell word, where `$x` and `` `x` `` are
/// the shell's expansions.
fn tokenize(text: &str, dialect: Dialect, holes: bool, backslash: Backslash) -> Option<Vec<Token>> {
    let mut tokens = Vec::new();
    tokenize_into(text, dialect, holes, backslash, &mut tokens)?;
    Some(tokens)
}

/// [`tokenize`], keeping the tokens before the string, comment or `$$` string
/// that is never closed: `true` when the text was cut whole.
fn tokenize_prefix(
    text: &str,
    dialect: Dialect,
    holes: bool,
    backslash: Backslash,
) -> (Vec<Token>, bool) {
    let mut tokens = Vec::new();
    let closed = tokenize_into(text, dialect, holes, backslash, &mut tokens).is_some();
    (tokens, closed)
}

fn tokenize_into(
    text: &str,
    dialect: Dialect,
    holes: bool,
    backslash: Backslash,
    tokens: &mut Vec<Token>,
) -> Option<()> {
    let chars: Vec<char> = text.chars().collect();
    let mut at = 0;
    // How many `/*! … */` comments are open: their text runs.
    let mut running = 0usize;
    while let Some(&c) = chars.get(at) {
        let next = chars.get(at + 1).copied();
        let starts_statement = matches!(
            tokens.last(),
            None | Some(Token::Symbol(';') | Token::Meta(_))
        );
        match c {
            c if c.is_whitespace() => at += 1,
            '-' if next == Some('-')
                && (!dialect.dash_needs_space()
                    || chars
                        .get(at + 2)
                        .is_none_or(|c| c.is_whitespace() || c.is_control())) =>
            {
                at = line(&chars, at).1;
            }
            '#' if dialect.hash_comments() => at = line(&chars, at).1,
            // With nothing pending, the shell skips a line that starts with
            // `#`, so a quote in it opens nothing.
            '#' if dialect.hash_lines()
                && starts_statement
                && (at == 0 || chars.get(at - 1) == Some(&'\n')) =>
            {
                at = line(&chars, at).1;
            }
            '/' if next == Some('/') && dialect == Dialect::Cql => at = line(&chars, at).1,
            '/' if next == Some('*') => {
                let marker = match (dialect, chars.get(at + 2), chars.get(at + 3)) {
                    (Dialect::MySql, Some('!'), _) => 3,
                    (Dialect::MySql, Some('M'), Some('!')) => 4,
                    _ => 0,
                };
                if marker > 0 {
                    running += 1;
                    at += marker;
                    while chars.get(at).is_some_and(char::is_ascii_digit) {
                        at += 1;
                    }
                } else {
                    at = block_comment(&chars, at, dialect.nesting())?;
                }
            }
            '*' if next == Some('/') && running > 0 => {
                running -= 1;
                at += 2;
            }
            '`' if holes => {
                let rest = chars.get(at + 1..)?;
                at += 1 + rest.iter().position(|c| *c == '`')? + 1;
                tokens.push(Token::Hole);
            }
            '\'' | '"' => {
                let escaped = dialect.escape_strings()
                    && c == '\''
                    && chars
                        .get(..at)
                        .and_then(|before| before.last())
                        .is_some_and(|before| matches!(before, 'e' | 'E'))
                    && at
                        .checked_sub(2)
                        .and_then(|i| chars.get(i))
                        .is_none_or(|c| !is_word_char(*c));
                let escapes = match backslash {
                    Backslash::Dialect => escaped || dialect.backslash_escapes(),
                    Backslash::Never => false,
                    Backslash::SingleQuotes => c == '\'',
                };
                let end = quoted(&chars, at, escapes)?;
                tokens.push(Token::Quoted(quote_of(&chars, at, end, escapes)));
                at = end;
            }
            '`' if dialect.backticks() => {
                let end = quoted(&chars, at, false)?;
                tokens.push(Token::Quoted(quote_of(&chars, at, end, false)));
                at = end;
            }
            '[' if dialect.brackets() => {
                let end = bracketed(&chars, at)?;
                tokens.push(Token::Quoted(quote_of(&chars, at, end, false)));
                at = end;
            }
            '%' if holes => {
                if let Some(end) = hole_end(&chars, at) {
                    at = end;
                    tokens.push(Token::Hole);
                } else {
                    tokens.push(Token::Symbol('%'));
                    at += 1;
                }
            }
            // A variable the client fills in, where a statement starts: `psql`'s
            // `:name`, `:'name'` and `:"name"`, and `sqlcmd`'s `$(name)`. What it
            // holds is not on the line.
            ':' if dialect == Dialect::Postgres
                && starts_statement
                && next.is_some_and(|c| is_word_char(c) || matches!(c, '\'' | '"')) =>
            {
                at = psql_variable_end(&chars, at);
                tokens.push(Token::Hole);
            }
            '$' if dialect == Dialect::SqlServer && starts_statement && next == Some('(') => {
                at = hole_end(&chars, at).unwrap_or(chars.len());
                tokens.push(Token::Hole);
            }
            '$' => {
                if holes {
                    if let Some(end) = hole_end(&chars, at) {
                        at = end;
                        tokens.push(Token::Hole);
                        continue;
                    }
                }
                // `$tag$ … $tag$`, or `$$ … $$` where only that is a string.
                let mut tag_end = at + 1;
                while chars.get(tag_end).is_some_and(|c| is_word_char(*c)) {
                    tag_end += 1;
                }
                let named = chars.get(at + 1).is_none_or(|c| !c.is_ascii_digit());
                let wanted = match dialect.dollar() {
                    Dollar::None => false,
                    Dollar::Plain => tag_end == at + 1,
                    Dollar::Tagged => true,
                };
                if wanted && chars.get(tag_end) == Some(&'$') && named {
                    let tag: Vec<char> = chars.get(at..=tag_end).unwrap_or_default().to_vec();
                    let body = chars.get(tag_end + 1..)?;
                    let end = body
                        .windows(tag.len())
                        .position(|window| window == tag.as_slice())?;
                    tokens.push(Token::Dollar(body.get(..end)?.iter().collect()));
                    at = tag_end + 1 + end + tag.len();
                } else {
                    at += 1;
                    tokens.push(Token::Symbol('$'));
                }
            }
            '\\' if dialect == Dialect::Postgres => {
                if next == Some('\\') {
                    at += 2;
                } else if next == Some('!') {
                    // `\!` hands the whole rest of its line to the shell.
                    let (meta, end) = line(&chars, at);
                    tokens.push(Token::Meta(meta));
                    at = end;
                } else {
                    let (meta, end) = psql_command(&chars, at);
                    tokens.push(Token::Meta(meta));
                    at = end;
                }
            }
            // `\g` and `\G` end a statement, as `;` does.
            '\\' if matches!(dialect, Dialect::MySql | Dialect::ClickHouse)
                && matches!(next, Some('g' | 'G')) =>
            {
                tokens.push(Token::Symbol(';'));
                at += 2;
            }
            // `\!` runs a program, `\.` the statements of a file.
            '\\' if dialect == Dialect::MySql && matches!(next, Some('!' | '.')) => {
                let (meta, end) = line(&chars, at);
                tokens.push(Token::Meta(meta));
                at = end;
            }
            // `\P` is `pager` and `\T` is `tee`, named so for the reader.
            '\\' if dialect == Dialect::MySql && matches!(next, Some('P' | 'T')) => {
                let (text, end) = line(&chars, at);
                let rest = text.get(2..).unwrap_or_default();
                let name = if next == Some('P') { "pager" } else { "tee" };
                tokens.push(Token::Meta(format!("{name}{rest}")));
                at = semicolon_or(&chars, at, end);
            }
            // `mysql`'s `system`, `pager` and `tee` where a statement starts.
            c if dialect == Dialect::MySql
                && starts_statement
                && is_word_char(c)
                && mysql_command(&chars, at) =>
            {
                let (meta, end) = line(&chars, at);
                tokens.push(Token::Meta(meta));
                at = semicolon_or(&chars, at, end);
            }
            // `sqlcmd`'s commands at the start of a line: `!!` (and `:!!`)
            // runs the rest of the line in the system's shell, `:out`,
            // `:error` and `:perftrace` send what follows to a file.
            '!' | ':' if dialect == Dialect::SqlServer && at_line_start(&chars, at) => {
                let (text, end) = line(&chars, at);
                if let Some(meta) = sqlcmd_command(&text) {
                    tokens.push(Token::Meta(meta));
                    at = end;
                } else {
                    tokens.push(Token::Symbol(c));
                    at += 1;
                }
            }
            '.' if dialect.dot_commands()
                && starts_statement
                && next.is_some_and(char::is_alphabetic) =>
            {
                let (meta, end) = line(&chars, at);
                tokens.push(Token::Meta(meta));
                at = end;
            }
            c if is_word_char(c) => {
                // A `$` is part of a word, but not one that starts a shell
                // expansion: `DROP$x` is `DROP` and the expansion, which may
                // be empty.
                let mut end = at;
                while chars.get(end).is_some_and(|c| {
                    is_word_char(*c) || (*c == '$' && !(holes && hole_end(&chars, end).is_some()))
                }) {
                    end += 1;
                }
                let word: String = chars.get(at..end).unwrap_or_default().iter().collect();
                tokens.push(Token::Word(word.to_uppercase()));
                at = end;
            }
            c => {
                tokens.push(Token::Symbol(c));
                at += 1;
            }
        }
    }
    (running == 0).then_some(())
}

fn is_word(token: Option<&Token>, word: &str) -> bool {
    matches!(token, Some(Token::Word(w)) if w == word)
}

/// For every `DELETE` or `UPDATE` of the statement `tokens`, whether it has a
/// `WHERE` that picks rows; the answers are at the verb's index. A `WHERE`
/// that picks all of them (`WHERE 1`, `WHERE TRUE`, `WHERE 1 = 1`) does not.
/// A verb's `WHERE` is the first one at its own depth of parentheses, before a
/// `)` that closes it or a word that starts the next statement. All of them
/// are found in one pass, so a statement of many verbs is read in linear time.
fn wheres(tokens: &[Token]) -> Vec<bool> {
    let mut found = vec![false; tokens.len()];
    // The verbs still looking for their `WHERE`, with the depth each is at;
    // a `)` ends the deeper ones, so the depths never fall up the stack.
    let mut pending: Vec<(usize, usize)> = Vec::new();
    let mut depth = 0usize;
    for (at, token) in tokens.iter().enumerate() {
        match token {
            Token::Symbol('(') => depth += 1,
            Token::Symbol(')') => {
                while pending.last().is_some_and(|(_, held)| *held >= depth) {
                    pending.pop();
                }
                depth = depth.saturating_sub(1);
            }
            Token::Word(word) => {
                let here = pending
                    .iter()
                    .rev()
                    .take_while(|(_, held)| *held == depth)
                    .count();
                if here > 0 && word == "WHERE" {
                    let picks = !picks_all(tokens.get(at + 1..).unwrap_or_default());
                    for (verb, _) in pending.split_off(pending.len() - here) {
                        if let Some(found) = found.get_mut(verb) {
                            *found = picks;
                        }
                    }
                } else if STARTS_A_STATEMENT.contains(&word.as_str()) {
                    pending.truncate(pending.len() - here);
                }
                if matches!(word.as_str(), "DELETE" | "UPDATE") {
                    pending.push((at, depth));
                }
            }
            _ => {}
        }
    }
    found
}

/// Whether the condition that starts `tokens` is one that is true for every
/// row.
fn picks_all(tokens: &[Token]) -> bool {
    // No condition that picks all rows has more than three parts, so a
    // fourth is enough to say it is not one.
    let condition: Vec<&str> = tokens
        .iter()
        .take_while(|token| {
            !matches!(token, Token::Symbol(';'))
                && !matches!(token, Token::Word(word) if matches!(
                    word.as_str(),
                    "ORDER" | "LIMIT" | "RETURNING" | "OUTPUT"
                ) || STARTS_A_STATEMENT.contains(&word.as_str()))
        })
        .filter_map(|token| match token {
            Token::Word(word) => Some(word.as_str()),
            Token::Symbol('=') => Some("="),
            Token::Symbol('(' | ')') => None,
            _ => Some("?"),
        })
        .take(4)
        .collect();
    matches!(
        condition.as_slice(),
        ["1" | "TRUE"] | ["1", "=", "1"] | ["TRUE", "=", "TRUE"]
    )
}

/// Whether the statement is a `MERGE`, possibly after a `WITH`.
fn is_merge(tokens: &[Token]) -> bool {
    match tokens.first() {
        Some(Token::Word(first)) if first == "MERGE" => true,
        Some(Token::Word(first)) if first == "WITH" => {
            let mut depth = 0usize;
            tokens.iter().any(|token| match token {
                Token::Symbol('(') => {
                    depth += 1;
                    false
                }
                Token::Symbol(')') => {
                    depth = depth.saturating_sub(1);
                    false
                }
                Token::Word(word) => depth == 0 && word == "MERGE",
                _ => false,
            })
        }
        _ => false,
    }
}

/// Whether the `THEN` before a verb ends a `WHEN [NOT] MATCHED …` clause, given
/// where the last `WHEN` before it is: only there is `THEN DELETE` or `THEN
/// UPDATE` part of a `MERGE`, which picks its rows with its `ON`.
fn in_matched_clause(tokens: &[Token], when: Option<usize>) -> bool {
    let Some(when) = when else {
        return false;
    };
    is_word(tokens.get(when + 1), "MATCHED")
        || (is_word(tokens.get(when + 1), "NOT") && is_word(tokens.get(when + 2), "MATCHED"))
}

/// Whether the `DROP` at `at` takes away something other than data: `DROP
/// NOT NULL`, `DROP DEFAULT`, `DROP CONSTRAINT`, `ALTER [COLUMN] c DROP
/// IDENTITY` and `DROP EXPRESSION`, `ON COMMIT DROP`, which ends a temporary table, and
/// `ClickHouse`'s `SYSTEM DROP … CACHE`.
fn drops_no_data(tokens: &[Token], at: usize, dialect: Dialect) -> bool {
    let on_commit =
        at >= 2 && is_word(tokens.get(at - 2), "ON") && is_word(tokens.get(at - 1), "COMMIT");
    let system = dialect == Dialect::ClickHouse && at == 1 && is_word(tokens.first(), "SYSTEM");
    on_commit
        || system
        || matches!(tokens.get(at + 1), Some(Token::Word(word)) if DROPS_NO_DATA.contains(&word.as_str()))
        || (matches!(tokens.get(at + 1), Some(Token::Word(word)) if DROPS_NO_DATA_OF_A_COLUMN.contains(&word.as_str()))
            && alters_a_column(tokens, at))
}

/// Whether what is before the `DROP` at `at` is `ALTER [COLUMN] name`: the
/// statement changes one column and does not drop it.
fn alters_a_column(tokens: &[Token], at: usize) -> bool {
    let name = |token: Option<&Token>| match token {
        Some(Token::Word(_)) => true,
        Some(Token::Quoted(quote)) => !quote.string,
        _ => false,
    };
    let before = |back: usize| at.checked_sub(back).and_then(|i| tokens.get(i));
    name(before(1))
        && (is_word(before(2), "ALTER")
            || (is_word(before(2), "COLUMN") && is_word(before(3), "ALTER")))
}

/// Whether the `DELETE` or `UPDATE` at `at` is part of another statement
/// and not one: a foreign key's `ON DELETE CASCADE`, a temporary table's
/// `ON COMMIT DELETE ROWS`.
fn is_clause(tokens: &[Token], at: usize) -> bool {
    let before = at.checked_sub(1).and_then(|i| tokens.get(i));
    let after = tokens.get(at + 1);
    let rule = is_word(before, "ON")
        && matches!(after, Some(Token::Word(word)) if REFERENTIAL.contains(&word.as_str()));
    let on_commit = is_word(before, "COMMIT")
        && at >= 2
        && is_word(tokens.get(at - 2), "ON")
        && is_word(after, "ROWS");
    rule || on_commit
}

/// How a read of SQL is placed: the client's dialect, whether the text came
/// from a double-quoted shell word, and how it came to be read.
#[derive(Debug, Clone, Copy)]
struct Scope {
    dialect: Dialect,
    holes: bool,
    /// The body of a `DO`: PL/pgSQL, where `EXECUTE` runs text built at run
    /// time.
    in_do: bool,
    /// How many strings deep it is: SQL in the text of SQL.
    depth: usize,
    /// How a string takes a backslash.
    backslash: Backslash,
}

/// The most strings of SQL inside strings of SQL that are read.
const MAX_DEPTH: usize = 8;

impl Scope {
    /// The scope of SQL found in a string of this one.
    fn within(self, in_do: bool) -> Self {
        Self {
            in_do,
            depth: self.depth + 1,
            ..self
        }
    }
}

/// What the text of a string, read as SQL, does. A string whose backslashes
/// escape is not read as its text says, so it is unknown.
fn read_string(quote: &Quote, scope: Scope) -> Reading {
    if quote.escapes && quote.body.contains('\\') {
        return Reading::UNREADABLE;
    }
    read_sql(&quote.body, scope)
}

/// The string literals that are the arguments of a call from `from` on, as
/// `[@name =] [N]'text'` separated by commas, and the index after them. Only
/// the first one when `every` is false; the others are its parameters.
/// `None` when an argument is anything but a literal (`@sql`, `'a' + @b`).
fn literal_args(tokens: &[Token], from: usize, every: bool) -> Option<(Vec<&Quote>, usize)> {
    let mut found = Vec::new();
    let mut i = from;
    loop {
        if tokens.get(i) == Some(&Token::Symbol('@'))
            && matches!(tokens.get(i + 1), Some(Token::Word(_)))
            && tokens.get(i + 2) == Some(&Token::Symbol('='))
        {
            i += 3;
        }
        if is_word(tokens.get(i), "N")
            && matches!(tokens.get(i + 1), Some(Token::Quoted(q)) if q.string)
        {
            i += 1;
        }
        let Some(Token::Quoted(quote)) = tokens.get(i) else {
            return None;
        };
        if !quote.string {
            return None;
        }
        found.push(quote);
        i += 1;
        match tokens.get(i) {
            Some(Token::Symbol(',')) if every => i += 1,
            Some(Token::Symbol(',')) | None => break,
            Some(Token::Symbol(')')) => break,
            Some(Token::Word(word)) if STARTS_A_STATEMENT.contains(&word.as_str()) => break,
            Some(_) => return None,
        }
    }
    Some((found, i))
}

/// The words that may stand between `REPLACE` and `TABLE` in a statement
/// that replaces a table: `CREATE OR REPLACE TEMPORARY TABLE`.
const TABLE_KINDS: [&str; 7] = [
    "TEMPORARY",
    "TEMP",
    "TRANSIENT",
    "GLOBAL",
    "LOCAL",
    "UNLOGGED",
    "VOLATILE",
];

/// Whether the `REPLACE` at `at` replaces a table, and with it the rows the
/// table held: `CREATE OR REPLACE TABLE` (`MariaDB`, `DuckDB`, `ClickHouse`)
/// and `ClickHouse`'s `REPLACE TABLE`. `REPLACE INTO` adds rows, and
/// `replace(…)` is a function.
fn replaces_table(tokens: &[Token], at: usize) -> bool {
    tokens
        .get(at + 1..)
        .unwrap_or_default()
        .iter()
        .find(|token| !matches!(token, Token::Word(w) if TABLE_KINDS.contains(&w.as_str())))
        .is_some_and(|token| is_word(Some(token), "TABLE"))
}

/// Whether the `RESTORE` at `at` writes a backup over a database: `RESTORE
/// DATABASE` or `RESTORE LOG` with a `FROM` after it.
fn restores_backup(tokens: &[Token], at: usize) -> bool {
    matches!(tokens.get(at + 1), Some(Token::Word(w)) if matches!(w.as_str(), "DATABASE" | "LOG"))
        && tokens
            .get(at + 2..)
            .unwrap_or_default()
            .iter()
            .any(|token| is_word(Some(token), "FROM"))
}

/// How a string that is the body of a function or procedure is written.
enum Prefix {
    /// `AS '…'`, and `AS E'…'`, whose backslashes escape.
    Plain,
    /// `AS U&'…'`, whose backslashes spell characters by their code.
    Unicode,
}

/// Whether the string at `at` comes right after `AS`, or after `AS` and the
/// prefix of a string (`E`, `U&`), as the body of a function does.
fn body_prefix(tokens: &[Token], at: usize) -> Option<Prefix> {
    let back = |n: usize| at.checked_sub(n).and_then(|i| tokens.get(i));
    if is_word(back(1), "AS") || (is_word(back(1), "E") && is_word(back(2), "AS")) {
        Some(Prefix::Plain)
    } else if back(1) == Some(&Token::Symbol('&'))
        && is_word(back(2), "U")
        && is_word(back(3), "AS")
    {
        Some(Prefix::Unicode)
    } else {
        None
    }
}

/// Whether a `CREATE` statement makes a function or a procedure, whose body
/// runs when it is called: `FUNCTION` or `PROCEDURE` before its first `(`.
fn creates_routine(tokens: &[Token]) -> bool {
    tokens
        .iter()
        .take_while(|token| **token != Token::Symbol('('))
        .any(|token| is_word(Some(token), "FUNCTION") || is_word(Some(token), "PROCEDURE"))
}

/// The arguments of a `dblink` call from `from` (after its `(`): the strings
/// it is given, which are its connection and its SQL, and the index after
/// them. A `TRUE` or `FALSE` (whether an error fails the call) is skipped.
/// `None` when an argument is anything else: SQL only known when it runs.
fn dblink_args(tokens: &[Token], from: usize) -> Option<(Vec<&Quote>, usize)> {
    let mut found = Vec::new();
    let mut i = from;
    loop {
        match tokens.get(i)? {
            Token::Quoted(quote) if quote.string => found.push(quote),
            Token::Word(word) if matches!(word.as_str(), "TRUE" | "FALSE") => {}
            _ => return None,
        }
        i += 1;
        match tokens.get(i)? {
            Token::Symbol(',') => i += 1,
            Token::Symbol(')') => break,
            _ => return None,
        }
    }
    // Two strings are a connection and the SQL; the connection is not SQL.
    if found.len() > 1 {
        found.remove(0);
    }
    Some((found, i))
}

/// Whether `name`, in upper case, is one of `dblink`'s functions that run
/// the SQL they are given.
fn is_dblink(name: &str) -> bool {
    matches!(name, "DBLINK" | "DBLINK_EXEC" | "DBLINK_SEND_QUERY")
}

/// The name of the T-SQL procedures that run the text they are given.
fn runs_text(name: &str) -> Option<bool> {
    match name {
        "SP_EXECUTESQL" => Some(false),
        "SP_MSFOREACHTABLE" | "SP_MSFOREACHDB" => Some(true),
        _ => None,
    }
}

/// What text that is run as SQL by the token at `at` does: `EXEC('…')`,
/// `sp_executesql`, `sp_MSforeachtable`, MySQL's `PREPARE s FROM '…'`; `None`
/// when the token runs nothing. Text that is not a literal is unknown.
fn dynamic_sql(tokens: &[Token], at: usize, scope: Scope) -> Option<Reading> {
    let found = match tokens.get(at)? {
        Token::Word(word) if matches!(word.as_str(), "EXEC" | "EXECUTE") => {
            if tokens.get(at + 1) != Some(&Token::Symbol('(')) {
                return None;
            }
            literal_args(tokens, at + 2, false)
                .filter(|(_, end)| tokens.get(*end) == Some(&Token::Symbol(')')))
        }
        Token::Word(word) if word == "PREPARE" && is_word(tokens.get(at + 2), "FROM") => {
            literal_args(tokens, at + 3, false)
        }
        // PostgreSQL's `dblink`, which runs the SQL it is given in a
        // database it connects to: `dblink_exec('dbname=x', 'DROP TABLE t')`,
        // and as a quoted name, `"dblink_exec"(…)`.
        Token::Word(word) if is_dblink(word) => {
            if tokens.get(at + 1) != Some(&Token::Symbol('(')) {
                return None;
            }
            dblink_args(tokens, at + 2)
        }
        Token::Word(word) => literal_args(tokens, at + 1, runs_text(word)?),
        Token::Quoted(quote) if !quote.string => {
            let name = quote.body.to_uppercase();
            if is_dblink(&name) {
                if tokens.get(at + 1) != Some(&Token::Symbol('(')) {
                    return None;
                }
                dblink_args(tokens, at + 2)
            } else {
                literal_args(tokens, at + 1, runs_text(&name)?)
            }
        }
        _ => return None,
    };
    let Some((strings, _)) = found else {
        return Some(Reading::UNREADABLE);
    };
    let mut reading = Reading::default();
    for quote in strings {
        reading.merge(read_string(quote, scope.within(false)));
    }
    Some(reading)
}

/// What one statement of SQL does.
fn statement(tokens: &[Token], scope: Scope) -> Reading {
    let mut reading = Reading::default();
    let Some(first) = tokens.first() else {
        return reading;
    };
    if *first == Token::Hole {
        return Reading::UNREADABLE;
    }
    let merge = is_merge(tokens);
    // Worked out once, for the first verb that needs it, and the last `WHEN`
    // seen: a statement of many verbs is read in linear time.
    let mut picked: Option<Vec<bool>> = None;
    let mut when = None;
    for (at, token) in tokens.iter().enumerate() {
        if let Some(found) = dynamic_sql(tokens, at, scope) {
            reading.merge(found);
        }
        let Token::Word(word) = token else { continue };
        let before = at.checked_sub(1).and_then(|i| tokens.get(i));
        if word == "WHEN" {
            when = Some(at);
        }
        match word.as_str() {
            "DROP" if !drops_no_data(tokens, at, scope.dialect) => reading.destroys = true,
            "TRUNCATE" if tokens.get(at + 1) != Some(&Token::Symbol('(')) => {
                reading.destroys = true;
            }
            "DELETE" | "UPDATE" => {
                let part = matches!(before, Some(Token::Symbol(',')))
                    || matches!(before, Some(Token::Word(w)) if NOT_A_VERB_AFTER.contains(&w.as_str()))
                    || is_clause(tokens, at)
                    || (merge && is_word(before, "THEN") && in_matched_clause(tokens, when));
                if !part
                    && !picked
                        .get_or_insert_with(|| wheres(tokens))
                        .get(at)
                        .copied()
                        .unwrap_or_default()
                {
                    reading.destroys = true;
                }
            }
            "REPLACE" if replaces_table(tokens, at) => reading.destroys = true,
            // SQL Server's `RESTORE DATABASE` and `RESTORE LOG` write the
            // backup they read `FROM` over the database they name (`WITH
            // REPLACE` over any one). Without a `FROM` (`WITH RECOVERY`) they
            // read no backup.
            "RESTORE" if restores_backup(tokens, at) => reading.destroys = true,
            "ATTACH" if at == 0 => reading.moves = true,
            "XP_CMDSHELL" => reading.program = true,
            "PROGRAM" if is_word(tokens.first(), "COPY") => reading.program = true,
            "SYSTEM" if at == 0 && scope.dialect == Dialect::MySql => reading.program = true,
            // The client's `source FILE` runs the statements of a file.
            "SOURCE" if at == 0 && matches!(scope.dialect, Dialect::MySql | Dialect::Cql) => {
                reading.unseen = true;
            }
            // PL/pgSQL's `EXECUTE` runs text that is only known when it
            // runs; a trigger's `EXECUTE FUNCTION` does not.
            "EXECUTE"
                if scope.in_do
                    && !matches!(tokens.get(at + 1), Some(Token::Word(w)) if matches!(w.as_str(), "FUNCTION" | "PROCEDURE")) =>
            {
                reading.unreadable = true;
            }
            _ => {}
        }
    }
    // The body of a function or procedure is run by every call of it:
    // `CREATE FUNCTION f() … AS $$ DELETE FROM t $$`, and `AS '…'`.
    if is_word(Some(first), "CREATE") && creates_routine(tokens) {
        for (at, token) in tokens.iter().enumerate() {
            match token {
                Token::Dollar(body) => reading.merge(read_sql(
                    body,
                    Scope {
                        dialect: Dialect::Postgres,
                        holes: false,
                        ..scope.within(true)
                    },
                )),
                Token::Quoted(quote) if quote.string => match body_prefix(tokens, at) {
                    Some(Prefix::Plain) => reading.merge(read_string(quote, scope.within(true))),
                    // A `U&'…'` string spells a character as `\0065`, or
                    // with the escape its `UESCAPE` names.
                    Some(Prefix::Unicode)
                        if quote.body.contains('\\') || is_word(tokens.get(at + 1), "UESCAPE") =>
                    {
                        reading.unreadable = true;
                    }
                    Some(Prefix::Unicode) => {
                        reading.merge(read_string(quote, scope.within(true)));
                    }
                    None => {}
                },
                _ => {}
            }
        }
    }
    statement_acts(tokens, scope, &mut reading);
    // `DO $$ … $$` and `DO '…'` run the statements in the string.
    if is_word(Some(first), "DO") {
        for token in tokens {
            match token {
                Token::Dollar(body) => {
                    reading.merge(read_sql(
                        body,
                        Scope {
                            dialect: Dialect::Postgres,
                            holes: false,
                            ..scope.within(true)
                        },
                    ));
                }
                Token::Quoted(quote) if quote.string && scope.dialect == Dialect::Postgres => {
                    reading.merge(read_string(quote, scope.within(true)));
                }
                _ => {}
            }
        }
    }
    reading
}

/// The token after the first `word` outside parentheses in `tokens`, from
/// `from` on, and its index.
fn after_word<'a>(tokens: &'a [Token], from: usize, word: &str) -> Option<(usize, &'a Token)> {
    let mut depth = 0usize;
    for (at, token) in tokens.iter().enumerate().skip(from) {
        match token {
            Token::Symbol('(') => depth += 1,
            Token::Symbol(')') => depth = depth.saturating_sub(1),
            Token::Word(w) if depth == 0 && w == word => {
                return tokens.get(at + 1).map(|next| (at + 1, next));
            }
            _ => {}
        }
    }
    None
}

/// The files a statement writes and the programs it runs that it shows:
/// `COPY … TO 'FILE'`, `INTO OUTFILE` and `INTO DUMPFILE`, `VACUUM INTO`,
/// `EXPORT DATABASE`, and the functions of the `sqlite3` shell that write a
/// file (`writefile`), load a library (`load_extension`) or run an editor
/// (`edit`). A file or a program the statement does not spell out is only
/// known when it runs.
fn statement_acts(tokens: &[Token], scope: Scope, reading: &mut Reading) {
    let write = |reading: &mut Reading, token: Option<&Token>, folder: bool| match token {
        Some(Token::Quoted(quote)) if !has_hole(&quote.body, scope.holes) => {
            reading.write(Written {
                name: quote.body.clone(),
                folder,
                database: false,
            });
        }
        _ => reading.unreadable = true,
    };
    let first = tokens.first();
    // `COPY t TO 'FILE'`; `TO STDOUT` is the client's output, and `TO
    // PROGRAM` runs a program (see [`statement`]).
    if is_word(first, "COPY") {
        // A name there is `DuckDB`'s `COPY FROM DATABASE a TO b`, which
        // copies into a database it has attached.
        if let Some((_, target)) = after_word(tokens, 1, "TO") {
            if !matches!(target, Token::Word(_)) {
                write(reading, Some(target), false);
            }
        }
    }
    // `VACUUM INTO 'FILE'` writes a copy of the database.
    if is_word(first, "VACUUM") {
        if let Some((_, target)) = after_word(tokens, 1, "INTO") {
            write(reading, Some(target), false);
        }
    }
    // `DuckDB`'s `EXPORT DATABASE ['db' TO] 'DIR'` writes a folder.
    if is_word(first, "EXPORT") && is_word(tokens.get(1), "DATABASE") {
        let target = match after_word(tokens, 2, "TO") {
            Some((_, target)) => Some(target),
            None => tokens.get(2),
        };
        write(reading, target, true);
    }
    let shell_functions = matches!(scope.dialect, Dialect::Sqlite | Dialect::DuckDb);
    for (at, token) in tokens.iter().enumerate() {
        let Token::Word(word) = token else { continue };
        let called = tokens.get(at + 1) == Some(&Token::Symbol('('));
        match word.as_str() {
            // `SELECT … INTO OUTFILE 'FILE'`, and `INTO DUMPFILE`.
            "INTO" if matches!(tokens.get(at + 1), Some(Token::Word(w)) if matches!(w.as_str(), "OUTFILE" | "DUMPFILE")) =>
            {
                write(reading, tokens.get(at + 2), false);
            }
            "WRITEFILE" if shell_functions && called => write(reading, tokens.get(at + 2), false),
            "LOAD_EXTENSION" if shell_functions && called => reading.program = true,
            // `edit(TEXT, EDITOR)` runs the editor as a command line; with no
            // editor it runs the one the environment names.
            "EDIT" if shell_functions && called => {
                match (tokens.get(at + 3), tokens.get(at + 4), tokens.get(at + 5)) {
                    (
                        Some(Token::Symbol(',')),
                        Some(Token::Quoted(editor)),
                        Some(Token::Symbol(')')),
                    ) if editor.string
                        && !editor.body.trim().is_empty()
                        && !has_hole(&editor.body, scope.holes) =>
                    {
                        reading.run(Program::Line(editor.body.clone()));
                    }
                    _ => reading.program = true,
                }
            }
            _ => {}
        }
    }
}

/// The words of a client command's arguments, as the client reads them:
/// spaces separate, `'…'`, `"…"` and `` `…` `` hold spaces and a backslash
/// quotes inside `'…'`. Also whether a backtick runs a program in them.
fn meta_words(text: &str) -> (Vec<String>, bool) {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut started = false;
    let mut backtick = false;
    let mut quote: Option<char> = None;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match quote {
            Some(q) if c == q => {
                if chars.peek() == Some(&q) {
                    word.push(q);
                    chars.next();
                } else {
                    quote = None;
                }
            }
            Some('\'') if c == '\\' => word.extend(chars.next()),
            Some(_) => word.push(c),
            None => match c {
                '\'' | '"' | '`' => {
                    quote = Some(c);
                    started = true;
                    backtick |= c == '`';
                }
                c if c.is_whitespace() => {
                    if started {
                        words.push(std::mem::take(&mut word));
                        started = false;
                    }
                }
                c => {
                    word.push(c);
                    started = true;
                }
            },
        }
    }
    if started {
        words.push(word);
    }
    (words, backtick)
}

/// A client command's name, lower case, and its arguments: `\gexec`, `\!`,
/// `\copy`, `.read`.
fn meta_name(text: &str) -> (String, &str) {
    let split = if let Some(command) = text.strip_prefix('\\') {
        let first = command.chars().next();
        let len = if first.is_some_and(|c| c.is_ascii_alphanumeric()) {
            command
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(command.len())
        } else {
            first.map_or(0, char::len_utf8)
        };
        command.split_at_checked(len)
    } else {
        text.split_once(char::is_whitespace).or(Some((text, "")))
    };
    let (name, rest) = split.unwrap_or((text, ""));
    let prefix = if text.starts_with('\\') { "\\" } else { "" };
    (format!("{prefix}{}", name.to_ascii_lowercase()), rest)
}

/// The dot commands of `sqlite3` and `duckdb` the reader has a rule for.
/// Both shells take any start of a command's name for the command
/// (`.sh echo hi` runs `.shell`, `.rea` is `.read`), so a name counts as every
/// one of these it starts.
const DOT_COMMANDS: [&str; 15] = [
    ".shell", ".system", ".open", ".attach", ".read", ".output", ".once", ".import", ".restore",
    ".backup", ".save", ".clone", ".cd", ".load", ".excel",
];

/// Whether the dot command `name` is `.backup` or `.save`, which write the
/// database to a file that they replace. Both shells take the shortest start
/// of the name that no other command has: `.bac` and `.sa`; `.ba` is also
/// `.bail`, and `.b` and `.s` start many.
fn is_backup(name: &str) -> bool {
    let starts = |command: &str, least: usize| name.len() >= least && command.starts_with(name);
    starts(".backup", ".bac".len()) || starts(".save", ".sa".len())
}

/// The variables whose value `psql` runs as a command line: the editor of
/// `\e`, the pager of a long result, and the shell of a bare `\!`.
const PSQL_PROGRAMS: [&str; 7] = [
    "EDITOR",
    "PSQL_EDITOR",
    "VISUAL",
    "PAGER",
    "PSQL_PAGER",
    "PSQL_WATCH_PAGER",
    "SHELL",
];

/// Whether `text`, from a double-quoted shell word when `holes`, holds an
/// expansion the shell fills in: what it is is only known when it runs.
fn has_hole(text: &str, holes: bool) -> bool {
    holes && text.contains(['$', '`', '%'])
}

/// What a client command (`\c db`, `\! ls`, `.shell ls`, `\gexec`) does.
/// `holes` says the text came from a double-quoted shell word.
fn meta(text: &str, holes: bool) -> Reading {
    let (name, rest) = meta_name(text);
    let (words, backtick) = meta_words(rest);
    let command = Command {
        written: &name,
        rest,
        words: &words,
        backtick,
        holes,
    };
    let mut reading = meta_command(&name, &command);
    // A dot command named by the start of its name is each command it starts.
    if name.starts_with('.') {
        for dot in DOT_COMMANDS {
            if dot != name && dot.starts_with(name.as_str()) {
                reading.merge(meta_command(dot, &command));
            }
        }
    }
    reading
}

/// A client command as it is written: its name, the text after it, and that
/// text as the client's words.
struct Command<'a> {
    /// The name as written, lower case: `.bac` for `.backup`.
    written: &'a str,
    /// The text after the name.
    rest: &'a str,
    words: &'a [String],
    /// Whether a backtick quotes part of the words.
    backtick: bool,
    /// Whether the text came from a double-quoted shell word.
    holes: bool,
}

/// What the client command `name`, written as `command`, does.
fn meta_command(name: &str, command: &Command<'_>) -> Reading {
    let Command {
        written,
        rest,
        words,
        backtick,
        holes,
    } = *command;
    let mut reading = Reading::default();
    // A command that writes to a file or, after a `|`, to a program.
    let pipes = words.iter().any(|word| word.starts_with('|'));
    let writes = matches!(
        name,
        "\\o"
            | "\\out"
            | "\\g"
            | "\\gx"
            | "\\w"
            | "\\write"
            | ".read"
            | ".output"
            | ".once"
            | ".import"
    );
    reading.program = match name {
        "\\copy" => words
            .iter()
            .any(|word| word.eq_ignore_ascii_case("program")),
        // A library loaded into the client, and the program that opens a
        // spreadsheet or the editor (`.once -x`, `.once -e`).
        ".load" | ".excel" => true,
        ".output" | ".once" => {
            pipes
                || words
                    .iter()
                    .any(|word| matches!(word.as_str(), "-e" | "-x"))
        }
        _ => writes && pipes,
    };
    // A backtick in a `psql` command runs a program; `\!` hands its line to
    // the shell as it is, backticks too.
    reading.program |= backtick && name.starts_with('\\') && name != "\\!";
    // What the result of a query runs, or sets for later, is not on the line.
    if matches!(name, "\\gexec" | "\\gset") {
        reading.unreadable = true;
    }
    // A target that only the shell knows may be `|program`.
    if writes && holes && words.iter().any(|word| word.starts_with(['$', '`', '%'])) {
        reading.unreadable = true;
    }
    if matches!(name, ".open" | ".attach") {
        reading.moves = true;
    }
    if matches!(name, "\\cd" | ".cd") {
        reading.acts.moves_folder = true;
    }
    // A command that runs the statements of a file: `psql`'s `\i` and
    // `\include` (and their `_relative` forms), `mysql`'s `\.`, and `.read`
    // of a file, not of a program.
    let includes = matches!(
        name,
        "\\i" | "\\ir" | "\\include" | "\\include_relative" | "\\."
    );
    if includes || (name == ".read" && !pipes && !words.is_empty()) {
        reading.unseen = true;
    }
    // `.restore` replaces the whole database with a file.
    if name == ".restore" {
        reading.destroys = true;
    }
    run_shown(&mut reading, name, rest, words, holes);
    write_shown(&mut reading, name, written, words, holes);
    reading
}

/// The program a client command runs with the command line it shows: `\!`,
/// `mysql`'s `system` and `pager`, `.shell` and `.system`, and the editor or
/// pager `\setenv` sets. With no command line it runs one the line does not
/// show (a bare `\!` starts a shell), and a line with a shell expansion in it
/// is only known when it runs.
fn run_shown(reading: &mut Reading, name: &str, rest: &str, words: &[String], holes: bool) {
    let line = match name {
        // The line as the shell gets it: what follows the name.
        "\\!" | "system" | "pager" => rest.trim().to_string(),
        // The words joined, each with a space in it quoted, as the shell of
        // `sqlite3` makes the command line.
        ".shell" | ".system" => words
            .iter()
            .map(|word| {
                if word.contains(' ') {
                    format!("\"{word}\"")
                } else {
                    word.clone()
                }
            })
            .collect::<Vec<_>>()
            .join(" "),
        "\\setenv" => {
            // Any other variable is in the environment of what it runs.
            let Some(variable) = words.first() else {
                return;
            };
            if !PSQL_PROGRAMS.contains(&variable.as_str()) {
                reading.acts.environment = true;
                return;
            }
            match words.get(1) {
                Some(value) => value.clone(),
                None => return,
            }
        }
        _ => return,
    };
    if line.is_empty() || has_hole(&line, holes) {
        reading.program = true;
    } else {
        reading.run(Program::Line(line));
    }
}

/// The file a client command writes, as it names it: `psql`'s `\o`, `\g`,
/// `\w`, `\s`, `\copy … to` and `\lo_export`; `.output`, `.once`, `.backup`,
/// `.save` and `.clone`; `mysql`'s `tee`; `sqlcmd`'s `:out`, `:error` and
/// `:perftrace`. A name with a shell expansion in it is only known when it
/// runs.
fn write_shown(reading: &mut Reading, name: &str, written: &str, words: &[String], holes: bool) {
    let mut database = false;
    let file = match name {
        "\\o" | "\\out" | "\\w" | "\\write" | "\\s" => words.first(),
        // `\g (format=csv) FILE`: the options in parentheses come first.
        "\\g" | "\\gx" => {
            let mut depth = 0usize;
            words.iter().find(|word| {
                let outside = depth == 0 && !word.starts_with('(');
                depth += word.matches('(').count();
                depth = depth.saturating_sub(word.matches(')').count());
                outside
            })
        }
        "\\lo_export" => words.get(1),
        "\\copy" => copy_target(words),
        ".output" | ".once" => words.iter().rev().find(|word| !word.starts_with('-')),
        ".backup" | ".save" if is_backup(written) => {
            database = true;
            words.last()
        }
        ".clone" => words.last(),
        "tee" => words.first(),
        ":out" | ":error" | ":perftrace" => words.first().filter(|word| {
            !["stdout", "stderr"]
                .iter()
                .any(|stream| word.eq_ignore_ascii_case(stream))
        }),
        _ => None,
    };
    let Some(file) = file else {
        return;
    };
    // `mysql`'s `tee` is read to the end of its line: a `;` ends it.
    let file = if name == "tee" {
        file.trim_end_matches(';')
    } else {
        file.as_str()
    };
    if file.is_empty() || file.starts_with('|') {
        return;
    }
    if has_hole(file, holes) {
        reading.unreadable = true;
    } else {
        reading.write(Written {
            name: file.to_string(),
            folder: false,
            database,
        });
    }
}

/// The file `\copy … to FILE` writes: the word after the first `to` outside
/// parentheses (`\copy (SELECT …) to FILE`), unless it is the client's own
/// output or a program. `\copy … from` writes nothing.
fn copy_target(words: &[String]) -> Option<&String> {
    let mut depth = 0usize;
    let mut iter = words.iter();
    while let Some(word) = iter.next() {
        if depth == 0 {
            if word.eq_ignore_ascii_case("from") {
                return None;
            }
            if word.eq_ignore_ascii_case("to") {
                return iter.next().filter(|target| {
                    !["stdout", "pstdout", "program"]
                        .iter()
                        .any(|name| target.eq_ignore_ascii_case(name))
                });
            }
        }
        depth += word.matches('(').count();
        depth = depth.saturating_sub(word.matches(')').count());
    }
    None
}

/// What the SQL in `text` does. `holes` says `text` came from a
/// double-quoted shell word, whose expansions are only known when it runs.
/// Where the server decides how a backslash in a string reads, it is read
/// with each rule, and what any of them shows counts. A client sends each
/// statement as its `;` arrives, so in such a reading what is before a string
/// that never closes runs: the statements that end before it count, and only
/// the open tail, which is not a statement the client sends, is left out.
pub(super) fn sql(text: &str, dialect: Dialect, holes: bool) -> Reading {
    let scope = Scope {
        dialect,
        holes,
        in_do: false,
        depth: 0,
        backslash: Backslash::Dialect,
    };
    let mut reading = read_sql(text, scope);
    for &backslash in dialect.other_backslash() {
        if let Some(other) = read_sql_prefix(text, Scope { backslash, ..scope }) {
            reading.merge(other);
        }
    }
    reading
}

/// What the SQL in `text` does, read in `scope`, as a client that sends each
/// statement when it ends reads it: if a string, comment or `$$` string is
/// never closed, the statements before it are read and the open tail is not.
/// `None` when it is nested too deep.
fn read_sql_prefix(text: &str, scope: Scope) -> Option<Reading> {
    if scope.depth > MAX_DEPTH {
        return None;
    }
    let (tokens, closed) = tokenize_prefix(text, scope.dialect, scope.holes, scope.backslash);
    if closed {
        return Some(read_tokens(&tokens, scope));
    }
    // Up to the last token that ends a statement.
    let sent = tokens
        .iter()
        .rposition(|token| matches!(token, Token::Symbol(';') | Token::Meta(_)))
        .map_or(0, |last| last + 1);
    Some(read_tokens(tokens.get(..sent).unwrap_or_default(), scope))
}

/// What the SQL in `text` does, read in `scope`.
fn read_sql(text: &str, scope: Scope) -> Reading {
    try_read_sql(text, scope).unwrap_or(Reading::UNREADABLE)
}

/// What the SQL in `text` does, read in `scope`; `None` when it cannot be
/// cut into tokens or is nested too deep.
fn try_read_sql(text: &str, scope: Scope) -> Option<Reading> {
    // SQL in a string in SQL, so deep that it is not read.
    if scope.depth > MAX_DEPTH {
        return None;
    }
    let tokens = tokenize(text, scope.dialect, scope.holes, scope.backslash)?;
    Some(read_tokens(&tokens, scope))
}

/// What the statements in `tokens` do.
fn read_tokens(tokens: &[Token], scope: Scope) -> Reading {
    let mut reading = Reading::default();
    let mut start = 0;
    for at in 0..=tokens.len() {
        let token = tokens.get(at);
        match token {
            None | Some(Token::Symbol(';')) => {
                reading.merge(statement(tokens.get(start..at).unwrap_or_default(), scope));
                start = at + 1;
            }
            Some(Token::Meta(text)) => {
                reading.merge(statement(tokens.get(start..at).unwrap_or_default(), scope));
                reading.merge(meta(text, scope.holes));
                start = at + 1;
            }
            Some(_) => {}
        }
    }
    reading
}

/// What the `MongoDB` shell script in `text` does: drops a database or a
/// collection, or deletes every document of one.
pub(super) fn mongo(text: &str, holes: bool) -> Reading {
    let chars: Vec<char> = text.chars().collect();
    let mut tokens = Vec::new();
    let mut at = 0;
    while let Some(&c) = chars.get(at) {
        let next = chars.get(at + 1).copied();
        match c {
            c if c.is_whitespace() => at += 1,
            '/' if next == Some('/') => at = line(&chars, at).1,
            '/' if next == Some('*') => {
                let Some(rest) = chars.get(at + 2..) else {
                    return Reading::UNREADABLE;
                };
                let Some(end) = rest.windows(2).position(|pair| pair == ['*', '/']) else {
                    return Reading::UNREADABLE;
                };
                at += 2 + end + 2;
            }
            '`' if holes => {
                let Some(close) = chars
                    .get(at + 1..)
                    .and_then(|rest| rest.iter().position(|c| *c == '`'))
                else {
                    return Reading::UNREADABLE;
                };
                at += close + 2;
                tokens.push(Js::Hole);
            }
            '\'' | '"' | '`' => {
                let quote = c;
                let mut body = String::new();
                at += 1;
                loop {
                    match chars.get(at) {
                        None => return Reading::UNREADABLE,
                        Some('\\') => {
                            body.extend(chars.get(at + 1));
                            at += 2;
                        }
                        Some(c) if *c == quote => {
                            at += 1;
                            break;
                        }
                        Some(c) => {
                            body.push(*c);
                            at += 1;
                        }
                    }
                }
                tokens.push(Js::Quoted(body));
            }
            '$' | '%' if holes && hole_end(&chars, at).is_some() => {
                at = hole_end(&chars, at).unwrap_or(at + 1);
                tokens.push(Js::Hole);
            }
            c if c.is_alphanumeric() || c == '_' || c == '$' => {
                // A name with an expansion in it is read with the expansion
                // empty: `dropDatabase$x()` may be `dropDatabase()`.
                let mut name = String::new();
                while let Some(&c) = chars.get(at) {
                    if c == '$' && holes {
                        if let Some(end) = hole_end(&chars, at) {
                            at = end;
                            continue;
                        }
                    }
                    if !(c.is_alphanumeric() || c == '_' || c == '$') {
                        break;
                    }
                    name.push(c);
                    at += 1;
                }
                tokens.push(Js::Name(name));
            }
            c => {
                tokens.push(Js::Symbol(c));
                at += 1;
            }
        }
    }
    if tokens.first() == Some(&Js::Hole) {
        return Reading::UNREADABLE;
    }
    let script = Script::new(tokens);
    let tokens = &script.tokens;
    let mut reading = Reading::default();
    // What each `delete` command's object deletes, worked out once.
    let mut commands: HashMap<usize, bool> = HashMap::new();
    for (at, token) in tokens.iter().enumerate() {
        let after = tokens.get(at + 1);
        // An operation of a `bulkWrite`, an object in its list.
        if token == &Js::Symbol('{') && script.in_list(at) {
            reading.destroys |= script.bulk_deletes_all(at);
            continue;
        }
        // A name is called (`db.dropDatabase()`) or a key (`{drop: 1}`); a
        // string is a key (`{"drop": 1}`) or a name in brackets that is
        // called (`db["dropDatabase"]()`). `args` is where what it is called
        // with starts.
        let (name, called, key, args) = match token {
            Js::Name(name) => (
                name,
                after == Some(&Js::Symbol('(')),
                after == Some(&Js::Symbol(':')),
                at + 2,
            ),
            Js::Quoted(name) if after == Some(&Js::Symbol(':')) => (name, false, true, at + 2),
            Js::Quoted(name)
                if after == Some(&Js::Symbol(']'))
                    && tokens.get(at + 2) == Some(&Js::Symbol('('))
                    && at
                        .checked_sub(1)
                        .is_some_and(|before| tokens.get(before) == Some(&Js::Symbol('['))) =>
            {
                (name, true, false, at + 3)
            }
            _ => continue,
        };
        match name.as_str() {
            "dropDatabase" | "dropCollection" | "drop" | "dropAllUsers" | "dropAllRoles"
                if called || key =>
            {
                reading.destroys = true;
            }
            "dropAllUsersFromDatabase" | "dropAllRolesFromDatabase" if key => {
                reading.destroys = true;
            }
            "deleteMany" | "remove" if called => {
                reading.destroys |= !script.picks(args);
            }
            // The `delete` command: `{delete: "users", deletes: [{q: {},
            // limit: 0}]}`.
            "delete" if key && script.is_command(at) => {
                reading.destroys |= match script.parent.get(at).copied().flatten() {
                    Some(open) => *commands
                        .entry(open)
                        .or_insert_with(|| script.deletes_all(open)),
                    None => true,
                };
            }
            // `load("drop.js")` runs the script of a file, which the line
            // does not show.
            "load" if called => reading.unseen = true,
            // Node's `child_process` runs programs from what the script
            // builds, which is not read; a module only known when it runs may
            // be it.
            "require" if called => match script.literals(args) {
                Some(names) if names.iter().all(|name| !is_child_process(name)) => {}
                _ => reading.program = true,
            },
            // The legacy shell's functions that run a program with the
            // words they are given: `runProgram('sh', '-c', 'ls')`. A free
            // call: `x.run(…)` is a method of something else.
            "runProgram"
            | "runNonMongoProgram"
            | "runMongoProgram"
            | "_runMongoProgram"
            | "startMongoProgram"
            | "startMongoProgramNoConnect"
            | "_startMongoProgram"
                if called =>
            {
                run_words(&mut reading, script.literals(args), holes);
            }
            "run"
                if called
                    && at.checked_sub(1).and_then(|before| tokens.get(before))
                        != Some(&Js::Symbol('.')) =>
            {
                run_words(&mut reading, script.literals(args), holes);
            }
            _ => {}
        }
    }
    reading
}

/// Whether the module `name` is Node's `child_process`.
fn is_child_process(name: &str) -> bool {
    name.strip_prefix("node:").unwrap_or(name) == "child_process"
}

/// Note the program a call runs with `words`, its arguments when each is a
/// string: none, or one not written out, is a program the line does not show.
/// A word with a shell expansion in it (`holes`), or a template literal's
/// `${…}`, is only known when it runs.
fn run_words(reading: &mut Reading, words: Option<Vec<String>>, holes: bool) {
    match words {
        Some(words)
            if !words.is_empty()
                && words
                    .iter()
                    .all(|word| !has_hole(word, holes) && !word.contains("${")) =>
        {
            reading.run(Program::Words(words));
        }
        _ => reading.program = true,
    }
}

/// A token of a `MongoDB` shell script.
#[derive(PartialEq)]
enum Js {
    Name(String),
    /// A string, with what it holds.
    Quoted(String),
    Hole,
    Symbol(char),
}

/// The tokens of a `MongoDB` shell script, with where each bracket closes
/// and which bracket holds each token, found in one pass so that each
/// question about the script is answered without reading it again.
struct Script {
    tokens: Vec<Js>,
    /// For a `{`, `[` or `(`, the index just past the bracket that closes it
    /// (or the end); for any other token, the index after it.
    close: Vec<usize>,
    /// The bracket each token is directly inside.
    parent: Vec<Option<usize>>,
}

impl Script {
    /// The arguments of the call whose `(` is just before `args`, when each
    /// is a string, as their text; `None` when any is anything else.
    fn literals(&self, args: usize) -> Option<Vec<String>> {
        let open = args.checked_sub(1)?;
        let end = self.close.get(open)?.checked_sub(1)?;
        let mut found = Vec::new();
        let mut at = args;
        while at < end {
            match self.tokens.get(at)? {
                Js::Quoted(text) => found.push(text.clone()),
                _ => return None,
            }
            at += 1;
            match self.tokens.get(at) {
                Some(Js::Symbol(',')) => at += 1,
                Some(Js::Symbol(')')) if at == end => {}
                _ => return None,
            }
        }
        Some(found)
    }

    fn new(tokens: Vec<Js>) -> Self {
        let mut close: Vec<usize> = (1..=tokens.len()).collect();
        let mut parent = vec![None; tokens.len()];
        let mut open: Vec<usize> = Vec::new();
        for (at, token) in tokens.iter().enumerate() {
            if let Some(slot) = parent.get_mut(at) {
                *slot = open.last().copied();
            }
            match token {
                Js::Symbol('{' | '[' | '(') => open.push(at),
                Js::Symbol('}' | ']' | ')') => {
                    if let Some(start) = open.pop() {
                        if let Some(slot) = close.get_mut(start) {
                            *slot = at + 1;
                        }
                    }
                }
                _ => {}
            }
        }
        // A bracket never closed runs to the end.
        for start in open {
            if let Some(slot) = close.get_mut(start) {
                *slot = tokens.len();
            }
        }
        Self {
            tokens,
            close,
            parent,
        }
    }

    /// The index just past the token at `at`, or past all the bracket there
    /// holds.
    fn past(&self, at: usize) -> usize {
        self.close
            .get(at)
            .copied()
            .unwrap_or(self.tokens.len())
            .max(at + 1)
    }

    /// Whether the filter that starts at `at` picks documents: an object
    /// written out with a field in it (`{a: 1}`, `{"a.b": 1}`, `{$or: […]}`).
    /// No filter (`)`), an empty one (`{}`), one with a spread from a value
    /// (`{...f}`, `{a: 1, ...f}`, where `f` may hold any field) and one only
    /// known when it runs (`f`, `$F`) pick every document there may be.
    fn picks(&self, at: usize) -> bool {
        self.tokens.get(at) == Some(&Js::Symbol('{'))
            && matches!(self.tokens.get(at + 1), Some(Js::Name(_) | Js::Quoted(_)))
            && self.tokens.get(at + 2) == Some(&Js::Symbol(':'))
            && !self.spreads(at)
    }

    /// The tokens written in the object from `open` (its `{`) at its own
    /// level, and the bracket that closes it: a bracket in it stands for all
    /// it holds.
    fn own(&self, open: usize) -> impl Iterator<Item = usize> + '_ {
        let end = self.past(open);
        std::iter::successors(Some(open + 1), move |at| Some(self.past(*at)))
            .take_while(move |at| *at < end)
    }

    /// Whether the object from `open` spreads a value at its own level
    /// (`{a: 1, ...o}`), which may set any key, or replace one written before
    /// it.
    fn spreads(&self, open: usize) -> bool {
        let dot = Some(&Js::Symbol('.'));
        self.own(open).any(|at| {
            self.tokens.get(at) == dot
                && self.tokens.get(at + 1) == dot
                && self.tokens.get(at + 2) == dot
        })
    }

    /// Where the value of the last key `name` written at the own level of
    /// the object from `open` starts, as JavaScript takes the last of keys of
    /// the same name. A spread is not looked into.
    fn key_of(&self, open: usize, name: &str) -> Option<usize> {
        self.own(open)
            .filter(|at| {
                matches!(self.tokens.get(*at), Some(Js::Name(key) | Js::Quoted(key)) if key == name)
                    && self.tokens.get(at + 1) == Some(&Js::Symbol(':'))
            })
            .last()
            .map(|at| at + 2)
    }

    /// Where the value of the key `name` of the object from `open` starts,
    /// when the line shows it: `None` when the object has no such key, or
    /// spreads a value that may set it.
    fn value_of(&self, open: usize, name: &str) -> Option<usize> {
        if self.spreads(open) {
            return None;
        }
        self.key_of(open, name)
    }

    /// Whether the `{` at `open` is an item of a list (`[{…}, {…}]`), where
    /// the operations of a `bulkWrite` are.
    fn in_list(&self, open: usize) -> bool {
        self.parent
            .get(open)
            .copied()
            .flatten()
            .is_some_and(|list| self.tokens.get(list) == Some(&Js::Symbol('[')))
    }

    /// The name of the call whose `(` is at `open`, if a name comes right
    /// before it.
    fn call_name(&self, open: usize) -> Option<&str> {
        if self.tokens.get(open) != Some(&Js::Symbol('(')) {
            return None;
        }
        match self.tokens.get(open.checked_sub(1)?)? {
            Js::Name(name) => Some(name),
            _ => None,
        }
    }

    /// Whether the operation of a `bulkWrite` written as the object from
    /// `open` deletes every document there may be: a `deleteMany` whose
    /// filter picks none (`{deleteMany: {filter: {}}}`, and in the client's
    /// `bulkWrite` of mongosh 2.3, `{name: "deleteMany", filter: {}}`). An
    /// operation with a spread that may make it one is read as one.
    fn bulk_deletes_all(&self, open: usize) -> bool {
        let named = self.key_of(open, "name");
        let operation = self.key_of(open, "deleteMany");
        if self.spreads(open) {
            return named.is_some() || operation.is_some();
        }
        if let Some(operation) = operation {
            let filter = match self.tokens.get(operation) {
                Some(Js::Symbol('{')) => self.value_of(operation, "filter"),
                _ => None,
            };
            if !filter.is_some_and(|filter| self.picks(filter)) {
                return true;
            }
        }
        named.is_some_and(
            |name| matches!(self.tokens.get(name), Some(Js::Quoted(name)) if name == "deleteMany"),
        ) && !self
            .value_of(open, "filter")
            .is_some_and(|filter| self.picks(filter))
    }

    /// Whether the key `delete` at `at` names the `delete` command, not a
    /// field: its object is what `runCommand` or `adminCommand` is given, or,
    /// in an object no other call is given, it is the first key, as a
    /// command's name is, and its value can be a collection's name.
    fn is_command(&self, at: usize) -> bool {
        let Some(open) = self.parent.get(at).copied().flatten() else {
            return false;
        };
        if self.tokens.get(open) != Some(&Js::Symbol('{')) {
            return false;
        }
        let call = self
            .parent
            .get(open)
            .copied()
            .flatten()
            .and_then(|outer| self.call_name(outer));
        if let Some(call) = call {
            return matches!(call, "runCommand" | "adminCommand");
        }
        let literal = |name: &str| {
            matches!(name, "true" | "false" | "null" | "undefined")
                || name.starts_with(|c: char| c.is_ascii_digit())
        };
        at == open + 1
            && match self.tokens.get(at + 2) {
                Some(Js::Quoted(_) | Js::Hole) => true,
                Some(Js::Name(name)) => !literal(name),
                _ => false,
            }
    }

    /// Whether the `delete` command written as the object from `open`
    /// deletes every document there may be: one of its `deletes` has a
    /// filter that picks none ([`Script::picks`]) and no `limit` of 1, or
    /// the deletes are not written out.
    fn deletes_all(&self, open: usize) -> bool {
        let Some(list) = self.value_of(open, "deletes") else {
            return true;
        };
        if self.tokens.get(list) != Some(&Js::Symbol('[')) {
            return true;
        }
        let end = self.past(list).saturating_sub(1);
        let mut each = list + 1;
        while each < end {
            match self.tokens.get(each) {
                Some(Js::Symbol(',')) => each += 1,
                Some(Js::Symbol('{')) => {
                    let one = self.value_of(each, "limit").is_some_and(
                        |limit| matches!(self.tokens.get(limit), Some(Js::Name(n)) if n == "1"),
                    );
                    let filter = self.value_of(each, "q");
                    if !one && !filter.is_some_and(|filter| self.picks(filter)) {
                        return true;
                    }
                    each = self.past(each);
                }
                // A delete only known when it runs.
                _ => return true,
            }
        }
        false
    }
}

/// Whether the Redis command `command` runs a script: its second word is the
/// script, a digest of one, or the name of a function.
pub(super) fn runs_script(command: &str) -> bool {
    matches!(
        command.to_ascii_lowercase().as_str(),
        "eval" | "evalsha" | "eval_ro" | "evalsha_ro" | "fcall" | "fcall_ro"
    )
}

/// Whether the Lua script `script` empties a database or deletes what it
/// lists: it names `FLUSHALL` or `FLUSHDB`, or calls `DEL` or `UNLINK` and
/// also `KEYS` or `SCAN`. The commands are the strings it calls, so `KEYS[1]`,
/// the keys the script is given, is not a listing.
fn script_destroys(script: &str) -> bool {
    let lower = script.to_ascii_lowercase();
    if lower.contains("flushall") || lower.contains("flushdb") {
        return true;
    }
    let (mut deletes, mut lists) = (false, false);
    for text in lua_strings(&lower) {
        match text.trim() {
            "del" | "unlink" => deletes = true,
            "keys" | "scan" => lists = true,
            _ => {}
        }
    }
    deletes && lists
}

/// The strings of a Lua script: `'…'`, `"…"` and `[[…]]` (with any number of
/// `=` between the brackets).
fn lua_strings(script: &str) -> Vec<String> {
    let chars: Vec<char> = script.chars().collect();
    let mut found = Vec::new();
    let mut at = 0;
    while let Some(&c) = chars.get(at) {
        match c {
            '\'' | '"' => {
                let mut text = String::new();
                at += 1;
                while let Some(&next) = chars.get(at) {
                    at += 1;
                    match next {
                        '\\' => {
                            text.extend(chars.get(at));
                            at += 1;
                        }
                        next if next == c => break,
                        next => text.push(next),
                    }
                }
                found.push(text);
            }
            '[' => {
                let equals = chars
                    .get(at + 1..)
                    .map_or(0, |rest| rest.iter().take_while(|c| **c == '=').count());
                if chars.get(at + 1 + equals) == Some(&'[') {
                    let close: Vec<char> = std::iter::once(']')
                        .chain(std::iter::repeat_n('=', equals))
                        .chain(std::iter::once(']'))
                        .collect();
                    let body = chars.get(at + 2 + equals..).unwrap_or_default();
                    let end = body
                        .windows(close.len())
                        .position(|window| window == close.as_slice())
                        .unwrap_or(body.len());
                    found.push(body.get(..end).unwrap_or_default().iter().collect());
                    at += 2 + equals + end + close.len();
                } else {
                    at += 1;
                }
            }
            _ => at += 1,
        }
    }
    found
}

/// What one Redis command, as its words, does: empties a database
/// (`FLUSHALL`, `FLUSHDB`), deletes every function (`FUNCTION FLUSH`), or
/// stops the server without saving what it holds in memory (`SHUTDOWN
/// NOSAVE`). A script (`EVAL`) that calls such a command does too.
pub(super) fn redis(words: &[&str]) -> Reading {
    let Some(command) = words.first() else {
        return Reading::default();
    };
    let rest = || words.iter().skip(1);
    let destroys = match command.to_ascii_lowercase().as_str() {
        "flushall" | "flushdb" => true,
        "function" => words
            .get(1)
            .is_some_and(|word| word.eq_ignore_ascii_case("flush")),
        "shutdown" => rest().any(|word| word.eq_ignore_ascii_case("nosave")),
        _ if runs_script(command) => words.iter().any(|word| script_destroys(word)),
        _ => false,
    };
    Reading {
        destroys,
        ..Reading::default()
    }
}

/// What the Redis commands in `text` do, one on each line.
pub(super) fn redis_lines(text: &str, holes: bool) -> Reading {
    let mut reading = Reading::default();
    for row in text.lines() {
        let words = shell_words(row);
        if words
            .first()
            .is_some_and(|word| holes && (word.starts_with('$') || word.starts_with('`')))
        {
            return Reading::UNREADABLE;
        }
        let words: Vec<&str> = words.iter().map(String::as_str).collect();
        // A script only known when it runs.
        if holes
            && words.first().is_some_and(|word| runs_script(word))
            && words
                .get(1)
                .is_some_and(|word| word.contains('$') || word.contains('`'))
        {
            return Reading::UNREADABLE;
        }
        reading.merge(redis(&words));
    }
    reading
}

/// A line cut into words the way redis-cli reads it: spaces, with `'…'` and
/// `"…"` holding spaces.
fn shell_words(row: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut open: Option<char> = None;
    let mut started = false;
    for c in row.chars() {
        match (open, c) {
            (Some(quote), c) if c == quote => open = None,
            (Some(_), c) => word.push(c),
            (None, '\'' | '"') => {
                open = Some(c);
                started = true;
            }
            (None, c) if c.is_whitespace() => {
                if started {
                    words.push(std::mem::take(&mut word));
                    started = false;
                }
            }
            (None, c) => {
                word.push(c);
                started = true;
            }
        }
    }
    if started {
        words.push(word);
    }
    words
}

#[cfg(test)]
mod tests {
    use super::*;

    fn destroys(text: &str) -> bool {
        sql(text, Dialect::Postgres, false).destroys
    }

    /// The dialect a client command is written in: dot commands are SQLite's.
    fn client(text: &str) -> Dialect {
        if text.starts_with('.') {
            Dialect::Sqlite
        } else {
            Dialect::Postgres
        }
    }

    #[test]
    fn the_statements_that_destroy() {
        for text in [
            "DROP TABLE users",
            "drop database prod;",
            "TRUNCATE users",
            "TRUNCATE TABLE users",
            "DELETE FROM users",
            "delete from users;",
            "UPDATE users SET admin = 0",
            "ALTER TABLE users DROP COLUMN email",
            "SELECT 1; DROP TABLE t",
            "BEGIN; DELETE FROM t; COMMIT",
            "DELETE FROM users WHERE 1=1",
            "DELETE FROM users WHERE true",
            "DELETE FROM users WHERE (1 = 1)",
            "WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d",
            "EXPLAIN ANALYZE DELETE FROM t",
            "DELETE FROM a DELETE FROM b WHERE x = 1",
            "DO $$ BEGIN DROP TABLE t; END $$",
            "DO LANGUAGE plpgsql $body$ BEGIN DELETE FROM t; END $body$",
            // A body runs wherever the function is called, which the line
            // need not show.
            "CREATE FUNCTION f() RETURNS int AS $$ BEGIN DELETE FROM t; END $$ LANGUAGE plpgsql",
            "CREATE OR REPLACE TABLE t (id int)",
            "REPLACE TABLE t AS SELECT 1",
            "RESTORE DATABASE x FROM DISK = 'x.bak' WITH REPLACE",
            "SELECT dblink_exec('dbname=x', 'DROP TABLE t')",
            "SELECT \"dblink_exec\"('dbname=x', 'DROP TABLE t')",
            "CREATE FUNCTION f() RETURNS void AS E'DELETE FROM t' LANGUAGE sql",
            "CREATE FUNCTION f() RETURNS void AS U&'DELETE FROM t' LANGUAGE sql",
        ] {
            assert!(destroys(text), "{text}");
        }
    }

    #[test]
    fn the_statements_that_do_not() {
        for text in [
            "SELECT 1",
            "SELECT * FROM users WHERE name = 'DROP TABLE x'",
            "SELECT 'a;DROP TABLE t'",
            "-- DROP TABLE t\nSELECT 1",
            "/* DROP TABLE t */ SELECT 1",
            "INSERT INTO t VALUES (1)",
            "INSERT INTO t VALUES (1) ON CONFLICT (a) DO UPDATE SET b = 1",
            "INSERT INTO t VALUES (1) ON DUPLICATE KEY UPDATE b = 1",
            "CREATE TABLE t (id int, p int REFERENCES p(id) ON DELETE CASCADE ON UPDATE CASCADE)",
            "CREATE TRIGGER x AFTER UPDATE OF c ON t FOR EACH ROW EXECUTE FUNCTION f()",
            "SELECT * FROM t FOR UPDATE",
            "SELECT * FROM t FOR NO KEY UPDATE",
            "GRANT SELECT, UPDATE ON t TO me",
            "DELETE FROM users WHERE id = 3",
            "UPDATE users SET a = 1 WHERE id = 3",
            "DELETE FROM t USING u WHERE t.id = u.id",
            "MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN UPDATE SET a = 1 WHEN NOT MATCHED BY SOURCE THEN DELETE",
            "SELECT TRUNCATE(1.234, 2)",
            "SELECT \"drop\" FROM t",
            "CREATE FUNCTION f() RETURNS int AS $$ BEGIN DELETE FROM t WHERE id = 3; END $$ LANGUAGE plpgsql",
            "CREATE OR REPLACE VIEW v AS SELECT 1",
            "REPLACE INTO t VALUES (1)",
            "RESTORE HEADERONLY FROM DISK = 'x.bak'",
            "RESTORE DATABASE x WITH RECOVERY",
            "CREATE FUNCTION f() RETURNS int AS E'SELECT 1' LANGUAGE sql",
            "SELECT dblink_exec('dbname=x', 'INSERT INTO t VALUES (1)')",
            "",
            "   ",
        ] {
            let reading = sql(text, Dialect::Postgres, false);
            assert!(!reading.destroys, "{text}");
            assert!(!reading.unreadable, "{text}");
        }
    }

    #[test]
    fn quoting_and_comments_follow_the_dialect() {
        let mysql = |text| sql(text, Dialect::MySql, false);
        // A backslash escapes the quote in MySQL, so the string runs on.
        assert!(!mysql("SELECT 'it\\'s'").destroys);
        assert!(!mysql("SELECT 'a\\'; SELECT 1").destroys);
        // With NO_BACKSLASH_ESCAPES the string ends at `\'` and the client
        // sends the DROP before the tail (`--'` is no comment) is open.
        assert!(mysql("SELECT 'a\\'; DROP TABLE t; --'").destroys);
        // In the other dialects the string ends and the DROP runs.
        assert!(destroys("SELECT 'a\\'; DROP TABLE t; --'"));
        assert!(!destroys("SELECT E'a\\'; DROP TABLE t; --'"));
        // A `#` comment is MySQL's alone.
        assert!(!mysql("SELECT 1 # ; DROP TABLE t").destroys);
        assert!(destroys("SELECT 1 # 2; DROP TABLE t"));
        // `--x` is not a comment in MySQL.
        assert!(mysql("SELECT 1 --x; DROP TABLE t").destroys);
        assert!(!mysql("SELECT 1 -- ; DROP TABLE t").destroys);
        // A comment that MySQL runs.
        assert!(mysql("/*!50000 DROP TABLE t */").destroys);
        assert!(mysql("SELECT 1 /*! ; DROP TABLE t */").destroys);
        assert!(!destroys("/*! DROP TABLE t */"));
        // CQL's `//`.
        assert!(!sql("// DROP TABLE t\nSELECT 1", Dialect::Cql, false).destroys);
    }

    #[test]
    fn what_cannot_be_closed_cannot_be_read() {
        for text in [
            "SELECT 'a",
            "SELECT \"a",
            "SELECT 1 /* DROP TABLE t",
            "DO $$ DROP TABLE t",
            "/*! DROP TABLE t",
        ] {
            let dialect = if text.starts_with("/*!") {
                Dialect::MySql
            } else {
                Dialect::Postgres
            };
            assert!(sql(text, dialect, false).unreadable, "{text}");
        }
    }

    #[test]
    fn a_shell_expansion_is_a_hole() {
        let read = |text| sql(text, Dialect::Postgres, true);
        assert!(read("$Q").unreadable);
        assert!(read("${Q}").unreadable);
        assert!(read("$(cat q.sql)").unreadable);
        assert!(read("`cat q.sql`").unreadable);
        assert!(read("SELECT 1; $Q").unreadable);
        assert!(read("$Q FROM t").unreadable);
        assert!(!read("DELETE FROM users WHERE id = $id").destroys);
        assert!(!read("DELETE FROM users WHERE id = $id").unreadable);
        assert!(read("DROP TABLE $t").destroys);
        assert!(read("DELETE FROM $t").destroys);
        // Outside a double-quoted word, `$1` is a parameter and `$$` a string.
        assert!(!sql("SELECT $1", Dialect::Postgres, false).unreadable);
    }

    #[test]
    fn client_commands_that_run_programs() {
        for text in [
            "\\!",
            "COPY t FROM PROGRAM 'rm -rf x'",
            "\\copy t from program 'x'",
            ".system",
            ".read |ls",
            ".load ./x",
            "EXEC xp_cmdshell 'dir'",
        ] {
            assert!(sql(text, client(text), false).program, "{text}");
        }
        // A command line the text shows is the program, read on its own.
        let line = |text: &str, dialect: Dialect| sql(text, dialect, false).acts.programs;
        let rm = vec![Program::Line("rm -rf x".to_string())];
        assert_eq!(line("\\! rm -rf x", Dialect::Postgres), rm);
        assert_eq!(
            line("\\! rm -rf x \\o y", Dialect::Postgres),
            vec![Program::Line("rm -rf x \\o y".to_string())]
        );
        assert_eq!(line(".shell rm -rf x", Dialect::Sqlite), rm);
        assert_eq!(
            line(".sh rm \"a b\"", Dialect::Sqlite),
            vec![Program::Line("rm \"a b\"".to_string())]
        );
        assert_eq!(line("system rm -rf x", Dialect::MySql), rm);
        assert_eq!(line("\\P rm -rf x", Dialect::MySql), rm);
        assert_eq!(line("!! rm -rf x", Dialect::SqlServer), rm);
        assert_eq!(line("SELECT 1\n  :!! rm -rf x", Dialect::SqlServer), rm);
        assert!(line("SELECT 1 !! rm -rf x", Dialect::SqlServer).is_empty());
        assert_eq!(line("SELECT edit('x', 'rm -rf x')", Dialect::Sqlite), rm);
        let files = |text: &str, dialect: Dialect| -> Vec<String> {
            sql(text, dialect, false)
                .acts
                .writes
                .into_iter()
                .map(|written| written.name)
                .collect()
        };
        for (text, dialect) in [
            ("\\o f", Dialect::Postgres),
            ("SELECT 1 \\g (format=csv) f", Dialect::Postgres),
            ("\\copy (SELECT 1) to 'f' csv", Dialect::Postgres),
            ("\\lo_export 1 f", Dialect::Postgres),
            ("COPY t TO 'f'", Dialect::Postgres),
            (".once --bom f", Dialect::Sqlite),
            (".bac main f", Dialect::Sqlite),
            ("VACUUM INTO 'f'", Dialect::Sqlite),
            ("EXPORT DATABASE x TO 'f'", Dialect::DuckDb),
            ("tee f;", Dialect::MySql),
            ("\\T f", Dialect::MySql),
            ("SELECT 1 INTO OUTFILE 'f'", Dialect::MySql),
            (":OUT f", Dialect::SqlServer),
        ] {
            assert_eq!(files(text, dialect), ["f"], "{text}");
        }
        for (text, dialect) in [
            ("\\copy t from 'f'", Dialect::Postgres),
            ("\\copy t to stdout", Dialect::Postgres),
            ("COPY t TO STDOUT", Dialect::Postgres),
            (".b f", Dialect::Sqlite),
            ("SELECT 'tee f'", Dialect::MySql),
            (":out stderr", Dialect::SqlServer),
        ] {
            assert!(files(text, dialect).is_empty(), "{text}");
        }
        for text in ["\\c prod", ".dump", ".read seed.sql", "COPY t FROM 'f.csv'"] {
            assert!(!sql(text, client(text), false).program, "{text}");
        }
        assert!(sql("ATTACH 'x.db' AS o", Dialect::Sqlite, false).moves);
        assert!(sql(".open other.db", Dialect::Sqlite, false).moves);
    }

    #[test]
    fn a_client_command_ends_at_its_line() {
        assert!(destroys("\\c prod\nDROP TABLE t;"));
        assert!(!destroys("\\c prod\nSELECT 1;"));
        assert!(sql(".mode csv\nDROP TABLE t", Dialect::Sqlite, false).destroys);
    }

    #[test]
    fn mongo_scripts() {
        for text in [
            "db.dropDatabase()",
            "db.users.drop()",
            "db.getCollection('users').drop()",
            "db.users.deleteMany({})",
            "db.users.deleteMany({ })",
            "db.users.deleteMany()",
            "db.users.remove({})",
            "db.users.remove({}, true)",
            "db.runCommand({dropDatabase: 1})",
            "db.runCommand({drop: 'users'})",
            "use('x'); db.dropDatabase();",
            "db.users.deleteMany(f)",
            "db.dropAllUsers()",
            "db.users.bulkWrite([{deleteMany: {filter: {}}}])",
            "db.runCommand({delete: 'users', deletes: [{q: {}, limit: 0}]})",
            "db.runCommand({delete: 'users', deletes: [{q: {a: 1}}, {q: {}}]})",
            "db.runCommand({delete: 'users'})",
            "db.runCommand({delete: 'users', deletes: [{q: {}, limit: 1, limit: 0}]})",
            "db.runCommand({delete: 'users', deletes: [{q: {a: 1}, ...o}]})",
            "db.users.bulkWrite([{deleteMany: {filter: {a: 1}, filter: {}}}])",
            "db.getMongo().bulkWrite([{namespace: 'a.b', name: 'deleteMany', filter: {}}])",
            "db['dropAllUsers']()",
            "db.users['deleteMany']({})",
        ] {
            assert!(mongo(text, false).destroys, "{text}");
        }
        for text in [
            "db.users.find()",
            "db.users.deleteMany({a: 1})",
            "db.users.deleteOne({})",
            "db.users.remove({a: 1})",
            "// db.dropDatabase()\ndb.users.find()",
            "print('db.dropDatabase()')",
            "db.users.bulkWrite([{deleteMany: {hint: {a: 1}, filter: {a: 1}}}])",
            "db.runCommand({delete: 'users', deletes: [{q: {}, limit: 1}, {q: {a: 1}}]})",
            "db.users.find({delete: false})",
            "db.users.insertOne({deleteMany: 1})",
            "db.getMongo().bulkWrite([{namespace: 'a.b', name: 'deleteMany', filter: {a: 1}}])",
            "db.users['deleteMany']({a: 1})",
        ] {
            let reading = mongo(text, false);
            assert!(!reading.destroys && !reading.unreadable, "{text}");
        }
        assert!(mongo("$JS", true).unreadable);
        assert!(mongo("db.a.find('", false).unreadable);
        assert!(!mongo("db.users.deleteMany({a: $a})", true).destroys);
    }

    #[test]
    fn redis_commands() {
        assert!(redis(&["FLUSHALL"]).destroys);
        assert!(redis(&["flushdb", "async"]).destroys);
        assert!(redis(&["eval", "redis.call('FLUSHALL')", "0"]).destroys);
        assert!(!redis(&["get", "k"]).destroys);
        assert!(!redis(&["del", "k"]).destroys);
        assert!(redis(&["FUNCTION", "FLUSH"]).destroys);
        assert!(redis(&["shutdown", "now", "nosave"]).destroys);
        assert!(!redis(&["SHUTDOWN", "SAVE"]).destroys);
        assert!(!redis(&["FUNCTION", "LIST"]).destroys);
        assert!(redis_lines("SET a 1\nFLUSHDB\n", false).destroys);
        assert!(!redis_lines("SET a \"FLUSHALL\"\n", false).destroys);
        assert!(redis_lines("$CMD", true).unreadable);
    }
}
