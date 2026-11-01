//! A small keyword reader over the text of a database statement: SQL, a
//! `MongoDB` script and Redis commands. It skips comments and string
//! literals and splits SQL on `;`. There is no grammar: it finds the few
//! words that destroy data and says what it could not read.

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

/// What a read of some statement text found.
#[allow(
    clippy::struct_excessive_bools,
    reason = "four independent findings, each read on its own"
)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct Reading {
    /// It drops, truncates or empties something.
    pub(super) destroys: bool,
    /// Part of it is only known when it runs, or cannot be read.
    pub(super) unreadable: bool,
    /// It runs a program of the machine (`\!`, `COPY … PROGRAM`, `.shell`).
    pub(super) program: bool,
    /// It opens or attaches another database (`ATTACH`, `.open`), so the
    /// file the client was given is not the only one it can change.
    pub(super) moves: bool,
}

impl Reading {
    pub(super) const UNREADABLE: Self = Self {
        destroys: false,
        unreadable: true,
        program: false,
        moves: false,
    };

    pub(super) fn merge(&mut self, other: Self) {
        self.destroys |= other.destroys;
        self.unreadable |= other.unreadable;
        self.program |= other.program;
        self.moves |= other.moves;
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

/// Cut `text` into tokens. `None` when a string, a comment or a `$$` string
/// is never closed: the rest of the text could be anything. `holes` says the
/// text came from a double-quoted shell word, where `$x` and `` `x` `` are
/// the shell's expansions.
fn tokenize(text: &str, dialect: Dialect, holes: bool, backslash: Backslash) -> Option<Vec<Token>> {
    let chars: Vec<char> = text.chars().collect();
    let mut tokens: Vec<Token> = Vec::new();
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
            '\\' if dialect == Dialect::MySql && next == Some('!') => {
                let (meta, end) = line(&chars, at);
                tokens.push(Token::Meta(meta));
                at = end;
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
                let mut end = at;
                while chars
                    .get(end)
                    .is_some_and(|c| is_word_char(*c) || *c == '$')
                {
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
    (running == 0).then_some(tokens)
}

fn is_word(token: Option<&Token>, word: &str) -> bool {
    matches!(token, Some(Token::Word(w)) if w == word)
}

/// Whether the statement `tokens`, whose `DELETE` or `UPDATE` is at `verb`,
/// has a `WHERE` that picks rows. A `WHERE` that picks all of them (`WHERE
/// 1`, `WHERE TRUE`, `WHERE 1 = 1`) does not.
fn has_where(tokens: &[Token], verb: usize) -> bool {
    let mut depth = 0usize;
    for (at, token) in tokens.iter().enumerate().skip(verb + 1) {
        match token {
            Token::Symbol('(') => depth += 1,
            Token::Symbol(')') => {
                if depth == 0 {
                    return false;
                }
                depth -= 1;
            }
            Token::Word(word) if depth == 0 => {
                if word == "WHERE" {
                    return !picks_all(tokens.get(at + 1..).unwrap_or_default());
                }
                if STARTS_A_STATEMENT.contains(&word.as_str()) {
                    return false;
                }
            }
            _ => {}
        }
    }
    false
}

/// Whether the condition that starts `tokens` is one that is true for every
/// row.
fn picks_all(tokens: &[Token]) -> bool {
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

/// Whether the `THEN` before the verb at `verb` ends a `WHEN [NOT] MATCHED …`
/// clause: only there is `THEN DELETE` or `THEN UPDATE` part of a `MERGE`,
/// which picks its rows with its `ON`.
fn in_matched_clause(tokens: &[Token], verb: usize) -> bool {
    let Some(when) = tokens.get(..verb).and_then(|before| {
        before
            .iter()
            .rposition(|token| is_word(Some(token), "WHEN"))
    }) else {
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
        Token::Word(word) => literal_args(tokens, at + 1, runs_text(word)?),
        Token::Quoted(quote) if !quote.string => {
            literal_args(tokens, at + 1, runs_text(&quote.body.to_uppercase())?)
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
    for (at, token) in tokens.iter().enumerate() {
        if let Some(found) = dynamic_sql(tokens, at, scope) {
            reading.merge(found);
        }
        let Token::Word(word) = token else { continue };
        let before = at.checked_sub(1).and_then(|i| tokens.get(i));
        match word.as_str() {
            "DROP" if !drops_no_data(tokens, at, scope.dialect) => reading.destroys = true,
            "TRUNCATE" if tokens.get(at + 1) != Some(&Token::Symbol('(')) => {
                reading.destroys = true;
            }
            "DELETE" | "UPDATE" => {
                let part = matches!(before, Some(Token::Symbol(',')))
                    || matches!(before, Some(Token::Word(w)) if NOT_A_VERB_AFTER.contains(&w.as_str()))
                    || is_clause(tokens, at)
                    || (merge && is_word(before, "THEN") && in_matched_clause(tokens, at));
                if !part && !has_where(tokens, at) {
                    reading.destroys = true;
                }
            }
            "ATTACH" if at == 0 => reading.moves = true,
            "XP_CMDSHELL" => reading.program = true,
            "PROGRAM" if is_word(tokens.first(), "COPY") => reading.program = true,
            "SYSTEM" if at == 0 && scope.dialect == Dialect::MySql => reading.program = true,
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

/// What a client command (`\c db`, `\! ls`, `.shell ls`, `\gexec`) does.
/// `holes` says the text came from a double-quoted shell word.
fn meta(text: &str, holes: bool) -> Reading {
    let (name, rest) = meta_name(text);
    let (words, backtick) = meta_words(rest);
    let mut reading = Reading::default();
    // A command that writes to a file or, after a `|`, to a program.
    let pipes = words.iter().any(|word| word.starts_with('|'));
    let writes = matches!(
        name.as_str(),
        "\\o" | "\\g" | "\\gx" | "\\w" | ".read" | ".output" | ".once" | ".import"
    );
    reading.program = match name.as_str() {
        "\\!" | ".shell" | ".system" => true,
        "\\copy" => words
            .iter()
            .any(|word| word.eq_ignore_ascii_case("program")),
        _ => writes && pipes,
    };
    // A backtick in a `psql` command runs a program.
    reading.program |= backtick && name.starts_with('\\');
    // What the result of a query runs, or sets for later, is not on the line.
    if matches!(name.as_str(), "\\gexec" | "\\gset") {
        reading.unreadable = true;
    }
    // A target that only the shell knows may be `|program`.
    if writes && holes && words.iter().any(|word| word.starts_with(['$', '`', '%'])) {
        reading.unreadable = true;
    }
    if matches!(name.as_str(), ".open" | ".attach") {
        reading.moves = true;
    }
    // `.restore` replaces the whole database with a file.
    if name == ".restore" {
        reading.destroys = true;
    }
    reading
}

/// What the SQL in `text` does. `holes` says `text` came from a
/// double-quoted shell word, whose expansions are only known when it runs.
/// Where the server decides how a backslash in a string reads, it is read
/// with each rule, and what any of them shows counts; a reading whose strings
/// do not close is not one the text can have, and is left out.
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
        if let Some(other) = try_read_sql(text, Scope { backslash, ..scope }) {
            reading.merge(other);
        }
    }
    reading
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
    Some(reading)
}

/// What the `MongoDB` shell script in `text` does: drops a database or a
/// collection, or deletes every document of one.
pub(super) fn mongo(text: &str, holes: bool) -> Reading {
    #[derive(PartialEq)]
    enum Js {
        Name(String),
        Quoted,
        Hole,
        Symbol(char),
    }
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
                at += 1;
                loop {
                    match chars.get(at) {
                        None => return Reading::UNREADABLE,
                        Some('\\') => at += 2,
                        Some(c) if *c == quote => {
                            at += 1;
                            break;
                        }
                        Some(_) => at += 1,
                    }
                }
                tokens.push(Js::Quoted);
            }
            '$' | '%' if holes && hole_end(&chars, at).is_some() => {
                at = hole_end(&chars, at).unwrap_or(at + 1);
                tokens.push(Js::Hole);
            }
            c if c.is_alphanumeric() || c == '_' || c == '$' => {
                let mut end = at;
                while chars
                    .get(end)
                    .is_some_and(|c| c.is_alphanumeric() || *c == '_' || *c == '$')
                {
                    end += 1;
                }
                tokens.push(Js::Name(
                    chars.get(at..end).unwrap_or_default().iter().collect(),
                ));
                at = end;
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
    let mut reading = Reading::default();
    for (at, token) in tokens.iter().enumerate() {
        let Js::Name(name) = token else { continue };
        let after = tokens.get(at + 1);
        let called = after == Some(&Js::Symbol('('));
        let key = after == Some(&Js::Symbol(':'));
        match name.as_str() {
            "dropDatabase" | "dropCollection" | "drop" if called || key => {
                reading.destroys = true;
            }
            "deleteMany" | "remove" if called => {
                // No filter, or an empty one.
                let empty = tokens.get(at + 2) == Some(&Js::Symbol(')'))
                    || (tokens.get(at + 2) == Some(&Js::Symbol('{'))
                        && tokens.get(at + 3) == Some(&Js::Symbol('}')));
                reading.destroys |= empty;
            }
            _ => {}
        }
    }
    reading
}

/// Whether the Redis command `command` runs a script: its second word is the
/// script, a digest of one, or the name of a function.
pub(super) fn runs_script(command: &str) -> bool {
    matches!(
        command.to_ascii_lowercase().as_str(),
        "eval" | "evalsha" | "eval_ro" | "evalsha_ro" | "fcall" | "fcall_ro"
    )
}

/// What one Redis command, as its words, does: empties a database. A script
/// (`EVAL`) that calls such a command does too.
pub(super) fn redis(words: &[&str]) -> Reading {
    let Some(command) = words.first() else {
        return Reading::default();
    };
    let destroys = match command.to_ascii_lowercase().as_str() {
        "flushall" | "flushdb" => true,
        _ if runs_script(command) => words.iter().any(|word| {
            let word = word.to_ascii_lowercase();
            word.contains("flushall") || word.contains("flushdb")
        }),
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
            "CREATE FUNCTION f() RETURNS int AS $$ BEGIN DELETE FROM t; END $$ LANGUAGE plpgsql",
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
        assert!(!mysql("SELECT 'a\\'; DROP TABLE t; --'").destroys);
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
            "\\! rm -rf x",
            "COPY t FROM PROGRAM 'rm -rf x'",
            "\\copy t from program 'x'",
            ".shell rm -rf x",
            ".system ls",
            ".read |ls",
            "EXEC xp_cmdshell 'dir'",
        ] {
            assert!(sql(text, client(text), false).program, "{text}");
        }
        assert!(sql("system ls", Dialect::MySql, false).program);
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
        assert!(redis_lines("SET a 1\nFLUSHDB\n", false).destroys);
        assert!(!redis_lines("SET a \"FLUSHALL\"\n", false).destroys);
        assert!(redis_lines("$CMD", true).unreadable);
    }
}
