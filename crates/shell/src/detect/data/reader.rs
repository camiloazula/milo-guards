//! A small keyword reader over the text of a database statement: SQL, a
//! `MongoDB` script and Redis commands. It skips comments and string
//! literals and splits SQL on `;`. There is no grammar: it finds the few
//! words that destroy data and says what it could not read.

/// How a SQL client reads quotes and comments, where the dialects differ in
/// ways that would hide or show a statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Dialect {
    /// `PostgreSQL`, `SQLite`, `DuckDB`, SQL Server: `--` comments, `''`
    /// strings, `$$` strings, no backslash escapes outside `E'…'`.
    Standard,
    /// `MySQL`, `MariaDB`, `ClickHouse`: `#` comments, backslash escapes in
    /// strings, `/*! … */` comments that run.
    MySql,
    /// Cassandra's CQL: `//` comments.
    Cql,
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    /// A bare word or number, in upper case.
    Word(String),
    /// A quoted string or identifier.
    Quoted,
    /// A `$$` string, with what is inside it.
    Dollar(String),
    /// An expansion of the shell, in text that came from a double-quoted
    /// word: its value is only known when it runs.
    Hole,
    /// A client command that runs to the end of its line (`\c db`, `.dump`).
    Meta(String),
    Symbol(char),
}

/// Words that, before `DELETE` or `UPDATE`, show it is not a statement but
/// part of one: `ON DELETE CASCADE`, `DO UPDATE SET`, `FOR UPDATE`,
/// `AFTER UPDATE`, `GRANT UPDATE`, `WHEN MATCHED THEN DELETE`.
const NOT_A_VERB_AFTER: [&str; 12] = [
    "ON", "DO", "KEY", "FOR", "OR", "AFTER", "BEFORE", "OF", "GRANT", "REVOKE", "DENY", "THEN",
];

/// Words that end the part of a statement that can hold its `WHERE`: the
/// next statement of a batch with no `;` between.
const STARTS_A_STATEMENT: [&str; 7] = [
    "DELETE", "UPDATE", "INSERT", "DROP", "TRUNCATE", "ALTER", "CREATE",
];

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

/// Cut `text` into tokens. `None` when a string, a comment or a `$$` string
/// is never closed: the rest of the text could be anything. `holes` says the
/// text came from a double-quoted shell word, where `$x` and `` `x` `` are
/// the shell's expansions.
fn tokenize(text: &str, dialect: Dialect, holes: bool) -> Option<Vec<Token>> {
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
                && (dialect != Dialect::MySql
                    || chars
                        .get(at + 2)
                        .is_none_or(|c| c.is_whitespace() || c.is_control())) =>
            {
                at = line(&chars, at).1;
            }
            '#' if dialect == Dialect::MySql => at = line(&chars, at).1,
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
                    let rest = chars.get(at + 2..)?;
                    let end = rest.windows(2).position(|pair| pair == ['*', '/'])?;
                    at += 2 + end + 2;
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
            '\'' | '"' | '`' => {
                let escaped = chars
                    .get(..at)
                    .and_then(|before| before.last())
                    .is_some_and(|before| matches!(before, 'e' | 'E'))
                    && c == '\''
                    && at
                        .checked_sub(2)
                        .and_then(|i| chars.get(i))
                        .is_none_or(|c| !is_word_char(*c));
                let escapes = escaped || (dialect == Dialect::MySql && c != '`');
                at = quoted(&chars, at, escapes)?;
                tokens.push(Token::Quoted);
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
            '$' => {
                if holes {
                    if let Some(end) = hole_end(&chars, at) {
                        at = end;
                        tokens.push(Token::Hole);
                        continue;
                    }
                }
                // `$tag$ … $tag$`
                let mut tag_end = at + 1;
                while chars.get(tag_end).is_some_and(|c| is_word_char(*c)) {
                    tag_end += 1;
                }
                let tag: String = chars.get(at..=tag_end).unwrap_or_default().iter().collect();
                let named = chars.get(at + 1).is_none_or(|c| !c.is_ascii_digit());
                if chars.get(tag_end) == Some(&'$') && named {
                    let body = chars.get(tag_end + 1..)?;
                    let tag_chars: Vec<char> = tag.chars().collect();
                    let end = body
                        .windows(tag_chars.len())
                        .position(|window| window == tag_chars.as_slice())?;
                    tokens.push(Token::Dollar(body.get(..end)?.iter().collect()));
                    at = tag_end + 1 + end + tag_chars.len();
                } else {
                    at += 1;
                    tokens.push(Token::Symbol('$'));
                }
            }
            '\\' if starts_statement => {
                let (meta, end) = line(&chars, at);
                tokens.push(Token::Meta(meta));
                at = end;
            }
            '.' if starts_statement && next.is_some_and(char::is_alphabetic) => {
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
                    "ORDER" | "LIMIT" | "RETURNING" | "OUTPUT" | "DELETE" | "UPDATE" | "INSERT"
                ))
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

/// What one statement of SQL does.
fn statement(tokens: &[Token]) -> Reading {
    let mut reading = Reading::default();
    let Some(first) = tokens.first() else {
        return reading;
    };
    if *first == Token::Hole {
        return Reading::UNREADABLE;
    }
    for (at, token) in tokens.iter().enumerate() {
        let Token::Word(word) = token else { continue };
        let before = at.checked_sub(1).and_then(|i| tokens.get(i));
        match word.as_str() {
            "DROP" => reading.destroys = true,
            "TRUNCATE" if tokens.get(at + 1) != Some(&Token::Symbol('(')) => {
                reading.destroys = true;
            }
            "DELETE" | "UPDATE" => {
                let part = matches!(before, Some(Token::Symbol(',')))
                    || matches!(before, Some(Token::Word(w)) if NOT_A_VERB_AFTER.contains(&w.as_str()));
                if !part && !has_where(tokens, at) {
                    reading.destroys = true;
                }
            }
            "ATTACH" if at == 0 => reading.moves = true,
            "XP_CMDSHELL" => reading.program = true,
            "PROGRAM" if is_word(tokens.first(), "COPY") => reading.program = true,
            "SYSTEM" if at == 0 => reading.program = true,
            _ => {}
        }
    }
    // `DO $$ … $$` runs the statements in the string.
    if is_word(Some(first), "DO") {
        for token in tokens {
            if let Token::Dollar(body) = token {
                reading.merge(sql(body, Dialect::Standard, false));
            }
        }
    }
    reading
}

/// What a client command (`\c db`, `\! ls`, `.shell ls`) does.
fn meta(text: &str) -> Reading {
    let lower = text.to_ascii_lowercase();
    let mut words = lower.split_whitespace();
    let name = words.next().unwrap_or_default();
    let rest: Vec<&str> = words.collect();
    let mut reading = Reading::default();
    if name.starts_with("\\!") || matches!(name, ".shell" | ".system") {
        reading.program = true;
    }
    // `.read |cmd` and `.output |cmd` run a command.
    if matches!(name, ".read" | ".output" | ".once" | ".import")
        && rest
            .iter()
            .any(|word| word.trim_start_matches(['\'', '"']).starts_with('|'))
    {
        reading.program = true;
    }
    if name.starts_with("\\copy") && rest.contains(&"program") {
        reading.program = true;
    }
    if matches!(name, ".open" | ".attach") {
        reading.moves = true;
    }
    reading
}

/// What the SQL in `text` does. `holes` says `text` came from a
/// double-quoted shell word, whose expansions are only known when it runs.
pub(super) fn sql(text: &str, dialect: Dialect, holes: bool) -> Reading {
    let Some(tokens) = tokenize(text, dialect, holes) else {
        return Reading::UNREADABLE;
    };
    let mut reading = Reading::default();
    let mut start = 0;
    for at in 0..=tokens.len() {
        let token = tokens.get(at);
        match token {
            None | Some(Token::Symbol(';')) => {
                reading.merge(statement(tokens.get(start..at).unwrap_or_default()));
                start = at + 1;
            }
            Some(Token::Meta(text)) => {
                reading.merge(statement(tokens.get(start..at).unwrap_or_default()));
                reading.merge(meta(text));
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

/// What one Redis command, as its words, does: empties a database. A script
/// (`EVAL`) that calls such a command does too.
pub(super) fn redis(words: &[&str]) -> Reading {
    let Some(command) = words.first() else {
        return Reading::default();
    };
    let lower = command.to_ascii_lowercase();
    let destroys = match lower.as_str() {
        "flushall" | "flushdb" => true,
        "eval" | "evalsha" | "eval_ro" | "fcall" | "fcall_ro" => words.iter().any(|word| {
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
        sql(text, Dialect::Standard, false).destroys
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
            let reading = sql(text, Dialect::Standard, false);
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
                Dialect::Standard
            };
            assert!(sql(text, dialect, false).unreadable, "{text}");
        }
    }

    #[test]
    fn a_shell_expansion_is_a_hole() {
        let read = |text| sql(text, Dialect::Standard, true);
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
        assert!(!sql("SELECT $1", Dialect::Standard, false).unreadable);
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
            assert!(sql(text, Dialect::Standard, false).program, "{text}");
        }
        assert!(sql("system ls", Dialect::Standard, false).program);
        for text in ["\\c prod", ".dump", ".read seed.sql", "COPY t FROM 'f.csv'"] {
            assert!(!sql(text, Dialect::Standard, false).program, "{text}");
        }
        assert!(sql("ATTACH 'x.db' AS o", Dialect::Standard, false).moves);
        assert!(sql(".open other.db", Dialect::Standard, false).moves);
    }

    #[test]
    fn a_client_command_ends_at_its_line() {
        assert!(destroys("\\c prod\nDROP TABLE t;"));
        assert!(!destroys("\\c prod\nSELECT 1;"));
        assert!(destroys(".mode csv\nDROP TABLE t"));
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
