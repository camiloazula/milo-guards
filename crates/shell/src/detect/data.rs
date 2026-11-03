//! The rule about data in a database: a statement a database client is
//! given that drops, truncates or empties something.
//!
//! The statement is where the client takes it: an option (`psql -c`,
//! `mysql -e`), an operand (`sqlite3 file 'stmt'`, `redis-cli FLUSHALL`), or
//! text on the line that is fed to it (a here-document, a here-string, an
//! `echo` piped in, through a `cat` or a `tee`). Statements the line does not
//! show (a file, `psql -f`, `< seed.sql`, a stage the rule does not read) may
//! drop anything, and are risky. A client in a container or on another
//! machine (`docker exec`, `kubectl exec`, `ssh`) is read as the client.

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use super::{resources, Checker};
use crate::path::Access;
use crate::unit::{Arg, Unit};
use crate::{Rule, Shell};

mod reader;

use reader::{Dialect, Reading};

/// How a client takes its statements on the command line.
struct Client {
    /// Short options that take a value (`-h host`, `-uroot`).
    short_values: &'static str,
    /// Short options whose value is a statement.
    short_statement: &'static str,
    /// Short options that take a value only when it is attached (`-p`).
    short_optional: &'static str,
    /// Long options that take a value.
    long_values: &'static [&'static str],
    /// Long options that take none. With `long_values` they are every long
    /// option the client has: a name that is the start of only one of them
    /// is that option.
    long_flags: &'static [&'static str],
    /// Long options whose value is a statement.
    long_statement: &'static [&'static str],
    /// Short options whose statement the client runs and then exits,
    /// without reading its input (`psql -c`).
    short_exits: &'static str,
    /// Long options whose statement the client runs and then exits.
    long_exits: &'static [&'static str],
    /// Short options whose value is a file of statements (`psql -f`).
    short_file: &'static str,
    /// Long options whose value is a file of statements (`--file`).
    long_file: &'static [&'static str],
    /// What a word that is no option and no option's value is.
    operands: Operands,
    /// The options whose value is never a word that starts with `-`: without
    /// a value they stand alone, as `mongosh -p` does (it prompts for the
    /// password), and the word is an option of its own.
    loose: Loose,
    /// Whether short options bundle (`-Atc`), or each is a word (`-Q`).
    bundles: bool,
    /// Whether a short option may also start with `/` (Windows `sqlcmd`).
    slash: bool,
    /// What the statement is written in.
    language: Language,
}

/// What a client makes of a word that is no option and no option's value.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Operands {
    /// Nothing it runs: a database, a user.
    Other,
    /// One that ends in `.js` is a script it runs (`mongosh db drop.js`).
    Scripts,
    /// Each is a statement (`clickhouse-client 'SELECT 1'`, and after `-n`,
    /// which takes no value).
    Statements,
}

/// Which options of a client take no value from a word that starts with `-`.
#[derive(Clone, Copy)]
enum Loose {
    /// None: the next word is the value, whatever it starts with.
    No,
    /// Every option that takes a value: `mongosh` parses with yargs, which
    /// never reads a word that starts with `-` as a value.
    Every,
    /// These long options: `clickhouse-client --password`, whose value is
    /// optional.
    Only(&'static [&'static str]),
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Language {
    Sql(Dialect),
    Mongo,
    /// `redis-cli`'s commands, one on each line.
    Redis,
}

const PSQL: Client = Client {
    short_values: "cdfFhLopPRTUv",
    short_statement: "c",
    short_optional: "",
    long_values: &[
        "command",
        "dbname",
        "file",
        "field-separator",
        "host",
        "log-file",
        "output",
        "port",
        "pset",
        "record-separator",
        "table-attr",
        "username",
        "set",
        "variable",
    ],
    long_flags: &[
        "echo-all",
        "no-align",
        "echo-queries",
        "echo-errors",
        "echo-hidden",
        "html",
        "list",
        "no-readline",
        "single-transaction",
        "quiet",
        "single-step",
        "single-line",
        "tuples-only",
        "version",
        "no-password",
        "password",
        "expanded",
        "no-psqlrc",
        "help",
        "csv",
        "field-separator-zero",
        "record-separator-zero",
    ],
    long_statement: &["command"],
    short_exits: "c",
    long_exits: &["command"],
    short_file: "f",
    long_file: &["file"],
    loose: Loose::No,
    bundles: true,
    slash: false,
    operands: Operands::Other,
    language: Language::Sql(Dialect::Postgres),
};

const MYSQL: Client = Client {
    short_values: "ehPuDSO",
    short_statement: "e",
    short_optional: "p",
    long_values: &[
        "execute",
        "init-command",
        "host",
        "user",
        "port",
        "database",
        "socket",
        "protocol",
        "defaults-file",
        "defaults-extra-file",
        "defaults-group-suffix",
        "default-character-set",
        "character-sets-dir",
        "prompt",
        "delimiter",
        "ssl-ca",
        "ssl-cert",
        "ssl-key",
        "plugin-dir",
        "login-path",
    ],
    long_flags: &[
        "auto-rehash",
        "no-auto-rehash",
        "auto-vertical-output",
        "batch",
        "binary-as-hex",
        "binary-mode",
        "column-names",
        "skip-column-names",
        "column-type-info",
        "comments",
        "skip-comments",
        "compress",
        "connect-expired-password",
        "debug-check",
        "debug-info",
        "enable-cleartext-plugin",
        "force",
        "help",
        "html",
        "ignore-spaces",
        "line-numbers",
        "skip-line-numbers",
        "named-commands",
        "no-beep",
        "no-defaults",
        "one-database",
        "pipe",
        "print-defaults",
        "quick",
        "raw",
        "reconnect",
        "safe-updates",
        "i-am-a-dummy",
        "show-warnings",
        "sigint-ignore",
        "silent",
        "ssl",
        "tee",
        "unbuffered",
        "verbose",
        "version",
        "vertical",
        "wait",
        "xml",
    ],
    long_statement: &["execute", "init-command"],
    short_exits: "e",
    long_exits: &["execute"],
    short_file: "",
    long_file: &[],
    loose: Loose::No,
    bundles: true,
    slash: false,
    operands: Operands::Other,
    language: Language::Sql(Dialect::MySql),
};

const CLICKHOUSE: Client = Client {
    short_values: "hudqfC",
    short_statement: "q",
    short_optional: "",
    long_values: &[
        "query",
        "host",
        "port",
        "user",
        "password",
        "database",
        "format",
        "queries-file",
        "config-file",
        "query_id",
        "secure-port",
    ],
    long_flags: &[
        "help",
        "version",
        "verbose",
        "multiline",
        "multiquery",
        "time",
        "stacktrace",
        "progress",
        "echo",
        "secure",
        "vertical",
        "ask-password",
        "no-warnings",
        "disable_suggestion",
        "highlight",
    ],
    long_statement: &["query"],
    short_exits: "q",
    long_exits: &["query"],
    short_file: "",
    long_file: &["queries-file"],
    loose: Loose::Only(&["password"]),
    bundles: true,
    slash: false,
    operands: Operands::Statements,
    language: Language::Sql(Dialect::ClickHouse),
};

const SQLCMD: Client = Client {
    short_values: "SUPdiohHwvstlazZVmyYfc",
    short_statement: "Qq",
    short_optional: "",
    long_values: &[
        "query",
        "initial-query",
        "server",
        "user-name",
        "password",
        "input-file",
    ],
    long_flags: &["help", "version", "trust-server-certificate"],
    long_statement: &["query", "initial-query"],
    short_exits: "Q",
    long_exits: &["query"],
    short_file: "i",
    long_file: &["input-file"],
    loose: Loose::No,
    bundles: false,
    slash: true,
    operands: Operands::Other,
    language: Language::Sql(Dialect::SqlServer),
};

const CQLSH: Client = Client {
    short_values: "uepkfb",
    short_statement: "e",
    short_optional: "",
    long_values: &[
        "execute",
        "file",
        "username",
        "password",
        "keyspace",
        "cqlversion",
        "encoding",
        "connect-timeout",
        "request-timeout",
        "cqlshrc",
        "protocol-version",
        "browser",
    ],
    long_flags: &[
        "help",
        "version",
        "color",
        "no-color",
        "debug",
        "ssl",
        "no-file-io",
        "tty",
        "secure-connect-bundle",
    ],
    long_statement: &["execute"],
    short_exits: "e",
    long_exits: &["execute"],
    short_file: "f",
    long_file: &["file"],
    loose: Loose::No,
    bundles: true,
    slash: false,
    operands: Operands::Other,
    language: Language::Sql(Dialect::Cql),
};

const MONGO: Client = Client {
    short_values: "upfh",
    short_statement: "",
    short_optional: "",
    long_values: &[
        "eval",
        "host",
        "port",
        "username",
        "password",
        "authenticationDatabase",
        "authenticationMechanism",
        "file",
        "apiVersion",
        "tlsCAFile",
        "tlsCertificateKeyFile",
        "tlsCertificateKeyFilePassword",
        "gssapiServiceName",
        "gssapiHostName",
        "sslCAFile",
        "sslPEMKeyFile",
        "sslPEMKeyPassword",
        "setName",
    ],
    long_flags: &[
        "shell",
        "nodb",
        "norc",
        "ipv6",
        "quiet",
        "json",
        "verbose",
        "help",
        "version",
        "tls",
        "tlsAllowInvalidCertificates",
        "tlsAllowInvalidHostnames",
        "tlsUseSystemCA",
        "ssl",
        "apiStrict",
        "apiDeprecationErrors",
        "retryWrites",
        "redactInfo",
    ],
    long_statement: &["eval"],
    short_exits: "",
    long_exits: &[],
    short_file: "f",
    long_file: &["file"],
    loose: Loose::Every,
    bundles: true,
    slash: false,
    operands: Operands::Scripts,
    language: Language::Mongo,
};

/// The text of a statement, and whether it has expansions in it: what is known
/// of a value, not the source of one that is only known when it runs. A
/// template with an escaped `$` or backtick in it is not known: the reader
/// turns `\$(…)`, `\${…}` and a pair of escaped backticks into one expansion,
/// which would hide the text between them from a client that gets it as it is.
fn statement_text(arg: &Arg) -> Option<(&str, bool)> {
    match arg {
        Arg::Known(text) => Some((text, false)),
        Arg::Template { source, .. } if source.contains("\\$") || source.contains("\\`") => None,
        Arg::Template { text, .. } => Some((text, true)),
        Arg::Unknown(_) | Arg::Input | Arg::Null => None,
    }
}

/// Whether the argument is a word that starts with `-`.
fn starts_with_dash(arg: &Arg) -> bool {
    view(arg).is_some_and(|(text, _)| text.starts_with('-'))
}

/// An argument's text for reading its options.
fn view(arg: &Arg) -> Option<(&str, bool)> {
    match arg {
        Arg::Known(text) => Some((text, false)),
        Arg::Template { text, .. } => Some((text, true)),
        Arg::Unknown(text) => Some((text, true)),
        Arg::Input | Arg::Null => None,
    }
}

/// Whether `text`, the source of a word only known when it runs, is a quoted
/// option (`"-c…"`, `"--execute=…"`, and `"/Q…"` for a client whose options
/// may start with `/`), which the client reads as one whatever it holds.
fn quoted_option(text: &str, slash: bool) -> bool {
    let inner = text
        .strip_prefix("@\"")
        .or_else(|| text.strip_prefix(['"', '\'']))
        .map(|inner| inner.trim_start_matches(['\r', '\n']));
    inner.is_some_and(|inner| inner.starts_with('-') || (slash && inner.starts_with('/')))
}

/// Whether an expansion in `arg` runs a command, as the parse found it.
fn runs(arg: &Arg) -> bool {
    matches!(arg, Arg::Template { runs: true, .. })
}

/// `text` as the value of an option attached to it, as an argument: a
/// template when it has expansions in it, which run a command when `runs`.
fn attached(rest: &str, holes: bool, runs: bool) -> Arg {
    if holes {
        Arg::Template {
            text: rest.to_string(),
            source: rest.into(),
            runs,
        }
    } else {
        Arg::Known(rest.to_string())
    }
}

/// The value of an option written attached to it (`-cSQL`), from the
/// argument `arg` it is part of, which may only be known when it runs.
fn carry(rest: &str, holes: bool, arg: &Arg) -> Arg {
    if matches!(arg, Arg::Unknown(_)) {
        Arg::Unknown(rest.to_string())
    } else {
        attached(rest, holes, runs(arg))
    }
}

/// What a client's command line gives it to run.
#[derive(Default)]
struct Given {
    /// The statements its options carry.
    statements: Vec<Arg>,
    /// The files of statements it names (`psql -f`, `mongosh x.js`).
    files: Vec<Arg>,
    /// Whether it is given a statement that it runs and then exits, without
    /// reading its input.
    exits: bool,
}

/// What a long option of a client does with what follows it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Long {
    /// Its value is a statement.
    Statement,
    /// Its value is a file of statements.
    File,
    /// It takes a value.
    Value,
    /// It takes a value, but not from a word that starts with `-`.
    Loose,
    /// It takes none, or is not an option of the client.
    Flag,
}

impl Client {
    /// The long option `name` is: the option of that name, or else the only
    /// one that starts with it (`getopt_long` and the clients' own parsers
    /// read any unique abbreviation: `psql --co` is `--command`, `--c` is
    /// ambiguous with `--csv` and runs nothing), with `_` read as `-` where
    /// no option has the name as it is written.
    fn resolve(&self, name: &str) -> Option<&'static str> {
        // `mysql --init_command` is `--init-command`.
        self.resolve_spelled(name).or_else(|| {
            name.contains('_')
                .then(|| self.resolve_spelled(&name.replace('_', "-")))
                .flatten()
        })
    }

    fn resolve_spelled(&self, name: &str) -> Option<&'static str> {
        let all = || self.long_values.iter().chain(self.long_flags).copied();
        if let Some(option) = all().find(|option| *option == name) {
            return Some(option);
        }
        if name.is_empty() {
            return None;
        }
        let mut starts = all().filter(|option| option.starts_with(name));
        match (starts.next(), starts.next()) {
            (Some(option), None) => Some(option),
            _ => None,
        }
    }

    /// What the long option `name` (see [`Self::resolve`]) does.
    fn long_option(&self, name: &str) -> Long {
        let Some(option) = self.resolve(name) else {
            return Long::Flag;
        };
        if self.long_statement.contains(&option) {
            Long::Statement
        } else if self.long_file.contains(&option) {
            Long::File
        } else if self.long_values.contains(&option) {
            match self.loose {
                Loose::Every => Long::Loose,
                Loose::Only(names) if names.contains(&option) => Long::Loose,
                Loose::No | Loose::Only(_) => Long::Value,
            }
        } else {
            Long::Flag
        }
    }

    /// Takes the value of an option from the arguments after it. A loose
    /// option takes none when the next word starts with `-`.
    fn value<'a>(iter: &mut std::slice::Iter<'a, Arg>, loose: bool) -> Option<&'a Arg> {
        if loose && iter.as_slice().first().is_some_and(starts_with_dash) {
            return None;
        }
        iter.next()
    }

    /// Takes the statement an option is given. Where a word that starts with
    /// `-` is no value, it is read as the statement too, and then as the
    /// option it may be: neither reading hides it from the other.
    fn statement_value(&self, iter: &mut std::slice::Iter<'_, Arg>, found: &mut Vec<Arg>) {
        let loose = matches!(self.loose, Loose::Every);
        match Self::value(iter, loose) {
            Some(next) => found.push(next.clone()),
            None => found.extend(iter.as_slice().first().cloned()),
        }
    }

    /// The statements the command line gives, from the options that carry
    /// one, and the files of statements it names.
    fn statements(&self, args: &[Arg]) -> Given {
        let mut given = Given::default();
        let found = &mut given.statements;
        let files = &mut given.files;
        let loose = matches!(self.loose, Loose::Every);
        let mut iter = args.iter();
        let mut ended = false;
        while let Some(arg) = iter.next() {
            let Some((text, holes)) = view(arg) else {
                // What `xargs` hands on is an operand only known when it runs.
                if self.operands == Operands::Statements && matches!(arg, Arg::Input) {
                    found.push(arg.clone());
                }
                continue;
            };
            // A quoted word only known when it runs that is an option (a
            // PowerShell `"--execute=… `$x $t"` that is no template) may
            // carry any statement.
            if matches!(arg, Arg::Unknown(_)) && !ended && quoted_option(text, self.slash) {
                found.push(arg.clone());
                continue;
            }
            // An operand that is a script the client runs.
            let script = |text: &str| {
                let lower = text.to_ascii_lowercase();
                self.operands == Operands::Scripts
                    && [".js", ".mjs", ".cjs"]
                        .iter()
                        .any(|end| lower.ends_with(end))
            };
            if ended || text == "--" {
                if ended && self.operands == Operands::Statements {
                    found.push(arg.clone());
                } else if ended && script(text) {
                    files.push(arg.clone());
                }
                ended = true;
                continue;
            }
            if let Some(name) = text.strip_prefix("--") {
                let (name, value) = match name.split_once('=') {
                    Some((name, value)) => (name, Some(value)),
                    None => (name, None),
                };
                let long = self.long_option(name);
                given.exits |= long == Long::Statement
                    && self
                        .resolve(name)
                        .is_some_and(|option| self.long_exits.contains(&option));
                if let Some(value) = value {
                    match long {
                        Long::Statement => found.push(carry(value, holes, arg)),
                        Long::File => files.push(carry(value, holes, arg)),
                        Long::Value | Long::Loose | Long::Flag => {}
                    }
                } else if long == Long::Statement {
                    self.statement_value(&mut iter, found);
                } else if long == Long::File {
                    files.extend(Self::value(&mut iter, loose).cloned());
                } else if long == Long::Value
                    || (long == Long::Loose && self.operands != Operands::Statements)
                {
                    Self::value(&mut iter, long == Long::Loose);
                }
                // An optional value is left where it is read as an operand
                // too: `clickhouse-client --password 'DROP TABLE t'` may run
                // the statement.
                continue;
            }
            let rest = match text.strip_prefix('-') {
                Some(rest) => rest,
                None if self.slash => match text.strip_prefix('/') {
                    Some(rest) if rest.len() == 1 => rest,
                    _ => {
                        if script(text) {
                            files.push(arg.clone());
                        }
                        continue;
                    }
                },
                None if self.operands == Operands::Statements => {
                    found.push(arg.clone());
                    continue;
                }
                None => {
                    if script(text) {
                        files.push(arg.clone());
                    }
                    continue;
                }
            };
            for (at, letter) in rest.char_indices() {
                let after = rest.get(at + letter.len_utf8()..).unwrap_or_default();
                if self.short_optional.contains(letter) {
                    break;
                }
                if self.short_file.contains(letter) {
                    if after.is_empty() {
                        files.extend(Self::value(&mut iter, loose).cloned());
                    } else {
                        files.push(carry(after, holes, arg));
                    }
                    break;
                }
                if self.short_values.contains(letter) || self.short_statement.contains(letter) {
                    if self.short_statement.contains(letter) {
                        given.exits |= self.short_exits.contains(letter);
                        if after.is_empty() {
                            self.statement_value(&mut iter, found);
                        } else {
                            found.push(carry(after, holes, arg));
                        }
                    } else if after.is_empty() {
                        Self::value(&mut iter, loose);
                    }
                    break;
                }
                if !self.bundles {
                    break;
                }
            }
        }
        given
    }
}

/// What the text `arg`, written in `language`, does.
fn read_text(language: Language, arg: &Arg) -> Reading {
    let Some((text, holes)) = statement_text(arg) else {
        return Reading::UNREADABLE;
    };
    let mut reading = match language {
        Language::Sql(dialect) => reader::sql(text, dialect, holes),
        Language::Mongo => reader::mongo(text, holes),
        Language::Redis => reader::redis_lines(text, holes),
    };
    // A command substitution prints what it likes, a whole statement too,
    // where a variable stands for a value.
    if runs(arg) {
        reading.merge(Reading::UNREADABLE);
    }
    reading
}

/// The files that the `.backup` and `.save` commands in the statement `arg`
/// write.
fn replaced_files(arg: &Arg, dialect: Dialect) -> Vec<String> {
    statement_text(arg)
        .map(|(text, holes)| reader::replaced_files(text, dialect, holes))
        .unwrap_or_default()
}

/// What the file a `SQLite`-style client opens is: the agent's own, or not.
struct Embedded<'a> {
    file: Option<&'a Arg>,
    statements: Vec<Arg>,
    /// The files of statements it runs (`-init`).
    files: Vec<Arg>,
    read_only: bool,
}

/// How a `SQLite`-style client takes its command line.
struct Options {
    /// The options whose value is a statement.
    statement: &'static [&'static str],
    /// The options that take one value.
    values: &'static [&'static str],
    /// The options that take two values.
    pairs: &'static [&'static str],
    /// The options whose value is a file of statements.
    files: &'static [&'static str],
}

/// Every option of `sqlite3 -help` that takes a value. A missing one would
/// move the file onto its value.
const SQLITE: Options = Options {
    statement: &["cmd"],
    values: &[
        "A",
        "alg",
        "escape",
        "heap",
        "hexkey",
        "init",
        "key",
        "maxsize",
        "mmap",
        "newline",
        "nonce",
        "nullvalue",
        "screenwidth",
        "separator",
        "sorterref",
        "textkey",
        "vfs",
    ],
    pairs: &["lookaside", "pagecache", "scratch"],
    files: &["init"],
};

const DUCKDB: Options = Options {
    statement: &["c", "s", "cmd"],
    values: &[
        "f",
        "init",
        "newline",
        "nullvalue",
        "separator",
        "storage-version",
    ],
    pairs: &[],
    files: &["f", "init"],
};

/// `sqlite3 [options] [FILE [STATEMENT…]]` and `duckdb` alike: single-dash
/// words, the first operand a file and the rest statements.
fn embedded<'a>(args: &'a [Arg], options: &Options) -> Embedded<'a> {
    let mut found = Embedded {
        file: None,
        statements: Vec::new(),
        files: Vec::new(),
        read_only: false,
    };
    let mut iter = args.iter();
    let mut options_end = false;
    while let Some(arg) = iter.next() {
        let Some((text, _)) = view(arg) else {
            found.statements.push(arg.clone());
            continue;
        };
        let name = text
            .strip_prefix('-')
            .filter(|name| !name.is_empty() && !options_end);
        match name {
            Some("-") => options_end = true,
            Some(name) => {
                let name = name.trim_start_matches('-');
                if name.eq_ignore_ascii_case("readonly") {
                    found.read_only = true;
                } else if options.statement.contains(&name) {
                    found.statements.extend(iter.next().cloned());
                } else if options.files.contains(&name) {
                    found.files.extend(iter.next().cloned());
                } else if options.values.contains(&name) {
                    iter.next();
                } else if options.pairs.contains(&name) {
                    iter.next();
                    iter.next();
                }
            }
            None if found.file.is_none() => found.file = Some(arg),
            None => found.statements.push(arg.clone()),
        }
    }
    found
}

/// Where a database name points.
enum Database {
    /// A database that lives only in memory.
    Memory,
    /// A file, by this path.
    Path(String),
    /// Something that is not a file of this machine, or that cannot be told.
    Elsewhere,
}

/// Whether `name` starts with a URI scheme (`md:`, `s3://`): a letter, then
/// letters, digits, `+`, `-` or `.`, then `:`, and more than one letter, so
/// that a Windows drive (`C:`) is a path.
fn has_scheme(name: &str) -> bool {
    let Some((scheme, _)) = name.split_once(':') else {
        return false;
    };
    scheme.len() > 1
        && scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// `%HH` escapes of a URI path, decoded; `None` when one is not valid or the
/// path holds a NUL.
fn percent_decoded(path: &str) -> Option<String> {
    let mut bytes = Vec::new();
    let mut chars = path.bytes();
    while let Some(byte) = chars.next() {
        if byte == b'%' {
            let high = char::from(chars.next()?).to_digit(16)?;
            let low = char::from(chars.next()?).to_digit(16)?;
            bytes.push(u8::try_from(high * 16 + low).ok()?);
        } else {
            bytes.push(byte);
        }
    }
    let text = String::from_utf8(bytes).ok()?;
    (!text.contains('\0')).then_some(text)
}

/// The database a name given to `sqlite3` or `duckdb` opens. `sqlite3` reads
/// `file:` names as URIs, and `duckdb` opens `md:` and the like remotely; a
/// name with a scheme is read from its path, or else is not the agent's own.
fn database(name: &str) -> Database {
    if name.is_empty() || name == ":memory:" {
        return Database::Memory;
    }
    if !has_scheme(name) {
        return Database::Path(name.to_string());
    }
    let Some(uri) = name
        .get(..5)
        .filter(|scheme| scheme.eq_ignore_ascii_case("file:"))
        .and_then(|_| name.get(5..))
    else {
        return Database::Elsewhere;
    };
    let uri = uri.split('#').next().unwrap_or(uri);
    let (path, query) = uri.split_once('?').unwrap_or((uri, ""));
    if query.split('&').any(|pair| pair == "mode=memory") {
        return Database::Memory;
    }
    // `file://authority/path`: only no authority, or `localhost`, is this
    // machine.
    let path = match path.strip_prefix("//") {
        Some(rest) => match rest.split_once('/') {
            Some(("" | "localhost", path)) => format!("/{path}"),
            _ => return Database::Elsewhere,
        },
        None => path.to_string(),
    };
    match percent_decoded(&path) {
        Some(path) if path == ":memory:" => Database::Memory,
        Some(path) if !path.is_empty() => Database::Path(path),
        _ => Database::Elsewhere,
    }
}

/// Redis options that take a value.
const REDIS_VALUES: &[&str] = &[
    "-h",
    "-p",
    "-s",
    "-a",
    "-u",
    "-r",
    "-i",
    "-d",
    "-D",
    "-n",
    "-t",
    "--user",
    "--pass",
    "--pattern",
    "--count",
    "--type",
    "--sni",
    "--cacert",
    "--capath",
    "--cert",
    "--key",
    "--tls-ciphers",
    "--tls-ciphersuites",
    "--rdb",
    "--functions-rdb",
    "--pipe-timeout",
    "--eval",
    "--lru-test",
    "--memkeys-samples",
    "--keystats-samples",
    "--cacertdir",
    "--show-pushes",
    "-X",
    "--quoted-pattern",
    "--intrinsic-latency",
];

/// `redis-cli [options] COMMAND [ARGUMENT…]`: the operands. `--cluster call
/// HOST:PORT COMMAND…` runs the command on every node of a cluster.
fn redis_operands(args: &[Arg]) -> Vec<&Arg> {
    let mut operands = Vec::new();
    let mut cluster = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.known() {
            Some(text) if operands.is_empty() && text.starts_with('-') && text.len() > 1 => {
                if REDIS_VALUES.contains(&text) {
                    iter.next();
                } else if text == "--cluster" {
                    cluster = true;
                }
            }
            _ => operands.push(arg),
        }
    }
    if cluster && operands.first().and_then(|arg| arg.known()) == Some("call") {
        operands.drain(..operands.len().min(2));
    }
    operands
}

/// Whether the line asks a tool for its help, and runs nothing else.
fn asks_help(args: &[Arg]) -> bool {
    args.iter()
        .filter_map(Arg::known)
        .any(|text| matches!(text, "--help" | "-h"))
}

/// The parameters of `Invoke-Sqlcmd` (the `SqlServer` module's), with
/// whether each takes a value, and the common parameters: a switch read as
/// taking one would hide the query after it.
const INVOKE_SQLCMD: &[(&str, bool)] = &[
    ("query", true),
    ("inputfile", true),
    ("serverinstance", true),
    ("database", true),
    ("username", true),
    ("password", true),
    ("credential", true),
    ("accesstoken", true),
    ("connectionstring", true),
    ("connectiontimeout", true),
    ("querytimeout", true),
    ("variable", true),
    ("applicationintent", true),
    ("applicationname", true),
    ("encrypt", true),
    ("errorlevel", true),
    ("severitylevel", true),
    ("failoverpartner", true),
    ("hostnameincertificate", true),
    ("maxbinarylength", true),
    ("maxcharlength", true),
    ("newpassword", true),
    ("outputas", true),
    ("as", true),
    ("outputsqlerrors", true),
    ("statisticsvariable", true),
    ("abortonerror", false),
    ("dedicatedadministratorconnection", false),
    ("disablecommands", false),
    ("disablevariables", false),
    ("encryptconnection", false),
    ("ignoreprovidercontext", false),
    ("includesqlusererrors", false),
    ("keepnullcharsinresults", false),
    ("multisubnetfailover", false),
    ("suppressprovidercontextwarning", false),
    ("trustservercertificate", false),
    ("verbose", false),
    ("vb", false),
    ("debug", false),
    ("db", false),
    ("erroraction", true),
    ("ea", true),
    ("warningaction", true),
    ("wa", true),
    ("informationaction", true),
    ("infa", true),
    ("ia", true),
    ("progressaction", true),
    ("proga", true),
    ("errorvariable", true),
    ("ev", true),
    ("warningvariable", true),
    ("wv", true),
    ("informationvariable", true),
    ("iv", true),
    ("outvariable", true),
    ("ov", true),
    ("outbuffer", true),
    ("ob", true),
    ("pipelinevariable", true),
    ("pv", true),
];

/// The queries an `Invoke-Sqlcmd` line gives: the value of `-Query`, and
/// every argument no parameter takes, since the query is its first
/// positional parameter; and the file of `-InputFile`. A parameter is any
/// start of one name, in any case; one that starts several names is refused
/// by PowerShell, and one that names none takes no value, so the argument
/// after either is read as a query too.
fn invoke_sqlcmd_queries(args: &[Arg]) -> Given {
    let mut given = Given::default();
    let found = &mut given.statements;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let name = arg
            .known()
            .and_then(|text| text.strip_prefix('-'))
            .filter(|name| name.starts_with(|c: char| c.is_ascii_alphabetic()));
        let Some(name) = name else {
            if !matches!(arg, Arg::Null) {
                found.push(arg.clone());
            }
            continue;
        };
        let colon = name.ends_with(':');
        let typed = name.trim_end_matches(':').to_ascii_lowercase();
        let exact = INVOKE_SQLCMD.iter().find(|(full, _)| *full == typed);
        let mut starts = INVOKE_SQLCMD
            .iter()
            .filter(|(full, _)| full.starts_with(&typed));
        let named = exact.or_else(|| match (starts.next(), starts.next()) {
            (Some(only), None) => Some(only),
            _ => None,
        });
        match named {
            Some(("query", _)) => found.extend(iter.next().cloned()),
            Some(("inputfile", _)) => given.files.extend(iter.next().cloned()),
            Some((_, true)) => {
                iter.next();
            }
            // `-Name:value` takes the value whatever the name is.
            _ if colon => {
                iter.next();
            }
            _ => {}
        }
    }
    given
}

/// How many readings of what a program says are kept: as written, and as
/// each of the shells that differ in what they decode prints it.
const READINGS: usize = 4;

/// What a piped `echo`, `printf` or `Write-Output` says: the text of its
/// words as they are written (the first), and as each shell prints it (the
/// others, see [`SHELLS`]).
struct Said {
    texts: [Arg; READINGS],
    /// Whether it ends the text with a newline.
    newline: bool,
    /// Whether it says more than the stage may: the text is not read.
    over: bool,
    /// Whether a word of it runs a command substitution, which prints what
    /// the line does not show.
    runs: bool,
}

/// What a shell decodes where shells differ. A line is read as every one of
/// them says it: it is not known which shell runs the line.
#[derive(Clone, Copy)]
struct Quirks {
    /// `\xHH`: dash leaves it as written.
    hex: bool,
    /// `\NNN` with no 0 in front, in `echo -e` and `%b`: bash's `echo` and
    /// zsh's leave it as written.
    bare: bool,
    /// `\"`, `\'` and `\?` in a `printf` format: bash decodes them, zsh and
    /// dash leave them as written.
    quotes: bool,
}

/// Bash (`printf`, `%b`), zsh (`printf`, `%b`, `echo`, and bash's `echo -e`)
/// and dash (`printf`, `%b`, `echo`).
const SHELLS: [Quirks; 3] = [
    Quirks {
        hex: true,
        bare: true,
        quotes: true,
    },
    Quirks {
        hex: true,
        bare: false,
        quotes: false,
    },
    Quirks {
        hex: false,
        bare: true,
        quotes: false,
    },
];

const NOTHING_KNOWN: Arg = Arg::Unknown(String::new());

/// The most programs of one stage that are read as the text fed to the client
/// after it; a larger group is `unknown`.
const MAX_PRODUCERS: usize = 256;

/// The most text a stage is read to say, written and printed together; more
/// is `unknown`.
const TEXT_LIMIT: usize = 1 << 18;

/// What an escape is, as a program reads it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reads {
    /// A `printf` format: `\NNN` is one to three octal digits, the 0 in front
    /// counting as one, and an escape it does not know is not read.
    Format,
    /// `echo -e` and `printf`'s `%b`: `\0NNN` is a 0 and up to three octal
    /// digits, `\c` ends the output, and what is not an escape stays as
    /// written.
    Echo,
}

/// What the escape at the front of the text is.
enum Escape {
    /// Decoded, and put on the output.
    Decoded,
    /// `\c`: the output ends.
    Ends,
    /// Not decoded here: the backslash stays as written.
    Literal,
    /// Not read the same way by every shell: the text is not known.
    Unknown,
}

/// The one escape that starts at the front of `chars` (the backslash already
/// read), and what it stands for, put on `out`. The text is left where it was
/// unless the escape was decoded.
fn escape(
    chars: &mut std::str::Chars<'_>,
    out: &mut String,
    reads: Reads,
    shell: Quirks,
) -> Escape {
    let not_read = match reads {
        Reads::Format => Escape::Unknown,
        Reads::Echo => Escape::Literal,
    };
    let mut ahead = chars.clone();
    let Some(c) = ahead.next() else {
        return not_read;
    };
    let digits = |ahead: &mut std::str::Chars<'_>, radix: u32, most: usize, mut value: u32| {
        let mut count = 0;
        while count < most {
            let Some(digit) = ahead.clone().next().and_then(|d| d.to_digit(radix)) else {
                break;
            };
            value = value * radix + digit;
            ahead.next();
            count += 1;
        }
        (value, count)
    };
    let value = match c {
        '\\' => u32::from(c),
        '"' | '\'' | '?' if reads == Reads::Format => {
            if shell.quotes {
                u32::from(c)
            } else {
                return Escape::Literal;
            }
        }
        'n' => 10,
        't' => 9,
        'r' => 13,
        'a' => 7,
        'b' => 8,
        'f' => 12,
        'v' => 11,
        'c' if reads == Reads::Echo => {
            *chars = ahead;
            return Escape::Ends;
        }
        'x' if shell.hex => match digits(&mut ahead, 16, 2, 0) {
            (_, 0) => return not_read,
            (value, _) => value,
        },
        'x' => return Escape::Literal,
        '0'..='7' => {
            let Some(first) = c.to_digit(8) else {
                return not_read;
            };
            match reads {
                Reads::Format => digits(&mut ahead, 8, 2, first).0,
                Reads::Echo if c == '0' => digits(&mut ahead, 8, 3, first).0,
                Reads::Echo if shell.bare => digits(&mut ahead, 8, 2, first).0,
                Reads::Echo => return Escape::Literal,
            }
        }
        _ => return not_read,
    };
    // Only ASCII: a byte of a longer character is not text here.
    let Some(decoded) = char::from_u32(value).filter(|c| c.is_ascii() && *c != '\0') else {
        return not_read;
    };
    out.push(decoded);
    *chars = ahead;
    Escape::Decoded
}

/// What `echo -e` prints for `text` in `shell`: its escapes decoded, and one
/// that is not an escape left as written. Also whether a `\c` ended it.
fn echoed(text: &str, shell: Quirks) -> (String, bool) {
    let mut out = String::new();
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match escape(&mut chars, &mut out, Reads::Echo, shell) {
                Escape::Ends => return (out, true),
                Escape::Decoded => {}
                Escape::Literal | Escape::Unknown => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    (out, false)
}

/// The longest text `printf` is read to print: a line is no longer than that,
/// so more is a format blown up on purpose, and is not read.
const PRINTED_LIMIT: usize = 1 << 16;

/// What `printf` prints, as far as it is read.
enum Printed {
    Text(String),
    /// Another directive or escape than the ones that are read, or more than
    /// [`PRINTED_LIMIT`].
    Unknown,
    /// More than what is left of the stage's [`TEXT_LIMIT`].
    Over,
}

/// What `printf FORMAT ARGUMENT…` prints in `shell`, as `printf` reads it:
/// the format's escapes and `%s`, `%b`, `%d` and `%%` filled from the
/// arguments, the format used again while arguments are left. It stops as
/// soon as it prints more than `left`, the text the stage may still say.
fn printed(format: &str, args: &[&str], shell: Quirks, left: usize) -> Printed {
    let mut out = String::new();
    let mut used = 0;
    loop {
        let before = used;
        let mut chars = format.chars();
        while let Some(c) = chars.next() {
            match c {
                '\\' => match escape(&mut chars, &mut out, Reads::Format, shell) {
                    Escape::Decoded => {}
                    Escape::Literal => out.push('\\'),
                    Escape::Ends | Escape::Unknown => return Printed::Unknown,
                },
                '%' => {
                    let arg = args.get(used).copied();
                    let Some(directive) = chars.next() else {
                        return Printed::Unknown;
                    };
                    match directive {
                        '%' => out.push('%'),
                        's' => {
                            used += 1;
                            out.push_str(arg.unwrap_or_default());
                        }
                        'b' => {
                            used += 1;
                            let (text, ended) = echoed(arg.unwrap_or_default(), shell);
                            out.push_str(&text);
                            if ended {
                                return fit(out, left);
                            }
                        }
                        'd' | 'i' => {
                            used += 1;
                            let number = arg.unwrap_or("0");
                            let digits = number.strip_prefix(['-', '+']).unwrap_or(number);
                            if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
                                return Printed::Unknown;
                            }
                            out.push_str(number);
                        }
                        _ => return Printed::Unknown,
                    }
                }
                c => out.push(c),
            }
        }
        if used >= args.len() || used == before || out.len() > PRINTED_LIMIT.min(left) {
            break;
        }
    }
    fit(out, left)
}

/// `out` as what `printf` printed, when it is within the limits.
fn fit(out: String, left: usize) -> Printed {
    if out.len() > PRINTED_LIMIT {
        Printed::Unknown
    } else if out.len() > left {
        Printed::Over
    } else {
        Printed::Text(out)
    }
}

/// The text of `args` joined by `separator`, and whether it has expansions in
/// it; `None` when a word is only known when it runs.
fn joined(args: &[&Arg], separator: char) -> Option<(String, bool)> {
    let mut text = String::new();
    let mut holes = false;
    for (at, arg) in args.iter().enumerate() {
        let (word, hole) = statement_text(arg)?;
        holes |= hole;
        if at > 0 {
            text.push(separator);
        }
        text.push_str(word);
    }
    Some((text, holes))
}

/// Whether `text` is an option of `echo`: `-n`, `-e`, `-E`, alone or bundled.
fn echo_option(text: &str) -> bool {
    text.strip_prefix('-')
        .is_some_and(|rest| !rest.is_empty() && rest.chars().all(|c| matches!(c, 'n' | 'e' | 'E')))
}

/// What a piped `echo` says. A POSIX `echo` may decode escapes (`sh`, `zsh`,
/// `echo -e`), so the text is read as written and as each shell decodes it.
fn echo_said(unit: &Unit) -> Said {
    let mut newline = true;
    let mut rest = unit.args.as_slice();
    while let Some((first, tail)) = rest.split_first() {
        match first.known() {
            Some(text) if echo_option(text) => {
                newline &= !text.contains('n');
                rest = tail;
            }
            _ => break,
        }
    }
    let words: Vec<&Arg> = rest.iter().collect();
    let Some((text, holes)) = joined(&words, ' ') else {
        return Said {
            texts: [NOTHING_KNOWN; READINGS],
            newline,
            over: false,
            runs: false,
        };
    };
    let runs_any = rest.iter().any(runs);
    let written = attached(&text, holes, runs_any);
    let decoded = |shell: Option<&Quirks>| match shell {
        Some(shell) if unit.shell == Shell::Posix => {
            attached(&echoed(&text, *shell).0, holes, runs_any)
        }
        _ => written.clone(),
    };
    Said {
        texts: [
            written.clone(),
            decoded(SHELLS.first()),
            decoded(SHELLS.get(1)),
            decoded(SHELLS.get(2)),
        ],
        newline,
        over: false,
        runs: unit.args.iter().any(runs),
    }
}

/// What a piped `printf` says: its format filled from its arguments, as far
/// as `left` of the stage's text allows.
fn printf_said(unit: &Unit, left: usize) -> Said {
    let mut rest = unit.args.iter();
    let mut format = None;
    while let Some(arg) = rest.next() {
        match arg.known() {
            Some("--") => {
                format = rest.next();
                break;
            }
            Some("-v") => {
                rest.next();
            }
            Some(text) if text.starts_with('-') && text.len() > 1 => {}
            _ => {
                format = Some(arg);
                break;
            }
        }
    }
    let rest: Vec<&Arg> = rest.collect();
    let mut over = false;
    let said = format.and_then(|format| {
        let (format, holes) = statement_text(format)?;
        let mut args = Vec::new();
        let mut holey = holes;
        for arg in &rest {
            let (word, hole) = statement_text(arg)?;
            holey |= hole;
            args.push(word);
        }
        // Every shell's reading of it, or none when one cannot be read.
        let mut texts = Vec::new();
        for shell in &SHELLS {
            match printed(format, &args, *shell, left) {
                Printed::Text(text) => texts.push(attached(&text, holey, false)),
                Printed::Unknown => return None,
                Printed::Over => {
                    over = true;
                    return None;
                }
            }
        }
        Some(texts)
    });
    let said = match (said, format) {
        (None, Some(_)) => vec![NOTHING_KNOWN; SHELLS.len()],
        (None, None) => vec![attached("", false, false); SHELLS.len()],
        (Some(said), _) => said,
    };
    let text = |at: usize| said.get(at).cloned().unwrap_or(NOTHING_KNOWN);
    Said {
        texts: [text(0), text(0), text(1), text(2)],
        newline: false,
        over,
        runs: unit.args.iter().any(runs),
    }
}

/// What a piped `Write-Output` says: its words, as written. PowerShell sends
/// each argument to a program as a line of its own, and `cmd`'s `echo` says
/// them with a space between.
fn output_said(unit: &Unit) -> Said {
    let words: Vec<&Arg> = unit.args.iter().collect();
    let separator = if unit.shell == Shell::PowerShell {
        '\n'
    } else {
        ' '
    };
    let said = joined(&words, separator)
        .map_or(NOTHING_KNOWN, |(text, holes)| attached(&text, holes, false));
    Said {
        texts: [said.clone(), said.clone(), said.clone(), said],
        newline: true,
        over: false,
        runs: unit.args.iter().any(runs),
    }
}

/// The text of what several programs said one after the other, as one
/// statement text: `echo -n DR; echo -n OP TABLE t` says `DROP TABLE t`.
fn together<'a>(said: impl Iterator<Item = (&'a Arg, bool)>) -> Arg {
    let mut text = String::new();
    let mut holes = false;
    for (arg, newline) in said {
        let Some((word, hole)) = statement_text(arg) else {
            return NOTHING_KNOWN;
        };
        holes |= hole;
        text.push_str(word);
        if newline {
            text.push('\n');
        }
    }
    attached(&text, holes, false)
}

/// `texts` without one that is the same as an earlier one.
fn unique<'a>(texts: impl Iterator<Item = &'a Arg>) -> Vec<&'a Arg> {
    let mut found: Vec<&Arg> = Vec::new();
    for text in texts {
        if !found.contains(&text) {
            found.push(text);
        }
    }
    found
}

/// A stage of a pipeline: the pipeline and the stage's index in it.
type StageKey = (usize, usize);

/// Where a unit runs: the folder a `cd` moved it to, and whether its
/// wildcards match hidden names.
type RunsIn = (Option<Arg>, bool);

/// What the line says to its clients, worked out once for each stage and
/// reused for every client of the stage after it: a line may hold thousands
/// of clients, and each one reading again what every program of the stage
/// before says would be the clients times the programs.
#[derive(Default)]
pub(super) struct Cache {
    /// What each stage says, as texts.
    said: HashMap<StageKey, Rc<Vec<Arg>>>,
    /// What each of those texts does, for each language it is read in.
    read: HashMap<(StageKey, Language), Rc<Vec<Reading>>>,
    /// The stages and languages whose findings a client has already given;
    /// another client of the same language says the same.
    judged: HashSet<(StageKey, Language)>,
    /// The files that `.backup` and `.save` in what each stage says write,
    /// for each dialect.
    files: HashMap<(StageKey, Language), Rc<Vec<String>>>,
    /// The places (the folder a `cd` moved to, and whether wildcards match
    /// hidden names) whose clients have judged those files.
    backed: HashMap<(StageKey, Language), Vec<RunsIn>>,
    /// The stages that hand on what the line does not show: a file, or the
    /// output of a program the rule does not read.
    unseen: HashSet<StageKey>,
    /// For each unit, the command it runs for (the innermost one: a `sh -c`,
    /// a substitution), once worked out.
    outer: Option<Vec<Option<usize>>>,
    /// For each unit, whether a file is redirected onto its input, once
    /// worked out.
    files_in: Option<Vec<bool>>,
    /// How many stages deep the text being worked out was handed on.
    depth: usize,
    /// For each unit, the function whose body holds it, the innermost one,
    /// by its index in [`crate::unit::Split::function_bodies`], once worked
    /// out; and for each function, the units that call it.
    bodies: Option<Bodies>,
    /// The `exec`s with no program that redirect the input of the shell,
    /// once worked out: every unit after them reads it.
    execs: Option<Vec<usize>>,
    /// How many commands deep the client being read runs behind a container
    /// or a remote shell.
    behind: usize,
    /// For a line run in a container or on another machine, the input the
    /// command that runs it is given: what its units read when nothing else
    /// on that line feeds them.
    inherited: Option<Rc<Input>>,
}

/// The stage whose output is the input of `unit`.
pub(super) fn feeding(unit: &Unit) -> Option<StageKey> {
    let stage = unit.stage.filter(|stage| stage.index > 0)?;
    Some((stage.pipeline, stage.index - 1))
}

/// The function whose body holds each unit, and the calls of each function
/// (see [`Cache::bodies`]).
type Bodies = (Vec<Option<usize>>, Vec<Vec<usize>>);

/// What a stage says, and what each of its texts does.
type StageReading = (Rc<Vec<Arg>>, Rc<Vec<Reading>>);

/// The input a command is given: the texts the line shows, and whether it
/// is also given what the line does not show.
#[derive(Default)]
struct Input {
    texts: Vec<Arg>,
    unseen: bool,
}

/// Where the input of a unit comes from.
#[derive(Default)]
struct Upstream {
    /// The stages whose output it reads.
    stages: Vec<StageKey>,
    /// The text fed to a command it runs for (`sh -c psql <<EOF`).
    texts: Vec<Arg>,
    /// Whether a file is redirected onto it, or onto a command it runs for,
    /// or the walk out went further than it is read.
    unseen: bool,
}

/// The reason for a client that runs statements the line does not show.
const UNSEEN: &str = "runs statements the line does not show";

/// The reason for a command in a container or on another machine run
/// behind more of them than are read.
const BEHIND: &str = "runs a command behind more containers and hosts than the guard reads";

/// The reason for a command on another machine that is only known when it
/// runs: the remote shell reads it as code.
const REMOTE_UNKNOWN: &str = "runs a command on another machine only known when it runs";

/// The most stages and commands the walk out from a client to its input
/// follows; further is not read.
const MAX_UPSTREAM: usize = 64;

/// The most steps the walk out from a client to its input takes in all,
/// through every call of the functions it runs in; more is not read.
const MAX_WALK: usize = 256;

/// The most containers and remote shells a client is read behind.
const MAX_BEHIND: usize = 8;

/// Whether `target`, the file of a redirect or an option given in `shell`,
/// is the null device, which holds nothing. `nul` is the null device on
/// Windows only: on POSIX it is a file like any other.
fn null_device(target: &Arg, shell: Shell) -> bool {
    match target {
        Arg::Null => true,
        Arg::Known(text) => {
            text == "/dev/null" || (shell != Shell::Posix && text.eq_ignore_ascii_case("nul"))
        }
        _ => false,
    }
}

/// Whether a file a client is told to run statements from in `shell` is a
/// file: not its own input (`-f -`), which is read as its input, and not the
/// null device.
fn runs_file(file: &Arg, shell: Shell) -> bool {
    !(null_device(file, shell) || is_stdin(file))
}

/// Whether `arg` names the standard input.
fn is_stdin(arg: &Arg) -> bool {
    matches!(
        arg.known(),
        Some("-" | "/dev/stdin" | "/dev/fd/0" | "/proc/self/fd/0")
    )
}

/// What a program of a stage does with the text the client after it gets.
enum Producer {
    /// It says a text of its own: `echo`, `printf`, `Write-Output`.
    Says,
    /// It hands on what it is given (`cat`, `tee`, `Out-String`); `changes`
    /// when it leaves some of it out or changes it (`grep`, `sed`), so that
    /// the client gets a text the line does not show; `files` when it also
    /// hands on files.
    Passes { changes: bool, files: bool },
    /// It prints nothing: `true`, `test`, `sleep`.
    Silent,
    /// It prints what the line does not show: files, a download, anything
    /// the rule does not read.
    Unseen,
}

/// What the program `unit` of a stage does with the text after it.
fn stage_kind(unit: &Unit) -> Producer {
    let Some(key) = unit.key() else {
        return Producer::Unseen;
    };
    let posix = unit.shell == Shell::Posix;
    let powershell = unit.shell == Shell::PowerShell;
    match key.as_str() {
        "cat" if posix => {
            let (input, files) = cat_reads(unit);
            if input {
                Producer::Passes {
                    changes: false,
                    files,
                }
            } else if files {
                Producer::Unseen
            } else {
                Producer::Silent
            }
        }
        "tee" if posix => Producer::Passes {
            changes: false,
            files: false,
        },
        "grep" | "egrep" | "fgrep" | "sed" if posix => Producer::Passes {
            changes: true,
            files: false,
        },
        "echo" if posix => Producer::Says,
        "printf" => Producer::Says,
        "out-string" | "tee-object" if powershell => Producer::Passes {
            changes: false,
            files: false,
        },
        "foreach-object" if powershell && hands_on_item(unit) => Producer::Passes {
            changes: false,
            files: false,
        },
        "echo" | "write-output" if powershell && unit.args.is_empty() => Producer::Passes {
            changes: false,
            files: false,
        },
        "echo" | "write-output" => Producer::Says,
        "true" | "false" | ":" | "[" | "test" | "sleep" | "wait" if posix => Producer::Silent,
        _ => Producer::Unseen,
    }
}

/// Whether a `ForEach-Object` hands on each item as it is: its one argument
/// is the block `{ $_ }`.
fn hands_on_item(unit: &Unit) -> bool {
    let [block] = unit.args.as_slice() else {
        return false;
    };
    block
        .text()
        .strip_prefix('{')
        .and_then(|rest| rest.strip_suffix('}'))
        .is_some_and(|body| body.trim() == "$_")
}

/// Whether a POSIX `cat` reads its input (it has no file operand, or `-` or
/// `/dev/stdin` among its operands, whatever its options, none of which takes
/// a value), and whether it reads a file. An operand only known when it runs
/// may be either.
fn cat_reads(unit: &Unit) -> (bool, bool) {
    let mut options = true;
    let mut input = false;
    let mut operands = false;
    let mut files = false;
    for arg in &unit.args {
        let Some(text) = arg.known() else {
            return (true, true);
        };
        if options && text == "--" {
            options = false;
        } else if is_stdin(arg) {
            input = true;
        } else if !(options && text.starts_with('-')) {
            operands = true;
            files |= !null_device(arg, unit.shell);
        }
    }
    (input || !operands, files)
}

impl Checker<'_> {
    /// The text a stage says to the stage after it: what the `echo`,
    /// `printf` and `Write-Output` of every program of the stage say,
    /// `{ echo 'BEGIN;'; echo 'DELETE FROM t;'; } | psql`, and what a `cat`,
    /// `tee` or `Out-String` hands on. Also whether it hands on what the line
    /// does not show: a file, or the output of a program the rule does not
    /// read.
    fn stage_texts(&mut self, key: StageKey) -> (Vec<Arg>, bool) {
        let producers = self.stages.get(&key).cloned().unwrap_or_default();
        // A group too large to read is not read.
        if producers.len() > MAX_PRODUCERS {
            return (vec![NOTHING_KNOWN], false);
        }
        let mut found = Vec::new();
        let mut said = Vec::new();
        let mut unseen = false;
        // The programs that hand on what they are given.
        let mut passes = 0usize;
        // What the stage may still say; once it has said more the rest is
        // not decoded.
        let mut left = TEXT_LIMIT;
        let mut over = false;
        for producer in producers {
            let Some(unit) = self.split.units.get(producer) else {
                continue;
            };
            let key = unit.key();
            match stage_kind(unit) {
                Producer::Says => {}
                Producer::Silent => continue,
                Producer::Unseen => {
                    unseen = true;
                    continue;
                }
                Producer::Passes { changes, files } => {
                    passes += 1;
                    unseen |= changes || files;
                    let (texts, hidden) = self.passed_on(producer);
                    found.extend(texts);
                    unseen |= hidden;
                    continue;
                }
            }
            if over {
                continue;
            }
            let each = match key.as_deref() {
                Some("echo") if unit.shell == Shell::Posix => echo_said(unit),
                Some("printf") => printf_said(unit, left),
                _ => output_said(unit),
            };
            let size: usize = unique(each.texts.iter())
                .iter()
                .map(|text| text.text().len())
                .sum();
            if each.over || size > left {
                over = true;
                continue;
            }
            left -= size;
            said.push(each);
        }
        // What one program hands on and another says, one after the other, is
        // a text that is not read as one.
        if passes > 0 && passes + said.len() > 1 {
            unseen = true;
        }
        if over || said.iter().any(|each| each.runs) {
            found.push(NOTHING_KNOWN);
        }
        if over {
            return (found, unseen);
        }
        for each in &said {
            found.extend(unique(each.texts.iter()).into_iter().cloned());
        }
        // What they say one after the other can be a statement that none says
        // alone, in each reading the same way.
        if said.len() > 1 {
            let whole: Vec<Arg> = (0..READINGS)
                .map(|reading| {
                    together(said.iter().filter_map(|each| {
                        each.texts.get(reading).map(|text| (text, each.newline))
                    }))
                })
                .collect();
            found.extend(unique(whole.iter()).into_iter().cloned());
        }
        (found, unseen)
    }

    /// What a program that hands on its input (`cat`, `tee`) is given: the
    /// text fed to it, and what the stage before it says. Also whether that
    /// is more than the line shows.
    fn passed_on(&mut self, producer: usize) -> (Vec<Arg>, bool) {
        let mut texts: Vec<Arg> = self.split.fed_to(producer).cloned().collect();
        let up = self.upstream(producer);
        texts.extend(up.texts);
        let mut unseen = up.unseen;
        for key in up.stages {
            if self.data.depth >= MAX_UPSTREAM {
                unseen = true;
            } else {
                self.data.depth += 1;
                let said = self.stage_said(key);
                self.data.depth -= 1;
                unseen |= self.data.unseen.contains(&key);
                texts.extend(said.iter().cloned());
            }
        }
        (texts, unseen)
    }

    /// What the stage `key` says, worked out once.
    pub(super) fn stage_said(&mut self, key: StageKey) -> Rc<Vec<Arg>> {
        if let Some(said) = self.data.said.get(&key) {
            return Rc::clone(said);
        }
        let (texts, unseen) = self.stage_texts(key);
        let said = Rc::new(texts);
        self.data.said.insert(key, Rc::clone(&said));
        if unseen {
            self.data.unseen.insert(key);
        }
        said
    }

    /// Whether the stage `key` hands on what the line does not show.
    fn stage_unseen(&mut self, key: StageKey) -> bool {
        self.stage_said(key);
        self.data.unseen.contains(&key)
    }

    /// The command the unit at `at` runs for, the innermost one: the `sh` of
    /// `sh -c psql`, the command of a substitution. It is handed that
    /// command's input.
    fn outer(&mut self, at: usize) -> Option<usize> {
        let split = self.split;
        let outer = self.data.outer.get_or_insert_with(|| {
            let mut outer: Vec<Option<(usize, usize)>> = vec![None; split.units.len()];
            for nested in &split.nested {
                let size = nested.inside.len();
                for inside in nested.inside.clone() {
                    if let Some(slot) = outer.get_mut(inside) {
                        if slot.is_none_or(|(_, known)| size < known) {
                            *slot = Some((nested.command.start, size));
                        }
                    }
                }
            }
            outer
                .into_iter()
                .map(|slot| slot.map(|(command, _)| command))
                .collect()
        });
        outer.get(at).copied().flatten()
    }

    /// Whether a file is redirected onto the input of the unit at `at`.
    fn file_fed(&mut self, at: usize) -> bool {
        let split = self.split;
        let fed = self.data.files_in.get_or_insert_with(|| {
            let mut fed = vec![false; split.units.len()];
            for redirect in &split.redirects {
                let shell = split
                    .units
                    .get(redirect.units.start)
                    .map_or(Shell::Posix, |unit| unit.shell);
                if redirect.input && !redirect.text && !null_device(&redirect.target, shell) {
                    for unit in redirect.units.clone() {
                        if let Some(slot) = fed.get_mut(unit) {
                            *slot = true;
                        }
                    }
                }
            }
            fed
        });
        fed.get(at).copied().unwrap_or_default()
    }

    /// For the unit at `at`, the units that call the function whose body
    /// holds it (the innermost one): a call hands the body its input.
    fn callers(&mut self, at: usize) -> Vec<usize> {
        let split = self.split;
        let (inside, calls) = self.data.bodies.get_or_insert_with(|| {
            let mut inside: Vec<Option<(usize, usize)>> = vec![None; split.units.len()];
            let mut names: HashMap<String, usize> = HashMap::new();
            for (index, (name, body)) in split.function_bodies.iter().enumerate() {
                names.insert(crate::unit::key(name, Shell::Posix), index);
                for unit in body.clone() {
                    if let Some(slot) = inside.get_mut(unit) {
                        if slot.is_none_or(|(_, size)| body.len() < size) {
                            *slot = Some((index, body.len()));
                        }
                    }
                }
            }
            let mut calls = vec![Vec::new(); split.function_bodies.len()];
            for (at, unit) in split.units.iter().enumerate() {
                let called = unit
                    .key()
                    .filter(|_| unit.shell == Shell::Posix)
                    .and_then(|key| names.get(&key));
                if let Some(calls) = called.and_then(|&index| calls.get_mut(index)) {
                    calls.push(at);
                }
            }
            let inside = inside
                .into_iter()
                .map(|slot| slot.map(|(index, _)| index))
                .collect();
            (inside, calls)
        });
        inside
            .get(at)
            .copied()
            .flatten()
            .and_then(|index| calls.get(index))
            .cloned()
            .unwrap_or_default()
    }

    /// The `exec`s with no program that redirect the shell's own input
    /// (`exec < f`, `exec <<EOF`): what runs after one reads that input.
    fn execs(&mut self) -> &[usize] {
        let split = self.split;
        self.data.execs.get_or_insert_with(|| {
            let mut fed: HashSet<usize> = HashSet::new();
            for redirect in split.redirects.iter().filter(|redirect| redirect.input) {
                fed.extend(redirect.units.clone());
            }
            split
                .units
                .iter()
                .enumerate()
                .filter(|(at, unit)| {
                    unit.shell == Shell::Posix
                        && unit.args.is_empty()
                        && unit.key().as_deref() == Some("exec")
                        && (fed.contains(at) || split.fed_to(*at).next().is_some())
                })
                .map(|(at, _)| at)
                .collect()
        })
    }

    /// The input of the line at the unit at `at`, which reads it: what an
    /// `exec` before it redirected, or what the command that runs this line
    /// in a container or on another machine is given.
    fn line_input(&mut self, at: usize, up: &mut Upstream) {
        let execs: Vec<usize> = self
            .execs()
            .iter()
            .copied()
            .take_while(|exec| *exec < at)
            .collect();
        for exec in execs {
            up.unseen |= self.file_fed(exec);
            up.texts.extend(self.split.fed_to(exec).cloned());
        }
        if let Some(inherited) = &self.data.inherited {
            up.texts.extend(inherited.texts.iter().cloned());
            up.unseen |= inherited.unseen;
        }
    }

    /// Where the input of the unit at `at` comes from: the stage before it,
    /// or, for the first stage of a pipeline, the stage the pipeline runs
    /// in, or the input of the command it runs for (`echo … | sh -c psql`),
    /// or of each call of the function it runs in (`echo … | f`), or else
    /// the line's own input. A file redirected onto it, or onto a command it
    /// runs for, is not shown by the line.
    fn upstream(&mut self, at: usize) -> Upstream {
        let mut up = Upstream::default();
        let mut todo = vec![at];
        let mut seen = HashSet::from([at]);
        let mut steps = 0;
        while let Some(mut current) = todo.pop() {
            loop {
                steps += 1;
                if steps > MAX_WALK {
                    up.unseen = true;
                    return up;
                }
                if self.file_fed(current) {
                    up.unseen = true;
                }
                if current != at {
                    up.texts.extend(self.split.fed_to(current).cloned());
                }
                let mut stage = self.split.units.get(current).and_then(|unit| unit.stage);
                let mut hops = 0;
                let mut before = None;
                while let Some(here) = stage {
                    if here.index > 0 {
                        before = Some((here.pipeline, here.index - 1));
                        break;
                    }
                    hops += 1;
                    if hops > MAX_UPSTREAM {
                        up.unseen = true;
                        return up;
                    }
                    stage = self.split.parents.get(&here.pipeline).copied();
                }
                if let Some(key) = before {
                    if !up.stages.contains(&key) {
                        up.stages.push(key);
                    }
                    break;
                }
                if let Some(command) = self.outer(current).filter(|command| *command != current) {
                    current = command;
                    continue;
                }
                let callers = self.callers(current);
                if callers.is_empty() {
                    self.line_input(current, &mut up);
                }
                for caller in callers {
                    if seen.insert(caller) {
                        todo.push(caller);
                    }
                }
                break;
            }
        }
        up
    }

    /// What each text the stage `key` says does when it is read in
    /// `language`, worked out once.
    fn stage_readings(&mut self, key: StageKey, language: Language) -> Rc<Vec<Reading>> {
        if let Some(readings) = self.data.read.get(&(key, language)) {
            return Rc::clone(readings);
        }
        let readings: Vec<Reading> = self
            .stage_said(key)
            .iter()
            .map(|text| read_text(language, text))
            .collect();
        let readings = Rc::new(readings);
        self.data.read.insert((key, language), Rc::clone(&readings));
        readings
    }

    /// Database clients and the tools that drop a database.
    pub(super) fn data(&mut self, at: usize, unit: &Unit, key: &str) {
        let args = unit.args.as_slice();
        // `Start-Process` joins its arguments into one command line, which
        // the client splits: a part only known when it runs may be any
        // options, a statement among them.
        if CLIENTS.contains(&key)
            && unit
                .wrappers
                .iter()
                .any(|wrapper| wrapper == "start-process")
            && args.iter().any(|arg| !matches!(arg, Arg::Known(_)))
        {
            self.add(
                Rule::Unknown,
                "starts a database client with arguments only known when it runs",
                Some(&unit.program),
            );
        }
        match key {
            "psql" => self.sql_client(at, unit, &PSQL, args),
            "mysql" | "mariadb" => self.sql_client(at, unit, &MYSQL, args),
            "clickhouse-client" => self.sql_client(at, unit, &CLICKHOUSE, args),
            "clickhouse" if args.first().and_then(Arg::known) == Some("client") => {
                self.sql_client(at, unit, &CLICKHOUSE, args.get(1..).unwrap_or_default());
            }
            "sqlcmd" => self.sql_client(at, unit, &SQLCMD, args),
            "cqlsh" => self.sql_client(at, unit, &CQLSH, args),
            "mongosh" | "mongo" => self.sql_client(at, unit, &MONGO, args),
            "sqlite3" => {
                let found = embedded(args, &SQLITE);
                self.embedded_client(at, unit, &found, Dialect::Sqlite);
            }
            "duckdb" => {
                let found = embedded(args, &DUCKDB);
                self.embedded_client(at, unit, &found, Dialect::DuckDb);
            }
            "redis-cli" | "valkey-cli" | "keydb-cli" => self.redis(at, unit.shell, args),
            "invoke-sqlcmd" if unit.shell == Shell::PowerShell => {
                self.invoke_sqlcmd(at, unit, args);
            }
            "pg_dropcluster" if !asks_help(args) => {
                let cluster = resources::words(args, &[]).get(1).copied();
                self.add(Rule::DropData, "deletes a database cluster", cluster);
            }
            "heroku" if !asks_help(args) => {
                let words = resources::words(args, resources::HEROKU_VALUES);
                if let Some(reset) = words
                    .first()
                    .filter(|word| word.known() == Some("pg:reset"))
                {
                    let database = words.get(1).copied().or(Some(*reset));
                    self.add(Rule::DropData, "deletes data in a database", database);
                }
            }
            "supabase" if !asks_help(args) => {
                let words = resources::words(args, resources::SUPABASE_VALUES);
                let command: Vec<Option<&str>> =
                    words.iter().take(2).map(|word| word.known()).collect();
                if command == [Some("db"), Some("reset")] {
                    self.add(
                        Rule::DropData,
                        "deletes data in a database",
                        words.get(1).copied(),
                    );
                }
            }
            "dropdb" | "dropuser" => {
                let help = args
                    .iter()
                    .filter_map(Arg::known)
                    .any(|text| matches!(text, "--help" | "-?" | "--version" | "-V"));
                if !help {
                    let name = crate::unit::operands(
                        args,
                        &[
                            "-U",
                            "-h",
                            "-p",
                            "--username",
                            "--host",
                            "--port",
                            "--maintenance-db",
                        ],
                    )
                    .first()
                    .copied();
                    self.add(Rule::DropData, "deletes data in a database", name);
                }
            }
            "mysqladmin" | "mariadb-admin" => self.mysqladmin(args),
            // A client run in a container or on another machine.
            "docker" | "podman" | "nerdctl" => self.engine_exec(at, unit, args),
            "docker-compose" | "podman-compose" => self.compose_exec(at, args),
            "kubectl" | "oc" => self.kube_exec(at, args),
            "ssh" => self.ssh(at, args),
            _ => {}
        }
    }

    /// A statement as a reader of its text takes it: a PowerShell
    /// double-quoted string whose expansions are only known when it runs is
    /// read as a template, as a POSIX one is (`psql -c "… WHERE id = $id"`).
    fn template(&self, unit: &Unit, statement: &Arg) -> Arg {
        match statement {
            Arg::Unknown(source) if unit.shell == Shell::PowerShell => self
                .split
                .template(source)
                .unwrap_or_else(|| statement.clone()),
            _ => statement.clone(),
        }
    }

    /// The arguments of a client as [`Checker::template`] reads each: a
    /// PowerShell double-quoted word is a template, so that an option and
    /// its value in one (`"--execute=DROP TABLE $t"`, `"-c$q"`) is read as a
    /// POSIX shell's is.
    fn templates(&self, unit: &Unit, args: &[Arg]) -> Vec<Arg> {
        args.iter().map(|arg| self.template(unit, arg)).collect()
    }

    /// Say what a client's statements do.
    fn judge(&mut self, reading: Reading, target: Option<&Arg>, own: bool) {
        if reading.unreadable {
            self.add(
                Rule::Unknown,
                "runs a database statement only known when it runs",
                target,
            );
        }
        if reading.program {
            self.add(
                Rule::Unknown,
                "runs a program from a database client",
                target,
            );
        }
        if reading.destroys && !own {
            self.add(Rule::DropData, "deletes data in a database", target);
        }
        if reading.unseen && !own {
            self.add(Rule::DropData, UNSEEN, target);
        }
    }

    /// A client of a database server: every database on a server is risky,
    /// since the line cannot tell a scratch one from production.
    fn sql_client(&mut self, at: usize, unit: &Unit, client: &Client, args: &[Arg]) {
        let args = self.templates(unit, args);
        self.client_given(at, unit, client.statements(&args), client.language);
    }

    /// What a client of a database server is given, its statements written
    /// in `language`, and what it reads from its input.
    fn client_given(&mut self, at: usize, unit: &Unit, given: Given, language: Language) {
        let mut statements: Vec<Arg> = given
            .statements
            .iter()
            .map(|statement| self.template(unit, statement))
            .collect();
        for file in given
            .files
            .iter()
            .filter(|file| runs_file(file, unit.shell))
        {
            self.judge(Reading::UNSEEN, Some(file), false);
        }
        // A client given a statement that it runs and then exits (`psql -c`,
        // `mysql -e`) does not read its input, unless a file of statements
        // it is given is its input (`-f -`).
        if given.exits && !given.files.iter().any(is_stdin) {
            for statement in &statements {
                let reading = read_text(language, statement);
                self.judge(reading, Some(statement), false);
            }
            return;
        }
        statements.extend(self.split.fed_to(at).cloned());
        let up = self.upstream(at);
        statements.extend(up.texts);
        for statement in &statements {
            let reading = read_text(language, statement);
            self.judge(reading, Some(statement), false);
        }
        if up.unseen {
            self.judge(Reading::UNSEEN, Some(&unit.program), false);
        }
        // What the stage before it says is judged once: every client of the
        // same language finds the same.
        for key in up.stages {
            if !self.data.judged.insert((key, language)) {
                continue;
            }
            let said = self.stage_said(key);
            let readings = self.stage_readings(key, language);
            for (statement, reading) in said.iter().zip(readings.iter()) {
                self.judge(*reading, Some(statement), false);
            }
            if self.stage_unseen(key) {
                self.judge(Reading::UNSEEN, Some(&unit.program), false);
            }
        }
    }

    /// The files that the `.backup` and `.save` commands in what the stage
    /// `key` says write, worked out once.
    fn stage_files(&mut self, key: StageKey, dialect: Dialect) -> Rc<Vec<String>> {
        let language = Language::Sql(dialect);
        if let Some(files) = self.data.files.get(&(key, language)) {
            return Rc::clone(files);
        }
        let mut files: Vec<String> = Vec::new();
        for text in self.stage_said(key).iter() {
            for name in replaced_files(text, dialect) {
                if !files.contains(&name) {
                    files.push(name);
                }
            }
        }
        let files = Rc::new(files);
        self.data.files.insert((key, language), Rc::clone(&files));
        files
    }

    /// Say that a file a database client replaces is not the agent's own.
    fn judge_files(&mut self, unit: &Unit, files: &[String]) {
        for name in files {
            if !self.is_own_database(unit, name) {
                let target = Arg::Known(name.clone());
                self.add(
                    Rule::DropData,
                    "replaces a file outside the workspace",
                    Some(&target),
                );
            }
        }
    }

    /// Whether the database `name` (as given to `sqlite3` or `duckdb`) is the
    /// agent's own: in memory, or a file the workspace or a temporary folder
    /// holds.
    fn is_own_database(&self, unit: &Unit, name: &str) -> bool {
        // A file in a container or on another machine is not the agent's.
        if self.data.behind > 0 {
            return false;
        }
        match database(name) {
            Database::Memory => true,
            Database::Path(path) => self
                .place(unit.shell, unit.scope(), &Arg::Known(path), Access::Content)
                .harmless(),
            Database::Elsewhere => false,
        }
    }

    /// `Invoke-Sqlcmd`: SQL Server's cmdlet, which runs its `-Query` and its
    /// `-InputFile`.
    fn invoke_sqlcmd(&mut self, at: usize, unit: &Unit, args: &[Arg]) {
        let args = self.templates(unit, args);
        let given = invoke_sqlcmd_queries(&args);
        self.client_given(at, unit, given, Language::Sql(Dialect::SqlServer));
    }

    /// `sqlite3` and `duckdb`: a database in a file is the agent's own when
    /// the file is in the workspace, judged like any file.
    fn embedded_client(&mut self, at: usize, unit: &Unit, found: &Embedded<'_>, dialect: Dialect) {
        let mut statements: Vec<Arg> = found
            .statements
            .iter()
            .map(|statement| self.template(unit, statement))
            .collect();
        statements.extend(self.split.fed_to(at).cloned());
        let up = self.upstream(at);
        statements.extend(up.texts);
        let own_file = match found.file {
            None => self.data.behind == 0,
            Some(_) if self.data.behind > 0 => false,
            Some(file) => match file.known() {
                Some(name) => self.is_own_database(unit, name),
                None => self
                    .place(unit.shell, unit.scope(), file, Access::Content)
                    .harmless(),
            },
        };
        let language = Language::Sql(dialect);
        let readings: Vec<Reading> = statements
            .iter()
            .map(|statement| read_text(language, statement))
            .collect();
        let stages: Vec<StageReading> = up
            .stages
            .iter()
            .map(|&key| (self.stage_said(key), self.stage_readings(key, language)))
            .collect();
        // `ATTACH` and `.open` reach another file than the one given, and
        // `-readonly` does not hold for it.
        let moves = readings
            .iter()
            .chain(stages.iter().flat_map(|(_, readings)| readings.iter()))
            .any(|reading| reading.moves);
        let own = !moves && (found.read_only || own_file);
        // `.backup` and `.save` replace the file they are given, even for a
        // client opened `-readonly`.
        for statement in &statements {
            self.judge_files(unit, &replaced_files(statement, dialect));
        }
        // Statements from a file, or from what the line does not show.
        let unseen = up.unseen || up.stages.iter().any(|&key| self.stage_unseen(key));
        let target = found.file.unwrap_or(&unit.program);
        for file in found
            .files
            .iter()
            .filter(|file| runs_file(file, unit.shell))
        {
            self.judge(Reading::UNSEEN, Some(file), own);
        }
        if unseen {
            self.judge(Reading::UNSEEN, Some(target), own);
        }
        for &key in &up.stages {
            // What the stage says is worked out once, and judged once for
            // each place its clients run in.
            let place = (unit.dir.clone(), unit.hidden);
            let judged = self.data.backed.entry((key, language)).or_default();
            if !judged.contains(&place) {
                judged.push(place);
                let files = self.stage_files(key, dialect);
                self.judge_files(unit, &files);
            }
        }
        let all = statements.iter().zip(readings).chain(
            stages
                .iter()
                .flat_map(|(said, readings)| said.iter().zip(readings.iter().copied())),
        );
        for (statement, reading) in all {
            self.judge(reading, found.file.or(Some(statement)), own);
        }
    }

    /// `redis-cli`: `FLUSHALL`, `FLUSHDB`, and a `DEL` or `UNLINK` of what a
    /// `KEYS` or `SCAN` on the same line finds.
    fn redis(&mut self, at: usize, shell: Shell, args: &[Arg]) {
        let operands = redis_operands(args);
        let mut reading = Reading::default();
        let target = operands.first().copied();
        if let Some(command) = operands.first() {
            match command.known() {
                Some(name) => {
                    let words: Vec<&str> = operands.iter().filter_map(|arg| arg.known()).collect();
                    reading.merge(reader::redis(&words));
                    // A script, or a function, only known when it runs.
                    if reader::runs_script(name)
                        && operands
                            .get(1)
                            .is_some_and(|script| script.known().is_none())
                    {
                        reading.merge(Reading::UNREADABLE);
                    }
                    let deletes = matches!(name.to_ascii_lowercase().as_str(), "del" | "unlink");
                    let found = operands
                        .iter()
                        .skip(1)
                        .any(|arg| matches!(arg, Arg::Input) || arg.is_unknown());
                    if deletes && found && self.line_scans_keys() {
                        reading.destroys = true;
                    }
                }
                None => reading.merge(Reading::UNREADABLE),
            }
        }
        for text in self.split.fed_to(at) {
            reading.merge(read_text(Language::Redis, text));
        }
        let up = self.upstream(at);
        for text in &up.texts {
            reading.merge(read_text(Language::Redis, text));
        }
        // With no command on the line it runs the commands of its input.
        let mut unseen = operands.is_empty() && up.unseen;
        for key in up.stages {
            for said in self.stage_readings(key, Language::Redis).iter() {
                reading.merge(*said);
            }
            unseen |= operands.is_empty() && self.stage_unseen(key);
        }
        // `--eval FILE` runs the script of a file.
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            if arg.known() == Some("--eval")
                && iter.next().is_some_and(|file| runs_file(file, shell))
            {
                unseen = true;
            }
        }
        reading.unseen |= unseen;
        self.judge(reading, target, false);
    }

    /// Whether the line lists keys in Redis, worked out once for the line.
    fn line_scans_keys(&mut self) -> bool {
        if let Some(scans) = self.scans_keys {
            return scans;
        }
        let scans = self.scans_keys();
        self.scans_keys = Some(scans);
        scans
    }

    /// Whether the line lists keys in Redis: `redis-cli --scan`, `keys` or
    /// `scan`.
    fn scans_keys(&self) -> bool {
        self.split.units.iter().any(|unit| {
            matches!(
                unit.key().as_deref(),
                Some("redis-cli" | "valkey-cli" | "keydb-cli")
            ) && {
                let operands = redis_operands(&unit.args);
                unit.args.iter().any(|arg| arg.known() == Some("--scan"))
                    || operands
                        .first()
                        .and_then(|arg| arg.known())
                        .is_some_and(|name| {
                            matches!(name.to_ascii_lowercase().as_str(), "keys" | "scan")
                        })
            }
        })
    }

    /// `mysqladmin drop DATABASE`.
    fn mysqladmin(&mut self, args: &[Arg]) {
        let mut iter = args.iter();
        let mut commands = Vec::new();
        while let Some(arg) = iter.next() {
            match arg.known() {
                Some(text) if text.starts_with('-') && text.len() > 1 => {
                    if matches!(
                        text,
                        "-h" | "-P"
                            | "-u"
                            | "-S"
                            | "-c"
                            | "-i"
                            | "--host"
                            | "--user"
                            | "--port"
                            | "--socket"
                            | "--count"
                            | "--sleep"
                            | "--protocol"
                    ) {
                        iter.next();
                    }
                }
                _ => commands.push(arg),
            }
        }
        // `mysqladmin` runs the command that any unique start of its name
        // (two letters or more) says: `dro` and `dr` are `drop`.
        if let Some(drop) = commands.iter().find(|arg| {
            arg.known().is_some_and(|text| {
                text.len() > 1
                    && text.len() <= "drop".len()
                    && "drop".starts_with(&text.to_ascii_lowercase())
            })
        }) {
            let name = commands
                .iter()
                .skip_while(|arg| *arg != drop)
                .nth(1)
                .copied();
            self.add(
                Rule::DropData,
                "deletes data in a database",
                name.or(Some(drop)),
            );
        }
    }

    /// `docker exec CONTAINER COMMAND…` and `docker container exec`, and
    /// `docker compose exec`: the command runs in the container.
    fn engine_exec(&mut self, at: usize, unit: &Unit, args: &[Arg]) {
        let Some((command, rest)) = resources::command(args, resources::ENGINE_VALUES) else {
            return;
        };
        // `podman exec --latest` runs in the container made last, and names
        // none.
        let podman = unit.key().as_deref() == Some("podman");
        match command.known() {
            Some("exec") => self.container_exec(at, rest, EXEC_VALUES, podman),
            Some("container") => {
                if let Some((sub, rest)) = resources::command(rest, &[]) {
                    if sub.known() == Some("exec") {
                        self.container_exec(at, rest, EXEC_VALUES, podman);
                    }
                }
            }
            Some("compose") => self.compose_exec(at, rest),
            _ => {}
        }
    }

    /// `docker-compose exec SERVICE COMMAND…`.
    fn compose_exec(&mut self, at: usize, args: &[Arg]) {
        let Some((command, rest)) = resources::command(args, resources::COMPOSE_VALUES) else {
            return;
        };
        if command.known() == Some("exec") {
            self.container_exec(at, rest, COMPOSE_EXEC_VALUES, false);
        }
    }

    /// The command after the container of an `exec`, whose options end at
    /// the container; with `podman`'s `-l` (`--latest`) there is no
    /// container, and the command starts after the options.
    fn container_exec(&mut self, at: usize, args: &[Arg], values: &[&str], podman: bool) {
        if podman && takes_latest(args, values) {
            let start = after_options(args, values);
            self.behind(at, args.get(start..).unwrap_or_default());
        } else if let Some((_, command)) = resources::command(args, values) {
            self.behind(at, command);
        }
    }

    /// `kubectl exec POD -- COMMAND…` and `oc exec`.
    fn kube_exec(&mut self, at: usize, args: &[Arg]) {
        let Some((command, rest)) = resources::command(args, resources::KUBECTL_VALUES) else {
            return;
        };
        if command.known() != Some("exec") {
            return;
        }
        if let Some(dash) = rest.iter().position(|arg| arg.known() == Some("--")) {
            self.behind(at, rest.get(dash + 1..).unwrap_or_default());
            return;
        }
        // The old form, with no `--`: the pod, then the command.
        let values = [resources::KUBECTL_VALUES, &["-c", "--container"]].concat();
        let Some((_, after)) = resources::command(rest, &values) else {
            return;
        };
        let start = after.iter().position(|arg| !is_option(arg));
        if let Some(start) = start {
            self.behind(at, after.get(start..).unwrap_or_default());
        }
    }

    /// `ssh [OPTIONS] HOST COMMAND…`: the words of the command, joined with
    /// spaces, are a line the remote shell runs.
    fn ssh(&mut self, at: usize, args: &[Arg]) {
        let mut host = false;
        let mut at_command = None;
        let mut index = 0;
        while let Some(arg) = args.get(index) {
            index += 1;
            let Some(text) = arg.known() else {
                if host {
                    at_command = Some(index - 1);
                    break;
                }
                host = true;
                continue;
            };
            if text == "--" {
                if host {
                    at_command = Some(index);
                    break;
                }
                continue;
            }
            match text.strip_prefix('-').filter(|rest| !rest.is_empty()) {
                Some(letters) => {
                    // The first letter that takes a value takes the rest of
                    // the word, or the next word.
                    if let Some(at) = letters.find(|c: char| SSH_VALUES.contains(c)) {
                        if at + 1 == letters.len() {
                            index += 1;
                        }
                    }
                }
                None if host => {
                    at_command = Some(index - 1);
                    break;
                }
                None => host = true,
            }
        }
        let Some(start) = at_command else {
            return;
        };
        let words = args.get(start..).unwrap_or_default();
        let known: Option<Vec<&str>> = words.iter().map(Arg::known).collect();
        match known {
            Some(known) => {
                let line = known.join(" ");
                if self.data.behind >= MAX_BEHIND {
                    self.add(Rule::Unknown, BEHIND, words.first());
                    return;
                }
                let split = crate::unit::split(&line, Shell::Posix, (None, None), false);
                self.judge_behind(at, &split);
            }
            // A word only known when it runs is part of the code the remote
            // shell reads.
            None => self.add(Rule::Unknown, REMOTE_UNKNOWN, words.first()),
        }
    }

    /// A command run in a container or on another machine, as its words:
    /// read as the line would read it here (wrappers come off, a shell's
    /// `-c` line is split), each database client in it judged as running
    /// there.
    fn behind(&mut self, at: usize, words: &[Arg]) {
        let Some((program, args)) = words.split_first() else {
            return;
        };
        if self.data.behind >= MAX_BEHIND {
            self.add(Rule::Unknown, BEHIND, Some(program));
            return;
        }
        let mut split = crate::unit::Split::default();
        let unit = Unit::new(Shell::Posix, program.clone(), args.to_vec(), None);
        crate::launch::add(&mut split, unit, 0);
        self.judge_behind(at, &split);
    }

    /// Judge the database clients of `split`, a line run in a container or
    /// on another machine by the unit at `at`, which hands it its input.
    /// What its grammar cannot read, or a program only known when it runs,
    /// is `unknown` there as it is here.
    fn judge_behind(&mut self, at: usize, split: &crate::unit::Split) {
        let (texts, unseen) = self.passed_on(at);
        let mut inner = Checker::new(split, self.resolver);
        inner.data.behind = self.data.behind + 1;
        inner.data.inherited = Some(Rc::new(Input { texts, unseen }));
        inner.found.extend(
            split
                .findings
                .iter()
                .filter(|finding| matches!(finding.rule, Rule::Unknown | Rule::Unreadable))
                .cloned(),
        );
        for (index, unit) in split.units.iter().enumerate() {
            if let Some(key) = unit.key() {
                inner.data(index, unit, &key);
            }
        }
        self.found.extend(inner.found);
    }
}

/// Whether the options of a `podman exec`, before the first word that is
/// not one, take `-l` (`--latest`), alone or bundled.
fn takes_latest(args: &[Arg], values: &[&str]) -> bool {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let Some(text) = arg.known().filter(|_| is_option(arg)) else {
            return false;
        };
        if text == "--" {
            return false;
        }
        if text == "--latest" {
            return true;
        }
        if values.contains(&text) {
            iter.next();
            continue;
        }
        if let Some(letters) = text.strip_prefix('-').filter(|rest| !rest.starts_with('-')) {
            // The letters up to the first that takes a value.
            for letter in letters.chars() {
                if letter == 'l' {
                    return true;
                }
                if values.contains(&format!("-{letter}").as_str()) {
                    break;
                }
            }
        }
    }
    false
}

/// Where the first word that is not an option is, past the values of the
/// options in `values`.
fn after_options(args: &[Arg], values: &[&str]) -> usize {
    let mut at = 0;
    while let Some(arg) = args.get(at) {
        let Some(text) = arg.known().filter(|_| is_option(arg)) else {
            return at;
        };
        at += 1;
        if text == "--" {
            return at;
        }
        if values.contains(&text) {
            at += 1;
        }
    }
    at
}

/// Options of `docker exec` and `podman exec` that take a value.
const EXEC_VALUES: &[&str] = &[
    "-e",
    "--env",
    "--env-file",
    "-u",
    "--user",
    "-w",
    "--workdir",
    "--detach-keys",
    "--preserve-fds",
    "--preserve-fd",
];

/// Options of `docker compose exec` that take a value.
const COMPOSE_EXEC_VALUES: &[&str] = &["-e", "--env", "-u", "--user", "-w", "--workdir", "--index"];

/// `ssh`'s options that take a value.
const SSH_VALUES: &str = "BbcDEeFIiJLlmOoPpQRSWw";

/// The database clients this rule reads.
const CLIENTS: &[&str] = &[
    "psql",
    "mysql",
    "mariadb",
    "clickhouse-client",
    "clickhouse",
    "sqlcmd",
    "cqlsh",
    "mongosh",
    "mongo",
    "sqlite3",
    "duckdb",
    "redis-cli",
];

/// Whether `arg` is a word that starts with `-`.
fn is_option(arg: &Arg) -> bool {
    arg.known()
        .is_some_and(|text| text.starts_with('-') && text.len() > 1)
}
