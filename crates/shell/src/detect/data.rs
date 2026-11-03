//! The rule about data in a database: a statement a database client is
//! given that drops, truncates or empties something.
//!
//! The statement is where the client takes it: an option (`psql -c`,
//! `mysql -e`), an operand (`sqlite3 file 'stmt'`, `redis-cli FLUSHALL`), or
//! text on the line that is fed to it (a here-document, a here-string, an
//! `echo` piped in). A file of statements (`psql -f`, `< seed.sql`) is the
//! workspace's own code and is not read.

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use super::Checker;
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
    loose: Loose::No,
    bundles: true,
    slash: false,
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
    loose: Loose::No,
    bundles: true,
    slash: false,
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
    loose: Loose::Only(&["password"]),
    bundles: true,
    slash: false,
    language: Language::Sql(Dialect::ClickHouse),
};

const SQLCMD: Client = Client {
    short_values: "SUPdiohHwvstlazZVmyYfc",
    short_statement: "Qq",
    short_optional: "",
    long_values: &["query", "initial-query", "server", "user-name", "password"],
    long_flags: &["help", "version", "trust-server-certificate"],
    long_statement: &["query", "initial-query"],
    loose: Loose::No,
    bundles: false,
    slash: true,
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
    loose: Loose::No,
    bundles: true,
    slash: false,
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
    loose: Loose::Every,
    bundles: true,
    slash: false,
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

/// `text` as the value of an option attached to it, as an argument.
fn attached(rest: &str, holes: bool) -> Arg {
    if holes {
        Arg::Template {
            text: rest.to_string(),
            source: rest.to_string(),
        }
    } else {
        Arg::Known(rest.to_string())
    }
}

/// The value of an option written attached to it (`-cSQL`), from an argument
/// that may only be known when it runs.
fn carry(rest: &str, holes: bool, unknown: bool) -> Arg {
    if unknown {
        Arg::Unknown(rest.to_string())
    } else {
        attached(rest, holes)
    }
}

/// What a long option of a client does with what follows it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Long {
    /// Its value is a statement.
    Statement,
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
    fn long_option(&self, name: &str) -> Long {
        let long = self.long_option_spelled(name);
        // `mysql --init_command` is `--init-command`.
        if long == Long::Flag && name.contains('_') {
            return self.long_option_spelled(&name.replace('_', "-"));
        }
        long
    }

    fn long_option_spelled(&self, name: &str) -> Long {
        let all = || self.long_values.iter().chain(self.long_flags);
        let kind = |option: &str| {
            if self.long_statement.contains(&option) {
                Long::Statement
            } else if self.long_values.contains(&option) {
                match self.loose {
                    Loose::Every => Long::Loose,
                    Loose::Only(names) if names.contains(&option) => Long::Loose,
                    Loose::No | Loose::Only(_) => Long::Value,
                }
            } else {
                Long::Flag
            }
        };
        if all().any(|option| *option == name) {
            return kind(name);
        }
        let mut starts = all().filter(|option| option.starts_with(name));
        match (starts.next(), starts.next()) {
            (Some(option), None) if !name.is_empty() => kind(option),
            _ => Long::Flag,
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
    /// one.
    fn statements(&self, args: &[Arg]) -> Vec<Arg> {
        let mut found = Vec::new();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            let Some((text, holes)) = view(arg) else {
                continue;
            };
            let unknown = matches!(arg, Arg::Unknown(_));
            if text == "--" {
                break;
            }
            if let Some(name) = text.strip_prefix("--") {
                let (name, value) = match name.split_once('=') {
                    Some((name, value)) => (name, Some(value)),
                    None => (name, None),
                };
                let long = self.long_option(name);
                if let Some(value) = value {
                    if long == Long::Statement {
                        found.push(carry(value, holes, unknown));
                    }
                } else if long == Long::Statement {
                    self.statement_value(&mut iter, &mut found);
                } else if long != Long::Flag {
                    Self::value(&mut iter, long == Long::Loose);
                }
                continue;
            }
            let rest = match text.strip_prefix('-') {
                Some(rest) => rest,
                None if self.slash => match text.strip_prefix('/') {
                    Some(rest) if rest.len() == 1 => rest,
                    _ => continue,
                },
                None => continue,
            };
            for (at, letter) in rest.char_indices() {
                let after = rest.get(at + letter.len_utf8()..).unwrap_or_default();
                if self.short_optional.contains(letter) {
                    break;
                }
                if self.short_values.contains(letter) || self.short_statement.contains(letter) {
                    if self.short_statement.contains(letter) {
                        if after.is_empty() {
                            self.statement_value(&mut iter, &mut found);
                        } else {
                            found.push(carry(after, holes, unknown));
                        }
                    } else if after.is_empty() {
                        Self::value(&mut iter, matches!(self.loose, Loose::Every));
                    }
                    break;
                }
                if !self.bundles {
                    break;
                }
            }
        }
        found
    }

    /// What the statement `arg` does.
    fn read(&self, arg: &Arg) -> Reading {
        read_text(self.language, arg)
    }
}

/// What the text `arg`, written in `language`, does.
fn read_text(language: Language, arg: &Arg) -> Reading {
    let Some((text, holes)) = statement_text(arg) else {
        return Reading::UNREADABLE;
    };
    match language {
        Language::Sql(dialect) => reader::sql(text, dialect, holes),
        Language::Mongo => reader::mongo(text, holes),
        Language::Redis => reader::redis_lines(text, holes),
    }
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
};

/// `sqlite3 [options] [FILE [STATEMENT…]]` and `duckdb` alike: single-dash
/// words, the first operand a file and the rest statements.
fn embedded<'a>(args: &'a [Arg], options: &Options) -> Embedded<'a> {
    let mut found = Embedded {
        file: None,
        statements: Vec::new(),
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

/// Whether the `cat` reads its input, and so passes on the text fed to it:
/// it has no file operand, or `-` or `/dev/stdin` among its operands,
/// whatever its options (none of them takes a value). An operand only known
/// when it runs may be `-`.
fn reads_input(unit: &Unit) -> bool {
    let mut options = true;
    let mut files = false;
    for arg in &unit.args {
        let Some(text) = arg.known() else {
            return true;
        };
        if options && text == "--" {
            options = false;
        } else if matches!(text, "-" | "/dev/stdin" | "/dev/fd/0" | "/proc/self/fd/0") {
            return true;
        } else if !(options && text.starts_with('-')) {
            files = true;
        }
    }
    !files
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
        };
    };
    let written = attached(&text, holes);
    let decoded = |shell: Option<&Quirks>| match shell {
        Some(shell) if unit.shell == Shell::Posix => attached(&echoed(&text, *shell).0, holes),
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
                Printed::Text(text) => texts.push(attached(&text, holey)),
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
        (None, None) => vec![attached("", false); SHELLS.len()],
        (Some(said), _) => said,
    };
    let text = |at: usize| said.get(at).cloned().unwrap_or(NOTHING_KNOWN);
    Said {
        texts: [text(0), text(0), text(1), text(2)],
        newline: false,
        over,
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
    let said =
        joined(&words, separator).map_or(NOTHING_KNOWN, |(text, holes)| attached(&text, holes));
    Said {
        texts: [said.clone(), said.clone(), said.clone(), said],
        newline: true,
        over: false,
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
    attached(&text, holes)
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
}

/// The stage whose output is the input of `unit`.
pub(super) fn feeding(unit: &Unit) -> Option<StageKey> {
    let stage = unit.stage.filter(|stage| stage.index > 0)?;
    Some((stage.pipeline, stage.index - 1))
}

impl Checker<'_> {
    /// The text a stage says to the stage after it: what the `echo`,
    /// `printf` (or `cat` fed a here-document) of every program of the stage
    /// say, `{ echo 'BEGIN;'; echo 'DELETE FROM t;'; } | psql`.
    fn stage_texts(&self, key: StageKey) -> Vec<Arg> {
        let producers = self.stages.get(&key).map(Vec::as_slice).unwrap_or_default();
        // A group too large to read is not read.
        if producers.len() > MAX_PRODUCERS {
            return vec![NOTHING_KNOWN];
        }
        let mut found = Vec::new();
        let mut said = Vec::new();
        // What the stage may still say; once it has said more the rest is
        // not decoded.
        let mut left = TEXT_LIMIT;
        let mut over = false;
        for &producer in producers {
            let Some(unit) = self.split.units.get(producer) else {
                continue;
            };
            let key = unit.key();
            if key.as_deref() == Some("cat") && reads_input(unit) {
                found.extend(self.split.fed_to(producer).cloned());
                continue;
            }
            if over {
                continue;
            }
            let each = match key.as_deref() {
                Some("echo") if unit.shell == Shell::Posix => echo_said(unit),
                Some("echo" | "write-output") => output_said(unit),
                Some("printf") => printf_said(unit, left),
                _ => continue,
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
        if over {
            found.push(NOTHING_KNOWN);
            return found;
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
        found
    }

    /// What the stage `key` says, worked out once.
    pub(super) fn stage_said(&mut self, key: StageKey) -> Rc<Vec<Arg>> {
        if let Some(said) = self.data.said.get(&key) {
            return Rc::clone(said);
        }
        let said = Rc::new(self.stage_texts(key));
        self.data.said.insert(key, Rc::clone(&said));
        said
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
            "redis-cli" => self.redis(at, unit, args),
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
            _ => {}
        }
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
    }

    /// A client of a database server: every database on a server is risky,
    /// since the line cannot tell a scratch one from production.
    fn sql_client(&mut self, at: usize, unit: &Unit, client: &Client, args: &[Arg]) {
        let mut statements = client.statements(args);
        statements.extend(self.split.fed_to(at).cloned());
        for statement in &statements {
            let reading = client.read(statement);
            self.judge(reading, Some(statement), false);
        }
        // What the stage before it says is judged once: every client of the
        // same language finds the same.
        let Some(key) = feeding(unit) else {
            return;
        };
        if self.data.judged.insert((key, client.language)) {
            let said = self.stage_said(key);
            let readings = self.stage_readings(key, client.language);
            for (statement, reading) in said.iter().zip(readings.iter()) {
                self.judge(*reading, Some(statement), false);
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
        match database(name) {
            Database::Memory => true,
            Database::Path(path) => self
                .place(unit.shell, unit.scope(), &Arg::Known(path), Access::Content)
                .harmless(),
            Database::Elsewhere => false,
        }
    }

    /// `sqlite3` and `duckdb`: a database in a file is the agent's own when
    /// the file is in the workspace, judged like any file.
    fn embedded_client(&mut self, at: usize, unit: &Unit, found: &Embedded<'_>, dialect: Dialect) {
        let mut statements = found.statements.clone();
        statements.extend(self.split.fed_to(at).cloned());
        let own_file = match found.file {
            None => true,
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
        let (said, said_readings) = match feeding(unit) {
            Some(key) => (self.stage_said(key), self.stage_readings(key, language)),
            None => (Rc::default(), Rc::default()),
        };
        // `ATTACH` and `.open` reach another file than the one given, and
        // `-readonly` does not hold for it.
        let moves = readings
            .iter()
            .chain(said_readings.iter())
            .any(|reading| reading.moves);
        let own = !moves && (found.read_only || own_file);
        // `.backup` and `.save` replace the file they are given, even for a
        // client opened `-readonly`.
        for statement in &statements {
            self.judge_files(unit, &replaced_files(statement, dialect));
        }
        if let Some(key) = feeding(unit) {
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
        let all = statements
            .iter()
            .zip(readings)
            .chain(said.iter().zip(said_readings.iter().copied()));
        for (statement, reading) in all {
            self.judge(reading, found.file.or(Some(statement)), own);
        }
    }

    /// `redis-cli`: `FLUSHALL`, `FLUSHDB`, and a `DEL` or `UNLINK` of what a
    /// `KEYS` or `SCAN` on the same line finds.
    fn redis(&mut self, at: usize, unit: &Unit, args: &[Arg]) {
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
        if let Some(key) = feeding(unit) {
            for said in self.stage_readings(key, Language::Redis).iter() {
                reading.merge(*said);
            }
        }
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
            unit.key().as_deref() == Some("redis-cli") && {
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
}
