//! The rule about data in a database: a statement a database client is
//! given that drops, truncates or empties something.
//!
//! The statement is where the client takes it: an option (`psql -c`,
//! `mysql -e`), an operand (`sqlite3 file 'stmt'`, `redis-cli FLUSHALL`), or
//! text on the line that is fed to it (a here-document, a here-string, an
//! `echo` piped in). A file of statements (`psql -f`, `< seed.sql`) is the
//! workspace's own code and is not read.

use super::Checker;
use crate::unit::{Arg, Unit};
use crate::Rule;

mod reader;

use reader::{Dialect, Reading};

/// How a client takes its statements on the command line.
struct Client {
    dialect: Dialect,
    /// Short options that take a value (`-h host`, `-uroot`).
    short_values: &'static str,
    /// Short options whose value is a statement.
    short_statement: &'static str,
    /// Short options that take a value only when it is attached (`-p`).
    short_optional: &'static str,
    /// Long options that take a value.
    long_values: &'static [&'static str],
    /// Long options whose value is a statement.
    long_statement: &'static [&'static str],
    /// Whether short options bundle (`-Atc`), or each is a word (`-Q`).
    bundles: bool,
    /// Whether a short option may also start with `/` (Windows `sqlcmd`).
    slash: bool,
    /// What the statement is written in.
    language: Language,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Language {
    Sql,
    Mongo,
}

const PSQL: Client = Client {
    dialect: Dialect::Standard,
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
    long_statement: &["command"],
    bundles: true,
    slash: false,
    language: Language::Sql,
};

const MYSQL: Client = Client {
    dialect: Dialect::MySql,
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
    long_statement: &["execute", "init-command"],
    bundles: true,
    slash: false,
    language: Language::Sql,
};

const CLICKHOUSE: Client = Client {
    dialect: Dialect::MySql,
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
    long_statement: &["query"],
    bundles: true,
    slash: false,
    language: Language::Sql,
};

const SQLCMD: Client = Client {
    dialect: Dialect::Standard,
    short_values: "SUPdiohHwvstlazZVmyYfc",
    short_statement: "Qq",
    short_optional: "",
    long_values: &["query", "initial-query", "server", "user-name", "password"],
    long_statement: &["query", "initial-query"],
    bundles: false,
    slash: true,
    language: Language::Sql,
};

const CQLSH: Client = Client {
    dialect: Dialect::Cql,
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
    long_statement: &["execute"],
    bundles: true,
    slash: false,
    language: Language::Sql,
};

const MONGO: Client = Client {
    dialect: Dialect::Standard,
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
    long_statement: &["eval"],
    bundles: true,
    slash: false,
    language: Language::Mongo,
};

/// An argument's text, and whether it came from a word with expansions.
/// The text of a statement, and whether it has expansions in it: what is known
/// of a value, not the source of one that is only known when it runs.
fn statement_text(arg: &Arg) -> Option<(&str, bool)> {
    match arg {
        Arg::Known(text) => Some((text, false)),
        Arg::Template { text, .. } => Some((text, true)),
        Arg::Unknown(_) | Arg::Input => None,
    }
}

/// An argument's text for reading its options.
fn view(arg: &Arg) -> Option<(&str, bool)> {
    match arg {
        Arg::Known(text) => Some((text, false)),
        Arg::Template { text, .. } => Some((text, true)),
        Arg::Unknown(text) => Some((text, true)),
        Arg::Input => None,
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

/// Whether `name` is the long option `long`, or a prefix of it long enough to
/// be one (clients read unique abbreviations).
fn long_is(name: &str, long: &str) -> bool {
    name == long || (name.len() >= 3 && long.starts_with(name))
}

impl Client {
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
                let statement = self.long_statement.iter().any(|long| long_is(name, long));
                let takes = statement || self.long_values.contains(&name);
                if let Some(value) = value {
                    if statement {
                        found.push(carry(value, holes, unknown));
                    }
                } else if takes {
                    let next = iter.next();
                    if statement {
                        found.extend(next.cloned());
                    }
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
                            found.extend(iter.next().cloned());
                        } else {
                            found.push(carry(after, holes, unknown));
                        }
                    } else if after.is_empty() {
                        iter.next();
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
        let Some((text, holes)) = statement_text(arg) else {
            return Reading::UNREADABLE;
        };
        match self.language {
            Language::Sql => reader::sql(text, self.dialect, holes),
            Language::Mongo => reader::mongo(text, holes),
        }
    }
}

/// What the file a `SQLite`-style client opens is: the agent's own, or not.
struct Embedded<'a> {
    file: Option<&'a Arg>,
    statements: Vec<Arg>,
    read_only: bool,
}

/// `sqlite3 [options] [FILE [STATEMENT…]]` and `duckdb` alike: single-dash
/// words, the first operand a file and the rest statements.
fn embedded<'a>(args: &'a [Arg], statement: &[&str], values: &[&str]) -> Embedded<'a> {
    let mut found = Embedded {
        file: None,
        statements: Vec::new(),
        read_only: false,
    };
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let Some((text, _)) = view(arg) else {
            found.statements.push(arg.clone());
            continue;
        };
        match text.strip_prefix('-').filter(|name| !name.is_empty()) {
            Some(name) => {
                let name = name.trim_start_matches('-');
                if name.eq_ignore_ascii_case("readonly") {
                    found.read_only = true;
                } else if statement.contains(&name) {
                    found.statements.extend(iter.next().cloned());
                } else if values.contains(&name) {
                    iter.next();
                }
            }
            None if found.file.is_none() => found.file = Some(arg),
            None => found.statements.push(arg.clone()),
        }
    }
    found
}

/// Whether `file` is a database that lives only in memory.
fn in_memory(file: &Arg) -> bool {
    file.known().is_some_and(|text| {
        text.is_empty() || text == ":memory:" || text.starts_with("file::memory:")
    })
}

/// Redis options that take a value.
const REDIS_VALUES: [&str; 25] = [
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
];

/// `redis-cli [options] COMMAND [ARGUMENT…]`: the operands.
fn redis_operands(args: &[Arg]) -> Vec<&Arg> {
    let mut operands = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.known() {
            Some(text) if operands.is_empty() && text.starts_with('-') && text.len() > 1 => {
                if REDIS_VALUES.contains(&text) {
                    iter.next();
                }
            }
            _ => operands.push(arg),
        }
    }
    operands
}

/// The words of `args` that are plain text, for a piped `echo` or `printf`.
fn said(args: &[Arg]) -> Arg {
    let mut text = String::new();
    let mut holes = false;
    for arg in args {
        if let Some(word) = arg.known() {
            if word.starts_with('-') && text.is_empty() {
                continue;
            }
        }
        let Some((word, hole)) = statement_text(arg) else {
            return Arg::Unknown(String::new());
        };
        holes |= hole;
        if !text.is_empty() {
            text.push(' ');
        }
        text.push_str(word);
    }
    attached(&text, holes)
}

impl Checker<'_> {
    /// The text on the line that is fed to the client at `at`: a
    /// here-string, a here-document, or what a piped `echo` or `printf`
    /// (or a `cat` fed a here-document) says.
    fn fed_statements(&self, at: usize, unit: &Unit) -> Vec<Arg> {
        let mut found: Vec<Arg> = self.split.fed_to(at).cloned().collect();
        let producer = unit
            .stage
            .filter(|stage| stage.index > 0)
            .and_then(|stage| self.producers.get(&(stage.pipeline, stage.index - 1)))
            .and_then(|&producer| Some((producer, self.split.units.get(producer)?)));
        if let Some((producer, unit)) = producer {
            match unit.key().as_deref() {
                Some("echo" | "printf" | "write-output") => found.push(said(&unit.args)),
                Some("cat") if unit.args.is_empty() => {
                    found.extend(self.split.fed_to(producer).cloned());
                }
                _ => {}
            }
        }
        found
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
                let found = embedded(
                    args,
                    &["cmd"],
                    &[
                        "init",
                        "separator",
                        "newline",
                        "nullvalue",
                        "vfs",
                        "mmap",
                        "pagecache",
                        "lookaside",
                        "maxsize",
                        "heap",
                        "memtrace",
                        "key",
                    ],
                );
                self.embedded_client(at, unit, &found);
            }
            "duckdb" => {
                let found = embedded(
                    args,
                    &["c", "s", "cmd"],
                    &["init", "separator", "nullvalue", "newline"],
                );
                self.embedded_client(at, unit, &found);
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
            "mysqladmin" => self.mysqladmin(args),
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
        statements.extend(self.fed_statements(at, unit));
        for statement in &statements {
            let reading = client.read(statement);
            self.judge(reading, Some(statement), false);
        }
    }

    /// `sqlite3` and `duckdb`: a database in a file is the agent's own when
    /// the file is in the workspace, judged like any file.
    fn embedded_client(&mut self, at: usize, unit: &Unit, found: &Embedded<'_>) {
        let mut statements = found.statements.clone();
        statements.extend(self.fed_statements(at, unit));
        let own_file = found.file.is_none_or(|file| {
            in_memory(file) || self.place(unit.shell, unit.scope(), file).harmless()
        });
        let readings: Vec<Reading> = statements.iter().map(embedded_read).collect();
        // `ATTACH` and `.open` reach another file than the one given.
        let moves = readings.iter().any(|reading| reading.moves);
        let own = found.read_only || (own_file && !moves);
        for (statement, reading) in statements.iter().zip(readings) {
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
                    let deletes = matches!(name.to_ascii_lowercase().as_str(), "del" | "unlink");
                    let found = operands
                        .iter()
                        .skip(1)
                        .any(|arg| matches!(arg, Arg::Input) || arg.is_unknown());
                    if deletes && found && self.scans_keys() {
                        reading.destroys = true;
                    }
                }
                None => reading.merge(Reading::UNREADABLE),
            }
        }
        for text in self.fed_statements(at, unit) {
            match statement_text(&text) {
                Some((text, holes)) => reading.merge(reader::redis_lines(text, holes)),
                None => reading.merge(Reading::UNREADABLE),
            }
        }
        self.judge(reading, target, false);
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
        if let Some(drop) = commands.iter().find(|arg| {
            arg.known()
                .is_some_and(|text| text.eq_ignore_ascii_case("drop"))
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

/// What a statement given to `sqlite3` or `duckdb` does.
fn embedded_read(arg: &Arg) -> Reading {
    match statement_text(arg) {
        Some((text, holes)) => reader::sql(text, Dialect::Standard, holes),
        None => Reading::UNREADABLE,
    }
}
