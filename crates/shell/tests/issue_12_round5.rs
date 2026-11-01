//! What a fifth review of `drop_data` found: a PowerShell backtick escape
//! that was not decoded in a string, `Write-Output` words that were joined
//! with spaces, Redis scripts that list keys and delete them, the file that
//! `.backup` and `.save` replace, `mariadb-admin`, and a `WHERE` that was
//! looked for again for each verb of a statement. Each table holds the lines
//! of one finding, safe and risky.

#![allow(
    clippy::disallowed_methods,
    reason = "the guard keeps no clock; only a test times it, to catch a quadratic read"
)]

mod common;

use std::fmt::Write;
use std::time::Duration;

use common::{check, posix, windows};
use milo_guards_shell::{classify, Rule, Shell};

fn posix_rows(safe: &[&str], risky: &[(&str, Rule)]) {
    check(Shell::Posix, &posix(), safe, risky);
}

fn windows_rows(safe: &[&str], risky: &[(&str, Rule)]) {
    check(Shell::PowerShell, &windows(), safe, risky);
}

/// The best of three times the guard takes to judge `line`.
fn took(line: &str) -> Duration {
    (0..3)
        .map(|_| {
            let started = std::time::Instant::now();
            let _ = classify(line, Shell::Posix, &posix());
            started.elapsed()
        })
        .min()
        .unwrap_or_default()
}

/// A line of a quarter of the size takes about a quarter of the time; one
/// that is read in quadratic time takes sixteen times as long. Compared with
/// itself, so a slow or busy machine does not fail it.
fn assert_linear(what: &str, line: impl Fn(usize) -> String) {
    let floor = Duration::from_millis(5);
    let mut last = (Duration::ZERO, Duration::ZERO);
    let linear = (0..3).any(|_| {
        let small = took(&line(16 * 1024));
        let big = took(&line(64 * 1024));
        last = (small, big);
        big <= 10 * small.max(floor)
    });
    assert!(
        linear,
        "{what}: 16 KB took {:?}, 64 KB took {:?}",
        last.0, last.1
    );
}

/// `part` repeated to fill `size` bytes, less `slack` for what is around it.
fn filled(part: &str, size: usize, slack: usize) -> String {
    part.repeat((size - slack) / part.len())
}

const NL: &str = "\n";

#[test]
fn a_backtick_in_an_expandable_string_is_the_character_it_names() {
    let body = "echo hi`nRemove-Item C:\\Users\\me -Recurse";
    let here = format!("@\"{NL}{body}{NL}\"@");
    windows_rows(
        &[
            // Nothing that a backtick makes of these is more than a message.
            "psql -c \"SELECT 1;`nSELECT 2\"",
            "psql -c \"SELECT `u{31}\"",
            "psql -c \"SELECT 1`tFROM t\"",
            "\"SELECT 1;`nSELECT 2\" | psql",
            // Single quotes take a backtick as it is.
            "psql -c 'SELECT 1;`nDROP TABLE t'",
            "Write-Output 'SELECT 1' 'SELECT 2' | psql",
        ],
        &[
            // A here-string whose body holds a line break made by a backtick.
            (&format!("iex {here}"), Rule::Delete),
            (&format!("powershell -Command {here}"), Rule::Delete),
            (&format!("pwsh -c {here}"), Rule::Delete),
            (&format!("Invoke-Expression -Command {here}"), Rule::Delete),
            (&format!("cmd /c {here}"), Rule::Delete),
            (
                &format!("bash -c @\"{NL}echo hi`nrm -rf ~{NL}\"@"),
                Rule::Delete,
            ),
            // Statements with a break or a tab between their words.
            ("psql -c \"BEGIN;`nTRUNCATE t;`nCOMMIT;\"", Rule::DropData),
            ("psql -c \"SELECT 1;`nDROP TABLE t\"", Rule::DropData),
            ("mysql -e \"SELECT 1 #`nDROP TABLE t\"", Rule::DropData),
            ("psql -c \"DROP`tTABLE t\"", Rule::DropData),
            ("psql -c \"SELECT 1;`r`nDROP TABLE t\"", Rule::DropData),
            ("psql -c \"SELECT 1;`u{a}DROP TABLE t\"", Rule::DropData),
            ("psql -c \"SELECT 1 --`nDROP TABLE t\"", Rule::DropData),
            ("\"SELECT 1;`nDROP TABLE t\" | psql", Rule::DropData),
            (
                &format!("@\"{NL}SELECT 1;`nDROP TABLE t{NL}\"@ | psql"),
                Rule::DropData,
            ),
        ],
    );
}

#[test]
fn powershell_sends_each_argument_to_a_program_as_a_line() {
    windows_rows(
        &[
            "Write-Output 'SELECT 1' 'SELECT 2' | psql",
            "echo 'SELECT 1' 'SELECT 2' | psql",
            "Write-Output 'SELECT 1' | psql",
        ],
        &[
            (
                "Write-Output 'SELECT 1 --' 'DROP TABLE t' | psql",
                Rule::DropData,
            ),
            ("echo 'SELECT 1 --' 'DROP TABLE t' | psql", Rule::DropData),
            (
                "Write-Output 'SELECT 1 #' 'DROP TABLE t' | mysql",
                Rule::DropData,
            ),
            (
                "Write-Output 'SELECT 1;' 'DROP TABLE t' | psql",
                Rule::DropData,
            ),
            // One argument still says what it says.
            ("Write-Output 'DROP TABLE t' | psql", Rule::DropData),
        ],
    );
}

#[test]
fn a_redis_script_that_lists_keys_and_deletes_them_destroys() {
    posix_rows(
        &[
            // The keys a script is given are not a listing.
            "redis-cli eval \"return redis.call('del', KEYS[1])\" 1 k",
            "redis-cli eval \"return redis.call('get', KEYS[1])\" 1 k",
            "redis-cli eval \"return redis.call('unlink', KEYS[1], KEYS[2])\" 2 a b",
            // A listing with nothing deleted.
            "redis-cli eval \"return redis.call('keys', '*')\" 0",
            "redis-cli eval \"return redis.call('scan', 0)\" 0",
            "redis-cli evalsha abc 1 k",
        ],
        &[
            (
                "redis-cli eval \"return redis.call('del', unpack(redis.call('keys', '*')))\" 0",
                Rule::DropData,
            ),
            (
                "redis-cli eval \"for _,k in ipairs(redis.call('keys','*')) do redis.call('del',k) end\" 0",
                Rule::DropData,
            ),
            (
                "redis-cli eval \"return redis.call('unlink', unpack(redis.call('scan', 0)))\" 0",
                Rule::DropData,
            ),
            (
                "redis-cli eval \"return redis.call('DEL', unpack(redis.call('KEYS', ARGV[1])))\" 0 'user:*'",
                Rule::DropData,
            ),
            (
                "redis-cli eval \"return redis.call([[del]], redis.call([==[keys]==], '*'))\" 0",
                Rule::DropData,
            ),
            (
                "redis-cli eval_ro \"redis.call('del', redis.call('keys', '*'))\" 0",
                Rule::DropData,
            ),
            // Text fed to it, a line at a time.
            (
                "echo \"eval \\\"return redis.call('del', unpack(redis.call('keys','*')))\\\" 0\" | redis-cli",
                Rule::DropData,
            ),
            // The flushes are still found.
            ("redis-cli eval \"redis.call('flushall')\" 0", Rule::DropData),
        ],
    );
}

#[test]
fn sqlite_backup_and_save_replace_the_file_they_are_given() {
    posix_rows(
        &[
            // A copy in the workspace or the temporary folder.
            "sqlite3 data.db '.backup backup.db'",
            "sqlite3 data.db '.backup /tmp/backup.db'",
            "sqlite3 data.db '.backup temp /tmp/backup.db'",
            "sqlite3 data.db '.save ./copy.db'",
            "sqlite3 -readonly data.db '.backup backup.db'",
            "sqlite3 data.db '.backup :memory:'",
            // Names that are not these commands.
            "sqlite3 data.db '.bail on'",
            "sqlite3 data.db '.ba on'",
            "sqlite3 data.db '.b ~/x.db'",
            "sqlite3 data.db '.schema'",
            // `VACUUM INTO` and `.clone` refuse a file that exists.
            "sqlite3 data.db \"VACUUM INTO '/home/me/y.db'\"",
            "sqlite3 data.db '.clone /home/me/y.db'",
        ],
        &[
            ("sqlite3 data.db '.backup /home/me/y.db'", Rule::DropData),
            ("sqlite3 data.db '.save ~/prod.db'", Rule::DropData),
            (
                "sqlite3 -readonly data.db '.backup ~/prod.db'",
                Rule::DropData,
            ),
            // The start of a name that no other command has.
            ("sqlite3 data.db '.bac ~/prod.db'", Rule::DropData),
            ("sqlite3 data.db '.back ~/prod.db'", Rule::DropData),
            ("sqlite3 data.db '.backu ~/prod.db'", Rule::DropData),
            ("sqlite3 data.db '.sav ~/prod.db'", Rule::DropData),
            ("sqlite3 data.db '.sa ~/prod.db'", Rule::DropData),
            ("sqlite3 data.db '.BACKUP ~/prod.db'", Rule::DropData),
            // A database name before the file, or an option.
            (
                "sqlite3 data.db '.backup temp /home/me/y.db'",
                Rule::DropData,
            ),
            ("sqlite3 data.db '.backup main ../y.db'", Rule::DropData),
            (
                "sqlite3 data.db '.backup \"/home/me/y db\"'",
                Rule::DropData,
            ),
            // After another statement, or fed to the client.
            (
                "sqlite3 data.db 'SELECT 1;' '.backup ~/prod.db'",
                Rule::DropData,
            ),
            ("echo '.backup ~/prod.db' | sqlite3 data.db", Rule::DropData),
            (
                "sqlite3 data.db <<EOF\n.backup ~/prod.db\nEOF",
                Rule::DropData,
            ),
            ("sqlite3 data.db <<< '.save ~/prod.db'", Rule::DropData),
            ("duckdb x.db '.backup /home/me/y.db'", Rule::DropData),
            // A file only the shell knows.
            ("sqlite3 data.db \".backup $x\"", Rule::Unknown),
            // Still `.restore`.
            ("sqlite3 ~/x.db '.restore b.db'", Rule::DropData),
        ],
    );
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn what_a_stage_backs_up_is_judged_where_each_client_runs() {
    posix_rows(
        &[
            "{ echo '.backup backup.db'; } | { sqlite3 d.db; sqlite3 e.db; }",
            "{ echo '.backup /tmp/b.db'; } | sqlite3 d.db",
        ],
        &[
            (
                "{ echo '.backup ~/prod.db'; } | { sqlite3 d.db; sqlite3 e.db; }",
                Rule::DropData,
            ),
            (
                "{ echo '.backup backup.db'; } | { sqlite3 d.db; cd /home/me; sqlite3 e.db; }",
                Rule::DropData,
            ),
            (
                "{ echo '.backup ~/prod.db'; echo '.save ~/x.db'; } | duckdb d.db",
                Rule::DropData,
            ),
        ],
    );
    // Many clients of a stage that backs up to many files.
    assert_linear("a stage of backups to many clients", |size| {
        let mut said = String::new();
        for at in 0..size / 80 {
            let _ = write!(said, "echo '.backup /home/me/{at}.db'; ");
        }
        let clients = filled("sqlite3 ~/x.db; ", size / 2, 40);
        format!("{{ {said}}} | {{ {clients}}}")
    });
}

#[test]
fn mariadb_admin_is_mysqladmin() {
    posix_rows(
        &[
            "mariadb-admin status",
            "mariadb-admin -u root ping",
            "mysqladmin status",
        ],
        &[
            ("mariadb-admin drop prod", Rule::DropData),
            ("mariadb-admin -u root drop prod", Rule::DropData),
            ("mariadb-admin dro prod", Rule::DropData),
            ("mysqladmin drop prod", Rule::DropData),
        ],
    );
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn a_where_is_found_for_every_verb_in_one_pass() {
    // Each verb that needs a `WHERE` used to look for it to the end of the
    // text, and a verb in an open parenthesis never found the end.
    assert_linear("psql -c DELETE (DELETE (…", |size| {
        format!("psql -c '{}'", filled("DELETE (", size, 20))
    });
    assert_linear("mysql -e DELETE (DELETE (…", |size| {
        format!("mysql -e '{}'", filled("DELETE (", size, 20))
    });
    assert_linear("UPDATE (UPDATE (…", |size| {
        format!("psql -c '{}'", filled("UPDATE (", size, 20))
    });
    // A group whose escapes make the shells read it differently.
    assert_linear("a piped group of escapes", |size| {
        let part = filled("\\x41\\101 DELETE (", size, 100);
        format!("{{ echo -n '{part}'; echo -n '\\x41\\101 '; echo '\\x41\\101 '; }} | mysql")
    });
    // `THEN DELETE` looked back to a `WHEN` for each one.
    assert_linear("MERGE … THEN DELETE …", |size| {
        format!("psql -c 'MERGE {}'", filled("THEN DELETE ", size, 20))
    });
    // A `WHERE` after each verb of a nest.
    assert_linear("DELETE (DELETE (… WHERE …", |size| {
        let opens = filled("DELETE (", size / 2, 10);
        let closes = filled(") WHERE x ", size / 2, 10);
        format!("psql -c '{opens}{closes}'")
    });
}

#[test]
fn a_where_is_still_found_where_it_belongs() {
    posix_rows(
        &[
            "psql -c 'DELETE FROM t WHERE id = 1'",
            "psql -c 'DELETE FROM t WHERE id IN (SELECT id FROM u)'",
            "psql -c 'WITH d AS (DELETE FROM t WHERE x = 1 RETURNING *) SELECT * FROM d'",
            "psql -c 'DELETE FROM t WHERE id = 1; UPDATE u SET a = 1 WHERE b = 2'",
            "psql -c 'UPDATE t SET a = (SELECT 1) WHERE id = 1'",
            "psql -c 'MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN DELETE WHEN NOT MATCHED THEN INSERT VALUES (1)'",
        ],
        &[
            ("psql -c 'DELETE FROM t'", Rule::DropData),
            ("psql -c 'DELETE FROM t WHERE 1 = 1'", Rule::DropData),
            ("psql -c 'DELETE FROM t WHERE (1)'", Rule::DropData),
            (
                "psql -c 'WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d WHERE x = 1'",
                Rule::DropData,
            ),
            (
                "psql -c 'DELETE FROM a DELETE FROM b WHERE x = 1'",
                Rule::DropData,
            ),
            (
                "psql -c 'SELECT (DELETE FROM t) WHERE x = 1'",
                Rule::DropData,
            ),
            (
                "psql -c 'DELETE FROM t WHERE id = 1; UPDATE u SET a = 1'",
                Rule::DropData,
            ),
            (
                "psql -c 'WITH x AS (SELECT 1) MERGE INTO t USING x ON true WHEN MATCHED THEN DELETE; DELETE FROM u'",
                Rule::DropData,
            ),
        ],
    );
}
