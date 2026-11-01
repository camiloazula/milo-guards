//! What a second review of `drop_data` found: statements a database client
//! is given that the guard read as one thing and the client ran as another,
//! and lines the guard read in quadratic time. Each table holds the lines of
//! one finding, safe and risky.

#![allow(
    clippy::disallowed_methods,
    reason = "the guard keeps no clock; only a test times it, to catch a quadratic read"
)]

mod common;

use common::{check, posix, windows};
use milo_guards_shell::{classify, Rule, Shell};

fn posix_rows(safe: &[&str], risky: &[(&str, Rule)]) {
    check(Shell::Posix, &posix(), safe, risky);
}

/// `part` repeated as often as a line may hold it.
fn repeated(part: &str) -> String {
    part.repeat(64 * 1024 / part.len())
}

#[test]
fn many_clients_on_one_line_are_read_in_linear_time() {
    // Each `redis-cli del` that is given keys asks whether the line lists
    // keys; each client asks for the text fed to it. Neither may walk every
    // unit or every text of the line again.
    for line in [repeated("redis-cli del $x; "), repeated("psql <<< x; ")] {
        let started = std::time::Instant::now();
        let _ = classify(&line, Shell::Posix, &posix());
        let took = started.elapsed();
        assert!(
            took < std::time::Duration::from_millis(200),
            "{} bytes took {took:?}",
            line.len()
        );
    }
}

#[test]
fn printf_reads_octal_as_every_shell_does() {
    posix_rows(
        &[
            r"printf 'SELECT \061;\n' | psql",
            r"printf 'SELECT 1;\0121' | psql",
            r"printf 'SELECT 1;\n' | psql",
            // `%b` and `echo` take `\0NNN`.
            r"printf '%b' 'SELECT \0061;' | psql",
        ],
        &[
            // `\0121` is a newline and a `1` in a format, not a `Q`: the
            // DROP is not in the comment.
            (
                r"printf 'SELECT -- x\0121 AS a; DROP TABLE t;' | psql",
                Rule::DropData,
            ),
            // `%b` and `echo` read `\0121` as a `Q`.
            (
                r"printf '%b' 'SELECT -- x\0121 AS a;\nDROP TABLE t;' | psql",
                Rule::DropData,
            ),
            (
                r"printf '%b' 'SELECT 1;\0121\nDROP TABLE t;' | psql",
                Rule::DropData,
            ),
            (r"printf '%b' 'D\0122OP TABLE t' | psql", Rule::DropData),
            // The first digit of an escape in a format may be any octal one.
            (r"printf 'DROP TABLE t;\101' | psql", Rule::DropData),
        ],
    );
}

#[test]
fn printf_and_echo_read_what_a_shell_leaves_as_written() {
    posix_rows(
        &[],
        &[
            // dash's `printf` leaves `\xHH` as written, and decodes `\n`:
            // the quote is not one there, and the DROP runs.
            (
                r"printf 'SELECT 1;\x27\nDROP TABLE t;\n\x27' | psql",
                Rule::DropData,
            ),
            (
                r"echo -e 'SELECT 1;\x27\nDROP TABLE t;\n\x27' | psql",
                Rule::DropData,
            ),
            (
                r"echo 'SELECT 1;\x27\nDROP TABLE t;\n\x27' | psql",
                Rule::DropData,
            ),
            (
                r"printf '%b' 'SELECT 1;\x27\nDROP TABLE t;\n\x27' | psql",
                Rule::DropData,
            ),
            // Where bash's `echo -e` and zsh's leave `\NNN` as written, dash
            // decodes it.
            (
                r"echo 'SELECT 1;\47\nDROP TABLE t;\n\47' | psql",
                Rule::DropData,
            ),
            // Bash decodes `\'` and zsh and dash leave it.
            (
                r#"printf "SELECT 'a\\'; DROP TABLE t; --'" | psql"#,
                Rule::DropData,
            ),
            // `\c` in a format is read differently: unknown.
            (r"printf 'SELECT 1;\c' | psql", Rule::Unknown),
        ],
    );
}

#[test]
fn dynamic_sql_in_text_on_the_line_is_read() {
    posix_rows(
        &[
            r#"psql -c "DO 'BEGIN PERFORM 1; END'""#,
            r#"psql -c "DO \$\$ BEGIN PERFORM 1; END \$\$""#,
            r#"psql -c "DO \$\$ BEGIN CREATE TRIGGER x AFTER INSERT ON t FOR EACH ROW EXECUTE FUNCTION f(); END \$\$""#,
            r#"mysql -e "PREPARE s FROM 'SELECT 1'; EXECUTE s""#,
            r#"sqlcmd -Q "EXEC sp_MSforeachtable 'SELECT COUNT(*) FROM ?'""#,
            r#"sqlcmd -Q "EXEC('SELECT 1')""#,
            r#"sqlcmd -Q "EXECUTE ('SELECT 1')""#,
            r#"sqlcmd -Q "EXEC sp_executesql N'SELECT 1'""#,
            r#"sqlcmd -Q "EXEC sp_executesql N'DELETE FROM t WHERE a = ''x''', N'@p int', @p = 1""#,
            r#"sqlcmd -Q "EXEC sys.sp_executesql @stmt = N'SELECT 1'""#,
        ],
        &[
            (r#"psql -c "DO 'BEGIN DROP TABLE t; END'""#, Rule::DropData),
            (
                r#"psql -c "DO LANGUAGE plpgsql 'BEGIN DELETE FROM t; END'""#,
                Rule::DropData,
            ),
            (
                r#"psql -c "DO 'BEGIN EXECUTE ''DROP TABLE t''; END'""#,
                Rule::Unknown,
            ),
            (
                r#"psql -c "DO \$\$ DECLARE r RECORD; BEGIN FOR r IN (SELECT tablename FROM pg_tables WHERE schemaname = 'public') LOOP EXECUTE 'DROP TABLE IF EXISTS ' || quote_ident(r.tablename) || ' CASCADE'; END LOOP; END \$\$;""#,
                Rule::Unknown,
            ),
            (
                r#"psql -c "DO \$\$ BEGIN EXECUTE format('DROP TABLE %I', 't'); END \$\$""#,
                Rule::Unknown,
            ),
            (
                r#"mysql -e "PREPARE s FROM 'DROP TABLE t'; EXECUTE s""#,
                Rule::DropData,
            ),
            (r#"mysql -e "PREPARE s FROM @q; EXECUTE s""#, Rule::Unknown),
            (
                r#"sqlcmd -Q "EXEC sp_MSforeachtable 'DELETE FROM ?'""#,
                Rule::DropData,
            ),
            (
                r#"sqlcmd -Q "EXEC sp_MSforeachdb @command1 = N'DROP TABLE t'""#,
                Rule::DropData,
            ),
            (r#"sqlcmd -Q "EXEC sp_MSforeachtable @c""#, Rule::Unknown),
            (r#"sqlcmd -Q "EXEC('DROP TABLE t')""#, Rule::DropData),
            (r#"sqlcmd -Q "EXECUTE('DROP TABLE t')""#, Rule::DropData),
            (
                r#"sqlcmd -Q "EXEC('DELETE FROM t WHERE a = ''x''; DROP TABLE t')""#,
                Rule::DropData,
            ),
            (r#"sqlcmd -Q "EXEC('DROP ' + @t)""#, Rule::Unknown),
            (r#"sqlcmd -Q "EXEC(@sql)""#, Rule::Unknown),
            (
                r#"sqlcmd -Q "EXEC sp_executesql N'DROP TABLE t'""#,
                Rule::DropData,
            ),
            (r#"sqlcmd -Q "EXEC sp_executesql @sql""#, Rule::Unknown),
            (
                r#"sqlcmd -Q "EXEC [sp_executesql] N'DROP TABLE t'""#,
                Rule::DropData,
            ),
            (
                r#"sqlcmd -Q "EXEC sp_executesql N'DROP ' + @t""#,
                Rule::Unknown,
            ),
            (r#"sqlcmd -Q "EXEC('$verb TABLE t')""#, Rule::Unknown),
        ],
    );
}

#[test]
fn sql_in_sql_is_read_a_few_levels_deep() {
    let mut text = "DROP TABLE t".to_string();
    for _ in 0..5 {
        text = format!("EXEC('{}')", text.replace('\'', "''"));
    }
    let line = format!("sqlcmd -Q \"{text}\"");
    posix_rows(&[], &[(&line, Rule::DropData)]);
    // Deeper than that is not read, and what is not read is unknown.
    let mut text = "DROP TABLE t".to_string();
    for _ in 0..12 {
        text = format!("EXEC('{}')", text.replace('\'', "''"));
    }
    let line = format!("sqlcmd -Q \"{text}\"");
    posix_rows(&[], &[(&line, Rule::Unknown)]);
    // A long chain of nested `DO` strings is read without going deep.
    let mut body = "SELECT 1".to_string();
    for level in 0..2_000 {
        body = format!("DO $t{level}$ {body} $t{level}$");
    }
    let line = format!("psql -c '{body}'");
    let started = std::time::Instant::now();
    let assessment = classify(&line, Shell::Posix, &posix());
    assert!(started.elapsed() < std::time::Duration::from_millis(200));
    assert!(!assessment.is_safe());
}

#[test]
fn on_before_a_verb_is_a_statement_unless_it_is_a_rule() {
    posix_rows(
        &[
            r#"psql -c "CREATE TEMP TABLE x (a int) ON COMMIT DELETE ROWS""#,
            r#"psql -c "CREATE TEMP TABLE x (a int) ON COMMIT DROP""#,
            r#"sqlcmd -Q "SET NOCOUNT ON DELETE FROM users WHERE id = 1""#,
            r#"psql -c "CREATE TABLE t (p int REFERENCES p(id) ON DELETE SET NULL ON UPDATE NO ACTION)""#,
            r#"psql -c "CREATE TABLE t (p int REFERENCES p(id) ON DELETE RESTRICT ON UPDATE CASCADE)""#,
            r#"mysql -e "CREATE TABLE t (a timestamp ON UPDATE CURRENT_TIMESTAMP)""#,
            r#"psql -c "CREATE RULE r AS ON DELETE TO t DO INSTEAD NOTHING""#,
            r#"psql -c "CREATE RULE r AS ON UPDATE TO t DO INSTEAD NOTHING""#,
        ],
        &[
            (
                r#"sqlcmd -Q "SET NOCOUNT ON DELETE FROM users""#,
                Rule::DropData,
            ),
            (
                "sqlcmd -Q \"SET QUOTED_IDENTIFIER ON\nDELETE FROM t\"",
                Rule::DropData,
            ),
            (
                r#"sqlcmd -Q "SET ANSI_NULLS ON UPDATE users SET a = 1""#,
                Rule::DropData,
            ),
            (
                r#"sqlcmd -Q "SET NOCOUNT ON UPDATE users SET a = 1 SELECT 1 WHERE b = 2""#,
                Rule::DropData,
            ),
            (
                r#"psql -c "CREATE TEMP TABLE x (a int) ON COMMIT DELETE ROWS; DELETE FROM t""#,
                Rule::DropData,
            ),
        ],
    );
}

#[test]
fn sqlite_skips_a_line_that_starts_with_a_hash() {
    posix_rows(
        &[
            "sqlite3 ~/x.db <<'EOF'\n# a note\nSELECT 1;\nEOF",
            "sqlite3 ~/x.db <<'EOF'\nSELECT 1;\n# it's a note\nSELECT 2;\nEOF",
            "duckdb ~/x.db <<'EOF'\n# a note\nSELECT 1;\nEOF",
            // A `#` that is not at the start of a line is not a comment, so
            // the quote after it opens a string.
            r#"sqlite3 ~/x.db "SELECT 1 # ' ; DROP TABLE t; --'""#,
            "sqlite3 ~/x.db <<'EOF'\nSELECT 1; # '\nDROP TABLE t; --'\nEOF",
            // Nor when a statement is pending.
            "sqlite3 ~/x.db <<'EOF'\nSELECT 1\n# ';\nDROP TABLE t; --'\nEOF",
            // Only SQLite and DuckDB skip it: in PostgreSQL the quote opens a
            // string.
            "psql <<'EOF'\n# it's\nDROP TABLE t;\n# '\nEOF",
        ],
        &[
            (
                "sqlite3 ~/x.db <<'EOF'\n# it's\nDROP TABLE t;\n# '\nEOF",
                Rule::DropData,
            ),
            (
                "sqlite3 ~/x.db <<'EOF'\nSELECT 1;\n# it's\nDROP TABLE t;\n# '\nEOF",
                Rule::DropData,
            ),
            (
                "duckdb ~/x.db <<'EOF'\n# it's\nDROP TABLE t;\n# '\nEOF",
                Rule::DropData,
            ),
            (
                "sqlite3 ~/x.db <<'EOF'\n.mode csv\n# it's\nDROP TABLE t;\n# '\nEOF",
                Rule::DropData,
            ),
        ],
    );
}

#[test]
fn a_backslash_ends_a_psql_command_and_starts_the_next() {
    posix_rows(
        &[
            r"psql -c '\set x 1'",
            r"psql -c '\set x 1 \set y 2'",
            r#"psql -c '\set x "a b" \echo done'"#,
            r"psql -c '\echo C:\\tmp'",
            "psql <<'EOF'\n\\set x 1\n\\set y 2\nEOF",
        ],
        &[
            (r"psql -c '\set x 1 \! touch /tmp/pwn'", Rule::Unknown),
            (
                "psql <<'EOF'\n\\set x 1 \\! touch /tmp/pwn\nEOF",
                Rule::Unknown,
            ),
            (
                r#"psql -c "SELECT 'DROP TABLE t' \set x 1 \gexec""#,
                Rule::Unknown,
            ),
            (r"psql -c '\echo hi \copy t from program x'", Rule::Unknown),
            (r"psql -c '\set x 1 \g \\ DROP TABLE t'", Rule::DropData),
            (r"psql -c '\set x 1 \o |cat'", Rule::Unknown),
        ],
    );
}

#[test]
fn duckdb_and_clickhouse_have_the_quoting_they_have() {
    posix_rows(
        &[
            // DuckDB: `$tag$` and `E'…'` strings, which hide what they hold.
            r#"duckdb ~/x.duckdb "SELECT \$a\$; DROP TABLE t; \$a\$""#,
            r#"duckdb ~/x.duckdb "SELECT E'a\\'; DROP TABLE t; --'""#,
            // ClickHouse: block comments nest.
            r#"clickhouse-client -q "/* /* ; DROP TABLE t */ */ SELECT 1""#,
        ],
        &[
            // What looked like a string is code.
            (
                r#"duckdb ~/x.duckdb "SELECT \$\$'\$\$; DROP TABLE t; SELECT \$\$'\$\$""#,
                Rule::DropData,
            ),
            (
                r#"duckdb ~/x.duckdb "SELECT E'a\\' ; SELECT '; DROP TABLE t; --'""#,
                Rule::DropData,
            ),
            // The comment ends at the last `*/`; the quote after the DROP is
            // never closed.
            (
                r#"clickhouse-client -q "/* /* */ ' */ DROP TABLE t; SELECT '""#,
                Rule::Unknown,
            ),
            (
                r#"clickhouse-client -q "/* /* */ ' */ SELECT 1; DROP TABLE t; /* ' */""#,
                Rule::DropData,
            ),
        ],
    );
}

#[test]
fn redis_options_that_take_a_value_do_not_move_the_command() {
    posix_rows(
        &[
            "redis-cli --tls --cacertdir /etc/ssl/certs GET k",
            "redis-cli --show-pushes no GET k",
            "redis-cli -X tag GET k",
            "redis-cli --quoted-pattern x --scan",
            "redis-cli --intrinsic-latency 5",
        ],
        &[
            (
                "redis-cli --tls --cacertdir /etc/ssl/certs FLUSHALL",
                Rule::DropData,
            ),
            ("redis-cli --show-pushes no FLUSHALL", Rule::DropData),
            ("redis-cli -X tag FLUSHALL", Rule::DropData),
            ("redis-cli --quoted-pattern x FLUSHALL", Rule::DropData),
            ("redis-cli --intrinsic-latency 5 FLUSHDB", Rule::DropData),
        ],
    );
}

#[test]
fn clickhouse_system_statements_are_not_programs_or_drops() {
    posix_rows(
        &[
            "clickhouse-client -q 'SYSTEM FLUSH LOGS'",
            "clickhouse-client -q 'SYSTEM RELOAD DICTIONARIES'",
            "clickhouse-client -q 'SYSTEM DROP DNS CACHE'",
            "clickhouse-client -q 'SYSTEM DROP MARK CACHE'",
            "clickhouse-client -q 'SYSTEM DROP UNCOMPRESSED CACHE'",
            "clickhouse client -q 'SYSTEM FLUSH LOGS'",
        ],
        &[
            // MySQL's `system` runs a program; nothing else has one.
            ("mysql -e 'system ls'", Rule::Unknown),
            ("mariadb -e 'system rm -rf x'", Rule::Unknown),
            // A `DROP` that is not after a leading `SYSTEM` still drops.
            (
                "clickhouse-client -q 'SYSTEM FLUSH LOGS; DROP TABLE t'",
                Rule::DropData,
            ),
            ("clickhouse-client -q 'DROP TABLE t'", Rule::DropData),
        ],
    );
}

#[test]
fn sqlite_restore_replaces_the_database() {
    posix_rows(
        &[
            // The agent's own file, as for a DROP.
            "sqlite3 ./x.db '.restore empty.db'",
            "sqlite3 :memory: '.restore empty.db'",
            "sqlite3 -readonly ~/x.db '.restore empty.db'",
            "sqlite3 ~/x.db '.backup out.db'",
        ],
        &[
            ("sqlite3 ~/x.db '.restore empty.db'", Rule::DropData),
            ("sqlite3 ~/x.db \".restore main empty.db\"", Rule::DropData),
            (
                "sqlite3 ~/x.db <<'EOF'\n.restore empty.db\nEOF",
                Rule::DropData,
            ),
            (
                "sqlite3 ./x.db '.restore other.db' '.open ~/y.db' '.restore z.db'",
                Rule::DropData,
            ),
        ],
    );
}

#[test]
fn a_long_option_is_any_unique_start_of_one() {
    posix_rows(
        &[
            // `--c` is ambiguous (`--command`, `--csv`): psql refuses to run.
            "psql --c 'DROP TABLE users'",
            // Not a statement option: its value is read as the next one.
            "psql --host h --dbname db -c 'SELECT 1'",
            "psql --ho h 'DROP TABLE users'",
            "psql --user-typo x",
            "mysql --e 'DROP TABLE t'",
            "mysql --host h 'DROP TABLE t'",
        ],
        &[
            ("psql --co 'DROP TABLE users'", Rule::DropData),
            ("psql --com 'DROP TABLE users'", Rule::DropData),
            ("psql --command 'DROP TABLE users'", Rule::DropData),
            ("psql --comm='DROP TABLE users'", Rule::DropData),
            ("psql --db x --co 'DROP TABLE users'", Rule::DropData),
            ("mysql --ex 'DROP TABLE t'", Rule::DropData),
            ("mysql --exec='DROP TABLE t'", Rule::DropData),
            ("mysql --init_command='DROP TABLE t'", Rule::DropData),
            ("mysql --init 'DROP TABLE t'", Rule::DropData),
            ("clickhouse-client --query 'DROP TABLE t'", Rule::DropData),
            ("sqlcmd --quer 'DROP TABLE t'", Rule::DropData),
            ("cqlsh --exe 'DROP TABLE t'", Rule::DropData),
            ("mongosh --ev 'db.dropDatabase()'", Rule::DropData),
        ],
    );
}

#[test]
fn on_powershell_and_cmd_an_expansion_in_a_statement_is_unknown() {
    // An expansion in a double-quoted word is not read as a word there:
    // what it holds is only known when it runs.
    check(
        Shell::PowerShell,
        &windows(),
        &[
            r#"psql -c "SELECT 1""#,
            r"psql -c 'DELETE FROM t WHERE id = $id'",
            r#"psql -c "DELETE FROM t WHERE id = 3""#,
        ],
        &[
            (r#"psql -c "DELETE FROM t WHERE id = $id""#, Rule::Unknown),
            (
                r#"psql -c "SELECT * FROM t WHERE name = '$name'""#,
                Rule::Unknown,
            ),
            (r#"psql -c "DROP TABLE t; $x""#, Rule::Unknown),
        ],
    );
    check(
        Shell::Cmd,
        &windows(),
        &[
            r#"psql -c "SELECT 1""#,
            r#"psql -c "DELETE FROM t WHERE id = 3""#,
        ],
        &[
            (r#"psql -c "DELETE FROM t WHERE id = %id%""#, Rule::Unknown),
            (r#"psql -c "DROP TABLE t; %x%""#, Rule::Unknown),
        ],
    );
}
