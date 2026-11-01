//! What a review of `drop_data` found: statements a database client is given
//! that the guard read as one thing and the client ran as another. Each table
//! holds the lines of one finding, safe and risky.

#![allow(
    clippy::disallowed_methods,
    reason = "the guard keeps no clock; only a test times it, to catch a quadratic read"
)]

mod common;

use common::{check, posix, windows};
use milo_guards_shell::{Rule, Shell};

fn posix_rows(safe: &[&str], risky: &[(&str, Rule)]) {
    check(Shell::Posix, &posix(), safe, risky);
}

#[test]
fn printf_and_echo_decode_their_escapes() {
    posix_rows(
        &[
            r"printf 'SELECT 1;\n' | psql",
            r"printf '%s\n' 'SELECT 1' | psql",
            r"printf 'SELECT %d;\n' 1 | psql",
            r#"printf 'SELECT %s;\n' "$id" | psql"#,
            r"printf '%%\n' | psql",
            r"echo 'SELECT 1;\nSELECT 2;' | psql",
            r"echo -e 'SELECT 1;\tSELECT 2;' | psql",
            r"echo -n 'SELECT 1' | psql",
            r"printf 'SELECT 1;\n' | redis-cli",
            "printf 'SELECT 1;\\n' | sqlite3 data.db",
        ],
        &[
            (
                r"printf 'SELECT 1;\nDROP TABLE users;\n' | psql",
                Rule::DropData,
            ),
            (
                r"printf 'BEGIN;\nDELETE FROM users;\nCOMMIT;\n' | psql app",
                Rule::DropData,
            ),
            (
                r"echo -e 'SELECT 1;\nDROP TABLE users;' | psql",
                Rule::DropData,
            ),
            (
                r"echo 'SELECT 1;\nDROP TABLE users;' | psql",
                Rule::DropData,
            ),
            (
                r"echo -e 'SELECT 1;\nDROP TABLE users;' | mysql app",
                Rule::DropData,
            ),
            (r"printf 'SET a 1\nFLUSHALL\n' | redis-cli", Rule::DropData),
            (r"printf '\x44ROP TABLE users' | psql", Rule::DropData),
            (r"printf 'D\122OP TABLE users' | psql", Rule::DropData),
            (r"echo -e 'DR\x4fP TABLE users' | psql", Rule::DropData),
            (r"printf 'DR%sP TABLE users' O | psql", Rule::DropData),
            (r"printf 'DR%bP TABLE users' '\x4f' | psql", Rule::DropData),
            (
                r"printf 'SELECT %d;\nDROP TABLE t;' 1 | psql",
                Rule::DropData,
            ),
            // The format is used again while arguments are left.
            (
                r"printf '%s\n' 'SELECT 1' 'DROP TABLE users' | psql",
                Rule::DropData,
            ),
            (
                r"printf '%s;%s' 'SELECT 1' 'DROP TABLE users' | psql",
                Rule::DropData,
            ),
            (r#"printf "DROP TABLE %s\n" "$t" | psql"#, Rule::DropData),
            // Anything else printf does is not read.
            (r"printf '%q' x | psql", Rule::Unknown),
            (r"printf '%5s\n' x | psql", Rule::Unknown),
            (r"printf '%d' x | psql", Rule::Unknown),
            (r"printf '\u0044ROP TABLE t' | psql", Rule::Unknown),
            (r"printf '\q' | psql", Rule::Unknown),
            (r#"printf '%s' "$Q" | psql"#, Rule::Unknown),
            (r"printf '\x80' | psql", Rule::Unknown),
        ],
    );
}

#[test]
fn every_program_of_a_stage_is_read() {
    posix_rows(
        &[
            "{ echo 'SELECT 1'; echo 'SELECT 2'; } | psql",
            "(echo 'BEGIN;'; echo 'SELECT 1;'; echo 'COMMIT;') | psql",
            "{ echo 'SELECT 1'; printf 'SELECT 2;\\n'; } | psql",
            "{ echo 'DROP TABLE users'; } | cat",
        ],
        &[
            (
                "{ echo 'BEGIN;'; echo 'DELETE FROM users;'; echo 'COMMIT;'; } | psql",
                Rule::DropData,
            ),
            (
                "(echo 'SELECT 1'; echo 'DROP TABLE users') | psql",
                Rule::DropData,
            ),
            (
                "(echo 'DROP TABLE users'; echo 'SELECT 1') | psql",
                Rule::DropData,
            ),
            (
                "{ echo 'SELECT 1'; printf 'DROP TABLE users;\\n'; } | psql",
                Rule::DropData,
            ),
            (
                "(echo 'SELECT 1'; echo 'FLUSHALL') | redis-cli",
                Rule::DropData,
            ),
            (
                "if true; then echo 'DROP TABLE users'; fi | psql",
                Rule::DropData,
            ),
            // What they say one after the other is one text.
            (
                "{ echo -n 'DR'; echo -n 'OP TABLE users'; } | psql",
                Rule::DropData,
            ),
            (
                "(printf 'DELETE FROM'; printf ' users') | psql",
                Rule::DropData,
            ),
            ("(echo 'SELECT 1'; echo \"$Q\") | psql", Rule::Unknown),
        ],
    );
}

#[test]
fn psql_commands_are_read_anywhere_outside_a_string() {
    posix_rows(
        &[
            r"psql <<< '\echo hi \\ SELECT 1;'",
            r"psql <<< '\o out.txt'",
            r"psql <<< '\copy t to out.csv csv'",
            r"psql <<< '\set ON_ERROR_STOP on'",
            r"psql -c 'SELECT 1 \g out.txt'",
            r"psql -c 'SELECT 1 \gx'",
            // A command runs to the end of its line: the `;` is its argument.
            r"psql -c 'SELECT 1 \g out.txt; DROP TABLE t'",
            "psql <<EOF\n\\dt\n\\d users\nSELECT 1;\nEOF",
            r#"psql -c "SELECT 'C:\\dir'""#,
            r"psql -c '\dt \\ \d users'",
            r"mysql -e 'SELECT * FROM t \G'",
            r"mysql -e 'SELECT 1\g'",
            r"clickhouse-client -q 'SELECT 1 \G'",
        ],
        &[
            // What the query result runs, or sets for later, is not on the line.
            (
                "psql <<EOF\nSELECT format('DROP TABLE %I', tablename) FROM pg_tables WHERE schemaname = 'public' \\gexec\nEOF",
                Rule::Unknown,
            ),
            (
                r#"psql <<< "SELECT 'DROP TABLE users' \gexec""#,
                Rule::Unknown,
            ),
            (r"psql -c 'SELECT a FROM t \gset'", Rule::Unknown),
            // A command that runs a program.
            (r"psql <<< 'SELECT 1 \! touch x'", Rule::Unknown),
            (r"psql <<< '\o |touch x'", Rule::Unknown),
            (r"psql <<< 'SELECT 1 \g |touch x'", Rule::Unknown),
            (r"psql <<< '\gx |touch x'", Rule::Unknown),
            (r"psql <<< '\w |touch x'", Rule::Unknown),
            (
                r"psql <<< 'SELECT 1 \g (format=csv) |touch x'",
                Rule::Unknown,
            ),
            (r"psql <<< '\echo `touch x`'", Rule::Unknown),
            (r"psql <<< '\o '\''|touch x'\'''", Rule::Unknown),
            (r#"psql <<< "\o $dest""#, Rule::Unknown),
            (r"psql -c '\copy t from program x'", Rule::Unknown),
            (r"mysql -e 'SELECT 1 \! touch x'", Rule::Unknown),
            // The SQL goes on after a command ends.
            (
                r"psql <<< '\echo hi \\ DROP TABLE users;'",
                Rule::DropData,
            ),
            (r"psql <<< '\\ DROP TABLE users'", Rule::DropData),
            (r"psql <<< '\i x.sql \\ DROP TABLE t'", Rule::DropData),
            (
                "psql <<EOF\n\\c prod\nDROP TABLE users;\nEOF",
                Rule::DropData,
            ),
            (
                r"psql -c 'SELECT 1 \g out.txt \\ DROP TABLE t'",
                Rule::DropData,
            ),
            // `\g` and `\G` end a MySQL statement.
            (
                r#"mysql -e "DELETE FROM t \g SELECT * FROM x WHERE a = 1""#,
                Rule::DropData,
            ),
            (r"mysql -e 'SELECT 1 \G DROP TABLE t'", Rule::DropData),
        ],
    );
}

#[test]
fn then_delete_is_part_of_a_merge_and_nothing_else() {
    posix_rows(
        &[
            "psql -c 'MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN DELETE'",
            "psql -c 'MERGE INTO t USING s ON t.id = s.id WHEN NOT MATCHED BY SOURCE THEN DELETE'",
            "psql -c 'MERGE INTO t USING s ON t.id = s.id WHEN MATCHED AND s.x THEN UPDATE SET a = 1 WHEN NOT MATCHED THEN INSERT VALUES (1)'",
            "psql -c 'WITH s AS (SELECT 1 AS id) MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN DELETE'",
        ],
        &[
            (
                "psql -c 'DO $$ BEGIN IF true THEN DELETE FROM users; END IF; END $$'",
                Rule::DropData,
            ),
            (
                "psql -c 'DO $$ BEGIN IF true THEN UPDATE users SET a = 1; END IF; END $$'",
                Rule::DropData,
            ),
            (
                "psql -c 'DO $$ BEGIN EXCEPTION WHEN OTHERS THEN DELETE FROM users; END $$'",
                Rule::DropData,
            ),
            (
                "psql -c 'DO $$ BEGIN IF true THEN DROP TABLE users; END IF; END $$'",
                Rule::DropData,
            ),
            (
                "psql -c 'SELECT CASE WHEN a THEN 1 END; DELETE FROM users'",
                Rule::DropData,
            ),
            // Not the matched clause of a MERGE.
            (
                "psql -c 'MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN DO NOTHING; IF x THEN DELETE FROM t'",
                Rule::DropData,
            ),
        ],
    );
}

#[test]
fn each_client_reads_its_own_quoting() {
    posix_rows(
        &[
            // PostgreSQL's `$tag$` and `E'…'` strings, and nested comments.
            "psql -c 'SELECT $a$; DROP TABLE t; $a$'",
            // DuckDB's parser is PostgreSQL's, so it has `$tag$` strings too.
            "duckdb ~/x.db 'SELECT $a$; DROP TABLE t; SELECT $a$'",
            r#"psql -c "SELECT E'a\\'; DROP TABLE t; --'""#,
            r#"psql -c "/* /* ; DROP TABLE t */ */ SELECT 1""#,
            // Comments do not nest in MySQL and SQLite: the string after the
            // first `*/` hides what follows.
            r#"mysql -e "/* /* */ ' */ DROP TABLE t; --'""#,
            r#"sqlite3 ~/x.db "/* /* */ ' */ DROP TABLE t; --'""#,
            // ClickHouse: heredocs, `#` comments, backslash escapes.
            "clickhouse-client -q 'SELECT $a$; DROP TABLE t; $a$'",
            "clickhouse-client -q 'SELECT 1 # ; DROP TABLE t'",
            r#"clickhouse-client -q "SELECT 'a\\'; DROP TABLE t; --'""#,
            // MySQL and SQLite: backticks.
            "mysql -e 'SELECT `a;b` FROM t'",
            "sqlite3 ~/x.db 'SELECT `a;b` FROM t'",
            // SQLite and SQL Server: brackets.
            "sqlite3 ~/x.db 'SELECT [a;b] FROM t'",
            "sqlcmd -Q 'SELECT [a;b] FROM t'",
            "sqlcmd -Q 'SELECT [a]]; DROP TABLE t; ] FROM t'",
            // CQL: `$$` strings.
            "cqlsh -e 'INSERT INTO t (a) VALUES ($$; DROP TABLE t; $$)'",
        ],
        &[
            // SQLite has no `$tag$` string.
            (
                "sqlite3 ~/x.db 'SELECT $a$; DROP TABLE t; SELECT $a$'",
                Rule::DropData,
            ),
            // MySQL and MariaDB read `$$` as an identifier.
            (
                "mysql -e 'SELECT 1 AS $$; DROP TABLE t; SELECT 1 AS $$'",
                Rule::DropData,
            ),
            // CQL has `$$` and no tag.
            ("cqlsh -e 'SELECT $a$; DROP TABLE t; $a$'", Rule::DropData),
            // `E'…'` is PostgreSQL's.
            (
                "sqlite3 ~/x.db <<'EOF'\nSELECT E'a\\';\nDROP TABLE t;\n--';\nEOF",
                Rule::DropData,
            ),
            // PostgreSQL has no backtick, and psql splits stdin on `;`.
            (
                "psql <<'EOF'\nSELECT `;\nDROP TABLE users;\nSELECT `;\nEOF",
                Rule::DropData,
            ),
            // PostgreSQL's and SQL Server's block comments nest.
            (
                r#"psql -c "/* /* */ ' */ DROP TABLE users; --'""#,
                Rule::DropData,
            ),
            (
                r#"sqlcmd -Q "/* /* */ ' */ DROP TABLE users; --'""#,
                Rule::DropData,
            ),
            // MySQL and ClickHouse read a backslash in a string.
            (
                r#"sqlite3 ~/x.db "SELECT 'a\\'; DROP TABLE t; --'""#,
                Rule::DropData,
            ),
            // DuckDB's comments may nest: not read.
            ("duckdb ~/x.db '/* /* */ */ DROP TABLE t'", Rule::Unknown),
            // `--` needs a space in MySQL, not in ClickHouse.
            ("mysql -e 'SELECT 1 --x; DROP TABLE t'", Rule::DropData),
            // A string, bracket or comment never closed.
            ("sqlite3 ~/x.db 'SELECT [a; DROP TABLE t'", Rule::Unknown),
            ("sqlcmd -Q 'SELECT [a; DROP TABLE t'", Rule::Unknown),
            ("sqlite3 ~/x.db 'SELECT `a; DROP TABLE t'", Rule::Unknown),
            ("duckdb ~/x.db 'SELECT 1 /* DROP TABLE t'", Rule::Unknown),
        ],
    );
}

#[test]
fn a_sqlite_database_name_can_be_a_uri_or_a_remote_database() {
    posix_rows(
        &[
            "sqlite3 file:x.db 'DROP TABLE t'",
            "sqlite3 file:./x.db 'DROP TABLE t'",
            "sqlite3 'file:x.db?mode=rwc' 'DROP TABLE t'",
            "sqlite3 'file:/home/me/work/repo/x.db' 'DROP TABLE t'",
            "sqlite3 'file:///home/me/work/repo/x.db' 'DROP TABLE t'",
            "sqlite3 'file://localhost/home/me/work/repo/x.db' 'DROP TABLE t'",
            "sqlite3 'file::memory:' 'DROP TABLE t'",
            "sqlite3 'file:x?mode=memory&cache=shared' 'DROP TABLE t'",
            "sqlite3 -readonly ~/x.db 'DROP TABLE t'",
            "sqlite3 -readonly ~/x.db 'SELECT 1'",
            "sqlite3 -nonce X x.db 'DROP TABLE t'",
            "sqlite3 -lookaside 100 5 x.db 'DROP TABLE t'",
            "sqlite3 -memtrace x.db 'DROP TABLE t'",
            "duckdb :memory: 'DROP TABLE t'",
            "duckdb x.db 'DROP TABLE t'",
            "sqlite3 '' 'DROP TABLE t'",
        ],
        &[
            ("sqlite3 file:/home/me/x.db 'DROP TABLE t'", Rule::DropData),
            (
                "sqlite3 'file:///home/me/x.db' 'DROP TABLE t'",
                Rule::DropData,
            ),
            (
                "sqlite3 'file://localhost/home/me/x.db' 'DROP TABLE t'",
                Rule::DropData,
            ),
            (
                "sqlite3 'file:///home/me/x%2Edb?mode=ro' 'DROP TABLE t'",
                Rule::DropData,
            ),
            ("sqlite3 'file://host/x.db' 'DROP TABLE t'", Rule::DropData),
            (
                "sqlite3 'file:///work/%zz.db' 'DROP TABLE t'",
                Rule::DropData,
            ),
            ("sqlite3 file: 'DROP TABLE t'", Rule::DropData),
            ("duckdb \"md:my_db\" 'DROP TABLE t'", Rule::DropData),
            ("duckdb 'motherduck:my_db' 'DROP TABLE t'", Rule::DropData),
            ("duckdb 's3://bucket/x.db' 'DROP TABLE t'", Rule::DropData),
            ("sqlite3 'postgres:dbname=x' 'DROP TABLE t'", Rule::DropData),
            // `-readonly` holds only while nothing opens another file.
            (
                "sqlite3 -readonly ~/x.db '.open /home/me/y.db' 'DROP TABLE t'",
                Rule::DropData,
            ),
            (
                "sqlite3 -readonly ~/x.db '.attach /home/me/y.db o' 'DROP TABLE o.t'",
                Rule::DropData,
            ),
            (
                "sqlite3 -readonly x.db 'ATTACH \"/home/me/o.db\" AS o' 'DROP TABLE o.t'",
                Rule::DropData,
            ),
            // An option that takes a value must not move the file onto it.
            ("sqlite3 -nonce X ~/data.db 'DROP TABLE t'", Rule::DropData),
            (
                "sqlite3 -screenwidth 80 ~/data.db 'DROP TABLE t'",
                Rule::DropData,
            ),
            (
                "sqlite3 -escape ascii ~/data.db 'DROP TABLE t'",
                Rule::DropData,
            ),
            ("sqlite3 -A x ~/data.db 'DROP TABLE t'", Rule::DropData),
            ("sqlite3 -alg a ~/data.db 'DROP TABLE t'", Rule::DropData),
            ("sqlite3 -hexkey k ~/data.db 'DROP TABLE t'", Rule::DropData),
            (
                "sqlite3 -textkey k ~/data.db 'DROP TABLE t'",
                Rule::DropData,
            ),
            ("sqlite3 -key k ~/data.db 'DROP TABLE t'", Rule::DropData),
            ("sqlite3 -vfs unix ~/data.db 'DROP TABLE t'", Rule::DropData),
            (
                "sqlite3 -lookaside 100 5 ~/data.db 'DROP TABLE t'",
                Rule::DropData,
            ),
            (
                "sqlite3 -pagecache 100 5 ~/data.db 'DROP TABLE t'",
                Rule::DropData,
            ),
            ("sqlite3 -- ~/data.db 'DROP TABLE t'", Rule::DropData),
            ("duckdb -f x.sql ~/data.db 'DROP TABLE t'", Rule::DropData),
            ("sqlite3 -cmd 'DROP TABLE t' ~/data.db", Rule::DropData),
        ],
    );
}

#[test]
fn redis_cli_options_and_scripts() {
    posix_rows(
        &[
            "redis-cli -t 5 GET k",
            "redis-cli -h db -t 5 GET k",
            "redis-cli --cluster info 127.0.0.1:7000",
            "redis-cli --cluster call 127.0.0.1:7000 GET k",
            "redis-cli --cluster call 127.0.0.1:7000 DBSIZE",
            "redis-cli EVAL 'return 1' 0",
            "redis-cli EVAL \"return redis.call('GET', KEYS[1])\" 1 k",
            "redis-cli --eval script.lua k , a",
        ],
        &[
            (
                "redis-cli --cluster call 127.0.0.1:7000 FLUSHALL",
                Rule::DropData,
            ),
            (
                "redis-cli -h db --cluster call 127.0.0.1:7000 FLUSHDB",
                Rule::DropData,
            ),
            ("redis-cli -t 5 FLUSHALL", Rule::DropData),
            ("redis-cli -h db -t 5 FLUSHDB", Rule::DropData),
            (
                "redis-cli --cluster call 127.0.0.1:7000 EVAL \"$S\" 0",
                Rule::Unknown,
            ),
            ("redis-cli EVAL \"$S\" 0", Rule::Unknown),
            ("redis-cli EVALSHA \"$SHA\" 0", Rule::Unknown),
            ("redis-cli FCALL \"$F\" 0", Rule::Unknown),
            ("redis-cli EVAL $(cat s.lua) 0", Rule::Unknown),
            ("echo \"EVAL \\\"$S\\\" 0\" | redis-cli", Rule::Unknown),
            (
                "redis-cli EVAL \"redis.call('FLUSHALL')\" 0",
                Rule::DropData,
            ),
        ],
    );
}

#[test]
fn a_batch_without_semicolons_keeps_each_where_with_its_statement() {
    posix_rows(
        &[
            "sqlcmd -Q 'UPDATE users SET active = 0 WHERE id = 1 SELECT * FROM users'",
            "psql -c 'UPDATE users SET a = (SELECT 1) WHERE id = 2'",
            "psql -c 'UPDATE users SET a = 1 FROM (SELECT 1 AS id) s WHERE users.id = s.id'",
            "sqlcmd -Q 'DELETE FROM users WHERE id = 1 PRINT 1'",
        ],
        &[
            (
                "sqlcmd -Q \"UPDATE users SET active = 0 SELECT * FROM users WHERE id = 1\"",
                Rule::DropData,
            ),
            (
                "psql -c \"UPDATE users SET a = 1 SELECT 1 WHERE id = 2\"",
                Rule::DropData,
            ),
            (
                "sqlcmd -Q \"DELETE FROM users PRINT 'x' SELECT 1 WHERE a = 1\"",
                Rule::DropData,
            ),
            (
                "sqlcmd -Q \"DELETE FROM users EXEC sp_who SELECT 1 WHERE a = 1\"",
                Rule::DropData,
            ),
            (
                "sqlcmd -Q \"DELETE FROM users EXECUTE sp_who WHERE a = 1\"",
                Rule::DropData,
            ),
            // A `WHERE` that picks every row, then another statement.
            (
                "psql -c \"UPDATE users SET a = 1 WHERE 1 SELECT 2\"",
                Rule::DropData,
            ),
        ],
    );
    check(
        Shell::PowerShell,
        &windows(),
        &["sqlcmd -S db -Q 'UPDATE users SET a = 0 WHERE id = 1 SELECT 1'"],
        &[(
            "sqlcmd -S db -Q 'UPDATE users SET a = 0 SELECT * FROM users WHERE id = 1'",
            Rule::DropData,
        )],
    );
}

#[test]
fn a_drop_that_deletes_no_data_is_safe() {
    posix_rows(
        &[
            "psql -c 'ALTER TABLE users ALTER COLUMN name DROP NOT NULL'",
            "psql -c 'ALTER TABLE users ALTER COLUMN name DROP DEFAULT'",
            "psql -c 'ALTER TABLE users ALTER COLUMN id DROP IDENTITY'",
            "psql -c 'ALTER TABLE users ALTER COLUMN id DROP IDENTITY IF EXISTS'",
            "psql -c 'ALTER TABLE users ALTER COLUMN c DROP EXPRESSION'",
            "psql -c 'ALTER TABLE users DROP CONSTRAINT users_pkey'",
            "psql -c 'ALTER TABLE users DROP CONSTRAINT IF EXISTS users_pkey CASCADE'",
            "psql -c 'CREATE TEMP TABLE t (a int) ON COMMIT DROP'",
            "sqlcmd -Q 'ALTER TABLE users DROP CONSTRAINT users_pkey'",
        ],
        &[
            (
                "psql -c 'ALTER TABLE users DROP COLUMN name'",
                Rule::DropData,
            ),
            ("psql -c 'ALTER TABLE users DROP name'", Rule::DropData),
            ("mysql -e 'ALTER TABLE t DROP PARTITION p1'", Rule::DropData),
            ("psql -c 'DROP TABLE users'", Rule::DropData),
            (
                "psql -c 'ALTER TABLE users DROP CONSTRAINT c, DROP COLUMN name'",
                Rule::DropData,
            ),
            (
                "psql -c 'ALTER TABLE users ALTER COLUMN name DROP NOT NULL; DROP TABLE users'",
                Rule::DropData,
            ),
            (
                "psql -c 'CREATE TEMP TABLE t (a int) ON COMMIT DROP; DROP TABLE users'",
                Rule::DropData,
            ),
            (
                "psql -c 'ALTER TABLE users DROP DEFAULT, DROP COLUMN name'",
                Rule::DropData,
            ),
        ],
    );
}

#[test]
fn a_group_too_large_to_read_is_unknown_and_quick() {
    let echoes = "echo a; ".repeat(300);
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[(&format!("{{ {echoes}}} | psql"), Rule::Unknown)],
    );
    // Many clients after a big group are not read over and over.
    let echoes = "echo a; ".repeat(3_000);
    let clients = "psql; ".repeat(3_000);
    let line = format!("{{ {echoes}}} | {{ {clients}}}");
    assert!(line.len() < 64 * 1024, "{}", line.len());
    let started = std::time::Instant::now();
    let rules = common::rules(&line, Shell::Posix, &posix());
    let took = started.elapsed();
    assert!(took < std::time::Duration::from_secs(5), "took {took:?}");
    assert!(rules.iter().all(|rule| *rule == Rule::Unknown), "{rules:?}");
}

#[test]
fn a_printf_blown_up_past_the_line_is_unknown() {
    // A format used again for every argument can print far more than the line
    // holds; that is not decoded.
    let format = "x".repeat(1_000);
    let args = "a ".repeat(100);
    let line = format!("printf '{format}%s' {args}| psql");
    check(Shell::Posix, &posix(), &[], &[(&line, Rule::Unknown)]);
    let short = format!("printf '{}%s' {}| psql", "x".repeat(10), "a ".repeat(10));
    check(Shell::Posix, &posix(), &[&short], &[]);
}
