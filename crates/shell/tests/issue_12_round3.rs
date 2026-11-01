//! What a third review of `drop_data` found: text a database client gets that
//! the guard read as another, and lines the guard read in time that grew with
//! the clients times the programs feeding them. Each table holds the lines of
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

fn windows_rows(safe: &[&str], risky: &[(&str, Rule)]) {
    check(Shell::PowerShell, &windows(), safe, risky);
}

/// How long the guard takes to judge `line`.
fn took(line: &str) -> std::time::Duration {
    let started = std::time::Instant::now();
    let _ = classify(line, Shell::Posix, &posix());
    started.elapsed()
}

#[test]
fn many_clients_on_one_line_are_read_in_linear_time() {
    let args = "a ".repeat(1000);
    let printf = format!("printf '%s{}' {args}; ", "x".repeat(60));
    let clients = |count: usize| "psql; ".repeat(count);
    let lines = [
        // Fifteen printfs, each saying 63 KB: more than a stage may say.
        format!("{{ {}}} | {{ {}}}", printf.repeat(15), clients(1000)),
        format!(
            "{{ {}}} | {{ {}}}",
            "printf '%s' a b c; ".repeat(64),
            clients(1800)
        ),
        format!(
            "{{ echo '{}'; }} | {{ {}}}",
            "x".repeat(30_000),
            clients(5000)
        ),
        format!(
            "{{ echo '{}'; }} | {{ {}}}",
            "x".repeat(20_000),
            "sqlite3 ~/x.db; ".repeat(2500)
        ),
        format!(
            "{{ echo '{}'; }} | {{ {}}}",
            "x".repeat(20_000),
            "redis-cli; ".repeat(4000)
        ),
        // Risky: every client has a finding to give.
        format!(
            "{{ echo 'DROP TABLE t; {}'; }} | {{ {}}}",
            "x".repeat(20_000),
            "psql; ".repeat(5000)
        ),
    ];
    for line in &lines {
        let took = took(line);
        assert!(
            took < std::time::Duration::from_millis(500),
            "{} bytes took {took:?}",
            line.len()
        );
    }
}

#[test]
fn a_stage_that_says_too_much_is_not_read_and_stays_quick() {
    // Five printfs of 63 KB each are more than a stage may say: unknown, and
    // not printed in full for each client.
    let args = "a ".repeat(1000);
    let printf = format!("printf '%s{}' {args}; ", "x".repeat(60));
    let line = format!("{{ {}}} | psql", printf.repeat(5));
    assert!(took(&line) < std::time::Duration::from_millis(500));
    posix_rows(&[], &[(&line, Rule::Unknown)]);
}

#[test]
fn every_client_of_a_stage_reads_what_the_stage_says() {
    posix_rows(
        &["{ echo 'SELECT 1;'; } | { psql; mysql; sqlite3 :memory:; }"],
        &[
            (
                "{ echo 'DROP TABLE t;'; } | { psql; mysql; }",
                Rule::DropData,
            ),
            (
                "{ echo 'DROP TABLE t;'; } | { sqlite3 :memory:; psql; }",
                Rule::DropData,
            ),
            (
                "{ echo 'FLUSHALL'; } | { redis-cli; redis-cli; }",
                Rule::DropData,
            ),
            (
                "{ printf 'DROP TABLE t;'; } | { redis-cli; psql; }",
                Rule::DropData,
            ),
        ],
    );
}

#[test]
fn an_unquoted_here_document_is_read_as_the_shell_feeds_it() {
    posix_rows(
        &[
            // A quoted delimiter feeds the body as it is.
            "psql <<'EOF'\nSELECT '\\$HOME' AS a;\nEOF",
            "psql <<\\EOF\nSELECT '$HOME' AS a;\nEOF",
            // `\$` is a `$` that the client gets, so the string is a string.
            "psql <<EOF\nSELECT '\\$HOME' AS a;\nEOF",
            // `\\` is one backslash.
            "psql <<EOF\nSELECT 'it\\\\' AS a;\nEOF",
            "psql <<EOF\nSELECT 1,\\\n2;\nEOF",
            // What a dollar-quoted string holds is not code, when its `$` are
            // the client's.
            "psql <<EOF\nSELECT \\$\\$ ; DROP TABLE t; \\$\\$;\nEOF",
            "psql <<'EOF'\nSELECT $$ ; DROP TABLE t; $$;\nEOF",
        ],
        &[
            // A backslash and a newline are taken out: `DROP`.
            ("psql <<EOF\nDR\\\nOP TABLE t\nEOF", Rule::DropData),
            ("cat <<EOF | psql\nDR\\\nOP TABLE t\nEOF", Rule::DropData),
            ("psql <<-EOF\n\tDR\\\n\tOP TABLE t\n\tEOF", Rule::DropData),
            // `$$` is the shell's process id, not a string.
            (
                "psql <<EOF\nSELECT $$ ; DROP TABLE t; $$\nEOF",
                Rule::DropData,
            ),
            (
                "cat <<EOF | psql\nSELECT $$ ; DROP TABLE t; $$\nEOF",
                Rule::DropData,
            ),
            // `\\!` is `\!` for the client.
            ("psql <<EOF\n\\\\! touch x\nEOF", Rule::Unknown),
            // `\$x` is `$x` and not a string.
            (
                "psql <<EOF\nSELECT 1; \\$x ; DROP TABLE t\nEOF",
                Rule::DropData,
            ),
            (
                "psql <<EOF\nSELECT 1; \\`x\\` ; DROP TABLE t\nEOF",
                Rule::DropData,
            ),
            // A body that has both an escaped and an expanding `$` is only
            // known when it runs.
            (
                "psql <<EOF\nSELECT 1; \\$( ; DROP TABLE t; $x\nEOF",
                Rule::Unknown,
            ),
            // A MySQL string that the backslashes leave open.
            ("mysql <<EOF\nSELECT 'a\\\\' AS x;\nEOF", Rule::Unknown),
        ],
    );
}

#[test]
fn a_backslash_in_a_string_is_read_both_ways_where_the_server_sets_it() {
    posix_rows(
        &[
            r#"mysql -e "SELECT 'it\\'s'""#,
            r#"mysql -e "INSERT INTO t VALUES ('it\\'s'); SELECT 1""#,
            "psql <<'EOF'\nSELECT E'it\\'s' AS a;\nEOF",
            r#"psql -c "SELECT 'a\\nb' AS x; SELECT 1""#,
            "mysql -e 'SELECT 1; SELECT 2'",
        ],
        &[
            // `NO_BACKSLASH_ESCAPES`: the string is `'a\'`, and the next
            // statement runs.
            (
                r#"mysql -e "SET sql_mode='NO_BACKSLASH_ESCAPES'; SELECT 'a\\'; DROP TABLE t; -- '""#,
                Rule::DropData,
            ),
            // `ANSI_QUOTES`: `"a\"` is an identifier.
            (
                r#"mysql -e "SET sql_mode='ANSI_QUOTES'; SELECT \"a\\\"; DROP TABLE t; -- \"""#,
                Rule::DropData,
            ),
            // `standard_conforming_strings` off: the string takes `\'`.
            (
                "psql <<'EOF'\nSET standard_conforming_strings = off;\nSELECT 'a\\'' ; DROP TABLE t; --';\nEOF",
                Rule::DropData,
            ),
            (
                r#"psql -c "SET standard_conforming_strings = off; SELECT 'a\\'' ; DROP TABLE t; --';""#,
                Rule::DropData,
            ),
            // A program, from the other reading.
            (
                r#"mysql -e "SELECT 'a\\'; \! touch x; -- '""#,
                Rule::Unknown,
            ),
        ],
    );
}

#[test]
fn a_variable_the_client_fills_in_is_not_read_where_a_statement_starts() {
    posix_rows(
        &[
            "psql -c 'SELECT 1::int'",
            "psql -c 'SELECT a::text FROM t'",
            "psql -c \"SELECT ':q'\"",
            "psql -c 'SELECT * FROM t WHERE a = :x'",
            "psql -c 'SELECT 1; SELECT :x'",
            "psql -c 'SELECT 1 -- :q'",
            "sqlcmd -Q 'SELECT * FROM t WHERE a = $(x)'",
            "sqlcmd -Q 'SELECT 1'",
            // Only `psql` has `:name`, and only `sqlcmd` has `$(name)`.
            "mysql -e 'SELECT :x'",
            "sqlite3 :memory: ':q'",
        ],
        &[
            ("psql -v q='DROP TABLE t' <<< ':q'", Rule::Unknown),
            ("psql -v q='DROP TABLE t' <<< \":'q'\"", Rule::Unknown),
            ("psql -v q='DROP TABLE t' <<< ':\"q\"'", Rule::Unknown),
            ("psql <<EOF\n\\set q 'DROP TABLE t'\n:q\nEOF", Rule::Unknown),
            ("psql -c 'BEGIN; :q'", Rule::Unknown),
            ("psql -c 'SELECT 1; :q;'", Rule::Unknown),
            ("echo ':q' | psql -v q='DROP TABLE t'", Rule::Unknown),
            ("sqlcmd -v s=\"DROP TABLE t\" -Q '$(s)'", Rule::Unknown),
            ("sqlcmd -Q 'SELECT 1; $(s)'", Rule::Unknown),
            // The statements the variable does not start are still read.
            ("psql -c ':q; DROP TABLE t'", Rule::DropData),
        ],
    );
}

#[test]
fn mysqladmin_runs_a_command_from_any_start_of_its_name() {
    posix_rows(
        &[
            "mysqladmin ping",
            "mysqladmin proc stat",
            "mysqladmin -u root status",
            "mysqladmin create test",
            // `d` starts `debug` too and `mysqladmin` refuses it.
            "mysqladmin d test",
            "mysqladmin drops test",
            "mysqladmin droppy test",
        ],
        &[
            ("mysqladmin drop test", Rule::DropData),
            ("mysqladmin dro test", Rule::DropData),
            ("mysqladmin dr test", Rule::DropData),
            ("mysqladmin DR test", Rule::DropData),
            ("mysqladmin -u root --force dro test", Rule::DropData),
            ("mysqladmin status dr test", Rule::DropData),
        ],
    );
}

#[test]
fn drop_identity_and_expression_drop_no_data_only_of_a_column() {
    posix_rows(
        &[
            "psql -c 'ALTER TABLE t ALTER COLUMN c DROP IDENTITY'",
            "psql -c 'ALTER TABLE t ALTER c DROP IDENTITY IF EXISTS'",
            "psql -c 'ALTER TABLE t ALTER COLUMN c DROP EXPRESSION'",
            "psql -c 'ALTER TABLE t ALTER c DROP expression'",
            "psql -c 'ALTER TABLE t ALTER COLUMN \"c\" DROP identity'",
            "psql -c 'ALTER TABLE t ALTER COLUMN identity DROP identity'",
            "psql -c 'ALTER TABLE t ALTER COLUMN c DROP NOT NULL'",
            "psql -c 'ALTER TABLE t ALTER COLUMN c DROP DEFAULT'",
            "psql -c 'ALTER TABLE t DROP CONSTRAINT k'",
        ],
        &[
            // The word `COLUMN` is optional and neither word is reserved.
            ("mysql -e 'ALTER TABLE users DROP identity'", Rule::DropData),
            ("psql -c 'ALTER TABLE t DROP expression'", Rule::DropData),
            (
                "psql -c 'ALTER TABLE t DROP COLUMN identity'",
                Rule::DropData,
            ),
            (
                "psql -c 'ALTER TABLE t DROP IF EXISTS identity'",
                Rule::DropData,
            ),
            (
                "psql -c 'ALTER TABLE t ALTER c TYPE int, DROP identity'",
                Rule::DropData,
            ),
            (
                "sqlite3 ~/x.db 'ALTER TABLE users DROP identity'",
                Rule::DropData,
            ),
            (
                "sqlite3 ~/x.db 'ALTER TABLE users DROP expression'",
                Rule::DropData,
            ),
        ],
    );
}

#[test]
fn cat_of_dash_reads_its_input_as_cat_does() {
    posix_rows(
        &[
            "cat - <<< 'SELECT 1' | psql",
            "cat -n <<< 'SELECT 1' | psql",
            "cat seed.sql <<< 'DROP TABLE t' | psql",
        ],
        &[
            ("cat <<< 'DROP TABLE t' | psql", Rule::DropData),
            ("cat - <<< 'DROP TABLE t' | psql", Rule::DropData),
            ("cat - - <<< 'DROP TABLE t' | psql", Rule::DropData),
            ("cat - <<EOF | psql\nDROP TABLE t\nEOF", Rule::DropData),
        ],
    );
}

#[test]
fn a_powershell_value_piped_into_a_client_says_what_it_is() {
    windows_rows(
        &[
            "'SELECT 1' | psql",
            "\"SELECT 1\" | psql",
            "@'\nSELECT 1\n'@ | psql",
            "@\"\nSELECT 1\n\"@ | psql",
            "'DELETE FROM t WHERE id = 1' | psql",
            "'SELECT 1' | Out-Null",
            "'x'",
        ],
        &[
            ("'DROP TABLE t' | psql", Rule::DropData),
            ("\"DROP TABLE t\" | psql", Rule::DropData),
            ("@'\nDROP TABLE t\n'@ | psql", Rule::DropData),
            ("@\"\nDROP TABLE t\n\"@ | psql", Rule::DropData),
            ("@\"\nDROP TABLE $t\n\"@ | psql", Rule::Unknown),
            ("'DROP TABLE t' | mysql", Rule::DropData),
            ("'DELETE FROM t' | sqlite3 C:\\x.db", Rule::DropData),
            ("'FLUSHALL' | redis-cli", Rule::DropData),
            // A variable, or anything computed, is only known when it runs.
            ("$q = 'DROP TABLE t'; $q | psql", Rule::Unknown),
            ("$x.y | psql", Rule::Unknown),
            ("(Get-Content q.sql) | psql", Rule::Unknown),
            ("\"DROP TABLE $t\" | psql", Rule::Unknown),
            ("'DROP ' + 'TABLE t' | psql", Rule::Unknown),
            ("\"a\", \"b\" | psql", Rule::Unknown),
        ],
    );
}
