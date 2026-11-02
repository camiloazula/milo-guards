//! A statement given to a database client that drops, truncates or empties
//! something is `drop_data`; reading, inserting, creating and a statement
//! that picks its rows are safe, and one the line does not show is `unknown`.
//! One table per client, then what every client shares: its commands, its
//! quoting, its long options, the `WHERE` of each verb, and the drops that
//! delete no data; then PowerShell and cmd, the reason a prompt can show, and
//! the timed tests. How the text a client gets is read (fed by `printf`,
//! `echo`, `cat` or a here-document) is in `drop_data_input.rs`; how
//! PowerShell hands words to a client is in
//! `tests/cases/powershell_arguments.cases`.

mod common;

use common::{assert_linear, check, filled, posix, rules, took, windows};
use milo_guards_shell::{classify, Rule, Shell};

#[test]
fn a_reason_and_a_target_a_prompt_can_show() {
    let assessment = classify("psql -c 'DROP TABLE users'", Shell::Posix, &posix());
    let finding = &assessment.findings()[0];
    assert_eq!(finding.rule, Rule::DropData);
    assert_eq!(finding.reason, "deletes data in a database");
    assert_eq!(finding.target.as_deref(), Some("DROP TABLE users"));
    let assessment = classify("psql -c \"$Q\"", Shell::Posix, &posix());
    assert_eq!(
        assessment.findings()[0].reason,
        "runs a database statement only known when it runs"
    );
}

#[test]
fn a_line_that_drops_data_changes_something() {
    // `effect` places every rule; dropping data is a change, not a read.
    common::check_effect(
        Shell::Posix,
        &posix(),
        milo_guards_shell::Effect::Changes,
        &[
            "psql -c 'DROP TABLE users'",
            "redis-cli FLUSHALL",
            "dropdb prod",
        ],
    );
}

#[test]
fn psql() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "psql",
            "psql -d app",
            "psql -c 'SELECT 1'",
            "psql -h db -U me -d app -c 'SELECT count(*) FROM users'",
            "psql -c 'INSERT INTO t VALUES (1)'",
            "psql -c 'CREATE TABLE t (id int)'",
            "psql -c 'UPDATE users SET a = 1 WHERE id = 3'",
            "psql -c \"DELETE FROM users WHERE id = 3\"",
            "psql -c 'DELETE FROM users WHERE id IN (SELECT id FROM gone)'",
            "psql -c 'SELECT * FROM users FOR UPDATE'",
            "psql -c 'CREATE TABLE t (p int REFERENCES p(id) ON DELETE CASCADE)'",
            "psql -c \"INSERT INTO t VALUES (1) ON CONFLICT (a) DO UPDATE SET b = 2\"",
            "psql -c \"SELECT 'DROP TABLE users'\"",
            "psql -c 'SELECT 1 -- DROP TABLE users'",
            "psql -c '/* DROP TABLE users */ SELECT 1'",
            "psql -c 'SELECT truncate(1.5)'",
            "psql -f migrations/001.sql",
            "psql -f schema.sql",
            "psql -f schema.sql -d app",
            "psql app < schema.sql",
            "psql -c \"DELETE FROM users WHERE id = $id\"",
            "psql -c \"SELECT * FROM $table\"",
            "psql -l",
            "psql --version",
            "psql -c '\\dt'",
            "psql -c '\\c other'",
            "pg_dump app > backup.sql",
            "echo 'DROP TABLE users' > notes.txt",
            "echo 'DROP TABLE users'",
            "grep -r 'DROP TABLE' migrations",
            "cat migrations/001.sql | psql app",
        ],
        &[
            ("psql -c 'DROP TABLE users'", Rule::DropData),
            ("psql -c 'drop table if exists users'", Rule::DropData),
            ("psql -c 'DROP DATABASE prod'", Rule::DropData),
            ("psql -c 'DROP SCHEMA public CASCADE'", Rule::DropData),
            ("psql -c 'DROP INDEX i'", Rule::DropData),
            ("psql -c 'DROP VIEW v'", Rule::DropData),
            ("psql --command 'DROP TABLE users'", Rule::DropData),
            ("psql --command='DROP TABLE users'", Rule::DropData),
            ("psql --comm 'DROP TABLE users'", Rule::DropData),
            ("psql -Atc 'DROP TABLE users'", Rule::DropData),
            ("psql -qc 'TRUNCATE users'", Rule::DropData),
            ("psql -cTRUNCATE\\ users", Rule::DropData),
            (
                "psql -h db -U me -d app -c 'TRUNCATE TABLE users'",
                Rule::DropData,
            ),
            ("psql -c 'SELECT 1' -c 'DROP TABLE users'", Rule::DropData),
            ("psql -c 'DELETE FROM users'", Rule::DropData),
            ("psql -c 'DELETE FROM users;'", Rule::DropData),
            ("psql -c 'UPDATE users SET admin = false'", Rule::DropData),
            ("psql -c 'DELETE FROM users WHERE 1=1'", Rule::DropData),
            ("psql -c 'DELETE FROM users WHERE true'", Rule::DropData),
            (
                "psql -c 'ALTER TABLE users DROP COLUMN email'",
                Rule::DropData,
            ),
            ("psql -c 'SELECT 1; DROP TABLE users'", Rule::DropData),
            ("psql -c 'BEGIN; DELETE FROM users; COMMIT'", Rule::DropData),
            (
                "psql -c 'WITH d AS (DELETE FROM users RETURNING *) SELECT * FROM d'",
                Rule::DropData,
            ),
            (
                "psql -c 'EXPLAIN ANALYZE DELETE FROM users'",
                Rule::DropData,
            ),
            (
                "psql -c 'DO $$ BEGIN DROP TABLE users; END $$'",
                Rule::DropData,
            ),
            ("psql -c \"DROP TABLE $t\"", Rule::DropData),
            ("psql -c \"DELETE FROM $t\"", Rule::DropData),
            ("psql -c 'SELECT 1 -- x\nDROP TABLE users'", Rule::DropData),
            (
                "psql -c \"SELECT 'a\\\\'; DROP TABLE users; --'\"",
                Rule::DropData,
            ),
            (
                "sudo -u postgres psql -c 'DROP DATABASE prod'",
                Rule::DropData,
            ),
            (
                "env PGPASSWORD=x psql -c 'DROP DATABASE prod'",
                Rule::DropData,
            ),
            ("/usr/bin/psql -c 'DROP DATABASE prod'", Rule::DropData),
            ("true && psql -c 'DROP TABLE users'", Rule::DropData),
            ("bash -c \"psql -c 'DROP TABLE users'\"", Rule::DropData),
            ("psql -c \"$Q\"", Rule::Unknown),
            ("psql -c $Q", Rule::Unknown),
            ("psql -c \"$(cat q.sql)\"", Rule::Unknown),
            ("psql --command=\"$Q\"", Rule::Unknown),
            ("psql -c \"$Q; SELECT 1\"", Rule::Unknown),
            ("psql -c \"SELECT 1; $Q\"", Rule::Unknown),
            ("psql -c \"SELECT 'unclosed\"", Rule::Unknown),
            ("psql -c '/* never closed'", Rule::Unknown),
            ("psql -c '\\! rm -rf build'", Rule::Unknown),
            ("psql -c \"COPY t FROM PROGRAM 'rm -rf x'\"", Rule::Unknown),
            ("xargs -I{} psql -c {} < statements", Rule::Unknown),
        ],
    );
}

#[test]
fn mysql_and_mariadb() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "mysql",
            "mysql -u root -p app",
            "mysql -uroot -psecret app",
            "mysql -e 'SELECT 1'",
            "mysql -u root -p -e 'SELECT * FROM users'",
            "mysql -e 'DELETE FROM users WHERE id = 3'",
            "mysql -e 'INSERT INTO t VALUES (1)'",
            "mysql -e 'CREATE TABLE t (id int)'",
            "mysql app < dump.sql",
            "mysql --execute='SHOW TABLES'",
            "mysql -e 'SELECT 1 # DROP TABLE t'",
            "mysql -e \"SELECT * FROM t WHERE a = '\\\\''\"",
            "mysqldump app > dump.sql",
            "mysql --version",
        ],
        &[
            ("mysql -e 'DROP DATABASE prod'", Rule::DropData),
            ("mysql -u root -p -e 'DROP DATABASE prod'", Rule::DropData),
            (
                "mysql -uroot -psecret -e 'DROP DATABASE prod'",
                Rule::DropData,
            ),
            (
                "mysql -uroot -psecret app -e 'TRUNCATE users'",
                Rule::DropData,
            ),
            (
                "mysql -h db -P 3307 -D app -e 'DELETE FROM users'",
                Rule::DropData,
            ),
            ("mysql --execute='DROP TABLE t'", Rule::DropData),
            ("mysql --execute 'DROP TABLE t'", Rule::DropData),
            ("mysql --exec 'DROP TABLE t'", Rule::DropData),
            ("mysql -Ne 'DROP TABLE t'", Rule::DropData),
            ("mysql -e'DROP TABLE t'", Rule::DropData),
            ("mysql -e 'UPDATE users SET admin = 0'", Rule::DropData),
            (
                "mysql -e 'ALTER TABLE users DROP COLUMN email'",
                Rule::DropData,
            ),
            ("mysql -e 'SELECT 1; DROP TABLE t'", Rule::DropData),
            ("mysql -e '/*!50000 DROP TABLE t */'", Rule::DropData),
            ("mysql -e 'SELECT 1 /*! ; DROP TABLE t */'", Rule::DropData),
            ("mysql -e 'SELECT 1 --x; DROP TABLE t'", Rule::DropData),
            ("mysql -e \"SELECT 'a\\\\''; DROP TABLE t\"", Rule::DropData),
            // With NO_BACKSLASH_ESCAPES the client sends `SELECT "a\"` and
            // then `DROP TABLE t`, which runs.
            (
                "mysql -e 'SELECT \"a\\\"; DROP TABLE t; --\"'",
                Rule::DropData,
            ),
            ("mysql --init-command='DROP TABLE t'", Rule::DropData),
            ("mariadb -e 'DROP DATABASE prod'", Rule::DropData),
            ("mysql -e \"$Q\"", Rule::Unknown),
            ("mysql -e '\\! rm -rf x'", Rule::Unknown),
            ("mysql -e 'system rm -rf x'", Rule::Unknown),
        ],
    );
}

#[test]
fn mysqladmin_and_mariadb_admin_run_a_command_from_any_start_of_its_name() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "mysqladmin ping",
            "mysqladmin status",
            "mysqladmin -u root status",
            "mysqladmin -h db variables",
            "mysqladmin version",
            "mysqladmin proc stat",
            "mysqladmin create test",
            // `d` starts `debug` too and `mysqladmin` refuses it.
            "mysqladmin d test",
            "mysqladmin drops test",
            "mysqladmin droppy test",
            "mariadb-admin status",
            "mariadb-admin -u root ping",
        ],
        &[
            ("mysqladmin drop prod", Rule::DropData),
            ("mysqladmin -f drop prod", Rule::DropData),
            ("mysqladmin -u root -p drop prod", Rule::DropData),
            ("mysqladmin -h db drop prod", Rule::DropData),
            ("mysqladmin --user root DROP prod", Rule::DropData),
            ("mysqladmin status drop prod", Rule::DropData),
            ("mysqladmin drop test", Rule::DropData),
            ("mysqladmin dro test", Rule::DropData),
            ("mysqladmin dr test", Rule::DropData),
            ("mysqladmin DR test", Rule::DropData),
            ("mysqladmin -u root --force dro test", Rule::DropData),
            ("mysqladmin status dr test", Rule::DropData),
            ("mariadb-admin drop prod", Rule::DropData),
            ("mariadb-admin -u root drop prod", Rule::DropData),
            ("mariadb-admin dro prod", Rule::DropData),
        ],
    );
}

#[test]
fn sqlite_and_duckdb_files_are_judged_like_any_file() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "sqlite3 data.db 'DROP TABLE t'",
            "sqlite3 data.db 'DELETE FROM users'",
            "sqlite3 ./data.db 'DROP TABLE t'",
            "sqlite3 db/app.sqlite 'DELETE FROM t'",
            "sqlite3 /home/me/work/repo/data.db 'DROP TABLE t'",
            "sqlite3 /home/me/work/repo/data.db 'TRUNCATE t'",
            "sqlite3 /tmp/scratch.db 'DROP TABLE t'",
            "sqlite3 :memory: 'DROP TABLE t'",
            "sqlite3 'DROP TABLE t'",
            "sqlite3 -readonly ~/data.db 'DROP TABLE t'",
            "sqlite3 data.db 'SELECT * FROM t'",
            "sqlite3 ~/data/data.db 'SELECT * FROM t'",
            "sqlite3 ~/data/data.db 'INSERT INTO t VALUES (1)'",
            "sqlite3 ~/data/data.db 'DELETE FROM t WHERE id = 1'",
            "sqlite3 ~/data/data.db '.dump'",
            "sqlite3 ~/data/data.db .schema",
            "sqlite3 -header -csv data.db 'SELECT 1'",
            "sqlite3 data.db < seed.sql",
            "sqlite3 ~/data/data.db < seed.sql",
            "sqlite3 data.db '.read seed.sql'",
            "sqlite3 -cmd '.mode csv' data.db 'SELECT 1'",
            "duckdb data.duckdb 'DROP TABLE t'",
            "duckdb -c 'DROP TABLE t'",
            "duckdb ~/x.duckdb 'SELECT 1'",
            "duckdb -readonly ~/x.duckdb 'DROP TABLE t'",
            "duckdb -c 'SELECT 1'",
            "cd work && sqlite3 data.db 'DROP TABLE t'",
        ],
        &[
            ("sqlite3 ~/data/data.db 'DROP TABLE t'", Rule::DropData),
            ("sqlite3 ~/data/data.db 'DELETE FROM users'", Rule::DropData),
            ("sqlite3 ~/data/data.db 'TRUNCATE t'", Rule::DropData),
            (
                "sqlite3 ~/data/data.db 'UPDATE t SET a = 1'",
                Rule::DropData,
            ),
            ("sqlite3 /var/lib/app/app.db 'DROP TABLE t'", Rule::DropData),
            ("sqlite3 ../other/data.db 'DROP TABLE t'", Rule::DropData),
            ("sqlite3 \"$DB\" 'DROP TABLE t'", Rule::DropData),
            ("sqlite3 $DB 'DELETE FROM t'", Rule::DropData),
            ("sqlite3 ~/data.db 'SELECT 1; DROP TABLE t'", Rule::DropData),
            (
                "sqlite3 ~/data.db 'SELECT 1' 'DROP TABLE t'",
                Rule::DropData,
            ),
            ("sqlite3 -cmd 'DROP TABLE t' ~/data.db", Rule::DropData),
            ("sqlite3 -header ~/data.db 'DROP TABLE t'", Rule::DropData),
            ("sqlite3 ~/data.db <<< 'DROP TABLE t'", Rule::DropData),
            (
                "sqlite3 ~/data.db <<EOF\nDROP TABLE t;\nEOF",
                Rule::DropData,
            ),
            ("echo 'DROP TABLE t' | sqlite3 ~/data.db", Rule::DropData),
            ("cd ~ && sqlite3 data.db 'DROP TABLE t'", Rule::DropData),
            (
                "sqlite3 data.db \"ATTACH '/home/me/x.db' AS o; DROP TABLE o.t\"",
                Rule::DropData,
            ),
            (
                "sqlite3 data.db '.open ~/x.db' 'DROP TABLE t'",
                Rule::DropData,
            ),
            ("duckdb ~/x.duckdb 'DROP TABLE t'", Rule::DropData),
            ("duckdb ~/x.duckdb -c 'DELETE FROM t'", Rule::DropData),
            ("duckdb ~/x.duckdb -s 'TRUNCATE t'", Rule::DropData),
            ("sqlite3 data.db \"$Q\"", Rule::Unknown),
            ("sqlite3 data.db '.shell rm -rf x'", Rule::Unknown),
            ("sqlite3 data.db '.read |ls'", Rule::Unknown),
            ("sqlite3 data.db .system", Rule::Unknown),
        ],
    );
}

#[test]
fn a_sqlite_database_name_can_be_a_uri_or_a_remote_database() {
    check(
        Shell::Posix,
        &posix(),
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
        ],
    );
}

#[test]
fn a_sqlite_dot_command_is_every_command_its_name_starts() {
    check(
        Shell::Posix,
        &posix(),
        &[
            // Names that start no command the guard reads.
            "sqlite3 :memory: '.schema'",
            "sqlite3 :memory: '.sch'",
            "sqlite3 :memory: '.tables'",
            "sqlite3 :memory: '.mode csv'",
            "sqlite3 :memory: '.headers on'",
            "sqlite3 :memory: '.quit'",
            "duckdb -c '.tables'",
            "sqlite3 ./x.db '.import data.csv t'",
            "sqlite3 ./x.db '.imp data.csv t'",
            "sqlite3 ./x.db '.output out.txt'",
            "sqlite3 data.db '.bail on'",
            "sqlite3 data.db '.ba on'",
            "sqlite3 data.db '.b ~/x.db'",
            "sqlite3 data.db '.schema'",
            // `.restore` of the agent's own file, as for a DROP.
            "sqlite3 ./x.db '.restore empty.db'",
            "sqlite3 :memory: '.restore empty.db'",
            "sqlite3 -readonly ~/x.db '.restore empty.db'",
            // `.backup` and `.save` to a copy in the workspace or the
            // temporary folder.
            "sqlite3 ~/x.db '.backup out.db'",
            "sqlite3 data.db '.backup backup.db'",
            "sqlite3 data.db '.backup /tmp/backup.db'",
            "sqlite3 data.db '.backup temp /tmp/backup.db'",
            "sqlite3 data.db '.save ./copy.db'",
            "sqlite3 -readonly data.db '.backup backup.db'",
            "sqlite3 data.db '.backup :memory:'",
            // `VACUUM INTO` and `.clone` refuse a file that exists.
            "sqlite3 data.db \"VACUUM INTO '/home/me/y.db'\"",
            "sqlite3 data.db '.clone /home/me/y.db'",
        ],
        &[
            // The start of `.shell` and `.system` runs the program.
            ("sqlite3 :memory: '.sh rm -rf ~'", Rule::Unknown),
            ("sqlite3 :memory: '.she rm -rf ~'", Rule::Unknown),
            ("sqlite3 :memory: '.shel rm -rf ~'", Rule::Unknown),
            ("sqlite3 :memory: '.sy rm -rf ~'", Rule::Unknown),
            ("sqlite3 :memory: '.syst rm -rf ~'", Rule::Unknown),
            ("duckdb -c '.sys rm -rf ~'", Rule::Unknown),
            ("sqlite3 :memory: <<'EOF'\n.sy rm -rf ~\nEOF", Rule::Unknown),
            // The start of `.output`, `.once`, `.read` and `.import` that
            // pipes to or reads from a program.
            ("sqlite3 :memory: '.o \"|rm -rf ~\"'", Rule::Unknown),
            ("sqlite3 :memory: '.onc \"|rm -rf ~\"'", Rule::Unknown),
            ("sqlite3 :memory: '.ou \"|rm -rf ~\"'", Rule::Unknown),
            ("sqlite3 x.db '.rea \"|rm -rf ~\"'", Rule::Unknown),
            ("sqlite3 x.db '.re \"|rm -rf ~\"'", Rule::Unknown),
            ("sqlite3 :memory: '.imp \"|rm -rf ~\" t'", Rule::Unknown),
            ("duckdb -c '.rea \"|rm -rf ~\"'", Rule::Unknown),
            // The start of `.open` and `.attach` reaches another file.
            (
                "sqlite3 x.db '.op /home/me/y.db' 'DELETE FROM t'",
                Rule::DropData,
            ),
            (
                "sqlite3 x.db '.att /home/me/y.db z' 'DROP TABLE t'",
                Rule::DropData,
            ),
            (
                "sqlite3 x.db '.open /home/me/y.db' 'DELETE FROM t'",
                Rule::DropData,
            ),
            // `.restore`, and the start of it, replaces the database.
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
            ("sqlite3 ~/x.db '.restore b.db'", Rule::DropData),
            ("sqlite3 ~/x.db '.rest b.db'", Rule::DropData),
            ("sqlite3 ~/x.db '.res b.db'", Rule::DropData),
            // `.backup` and `.save` replace the file they are given.
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
        ],
    );
}

#[test]
fn sqlite_skips_a_line_that_starts_with_a_hash() {
    check(
        Shell::Posix,
        &posix(),
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
fn redis() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "redis-cli",
            "redis-cli GET k",
            "redis-cli get k",
            "redis-cli -h cache -p 6380 -n 2 GET k",
            "redis-cli SET k v",
            "redis-cli DEL k",
            "redis-cli del k1 k2",
            "redis-cli UNLINK k",
            "redis-cli del \"$K\"",
            "redis-cli keys 'sess:*'",
            "redis-cli --scan --pattern 'sess:*'",
            "redis-cli --scan | head",
            "redis-cli INFO",
            "redis-cli -a secret PING",
            "redis-cli <<< 'GET k'",
            "echo 'SET a 1' | redis-cli",
            "cat commands.txt | redis-cli",
            "printf 'a\\nb\\n' | xargs redis-cli del",
            "cat keys.txt | xargs -n1 redis-cli del",
            "redis-cli --version",
            "redis-cli -t 5 GET k",
            "redis-cli -h db -t 5 GET k",
            "redis-cli --cluster info 127.0.0.1:7000",
            "redis-cli --cluster call 127.0.0.1:7000 GET k",
            "redis-cli --cluster call 127.0.0.1:7000 DBSIZE",
            // Options that take a value do not move the command onto it.
            "redis-cli --tls --cacertdir /etc/ssl/certs GET k",
            "redis-cli --show-pushes no GET k",
            "redis-cli -X tag GET k",
            "redis-cli --quoted-pattern x --scan",
            "redis-cli --intrinsic-latency 5",
        ],
        &[
            ("redis-cli FLUSHALL", Rule::DropData),
            ("redis-cli flushall", Rule::DropData),
            ("redis-cli FLUSHDB", Rule::DropData),
            ("redis-cli FLUSHALL ASYNC", Rule::DropData),
            ("redis-cli -n 3 FLUSHDB", Rule::DropData),
            (
                "redis-cli -h cache -p 6380 -a secret FLUSHALL",
                Rule::DropData,
            ),
            ("redis-cli --user me --pass x FLUSHALL", Rule::DropData),
            ("redis-cli -u redis://cache:6379/0 flushdb", Rule::DropData),
            ("redis-cli -r 3 flushall", Rule::DropData),
            ("redis-cli <<< 'FLUSHALL'", Rule::DropData),
            ("redis-cli <<EOF\nSET a 1\nFLUSHDB\nEOF", Rule::DropData),
            ("echo FLUSHALL | redis-cli", Rule::DropData),
            ("echo 'SET a 1\nFLUSHDB' | redis-cli -n 1", Rule::DropData),
            (
                "redis-cli --scan --pattern 'sess:*' | xargs redis-cli del",
                Rule::DropData,
            ),
            (
                "redis-cli --scan --pattern 'a*' | xargs redis-cli del",
                Rule::DropData,
            ),
            (
                "redis-cli --scan --pattern 'sess:*' | xargs -L 100 redis-cli unlink",
                Rule::DropData,
            ),
            (
                "redis-cli -h cache keys 'sess:*' | xargs redis-cli -h cache DEL",
                Rule::DropData,
            ),
            ("redis-cli del $(redis-cli keys 'sess:*')", Rule::DropData),
            (
                "redis-cli unlink $(redis-cli --scan --pattern 'a*')",
                Rule::DropData,
            ),
            (
                "redis-cli --scan | xargs -I{} redis-cli del {}",
                Rule::DropData,
            ),
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
                "redis-cli --tls --cacertdir /etc/ssl/certs FLUSHALL",
                Rule::DropData,
            ),
            ("redis-cli --show-pushes no FLUSHALL", Rule::DropData),
            ("redis-cli -X tag FLUSHALL", Rule::DropData),
            ("redis-cli --quoted-pattern x FLUSHALL", Rule::DropData),
            ("redis-cli --intrinsic-latency 5 FLUSHDB", Rule::DropData),
            ("redis-cli $CMD", Rule::Unknown),
            ("redis-cli \"$CMD\" k", Rule::Unknown),
            ("redis-cli <<< \"$CMD\"", Rule::Unknown),
        ],
    );
}

#[test]
fn a_redis_script_that_lists_keys_and_deletes_them_drops_data() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "redis-cli EVAL 'return 1' 0",
            "redis-cli EVAL \"return redis.call('GET', KEYS[1])\" 1 k",
            "redis-cli --eval script.lua k , a",
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
            (
                "redis-cli EVAL \"redis.call('FLUSHALL')\" 0",
                Rule::DropData,
            ),
            ("redis-cli eval \"redis.call('flushall')\" 0", Rule::DropData),
            // A script only known when it runs.
            (
                "redis-cli --cluster call 127.0.0.1:7000 EVAL \"$S\" 0",
                Rule::Unknown,
            ),
            ("redis-cli EVAL \"$S\" 0", Rule::Unknown),
            ("redis-cli EVALSHA \"$SHA\" 0", Rule::Unknown),
            ("redis-cli FCALL \"$F\" 0", Rule::Unknown),
            ("redis-cli EVAL $(cat s.lua) 0", Rule::Unknown),
            ("echo \"EVAL \\\"$S\\\" 0\" | redis-cli", Rule::Unknown),
        ],
    );
}

#[test]
fn mongodb() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "mongosh",
            "mongosh script.js",
            "mongosh --file migrate.js",
            "mongosh --eval 'db.users.find()'",
            "mongosh mongodb://localhost/app --eval 'db.users.countDocuments()'",
            "mongosh --eval 'db.users.deleteMany({age: {$lt: 3}})'",
            "mongosh --eval 'db.users.deleteOne({})'",
            "mongosh --eval 'db.users.insertOne({a: 1})'",
            "mongosh --eval \"print('db.dropDatabase()')\"",
            "mongosh --eval '// db.dropDatabase()'",
            "mongo --eval 'db.stats()'",
            "mongodump --db app",
            "mongosh <<< 'db.users.find()'",
        ],
        &[
            ("mongosh --eval 'db.dropDatabase()'", Rule::DropData),
            ("mongosh --eval=\"db.dropDatabase()\"", Rule::DropData),
            ("mongosh app --eval 'db.users.drop()'", Rule::DropData),
            (
                "mongosh --host db --port 27018 --eval 'db.users.drop()'",
                Rule::DropData,
            ),
            (
                "mongosh -u me -p x --eval 'db.dropDatabase()'",
                Rule::DropData,
            ),
            (
                "mongosh --eval 'db.getCollection(\"users\").drop()'",
                Rule::DropData,
            ),
            ("mongosh --eval 'db.users.deleteMany({})'", Rule::DropData),
            ("mongosh --eval 'db.users.deleteMany({ })'", Rule::DropData),
            ("mongosh --eval 'db.users.deleteMany()'", Rule::DropData),
            ("mongosh --eval 'db.users.remove({})'", Rule::DropData),
            (
                "mongosh --eval 'db.runCommand({dropDatabase: 1})'",
                Rule::DropData,
            ),
            (
                "mongosh --eval 'db.stats(); db.dropDatabase()'",
                Rule::DropData,
            ),
            (
                "mongosh --eval 'db.dropCollection(\"users\")'",
                Rule::DropData,
            ),
            ("mongo --eval 'db.dropDatabase()'", Rule::DropData),
            ("mongo app --eval 'db.users.drop()'", Rule::DropData),
            ("mongosh <<< 'db.dropDatabase()'", Rule::DropData),
            ("mongosh <<EOF\ndb.users.drop()\nEOF", Rule::DropData),
            ("echo 'db.dropDatabase()' | mongosh", Rule::DropData),
            ("mongosh --eval \"$JS\"", Rule::Unknown),
            ("mongosh --eval \"db.$c.drop()\"", Rule::DropData),
            ("mongosh --eval 'db.users.find(\"x'", Rule::Unknown),
        ],
    );
}

#[test]
fn clickhouse_sqlcmd_and_cqlsh() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "clickhouse-client -q 'SELECT 1'",
            "clickhouse-client --query 'INSERT INTO t VALUES (1)'",
            "clickhouse-client --query \"ALTER TABLE t DELETE WHERE id = 3\"",
            "clickhouse-client --queries-file migrate.sql",
            "clickhouse client -q 'SELECT 1'",
            "clickhouse-client < schema.sql",
            // ClickHouse's `SYSTEM` statements are not programs or drops.
            "clickhouse-client -q 'SYSTEM FLUSH LOGS'",
            "clickhouse-client -q 'SYSTEM RELOAD DICTIONARIES'",
            "clickhouse-client -q 'SYSTEM DROP DNS CACHE'",
            "clickhouse-client -q 'SYSTEM DROP MARK CACHE'",
            "clickhouse-client -q 'SYSTEM DROP UNCOMPRESSED CACHE'",
            "clickhouse client -q 'SYSTEM FLUSH LOGS'",
            "sqlcmd -S db -Q 'SELECT 1'",
            "sqlcmd -S db -U sa -P x -Q 'DELETE FROM users WHERE id = 3'",
            "sqlcmd -i schema.sql",
            "sqlcmd -S db -C -Q 'SELECT 1'",
            "cqlsh -e 'SELECT * FROM t'",
            "cqlsh -f schema.cql",
            "cqlsh host 9042 -e \"DELETE FROM t WHERE k = 1\"",
            "cqlsh -e '// DROP TABLE t\nSELECT 1'",
        ],
        &[
            ("clickhouse-client -q 'DROP TABLE t'", Rule::DropData),
            (
                "clickhouse-client --query 'TRUNCATE TABLE t'",
                Rule::DropData,
            ),
            (
                "clickhouse-client --query='DROP DATABASE d'",
                Rule::DropData,
            ),
            (
                "clickhouse-client -h db -u me -q 'DROP TABLE t'",
                Rule::DropData,
            ),
            (
                "clickhouse-client -q 'ALTER TABLE t DELETE WHERE 1'",
                Rule::DropData,
            ),
            (
                "clickhouse-client -q 'ALTER TABLE t DROP PARTITION 1'",
                Rule::DropData,
            ),
            ("clickhouse client -q 'DROP TABLE t'", Rule::DropData),
            ("clickhouse-client <<< 'DROP TABLE t'", Rule::DropData),
            // A `DROP` that is not after a leading `SYSTEM` still drops.
            (
                "clickhouse-client -q 'SYSTEM FLUSH LOGS; DROP TABLE t'",
                Rule::DropData,
            ),
            // MySQL's `system` runs a program; nothing else has one.
            ("mysql -e 'system ls'", Rule::Unknown),
            ("mariadb -e 'system rm -rf x'", Rule::Unknown),
            ("sqlcmd -S db -Q 'DROP TABLE users'", Rule::DropData),
            (
                "sqlcmd -S db -U sa -P x -d app -Q 'TRUNCATE TABLE users'",
                Rule::DropData,
            ),
            ("sqlcmd -q 'DELETE FROM users'", Rule::DropData),
            ("sqlcmd -Q\"DROP TABLE users\"", Rule::DropData),
            (
                "sqlcmd -S db -Q 'DELETE FROM a DELETE FROM b WHERE x = 1'",
                Rule::DropData,
            ),
            ("sqlcmd -S db -Q \"EXEC xp_cmdshell 'dir'\"", Rule::Unknown),
            ("sqlcmd -Q \"$Q\"", Rule::Unknown),
            ("cqlsh -e 'DROP KEYSPACE app'", Rule::DropData),
            ("cqlsh -e 'TRUNCATE app.users'", Rule::DropData),
            ("cqlsh --execute 'DROP TABLE t'", Rule::DropData),
            (
                "cqlsh host 9042 -u me -p x -e 'DROP TABLE t'",
                Rule::DropData,
            ),
            ("cqlsh -e 'DELETE FROM t'", Rule::DropData),
            ("cqlsh -e \"$Q\"", Rule::Unknown),
        ],
    );
}

#[test]
fn the_tools_that_drop_a_database() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "dropdb --help",
            "dropdb --version",
            "createdb app",
            "pg_dump app",
        ],
        &[
            ("dropdb prod", Rule::DropData),
            ("dropdb -h db -U me prod", Rule::DropData),
            ("dropdb --if-exists prod", Rule::DropData),
            ("dropdb -e prod", Rule::DropData),
            ("sudo -u postgres dropdb prod", Rule::DropData),
            ("dropuser alice", Rule::DropData),
            ("dropuser --if-exists alice", Rule::DropData),
            ("dropdb \"$DB\"", Rule::DropData),
        ],
    );
}

#[test]
fn a_line_that_runs_no_client_is_safe() {
    // The rule reads the program, not the text.
    check(
        Shell::Posix,
        &posix(),
        &[
            "echo 'psql -c \"DROP TABLE t\"'",
            "grep FLUSHALL notes.txt",
            "git log --grep='DROP TABLE'",
            "psqlx -c 'DROP TABLE t'",
            "python3 scripts/gen.py",
            "sqlx migrate run",
            "rails db:migrate",
        ],
        &[],
    );
}

#[test]
fn a_client_command_is_read_anywhere_outside_a_string() {
    check(
        Shell::Posix,
        &posix(),
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
            // A backslash ends a command and starts the next.
            r"psql -c '\set x 1'",
            r"psql -c '\set x 1 \set y 2'",
            r#"psql -c '\set x "a b" \echo done'"#,
            r"psql -c '\echo C:\\tmp'",
            "psql <<'EOF'\n\\set x 1\n\\set y 2\nEOF",
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
            (
                r#"psql -c "SELECT 'DROP TABLE t' \set x 1 \gexec""#,
                Rule::Unknown,
            ),
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
            (r"psql -c '\set x 1 \! touch /tmp/pwn'", Rule::Unknown),
            (
                "psql <<'EOF'\n\\set x 1 \\! touch /tmp/pwn\nEOF",
                Rule::Unknown,
            ),
            (r"psql -c '\echo hi \copy t from program x'", Rule::Unknown),
            (r"psql -c '\set x 1 \o |cat'", Rule::Unknown),
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
            (r"psql -c '\set x 1 \g \\ DROP TABLE t'", Rule::DropData),
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
fn each_client_reads_its_own_quoting() {
    check(
        Shell::Posix,
        &posix(),
        &[
            // PostgreSQL's `$tag$` and `E'…'` strings, and nested comments.
            "psql -c 'SELECT $a$; DROP TABLE t; $a$'",
            // DuckDB's parser is PostgreSQL's, so it has `$tag$` and `E'…'`
            // strings too, which hide what they hold.
            "duckdb ~/x.db 'SELECT $a$; DROP TABLE t; SELECT $a$'",
            r#"duckdb ~/x.duckdb "SELECT \$a\$; DROP TABLE t; \$a\$""#,
            r#"duckdb ~/x.duckdb "SELECT E'a\\'; DROP TABLE t; --'""#,
            r#"psql -c "SELECT E'a\\'; DROP TABLE t; --'""#,
            r#"psql -c "/* /* ; DROP TABLE t */ */ SELECT 1""#,
            // Comments do not nest in MySQL and SQLite: the string after the
            // first `*/` hides what follows.
            r#"mysql -e "/* /* */ ' */ DROP TABLE t; --'""#,
            r#"sqlite3 ~/x.db "/* /* */ ' */ DROP TABLE t; --'""#,
            // ClickHouse: heredocs, `#` comments, backslash escapes, and
            // block comments that nest.
            "clickhouse-client -q 'SELECT $a$; DROP TABLE t; $a$'",
            "clickhouse-client -q 'SELECT 1 # ; DROP TABLE t'",
            r#"clickhouse-client -q "SELECT 'a\\'; DROP TABLE t; --'""#,
            r#"clickhouse-client -q "/* /* ; DROP TABLE t */ */ SELECT 1""#,
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
            // In DuckDB, what looked like a string is code.
            (
                r#"duckdb ~/x.duckdb "SELECT \$\$'\$\$; DROP TABLE t; SELECT \$\$'\$\$""#,
                Rule::DropData,
            ),
            (
                r#"duckdb ~/x.duckdb "SELECT E'a\\' ; SELECT '; DROP TABLE t; --'""#,
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
            // So do ClickHouse's: the comment ends at the last `*/`, and the
            // quote after the DROP is never closed.
            (
                r#"clickhouse-client -q "/* /* */ ' */ DROP TABLE t; SELECT '""#,
                Rule::Unknown,
            ),
            (
                r#"clickhouse-client -q "/* /* */ ' */ SELECT 1; DROP TABLE t; /* ' */""#,
                Rule::DropData,
            ),
            // MySQL and ClickHouse read a backslash in a string.
            (
                r#"sqlite3 ~/x.db "SELECT 'a\\'; DROP TABLE t; --'""#,
                Rule::DropData,
            ),
            // DuckDB's comments may nest: not read.
            ("duckdb ~/x.db '/* /* */ */ DROP TABLE t'", Rule::Unknown),
            // A string, bracket or comment never closed.
            ("sqlite3 ~/x.db 'SELECT [a; DROP TABLE t'", Rule::Unknown),
            ("sqlcmd -Q 'SELECT [a; DROP TABLE t'", Rule::Unknown),
            ("sqlite3 ~/x.db 'SELECT `a; DROP TABLE t'", Rule::Unknown),
            ("duckdb ~/x.db 'SELECT 1 /* DROP TABLE t'", Rule::Unknown),
        ],
    );
}

/// Statements that end before a string that never closes still run: a client
/// sends each one as its `;` arrives.
#[test]
fn statements_before_an_open_string_run() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "mysql -e \"SELECT 'it\\'s'\"",
            "mysql -e \"SELECT 'it\\'s'; SELECT 1\"",
            "mariadb -e \"SELECT 'it\\'s'\"",
        ],
        &[
            (
                "mysql -e \"SET sql_mode='NO_BACKSLASH_ESCAPES'; SELECT 'a\\'; DROP TABLE t; SELECT '\"",
                Rule::DropData,
            ),
            (
                "mariadb -e \"SET sql_mode='NO_BACKSLASH_ESCAPES'; SELECT 'a\\'; DROP TABLE t; SELECT '\"",
                Rule::DropData,
            ),
            (
                "mysql <<'EOF'\nSET sql_mode='NO_BACKSLASH_ESCAPES'; SELECT 'a\\'; DROP TABLE t; SELECT '\nEOF",
                Rule::DropData,
            ),
            (
                "mysql -e \"SET sql_mode='ANSI_QUOTES'; SELECT \\\"a\\\\\\\"; DROP TABLE t; SELECT \\\"\"",
                Rule::DropData,
            ),
            (
                "mysql -e \"SELECT 'a\\'; DROP TABLE t; SELECT '\"",
                Rule::DropData,
            ),
            (
                "psql <<'EOF'\nSET standard_conforming_strings = off;\nSELECT 'a\\''; DROP TABLE t; SELECT ';\nEOF",
                Rule::DropData,
            ),
        ],
    );
}

#[test]
fn a_long_option_is_any_unique_start_of_one() {
    check(
        Shell::Posix,
        &posix(),
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
fn a_password_option_with_no_value_does_not_take_the_statement_option() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "mongosh -u admin -p --eval 'db.users.find()'",
            "mongosh -u admin -p secret --eval 'db.users.find()'",
            "mongosh --username admin --password secret --eval 'db.users.find()'",
            "mongosh --username admin --password --eval 'db.users.find()'",
            "mongosh --password=secret --eval 'db.users.find()'",
            "mongo -u admin -p --eval 'db.users.find()'",
            "clickhouse-client --password secret --query 'SELECT 1'",
            "clickhouse-client --password --query 'SELECT 1'",
            "clickhouse-client --password=secret -q 'SELECT 1'",
            "clickhouse-client --password -q 'SELECT 1'",
        ],
        &[
            // The word after a password with no value is an option of its own.
            (
                "mongosh -u admin -p --eval 'db.dropDatabase()'",
                Rule::DropData,
            ),
            (
                "mongosh --username admin --password --eval 'db.dropDatabase()'",
                Rule::DropData,
            ),
            (
                "mongo -u admin -p --eval 'db.dropDatabase()'",
                Rule::DropData,
            ),
            (
                "mongosh --host -p --eval 'db.dropDatabase()'",
                Rule::DropData,
            ),
            (
                "clickhouse-client --password --query 'DROP TABLE t'",
                Rule::DropData,
            ),
            (
                "clickhouse-client --password -q 'DROP TABLE t'",
                Rule::DropData,
            ),
            ("clickhouse-client --pass -q 'DROP TABLE t'", Rule::DropData),
            // A password that has a value still leaves the statement read.
            (
                "mongosh -u admin -p secret --eval 'db.dropDatabase()'",
                Rule::DropData,
            ),
            (
                "clickhouse-client --password secret --query 'DROP TABLE t'",
                Rule::DropData,
            ),
            // A statement that starts with `-` is read as one too.
            ("mongosh --eval '-1; db.dropDatabase()'", Rule::DropData),
        ],
    );
}

/// A `WHERE` picks the rows of its own statement only: a batch without
/// semicolons keeps each `WHERE` with the statement it follows.
#[test]
fn a_where_picks_the_rows_of_its_own_statement() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "psql -c 'DELETE FROM t WHERE id = 1'",
            "psql -c 'DELETE FROM t WHERE id IN (SELECT id FROM u)'",
            "psql -c 'WITH d AS (DELETE FROM t WHERE x = 1 RETURNING *) SELECT * FROM d'",
            "psql -c 'DELETE FROM t WHERE id = 1; UPDATE u SET a = 1 WHERE b = 2'",
            "psql -c 'UPDATE t SET a = (SELECT 1) WHERE id = 1'",
            "psql -c 'UPDATE users SET a = (SELECT 1) WHERE id = 2'",
            "psql -c 'UPDATE users SET a = 1 FROM (SELECT 1 AS id) s WHERE users.id = s.id'",
            "psql -c 'MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN DELETE WHEN NOT MATCHED THEN INSERT VALUES (1)'",
            "sqlcmd -Q 'UPDATE users SET active = 0 WHERE id = 1 SELECT * FROM users'",
            "sqlcmd -Q 'DELETE FROM users WHERE id = 1 PRINT 1'",
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
fn on_before_a_verb_is_a_statement_unless_it_is_a_rule() {
    check(
        Shell::Posix,
        &posix(),
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
fn then_delete_is_part_of_a_merge_and_nothing_else() {
    check(
        Shell::Posix,
        &posix(),
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

/// A `DROP` that takes away a constraint, a default, an identity or an
/// expression deletes no data; `DROP IDENTITY` and `DROP EXPRESSION` only of
/// a column.
#[test]
fn a_drop_that_deletes_no_data_is_safe() {
    check(
        Shell::Posix,
        &posix(),
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
            (
                "psql -c 'ALTER TABLE users DROP COLUMN name'",
                Rule::DropData,
            ),
            ("psql -c 'ALTER TABLE users DROP name'", Rule::DropData),
            ("mysql -e 'ALTER TABLE t DROP PARTITION p1'", Rule::DropData),
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
fn on_windows() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "sqlcmd -S db -Q 'SELECT 1'",
            "sqlcmd -S db -Q \"DELETE FROM users WHERE id = 3\"",
            "psql -c 'SELECT 1'",
            "sqlite3 data.db 'DROP TABLE t'",
            "sqlite3 C:\\Users\\me\\dev\\repo\\data.db 'DROP TABLE t'",
            "Get-Content schema.sql | psql app",
            "Write-Output 'SELECT 1' | psql app",
            "Select-String 'DROP TABLE' migrations\\001.sql",
        ],
        &[
            ("sqlcmd -S db -Q 'DROP TABLE users'", Rule::DropData),
            ("sqlcmd -S db -Q \"TRUNCATE TABLE users\"", Rule::DropData),
            ("sqlcmd -S db -Q 'DELETE FROM users'", Rule::DropData),
            ("sqlcmd -S db -q 'DROP DATABASE prod'", Rule::DropData),
            ("psql -c 'DROP TABLE users'", Rule::DropData),
            ("psql.exe -c 'DROP TABLE users'", Rule::DropData),
            ("mysql -e 'DROP DATABASE prod'", Rule::DropData),
            (
                "sqlite3 C:\\Users\\me\\data.db 'DROP TABLE t'",
                Rule::DropData,
            ),
            ("sqlite3 $env:DB 'DROP TABLE t'", Rule::DropData),
            ("redis-cli FLUSHALL", Rule::DropData),
            ("dropdb prod", Rule::DropData),
            ("Write-Output 'DROP TABLE users' | psql app", Rule::DropData),
            ("echo 'DROP TABLE users' | psql app", Rule::DropData),
            ("sqlcmd -S db -Q $q", Rule::Unknown),
        ],
    );
    check(
        Shell::Cmd,
        &windows(),
        &[
            "sqlcmd -S db -Q \"SELECT 1\"",
            "sqlcmd -S db -Q \"DELETE FROM users WHERE id = 3\"",
            "sqlcmd -i schema.sql",
        ],
        &[
            ("sqlcmd -S db -Q \"DROP TABLE users\"", Rule::DropData),
            ("sqlcmd -S db -Q \"TRUNCATE TABLE users\"", Rule::DropData),
            ("sqlcmd /S db /Q \"DROP TABLE users\"", Rule::DropData),
            ("psql -c \"DROP TABLE users\"", Rule::DropData),
            ("redis-cli FLUSHALL", Rule::DropData),
            ("echo DROP TABLE users | sqlcmd -S db", Rule::DropData),
            ("sqlcmd -S db -Q \"%Q%\"", Rule::Unknown),
        ],
    );
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

#[test]
#[cfg_attr(
    coverage,
    ignore = "timing: `just timing` runs it in an optimized build"
)]
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
    let took = took(&line, Shell::Posix, &posix());
    assert!(took < std::time::Duration::from_secs(5), "took {took:?}");
    let rules = rules(&line, Shell::Posix, &posix());
    assert!(rules.iter().all(|rule| *rule == Rule::Unknown), "{rules:?}");
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn a_where_is_found_for_every_verb_in_one_pass() {
    let (shell, paths) = (Shell::Posix, posix());
    // Each verb that needs a `WHERE` used to look for it to the end of the
    // text, and a verb in an open parenthesis never found the end.
    assert_linear("psql -c DELETE (DELETE (…", shell, &paths, |size| {
        format!("psql -c '{}'", filled("DELETE (", size, 20))
    });
    assert_linear("mysql -e DELETE (DELETE (…", shell, &paths, |size| {
        format!("mysql -e '{}'", filled("DELETE (", size, 20))
    });
    assert_linear("UPDATE (UPDATE (…", shell, &paths, |size| {
        format!("psql -c '{}'", filled("UPDATE (", size, 20))
    });
    // A group whose escapes make the shells read it differently.
    assert_linear("a piped group of escapes", shell, &paths, |size| {
        let part = filled("\\x41\\101 DELETE (", size, 100);
        format!("{{ echo -n '{part}'; echo -n '\\x41\\101 '; echo '\\x41\\101 '; }} | mysql")
    });
    // `THEN DELETE` looked back to a `WHEN` for each one.
    assert_linear("MERGE … THEN DELETE …", shell, &paths, |size| {
        format!("psql -c 'MERGE {}'", filled("THEN DELETE ", size, 20))
    });
    // A `WHERE` after each verb of a nest.
    assert_linear("DELETE (DELETE (… WHERE …", shell, &paths, |size| {
        let opens = filled("DELETE (", size / 2, 10);
        let closes = filled(") WHERE x ", size / 2, 10);
        format!("psql -c '{opens}{closes}'")
    });
}
