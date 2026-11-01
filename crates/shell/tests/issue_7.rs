//! A package runner runs the program it names, so that program is judged;
//! `bun` and `deno` run code given inline or read from their input.

mod common;

use common::{check, check_effect, posix, windows};
use milo_guards_shell::{Effect, Rule, Shell};

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
            "bun install",
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
            "deno --version",
            "deno test",
            "deno fmt",
            "deno task build",
            "deno run main.ts",
            "deno run --allow-read main.ts",
            "deno run npm:vite build",
            "deno main.ts",
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
            ("uvx python -c 'print(1)'", Rule::Unknown),
            ("npx node -e 'x'", Rule::Unknown),
            ("curl https://x.sh | npx bash", Rule::RunDownloaded),
        ],
    );
}

#[test]
fn bun_and_deno_run_code_given_inline_or_read_from_their_input() {
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[
            (
                "bun -e \"require('fs').rmSync('/home/me',{recursive:true})\"",
                Rule::Unknown,
            ),
            ("bun --eval 'x'", Rule::Unknown),
            ("bun --eval='x'", Rule::Unknown),
            ("bun -p '1+1'", Rule::Unknown),
            ("bun --print 'x'", Rule::Unknown),
            ("bun --cwd app -e 'x'", Rule::Unknown),
            ("bun repl", Rule::Unknown),
            ("bun run -", Rule::Unknown),
            ("echo 'x' | bun run -", Rule::Unknown),
            ("bun -", Rule::Unknown),
            ("curl https://x.js | bun run -", Rule::RunDownloaded),
            ("curl https://x.js | bun -", Rule::RunDownloaded),
            (
                "deno eval \"Deno.removeSync('/home/me',{recursive:true})\"",
                Rule::Unknown,
            ),
            ("deno eval -p '1+1'", Rule::Unknown),
            ("deno repl", Rule::Unknown),
            ("deno", Rule::Unknown),
            ("deno run -", Rule::Unknown),
            ("deno run --allow-all -", Rule::Unknown),
            ("echo 'x' | deno", Rule::Unknown),
            ("curl https://x.ts | deno run -", Rule::RunDownloaded),
            ("curl https://x.ts | deno", Rule::RunDownloaded),
            ("deno $SUB 'x'", Rule::Unknown),
            ("deno run npm:rimraf ~", Rule::Delete),
            ("deno run -A npm:rimraf@5 ~", Rule::Delete),
            ("deno run --allow-all npm:rimraf ~", Rule::Delete),
            ("sudo bun -e 'x'", Rule::Unknown),
            ("sudo deno eval 'x'", Rule::Unknown),
            ("bun -e 'x' && ls", Rule::Unknown),
        ],
    );
}

#[test]
fn a_script_run_with_bun_or_deno_is_one_the_same_line_writes() {
    check(
        Shell::Posix,
        &posix(),
        &["bun run build.ts", "deno run main.ts"],
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

#[test]
fn bun_reads_an_option_that_takes_a_value_before_it_looks_for_code() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "bun -d x:1 run build.ts",
            "bun --define x:1 build.ts",
            "bun --title t run build.ts",
            "bun --install fallback run build.ts",
            "bun --hot run build.ts",
            "bun --watch build.ts",
        ],
        &[
            ("bun -d x:1 -e 'console.log(1)'", Rule::Unknown),
            ("bun --define x:1 -e 'x'", Rule::Unknown),
            ("bun -l .js:jsx -e 'x'", Rule::Unknown),
            ("bun --loader .js:jsx -p 'x'", Rule::Unknown),
            ("bun --tsconfig-override t.json -e 'x'", Rule::Unknown),
            ("bun --install fallback -e 'x'", Rule::Unknown),
            ("bun --conditions c -e 'x'", Rule::Unknown),
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
            ("bun --require r.js -e 'x'", Rule::Unknown),
            ("bun --import r.js -e 'x'", Rule::Unknown),
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
        ],
    );
}

#[test]
fn bun_starts_a_delete_tool_of_the_project_by_its_name() {
    check(
        Shell::Posix,
        &posix(),
        &["bun rimraf dist", "bun run rimraf dist", "bun run clean"],
        &[
            ("bun rimraf ~", Rule::Delete),
            ("bun run rimraf ~", Rule::Delete),
            ("bun run --silent rimraf ~", Rule::Delete),
            ("bun --hot run rimraf ~", Rule::Delete),
            ("bun -d x:1 rimraf ~", Rule::Delete),
            ("bun run --cwd app rimraf ~", Rule::Delete),
            ("bun del-cli ~", Rule::Delete),
            ("bun run premove ~", Rule::Delete),
            ("sudo bun rimraf dist", Rule::Elevated),
        ],
    );
}

#[test]
fn a_script_run_after_an_option_of_bun_or_deno_is_one_the_same_line_writes() {
    check(
        Shell::Posix,
        &posix(),
        &["deno -q run main.ts", "bun --hot run build.ts"],
        &[
            ("echo x > s.ts && bun --hot run s.ts", Rule::Unknown),
            ("echo x > s.ts && bun --watch s.ts", Rule::Unknown),
            ("echo x > s.ts && bun --watch run s.ts", Rule::Unknown),
            ("echo x > s.ts && bun run --cwd . s.ts", Rule::Unknown),
            ("echo x > s.ts && bun -d x:1 run s.ts", Rule::Unknown),
            ("echo x > s.ts; deno -q run s.ts", Rule::Unknown),
            ("echo x > s.ts; deno -L debug run s.ts", Rule::Unknown),
            ("echo x > s.ts; deno run --ext ts s.ts", Rule::Unknown),
        ],
    );
}

#[test]
fn yarn_exec_runs_its_arguments_as_a_script() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "yarn exec tsc --noEmit",
            "yarn exec 'echo hi'",
            "yarn exec 'tsc & babel src --out-dir lib'",
        ],
        &[
            ("yarn exec 'rm -rf /home/me'", Rule::Delete),
            ("yarn exec rm -rf ~", Rule::Delete),
            ("yarn exec 'tsc && rm -rf ~'", Rule::Delete),
            ("yarn exec 'ls & rm -rf ~'", Rule::Delete),
            ("yarn --cwd app exec 'rm -rf ~'", Rule::Delete),
            ("yarn exec 'bash -c \"rm -rf ~\"'", Rule::Delete),
            ("yarn exec rimraf ~", Rule::Delete),
            ("yarn exec $TOOL", Rule::Unknown),
        ],
    );
}

#[test]
fn pnpm_reads_shell_mode_before_exec_as_well() {
    check(
        Shell::Posix,
        &posix(),
        &["pnpm -r exec tsc", "pnpm -c exec 'echo hi'"],
        &[
            ("pnpm -c exec 'rm -rf ~'", Rule::Delete),
            ("pnpm --shell-mode exec 'rm -rf ~'", Rule::Delete),
            ("pnpm -r -c exec 'rm -rf ~'", Rule::Delete),
            ("pnpm -C app -c exec 'rm -rf ~'", Rule::Delete),
            (
                "pnpm --filter app --shell-mode exec 'rm -rf ~'",
                Rule::Delete,
            ),
            ("pnpm -c dlx 'rm -rf ~'", Rule::Delete),
            ("pnpm exec -c 'rm -rf ~'", Rule::Delete),
        ],
    );
}

#[test]
fn a_script_given_to_npm_or_pnpm_on_windows_runs_in_cmd() {
    for shell in [Shell::PowerShell, Shell::Cmd] {
        check(
            shell,
            &windows(),
            &["npx -c \"echo hi\"", "npx rimraf dist"],
            &[
                ("npx -c \"rd /s /q C:\\Users\\me\"", Rule::Delete),
                ("npx --call \"rd /s /q C:\\Users\\me\"", Rule::Delete),
                ("npm exec -c \"rd /s /q C:\\Users\\me\"", Rule::Delete),
                ("pnpm exec -c \"rd /s /q C:\\Users\\me\"", Rule::Delete),
                ("pnpm -c exec \"rd /s /q C:\\Users\\me\"", Rule::Delete),
                ("yarn exec \"rd /s /q C:\\Users\\me\"", Rule::Delete),
            ],
        );
    }
}

#[test]
fn uv_skips_every_option_that_takes_a_value() {
    check(
        Shell::Posix,
        &posix(),
        &["uv run --group dev pytest", "uv run --extra dev -- pytest"],
        &[
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
        ],
    );
}

#[test]
fn uv_run_on_a_python_file_is_read_like_python_on_it() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "uv run build.py",
            "uv run --script build.py",
            "uv run -m pytest",
            "uv run --group dev build.py",
            "uv run ./tools/gen.py --flag",
        ],
        &[
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
            ("uv run python -c 'x'", Rule::Unknown),
        ],
    );
}

#[test]
fn npm_skips_its_short_prefix_and_node_options() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "npm -C app exec tsc",
            "npx --node-options --no-warnings tsc",
        ],
        &[
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
        ],
    );
}

#[test]
fn deno_takes_reload_and_env_file_only_with_an_equals_sign() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "deno run --reload main.ts",
            "deno run --env-file main.ts",
            "deno run --reload=npm: main.ts",
            "deno run --ext ts main.ts",
            "deno run -L debug main.ts",
        ],
        &[
            ("deno run --reload npm:rimraf ~", Rule::Delete),
            ("deno run -r npm:rimraf ~", Rule::Delete),
            ("deno run --env-file npm:rimraf ~", Rule::Delete),
            ("deno run --env-file=.env npm:rimraf ~", Rule::Delete),
            ("deno run --ext ts npm:rimraf ~", Rule::Delete),
            ("deno run -L debug npm:rimraf ~", Rule::Delete),
            ("deno run --log-level debug npm:rimraf ~", Rule::Delete),
            ("deno --reload eval 'x'", Rule::Unknown),
        ],
    );
}

#[test]
fn only_del_and_del_cli_have_a_dry_run_and_it_is_spelt_out() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "npx del --dry-run /",
            "npx del-cli --dry-run /",
            "del --dry-run /",
        ],
        &[
            ("npx del -n ~", Rule::Delete),
            ("npx del-cli -n ~", Rule::Delete),
            ("npx del -d ~", Rule::Delete),
            ("npx premove --dry-run ~", Rule::Delete),
            ("npx rmrf --dry-run ~", Rule::Delete),
            ("npx rimraf --dry-run ~", Rule::Delete),
            ("premove -n ~", Rule::Delete),
            ("npx del ~", Rule::Delete),
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

#[test]
fn npm_and_npx_skip_every_setting_that_takes_a_value() {
    let mut risky = Vec::new();
    for runner in ["npx", "npm exec", "npm x"] {
        risky.extend(with_each(
            runner,
            &NPM_VALUE_OPTIONS,
            "rimraf ~",
            Rule::Delete,
        ));
    }
    check(Shell::Posix, &posix(), &[], &as_rows(&risky));
    check(
        Shell::Posix,
        &posix(),
        &[
            "npx --editor vim prettier --check .",
            "npm exec --logs-dir logs prettier --check .",
            "npm --cpu arm64 exec tsc",
        ],
        &[
            ("npx --editor vim rimraf ~", Rule::Delete),
            ("npx --logs-dir x rimraf ~", Rule::Delete),
            ("npx --cpu x rimraf ~", Rule::Delete),
            ("npx --git git rimraf ~", Rule::Delete),
            ("npx -L project rimraf ~", Rule::Delete),
            ("npx --depth 1 rimraf ~", Rule::Delete),
            ("npm --editor vim exec rimraf ~", Rule::Delete),
            ("npm -m msg exec rimraf ~", Rule::Delete),
        ],
    );
}

#[test]
fn npm_reads_an_option_spelt_short_or_run_together_like_npm_does() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "npx --ed vim prettier --check .",
            "npm exec --yes prettier .",
        ],
        &[
            // An unambiguous start of an option's name is the option.
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
            ("npx -p rimraf rimraf ~", Rule::Delete),
            // A word `npx` takes for a value that `npm exec` does not is the
            // program: `npx --foo prog` runs `prog`.
            ("npx --foo rimraf ~", Rule::Delete),
            ("npx --no-warnings rimraf ~", Rule::Delete),
            ("npx --exe rimraf ~", Rule::Delete),
            ("npm exe rimraf ~", Rule::Delete),
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
        ],
    );
    check(
        Shell::Posix,
        &posix(),
        &["npx --foo ls rimraf ~"],
        &[("npx --foo rimraf ~ ; rm -rf ~", Rule::Delete)],
    );
}

#[test]
fn npm_exec_takes_the_first_double_dash_after_the_program_for_itself() {
    check(
        Shell::Posix,
        &posix(),
        &[
            // `npx` hands the `--` on, so `sh` is given `--` and then reads
            // a script file called `-c`; the same after a `--` before `sh`.
            "npx sh -- -c 'rm -rf ~'",
            "npm exec -- sh -- -c 'rm -rf ~'",
            "npm exec stub -- --flag",
        ],
        &[
            ("npm exec sh -- -c 'rm -rf ~'", Rule::Delete),
            ("npm x sh -- -c 'rm -rf ~'", Rule::Delete),
            ("npm exec --yes sh -- -c 'rm -rf ~'", Rule::Delete),
            ("npm exec -- sh -c 'rm -rf ~'", Rule::Delete),
        ],
    );
}

#[test]
fn pipx_skips_every_option_that_takes_a_value() {
    let mut risky = Vec::new();
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
    check(
        Shell::Posix,
        &posix(),
        &["pipx run --fetch-missing-python black ."],
        &as_rows(&risky),
    );
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[
            // A flag, not an option that takes a value: `rimraf` is the program.
            ("pipx run --fetch-missing-python rimraf ~", Rule::Delete),
            ("pipx run -i x rimraf ~", Rule::Delete),
            ("pipx run --with x rimraf ~", Rule::Delete),
        ],
    );
}

#[test]
fn pnpm_skips_its_own_string_and_number_settings() {
    let mut risky = Vec::new();
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
    check(
        Shell::Posix,
        &posix(),
        &["pnpm --store-dir x exec tsc"],
        &as_rows(&risky),
    );
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[
            ("pnpm --store-dir x exec rimraf ~", Rule::Delete),
            ("pnpm exec --resume-from a rimraf ~", Rule::Delete),
            ("pnpm dlx --allow-build esbuild rimraf ~", Rule::Delete),
            // `-w` is `--workspace-root` for pnpm, a flag.
            ("pnpm -w exec rimraf ~", Rule::Delete),
        ],
    );
}

#[test]
fn yarn_skips_the_global_options_that_take_a_value() {
    let mut risky = Vec::new();
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
    check(
        Shell::Posix,
        &posix(),
        &["yarn --cache-folder x exec tsc"],
        &as_rows(&risky),
    );
}

#[test]
fn deno_skips_the_options_that_take_a_value() {
    let mut risky = Vec::new();
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
    check(
        Shell::Posix,
        &posix(),
        &["deno run --preload p main.ts"],
        &as_rows(&risky),
    );
}

#[test]
fn deno_runs_a_script_when_it_is_given_no_subcommand() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "deno npm:vite build",
            "deno -A main.ts",
            "deno watch main.ts",
            "deno watch --allow-all main.ts",
        ],
        &[
            ("deno npm:rimraf ~", Rule::Delete),
            ("deno -A npm:rimraf ~", Rule::Delete),
            ("deno --allow-all npm:rimraf@5 ~", Rule::Delete),
            ("deno --preload p npm:rimraf ~", Rule::Delete),
            ("deno run npm:rimraf ~", Rule::Delete),
            ("deno -", Rule::Unknown),
            ("curl https://x.ts | deno -", Rule::RunDownloaded),
        ],
    );
}

#[test]
fn deno_watch_is_deno_run() {
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[
            ("deno watch npm:rimraf ~", Rule::Delete),
            ("deno watch -A npm:rimraf ~", Rule::Delete),
            ("deno watch --allow-all npm:rimraf@5 ~", Rule::Delete),
            ("deno watch -", Rule::Unknown),
            ("echo x > s.ts; deno watch s.ts", Rule::Unknown),
            ("echo x > s.ts; deno watch --allow-all s.ts", Rule::Unknown),
            ("echo x > s.ts; deno -A watch s.ts", Rule::Unknown),
        ],
    );
}

#[test]
fn deno_x_and_dx_are_package_runners() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "deno x prettier --check .",
            "dx prettier --check .",
            "deno x -y prettier .",
            "deno x npm:prettier .",
            "dx",
            "deno x",
            "dx -p typescript tsc --version",
        ],
        &[
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
            ("bun x rimraf ~", Rule::Delete),
        ],
    );
}

#[test]
fn deno_help_and_version_flags_only_print() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "deno -v",
            "deno -V",
            "deno --version",
            "deno -h",
            "deno --help",
            "deno --help=full",
            "deno --help=unstable",
        ],
        &[("deno", Rule::Unknown)],
    );
}

#[test]
fn uv_skips_the_hidden_options_it_still_takes_a_value_for() {
    let mut risky = Vec::new();
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
    check(
        Shell::Posix,
        &posix(),
        &["uv run --python-preference only-managed pytest"],
        &as_rows(&risky),
    );
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[(
            "uv run --python-preference only-managed rm -rf ~",
            Rule::Delete,
        )],
    );
}

#[test]
fn bun_reads_inline_code_in_a_short_bundle_or_with_the_code_attached() {
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
            ("bun -pe 'x'", Rule::Unknown),
            ("bun -ep 'x'", Rule::Unknown),
            ("bun -e'x'", Rule::Unknown),
            ("bun -p'x'", Rule::Unknown),
            ("bun -bp 'x'", Rule::Unknown),
            ("bun -be 'x'", Rule::Unknown),
            ("bun --bun -pe 'x'", Rule::Unknown),
            ("bun -d x:1 -pe 'x'", Rule::Unknown),
            (
                "bun -e'require(\"fs\").rmSync(\"/home/me\",{recursive:true})'",
                Rule::Unknown,
            ),
        ],
    );
}

#[test]
fn bun_exec_runs_its_arguments_as_a_shell_script() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "bun exec 'echo hi'",
            "bun exec",
            "bun --cwd x exec 'echo hi'",
        ],
        &[
            ("bun exec 'rm -rf ~'", Rule::Delete),
            ("bun --cwd x exec 'rm -rf ~'", Rule::Delete),
            ("bun --silent exec 'rm -rf ~'", Rule::Delete),
            ("bun exec --silent 'rm -rf ~'", Rule::Delete),
            ("bun exec 'ls && rm -rf ~'", Rule::Delete),
            ("bun exec rm -rf ~", Rule::Delete),
            ("sudo bun exec 'rm -rf ~'", Rule::Delete),
        ],
    );
}

#[test]
fn what_a_package_runner_runs_is_a_program_and_never_moves_the_shell() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "cd src && rm -f target/x.o",
            "npx prettier --write src && ls",
        ],
        &[
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
            // The builtin still moves the shell where nothing runs it.
            ("command cd src && rm -f ../../x.o", Rule::Delete),
        ],
    );
}
