//! A measurement for step 2 of #270, not to merge: times one cmd line that
//! is ten to twenty times slower on GitHub's runner than on a fast machine,
//! beside variants that each drop one of its parts.
#![allow(clippy::disallowed_methods, reason = "a measurement reads the clock")]

#[allow(dead_code)]
mod common;

use milo_guards_shell::{classify, Shell};
use std::time::{Duration, Instant};

fn fit(unit: &str, size: usize) -> String {
    unit.repeat(size / unit.len())
}

fn quickest(line: &str, shell: Shell) -> Duration {
    let paths = if shell == Shell::Posix {
        common::posix()
    } else {
        common::windows()
    };
    (0..3)
        .map(|_| {
            let started = Instant::now();
            let _ = classify(line, shell, &paths);
            started.elapsed()
        })
        .min()
        .unwrap_or_default()
}

#[test]
#[ignore = "a measurement: run with --ignored --nocapture"]
fn time_the_slow_cmd_row_and_its_parts() {
    let rows: [(&str, Shell, &str); 5] = [
        ("cmd cd+echo>NUL", Shell::Cmd, "cd x; echo y > NUL; "),
        ("cmd cd+echo", Shell::Cmd, "cd x; echo y; "),
        ("cmd echo>NUL", Shell::Cmd, "echo y > NUL; "),
        ("cmd cd only", Shell::Cmd, "cd x; "),
        (
            "posix cd+echo>/dev/null",
            Shell::Posix,
            "cd x; echo y > /dev/null; ",
        ),
    ];
    for (name, shell, unit) in rows {
        let times: Vec<String> = [1, 2, 4, 8, 16, 32, 64]
            .iter()
            .map(|kb| {
                format!(
                    "{kb}K={:.1}ms",
                    quickest(&fit(unit, kb * 1024), shell).as_secs_f64() * 1000.0
                )
            })
            .collect();
        println!("PROBE {name:<26} {}", times.join("  "));
    }
}
