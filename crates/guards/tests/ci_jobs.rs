//! CI runs the gate `just verify` runs locally, in two jobs: the `verify`
//! job runs every recipe of it but `timing`, in its order, and the `timing`
//! job runs `just timing` alone. A recipe added to `verify` and not to CI
//! fails here.

#![allow(
    clippy::disallowed_methods,
    clippy::disallowed_macros,
    reason = "this test reads the repository's own files, which no guard may do"
)]

use std::fs;
use std::path::Path;

/// A file at the repository root, or a message saying which one is missing.
fn read(relative: &str) -> Result<String, String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative);
    fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {relative} ({e}) at {}", path.display()))
}

/// The recipes `recipe` depends on in `justfile`, in order.
fn dependencies(justfile: &str, recipe: &str) -> Result<Vec<String>, String> {
    let head = format!("{recipe}:");
    justfile
        .lines()
        .find_map(|line| line.strip_prefix(&head))
        .map(|rest| rest.split_whitespace().map(str::to_string).collect())
        .ok_or_else(|| format!("the justfile has no recipe `{recipe}`"))
}

/// The commands of every `run:` step of the job `job` in `workflow`, in
/// order: the lines below `  job:` up to the next job, each written
/// `- run: …` or `run: …`.
fn runs(workflow: &str, job: &str) -> Result<Vec<String>, String> {
    let head = format!("  {job}:");
    let mut lines = workflow.lines().skip_while(|line| *line != head);
    if lines.next().is_none() {
        return Err(format!("ci.yml has no job `{job}`"));
    }
    Ok(lines
        .take_while(|line| line.is_empty() || line.starts_with("    "))
        .filter_map(|line| {
            let step = line.trim_start();
            step.strip_prefix("- run:")
                .or_else(|| step.strip_prefix("run:"))
        })
        .map(|command| command.trim().to_string())
        .collect())
}

#[test]
fn ci_runs_every_recipe_of_verify_with_timing_in_a_job_of_its_own() -> Result<(), String> {
    let verify = dependencies(&read("justfile")?, "verify")?;
    let workflow = read(".github/workflows/ci.yml")?;
    assert!(
        verify.iter().any(|recipe| recipe == "timing"),
        "`just verify` must run `timing` locally: {verify:?}"
    );
    let deterministic: Vec<&str> = verify
        .iter()
        .map(String::as_str)
        .filter(|recipe| *recipe != "timing")
        .collect();
    assert_eq!(
        runs(&workflow, "verify")?,
        [format!("just {}", deterministic.join(" "))],
        "the verify job of ci.yml must run every recipe of `just verify` but `timing`, in its order"
    );
    assert_eq!(
        runs(&workflow, "timing")?,
        ["just timing"],
        "the timing job of ci.yml must run `just timing` alone"
    );
    Ok(())
}
