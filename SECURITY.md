# Security

## Reporting a vulnerability

Please do not open a public issue for a security problem. Report it
privately through GitHub's vulnerability reporting for this repository:

https://github.com/camiloazula/milo-guards/security/advisories/new

You will get an acknowledgement within a few days. Once a fix is ready it
is merged with a note that credits the reporter, unless they prefer
otherwise.

## What a guard promises

A guard reads what an agent is about to do, such as a shell line, and says
whether it is safe to do without asking, or risky and why. It reads the text
and the directories the caller gives it. It does not run anything, touch the
file system or read the environment.

It is not a sandbox. A line a guard lets through still runs with all the
rights of the user who runs it, and nothing isolates it. And a Safe verdict is
not a proof: it means no rule found anything, not that nothing can go wrong.
What a guard cannot read it reports as risky, so an unusual line asks rather
than runs.

## What counts

A report is in scope when:

- a line is judged Safe that should not be: it deletes, overwrites or sends
  something beyond the workspace, or runs something the line does not show,
  and no rule says so;
- a guard panics, hangs or exhausts the machine on a crafted input;
- a guard reads a file or the environment, or gives a different answer for the
  same input.

A line judged Risky that is harmless is a bug, not a vulnerability: open an
issue. What a caller does with a verdict is the caller's, and a hole in the
caller's policy is reported there.

## Supported versions

The latest release of the crates on crates.io gets fixes, as a patch of
its minor version: a caller that depends on `"0.1"` takes one with `cargo
update`. Older minor versions get none. A caller that depends on a git tag
moves to the fix by bumping it.

## Dependencies

Every dependency is audited against the RustSec database with `cargo deny`
in CI.
