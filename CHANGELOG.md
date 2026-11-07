# Changelog

Every release of the milo-guards crates, newest first. The crates share one
version ([Releasing](CONTRIBUTING.md#releasing)); what a release changes for
a caller is here, what it changes inside a guard is in the commits.

## Unreleased

Lines the guards judged wrong, nothing a caller compiles against: a patch.
Each line below was safe, or slow, and is now judged as it reads.

- `milo-guards-shell`: an `alias` with a word only known when it runs
  (`alias x="$CMD"`) is `unknown`, and a call of it no longer slips through
  as an unknown bare name (#285).
- `milo-guards-shell`: the files `find` writes with `-fprint`, `-fprint0`,
  `-fls` and `-fprintf` are judged as a redirect's are, so
  `find . -fprint ~/.bashrc` is `overwrite` (#287).
- `milo-guards-shell`: `firejail`, `fakeroot`, `faketime`, `entr`, `bwrap`
  and `proot` run the command after their options, which is judged as
  written; `bwrap` and `proot` map the file system, so their lines are
  `unreadable` as well. `man -P CMD`, `man -H CMD` and fzf's
  `--preview CMD` hand a command to a shell, which is read; a key binding of
  fzf (`--bind`) is `unreadable` (#288).
- `milo-guards-core`: a write into a long wildcard pattern is placed in time
  linear in its parts; a line of 60 KB of `**/` took 15 s and takes a tenth
  of one (#286).
- `milo-guards-core`: the home directory, the sensitive places and the
  protected paths compare in either Unicode canonical spelling (`é` as one
  character, or `e` and a combining accent, as HFS+ keeps it), so the file
  guard's `write_protected` and the shell guard's findings hold for both
  (#290).
- `milo-guards-code`: code nested past the depth the reader walks is never
  `Understood` (#289).

## 0.1.1 (2026-11-05)

The pages on crates.io, nothing a caller compiles against or a guard answers.

- Each crate carries a README of its own (what it reads, how to depend on
  it, its example, compiled with the doctests), where every crate showed the
  workspace's; the front door `milo-guards` keeps that one.
- The README's logo is named by its absolute URL, so crates.io shows it.

## 0.1.0 (2026-11-05)

The first release, on crates.io as `milo-guards` with the guards behind it.

- `milo-guards-shell`: judges a shell line, POSIX shell, PowerShell or cmd,
  parsed with tree-sitter 0.26; `effect` says whether it only reads and
  where, `explain` how the line was read; inline Python and JavaScript are
  read with the `code` reader (feature `inline`, on by default).
- `milo-guards-file`: judges one read or write of a path.
- `milo-guards-url`: judges a URL by the host a parser reads, its scheme
  and its user-info.
- `milo-guards-secrets`: finds credentials and personal data in a text,
  with the spans to scrub, never the secret.
- `milo-guards-code`: reads Python and JavaScript for the acts the code is
  certain to do; not a guard.
- `milo-guards-core`: the `Paths` a call is judged against, `Protected`
  paths in the caller's words, `Assessment` and `Finding` with `instead`,
  the `RuleName` trait, and a test kit behind the `testing` feature.

Every guard keeps the contract: no I/O and no environment reads,
deterministic, no policy, what cannot be read is risky, never panics.
