# milo-guards-secrets

Reads a text and says whether it holds a credential (a key, a token, a
password) or personal data, and where. The secrets guard of
[milo-guards](https://github.com/camiloazula/milo-guards).

A caller that puts text in front of a model scrubs it first, and a caller
that lets an agent write a source file asks whether the content carries a key
into it. Both are the same question of a text: what in it is a secret. The
text has no place, so unlike the guards that judge a path there is no `Paths`
here: a text in, findings out.

- **A finding never carries the secret.** Its target is masked: the public
  prefix of a key and its length (`AKIA… (20 chars)`), only the length when
  what was found begins with the secret itself, or the first line of a block
  of private key.
- **The spans are offsets, not text.** `find_spans` gives the byte range of
  each thing found, on character boundaries, so a caller can replace it and
  leave the text around it as it was.
- **The table is judged by shape and by value.** A key is found by the prefix
  and the length its provider publishes; a password only where a name says
  so; a number only when it passes its own check (the Luhn check of a card).
- **A text that is no key is safe.** SHAs, UUIDs, base64 fixtures, hashes,
  minified code and a lockfile's integrity hashes are safe.
- **Shapeless secrets are a second function**, `find_high_entropy`, never a
  part of `find`: a guard has no modes, and a caller that wants a guess calls
  it.

The text is read in time linear in its length, whatever it holds.

## Install

Through the front door, where it is the `secrets` feature (opt in: most
callers want the other guards and not a table of credential patterns in
their binary):

```toml
[dependencies]
milo-guards = { version = "0.1", features = ["secrets"] }
```

Or on its own:

```toml
[dependencies]
milo-guards-secrets = "0.1"
```

## Example

```rust
use milo_guards_secrets::{find, find_spans, Rule};

assert!(find("let sha = \"3f786850e387550fdab836ed7e6dc881de23001b\";").is_safe());

// `AKIA` and sixteen characters: an AWS access key.
let text = format!("key = {}", ["AKIA", "FAKE2KEY3ID4TEST"].concat());
let assessment = find(&text);
let finding = &assessment.findings()[0];
assert_eq!(finding.rule, Rule::CloudKey);
assert_eq!(finding.reason, "holds an AWS access key");
assert_eq!(finding.target.as_deref(), Some("AKIA… (20 chars)"));

// A caller that scrubs replaces the span, and nothing else.
let span = find_spans(&text)[0];
assert_eq!((span.rule, span.start, span.end), (Rule::CloudKey, 6, 26));
assert_eq!(format!("{}[hidden]{}", &text[..span.start], &text[span.end..]), "key = [hidden]");
```

## Contract

Like every milo-guards crate: no I/O and no environment reads, deterministic
(the same input gives the same answer on every machine), no policy (it
reports, and what to do with a finding is the caller's), what cannot be read
is risky, and nothing it is given makes it panic. The rules are on the
repository's [guidelines](https://github.com/camiloazula/milo-guards/blob/main/GUIDELINES.md).

## License

MIT or Apache-2.0, at your option
([LICENSE-MIT](https://github.com/camiloazula/milo-guards/blob/main/LICENSE-MIT),
[LICENSE-APACHE](https://github.com/camiloazula/milo-guards/blob/main/LICENSE-APACHE)). Part of
[milo-guards](https://github.com/camiloazula/milo-guards); the API is on
[docs.rs](https://docs.rs/milo-guards-secrets).
