# Secrets

`milo-guards-secrets` reads a text and says what in it is a credential or
personal data, and where. A caller that puts text in front of a model scrubs it
first; a caller that lets an agent write a source file asks whether the content
carries a key into it, or whether a tool result the agent is about to repeat
holds one. One table serves every use.

```rust
find(text) -> Assessment
find_spans(text) -> Vec<Span>
find_high_entropy(text, bits) -> Vec<Span>
```

There is no `Paths`: a text has no place. The answer is `Safe`, or `Risky` with
a finding for each thing found, in the order the text reads: a rule, a reason
a prompt can show, and a masked target. The types are core's; see
[Core](core.md). The guard only reports. What to do about a finding (block the
write, scrub the span, ask) is the caller's choice, and the caller can choose a
different one for each rule.

The guard is not in the front door's `default` features: most callers want the
shell, file and URL guards and not a table of patterns in their binary. A
caller enables it with the feature `secrets`.

## The masking promise

**A finding never carries the secret.** `Finding::target` is a masked form of
what was found, and nothing else in the answer repeats it:

- A key whose first characters are the same on every key of its kind shows
  that prefix (at most four characters) and the length: `AKIA… (20 chars)`,
  `ghp_… (40 chars)`, `eyJ… (151 chars)`. Where the prefix is shorter than
  four characters (`sk-` and a random character after it), only the prefix
  is shown.
- What begins with the secret itself shows its length alone: `… (8 chars)`.
  That is a password, a card number, an id number, an address.
- A block of private key shows its first line, which is the same on every
  key: `-----BEGIN RSA PRIVATE KEY-----`.

The length counts characters of the text as it is read (see
[Escapes](#escapes)). A test asserts, for every row of the table, that neither
the target nor the reason holds the secret, nor any run of eight characters of
it.

`find_spans` gives the same things as byte offsets. A `Span` is a rule and a
range, never text, so it is as safe to log as a finding. The range covers the
secret alone: the password of a connection string and not its host, the value
of `password=` and not its name or quotes, the whole of a key or a block. It
is on character boundaries, so `&text[start..end]` never panics and replacing
it leaves the rest of the text byte for byte as it was, with multi-byte text
around it. Spans are in order, none overlaps another, and they are one for one
with the findings.

## Rules

A rule is a kind, as wide as what a caller would treat alike; the reason says
which. A finer split later is a new rule, never a rename. `Rule` is exhaustive,
with `Rule::ALL`, and a wire name never changes once a caller uses it.

| Rule | Wire name | Holds |
| --- | --- | --- |
| `PrivateKey` | `private_key` | a block of private key, or an age secret key |
| `CloudKey` | `cloud_key` | a key of AWS, Google, Azure or DigitalOcean |
| `ApiKey` | `api_key` | a key or token of Anthropic, OpenAI, GitHub, GitLab, Slack, Stripe, SendGrid, Twilio, npm, PyPI, crates.io, Hugging Face or Shopify |
| `Jwt` | `jwt` | a JSON web token |
| `BasicAuth` | `basic_auth` | the base64 of `user:password` after `Basic` |
| `BearerToken` | `bearer_token` | a token after `Bearer` that no other rule found |
| `ConnectionString` | `connection_string` | the password in the address of a database or a broker |
| `UrlCredentials` | `url_credentials` | the password in any other URL |
| `GenericSecret` | `generic_secret` | a password, secret or token written as the value of a name; and, from the entropy pass, a run that looks random |
| `CreditCard` | `credit_card` | a payment card number |
| `GovernmentId` | `government_id` | a US social security number, a UK national insurance number, a Brazilian CPF |
| `Email` | `email` | an email address |
| `Phone` | `phone` | a phone number in the international form |
| `PublicIp` | `public_ip` | a public IPv4 or IPv6 address |

Reasons are plain words that start with `holds`: `holds an AWS access key`,
`holds a GitHub token`, `holds a password in a connection string`. A row of the
table has its own reason; one rule has several rows.

## How it works

1. **Read the text as it means.** An escape of a printable ASCII character is
   that character, and a character that shows nothing is dropped
   ([Escapes](#escapes)).
2. **Run the detectors**, from the most specific to the least, over that text:
   a block of private key, the provider rows (cloud, then service keys), a JWT,
   a password in an address, the `Basic` and `Bearer` headers, a name assigned
   a value, then personal data (a card, an id, an email, a phone, an address).
3. **Settle overlaps.** A hit that overlaps one already kept is dropped, so a
   GitHub token after `token=` is a GitHub token and not also a generic
   secret, and the address inside a URL is not found a second time.
4. **Carry each range back** to the text as it was written.

The table is written from each provider's published description of its own key
format: the prefix, the length and the alphabet. A shape that is common never
decides alone: a card number must pass the Luhn check and begin as a network's
numbers do, a `Basic` header must decode to `user:password`, an address must be
public, an id must be one a government issues. A key must stand alone: an ASCII
letter or digit touching it on either side means it is a piece of something
longer (a base64 blob, an identifier). Only ASCII counts, because text written
without spaces runs words together and a key beside it is still a key.

Each key of a provider is matched on its own prefix, so none is guessed from
its length alone. A provider whose secret has no mark of its own (an AWS secret
key, a Twilio auth token, an Azure storage key) is found only where it is
named: `aws_secret_access_key = …`.

## A private key

A block is the `-----BEGIN … PRIVATE KEY-----` line (`RSA`, `EC`, `DSA`,
`OPENSSH`, `ENCRYPTED`, `PGP … BLOCK`), the body and the `-----END` line. The
span is the whole block. A header alone is not a key, so text that explains the
format is Safe; what follows the header must look like a body: at least 32
base64 characters on lines that hold nothing but base64. The lines of an
armour header (`Proc-Type: 4,ENCRYPTED`, `Version: …`) are allowed and do not
count. A body written in a JSON string with `\n` for its line ends is a key, so
is one indented or quoted by `#`, `>`, `*` or `|`, and so is one cut short
with no `END` line: a key as far as it goes.

## A name assigned a value

`password=`, `secret=` and `token=` followed by a value is the one detector
that reads a name, so it is the one where code is easy to mistake for a secret
(`password: String`, `token = self.token`). It judges the value:

- **The name** ends in a word that names a secret: `password`, `passwd`,
  `passphrase`, `secret`, `token`, `api_key`, `access_key`, `secret_key`,
  `private_key`, `auth_key`, `credential(s)`, `pwd`, and `pass` alone or after
  `_`, `-` or `.`; in any case, with `_`, `-` and `.` ignored. `tokens`,
  `max_tokens`, `password_hash` and `bypass` do not.
- **The value** is the text after `=`, `:`, `:=`, `==` or `=>`: a string in
  quotes (also written `\"…\"` inside a string), or a word up to a space, a
  quote or one of `,` `;` `&` `|` `(` `)`.
- **It is no secret** when it is shorter than six characters; a reference to a
  variable or a template field (`$TOKEN`, `${TOKEN}`, `{{ token }}`,
  `<password>`, `%s`); a redaction or a mask (`[REDACTED]`, `****`, `xxxxxx`);
  a label of a field (`"password": "Password"`, `string`, `null`, `true`); the
  name said twice (`password=password`); a placeholder that begins `your_`; a
  value AWS's documentation shows (ends in `EXAMPLE`); a call (`get_token()`);
  a chain of names (`self.token`, `config::TOKEN`); or an index (`env["X"]`).
- **A quoted value** has no space in it. **An unquoted one** is a secret when
  the name is tied to it with `=` and no space (`password=value`, the way an
  environment file, a query and a connection string write it), or when it has
  a digit in it (`password: hunter22`), which a word of code does not, or when
  it ends in `=` (a base64 padding, as a Kubernetes secret is written).

The span is the value without its quotes.

## Escapes

A secret written `ghp_…`, `AKIA%41…`, `\x41KIA…` or with a zero-width
space in the middle is the same secret to whatever reads it next, so it is
judged as the same one. Before the table runs, the text is read into a second
one in which `%41`, `\x41`, `A`, `\u{41}`, `&#65;` and `&#x41;` are the
character they stand for when that is printable ASCII, and the characters that
show nothing (zero-width space, joiners, word joiner, byte order mark, soft
hyphen, combining grapheme joiner, Mongolian vowel separator) are dropped. A
range found in the second text is carried back to the first and covers the
whole escape. Only printable ASCII is read, so no line end is made (`%0A` is
left alone) and the reading never makes a character the text had no spelling of.

## What is safe on purpose

These are Safe, and each has a row in the tests:

- Hashes, UUIDs, commit SHAs, base64 fixtures and encoded data, minified
  JavaScript, a lockfile's integrity hashes (`sha512-…`) and checksums: no row
  reads a run for its shape alone.
- A page of source: `password: String`, `let token = self.token`,
  `max_tokens=100000`, `password_hash`, a call that fetches a password.
- Stand-ins for a secret that a document writes on purpose: `ghp_` and `AKIA`
  followed by one repeated character, a value that ends in `EXAMPLE`, a
  `${TOKEN}`, `<password>`, `YOUR_TOKEN_HERE`, `[REDACTED]`. Each key row
  (the JWT and the Slack webhook apart) requires the last sixteen characters
  to be varied, six different ones at least: a placeholder is not random and
  a key is.
- The pair RFC 7617 writes its `Basic` example with (`Aladdin:open sesame`).
- A header or a prefix alone: `-----BEGIN PRIVATE KEY-----` with no body, the
  word `Bearer` with nothing after it, the word `Basic` before a word that is
  not a `user:password` pair.
- An address on a name reserved for examples (`example.com`, `.org`, `.net`,
  `.test`, `.invalid`, `.example`, `.localhost`), the `@2x` of an image's file
  name, the `git@github.com` of a remote written `host:path`, a login in a URL
  (`https://me@host/`) that holds no password.
- An address that belongs to no one: private, shared, loopback, link-local,
  documentation, benchmarking, multicast and reserved IPv4 ranges; IPv6
  outside `2000::/3`, and in it the documentation, protocol and 6to4 ranges;
  `std::string::String`, `12:30:45`, `1.2.3.4.5`.
- An id or a number that is not one: a social security number with an area of
  `000`, `666` or `9xx`; a number that fails the Luhn check; a digit string
  that begins like no card network; a `+` and nine digits or fewer with no spaces (`+20240101`).

## Accepted false alarms

The table reads shapes, and a few shapes are shared with other things. These
are found although they are not secrets, and the reasons they are accepted are
that each is rare in source and that a missed secret costs more than a
prompt:

- A card number of a network's shape that passes the Luhn check is found
  whatever it is: the published test numbers (`4111…`), and a sixteen-digit
  id that happens to begin with a `4` and pass (one in ten of those that do).
- A social security number's shape, `ddd-dd-dddd`, with a valid area, group
  and serial: a part number or a phone number written that way.
- A UK national insurance number's shape, `AB123456C`, is a product code too.
- An email-shaped text that is not an address: `me@host.io` in a `ssh`
  command, a package named `name@scope.tld`.
- Four numbers joined by dots that are public: the version `1.2.3.4`, an
  assembly version `1.0.0.0`, and a DNS server written in a document
  (`8.8.8.8`). A version after a letter or a dash (`v1.2.3.4`) and a longer
  dotted number are not found.
- A `token=` or `password:` whose value is a pagination cursor, a CSRF token
  or a word of code that has a digit in it (`token: token2`).
- A line of a patch that adds ten to fifteen digits after a `+`.
- A key's published test value: Stripe's `sk_test_…`, GitHub's example tokens.
  A value that is a key by its format is found whatever its docs say; only
  what is varied is read as random.

## Known limits

- **A secret with no shape and no name** is not found by `find`: an AWS secret
  key on a line by itself, a random password in a list. `find_high_entropy`
  guesses these.
- **A secret spelled across a join** is not found: two strings concatenated in
  code, a line continuation, a key split over two lines. The text is read as
  written, after escapes only.
- **Other escapes** are not read: a doubled escape (`%2541`), a secret
  base64-encoded inside another one, an ANSI sequence in the middle of a key.
- **Unicode look-alikes** (full-width `ＡＫＩＡ`, Cyrillic letters that look
  like Latin) are not folded: a key spelled with them is not that key to a
  client either.
- **Flags** (`--password hunter22`, `curl -u user:pass`, `mysql -pSecret`) are
  the shell's: the shell guard reads a command line. A name assigned a value
  with `=`, as `--password=hunter22`, is found.
- **A password shorter than six characters** after a name is not found, and
  neither is a password of words: `password: correct horse battery staple`.
  An unquoted value of letters alone after `name: ` or `name = ` is read as
  code, not a secret.
- **A key that is not on the list** is not found: a provider's key needs a row.
  A new provider is a new row, not a new rule.
- **Government ids** are the three above; a text with another country's id
  number is not read for it. A phone number must have its `+`: a national
  number without one is digits.
- **GitHub's token checksum** is not checked, and npm's neither. Each token
  carries a CRC-32 of its own random part, which could tell a token from a
  placeholder, but a wrong reading of it would silently miss real tokens,
  and what it would remove (a placeholder written as a token) is already
  removed by the variety check.
- **Time and memory** are linear in the text, whatever it holds, and there is
  no limit: a text is never unreadable. A text of a million characters of one
  kind takes a fraction of a second.

## The entropy pass

`find_high_entropy(text, bits)` is a separate function and never a part of
`find`: a guard has no modes, and a caller that wants a guess calls it. It
returns spans, all `GenericSecret`, in order and apart.

A run is a stretch of letters, digits, `+`, `/`, `_` and `-`, at least 20
long, with edge characters (`-`, `_`, `/`, `+`) left off, that has a letter and
a digit, and whose Shannon entropy is at least `bits` per character. It is
read after the same [escapes](#escapes). These runs are never a guess: a hash
(32, 40, 56, 64, 96 or 128 hex digits), a UUID, an integrity hash that
begins `sha1-`, `sha256-`, `sha384-` or `sha512-`.

A random base64 string has about 5.5 bits per character, a random hex string at
most 4, English words and identifiers 3 to 4. `4.5` finds the first and not
the others. A `bits` that is not a number finds nothing; `0.0` finds every run
of the right shape.

It has false alarms the table does not: an encoded image, a compressed blob, a
long base64 fixture. A caller that scrubs is safe from them; a caller that
blocks chooses.

## Speed

The text is read in time linear in its length. Every pattern is a regular
expression of the `regex` crate, which never backtracks, and compiles once
(`std::sync::OnceLock`); a row whose text cannot be there (the lowercase text
holds none of its needles) is skipped; the hand loops (a block of key, a name
and its value, the escapes) move forward and never rescan what they passed.
`tests/robust.rs` measures: a megabyte of one character, of nested quotes, of
base64, of partial prefixes, and thirty more kinds of hostile text are read
inside a bound, and four times the text takes less than ten times as long
(a read that rescans takes sixteen). The test keeps the clock; the crate never
does.

## Tests

- `tests/rules.rs`: one table of texts per rule, with the spelling variants a
  reviewer would try as rows of their own.
- `tests/safe.rs`: the texts that must be Safe.
- `tests/spans.rs`: replacing every span leaves the text around it as it was,
  with multi-byte text beside it; spans are in order and apart; escapes are
  read and carried back.
- `tests/rows.rs`: one sample for every row of the table finds exactly its
  secret with its rule and reason, and no target or reason holds the secret.
- `tests/entropy.rs`, `tests/names.rs` and `tests/robust.rs`.
