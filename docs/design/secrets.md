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
| `PrivateKey` | `private_key` | a block of private key (PEM, PGP, SSH.com), a PuTTY key's private lines, or an age secret key |
| `CloudKey` | `cloud_key` | a key of AWS, Google, Azure (storage keys, client secrets, shared access signatures) or DigitalOcean |
| `ApiKey` | `api_key` | a key or token of Anthropic, OpenAI, GitHub, GitLab, Slack, Discord, Telegram, Stripe, SendGrid, Twilio, npm, PyPI, crates.io, Hugging Face or Shopify |
| `Jwt` | `jwt` | a JSON web token |
| `BasicAuth` | `basic_auth` | the base64 of `user:password` after `Basic`, or as a Docker `auth` |
| `BearerToken` | `bearer_token` | a token after `Bearer` that no other rule found |
| `ConnectionString` | `connection_string` | the password in the address of a database or a broker |
| `UrlCredentials` | `url_credentials` | the password in any other URL |
| `GenericSecret` | `generic_secret` | a password, secret or token written as the value of a name, or after `password` in a `.netrc`; and, from the entropy pass, a run that looks random |
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
3. **Settle overlaps.** Hits that overlap become one hit that covers both,
   with the rule of the more specific. `password=Xy9!` followed by a key and
   `/tail9` is one secret, and a span that stopped at the key would leave the
   rest of the password in the text a caller scrubs. A GitHub token after
   `token=` is one finding of the GitHub rule, and the address inside a
   password is not a second one. A range that now begins earlier shows no
   prefix: its first characters are not the key's.
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
named: `aws_secret_access_key = …`; or, for an AWS secret, where an access key
id is written beside it, with a separator and nothing else between, as the
console's credentials file writes them. A Discord bot token, a Discord webhook
URL and a Telegram bot token (`bot` and the token, in a URL, as the API takes
it) are found by their parts; an Azure shared access signature by `sig=` in a
query that also has `sv=`, `se=`, `sp=`, `sr=` or `srt=`; the `auth` of a
Docker `config.json` by its value decoding to `user:password`; a `.netrc`
password by the word `password` after a `machine`, a `login` or `default`.

A Discord bot token is three dotted parts of base64url, and the lengths alone
are those of a chain of ordinary identifiers (`Controller.handler.processRequest`),
so its first part must also decode to the 17 to 21 digits of a user's id, as
every real token's does. A match that fails this check is searched again from
one character after its start, not after its end, so a decoy that overlaps or
precedes a real token (`NMTIz…` with a glued letter, a chain of identifiers
whose last part swallows the id) does not hide it; up to three base64url
characters may touch the front of the token, as such a decoy leaves, but four
or more make it the tail of a longer id.

## A private key

A block is the `-----BEGIN … PRIVATE KEY-----` line (`RSA`, `EC`, `DSA`,
`OPENSSH`, `ENCRYPTED`, `PGP … BLOCK`; SSH.com's `---- BEGIN SSH2 ENCRYPTED
PRIVATE KEY ----` too), the body and the `END` line. The span is the whole
block. A header alone is not a key, so text that explains the format is Safe;
what follows the header must look like a body: at least 32 base64 characters on
lines that hold nothing but base64.

Before the body come the lines of an armour header (`Proc-Type: 4,ENCRYPTED`,
`Version:`, `Comment: "a long, odd (comment)"`), up to a blank line. They may
hold anything but a line end, a line that ends in a backslash goes on with the
next, and they are part of the block and count for nothing. A body written in a
string with `\n` for its line ends is a key, so is one in a string in a string
(`\\n`), one indented, one with each line quoted (`"…\n"`) or commented
(`#`, `>`, `*`, `|`), and so is one cut short with no `END` line: a key as far
as it goes.

A PuTTY key file's `Private-Lines: N` is followed by `N` lines of base64; those
lines are the key, and the public lines before them are not. An age secret key
is one line (`AGE-SECRET-KEY-1` and fifty-eight characters of bech32).

Each line is read once, a line of armour is at most 256 bytes and there are at
most 24 of them, and a line ends where a run of dashes begins, so a text of
headers is read in time linear in its length.

## A name assigned a value

`password=`, `secret=` and `token=` followed by a value is the one detector
that reads a name, so it is the one where code is easy to mistake for a secret
(`password: String`, `token = self.token`). It judges the value.

**Where a value ends is decided on the text as it was written**, with the
quoting and the separators of that text. Reading escapes is for recognising a
secret, never for ending one: `%26`, `%20`, `\u0022`, `%22` and a JSON `\"`
inside a value are part of it, so the span covers all of it and no byte of the
secret stays in a scrubbed text.

- A value in quotes ends at its closing quote, read with the escaping of the
  formats that write one: a backslash escapes what follows (JSON, shell, code),
  `''` inside `'…'` is a quote of the value (YAML, SQL). A string written
  `\"…\"` inside another string ends at the closing `\"`. A quote that never
  closes on its line is not one: the value is the word after it.
- A value in braces, as a connection string quotes one that holds a `;`
  (`Pwd={a;b}`, `}}` for a brace of the value), ends at the closing brace. The
  value is what is inside. (`{{` and `{%` begin a template, not a value.)
- Any other value ends at white space or the end of the line; at the closer of
  the quote or bracket the name sits in (`echo "password=…"`, `login(password=…)`,
  `{password: …}`), where a quote that is escaped (`\"`, or `''` inside `'…'`)
  does not close the string; and at the format's own separator: a `&` before another
  `name=` (a query), a `;` before another `Name=` (a connection string, whose
  names may have spaces). `|`, `,`, `(` and a backtick do not end it.
- The scan runs once from front to back and goes on after a value that was read,
  accepted or not, so no byte is read twice: a long value full of names is read
  once. (A name inside the value of a name that is no secret's is still found.)

**The name** ends in a word that names a secret: `password`, `passwd`,
`passphrase`, `secret`, `token`, `api_key`, `access_key`, `secret_key`,
`private_key`, `auth_key`, `credential(s)`, `pwd`, and `pass` alone or after
`_`, `-` or `.`; in any case, with `_`, `-` and `.` ignored. `tokens`,
`max_tokens`, `password_hash` and `bypass` do not.

**It is no secret** when it is:

- shorter than six characters;
- a reference to a variable or a template field (`$TOKEN`, `${TOKEN}`,
  `{{ token }}`, `<password>`, `%s`, `[REDACTED]`);
- a stand-in. **A stand-in is recognised by the shape of the whole value, never
  by a prefix or by what it contains**: anything else is a value, because a
  password missed costs more than a mask too many. The shapes, each with rows in
  the tests, none a list of words that grows:
  - **its own name, all of it**: `api_key=api_key`, `password=PASSWORD`,
    `token=Token`, with case, `_`, `-` and `.` left out on both sides (and for
    `secret_key` also `secret`). A value that merely contains the word
    (`Password1`, `MyPassword!`, `prod_api_key_9Xq`) is a value;
  - **a literal**: `string`, `null`, `none`, `true`, `false`, `undefined`, …;
  - **a stem of a closed list, alone or with the name's word, and up to three
    digits**: `example`, `changeme123`, `dummy_password`, `your_api_key_here`.
    The stems are `changeme`, `replaceme`, `replace`, `dummy`, `placeholder`,
    `example`, `sample`, `todo`, `fixme`, `your`. One followed by other
    characters (`Example#2024`, `Sample1234`, `Replace!Me9x`) is a value;
  - **a constant**, only when unquoted, not in an address and not on a line
    of an environment file (`NAME=value`, `export NAME=value`), which has no
    constants to name: upper snake case
    of capital letters (a last word of one or two digits is allowed):
    `DEFAULT_TOKEN`, `REPLACE_ME`. `K7X_93QZ_M2PL_W8RT`, a quoted
    `"QZ7W_P3XK_M2LV"` and `DB_PASSWORD=HUNTER_TWO` in an environment file are
    values;
  - **a mask, two kinds of character, or an elision**: `****`, `xxxxxxxx`,
    `abababab`; or a short head that ends in `_` or `-` (or is capitals, as
    `AKIA`) and then a run of `.`, `…`, `*` (three), or `x`, `0`, `#` (eight) to
    the end: `sk-...`, `ghp_xxxxxxxx`. A visible head and tail around dots
    (`ab...cd9X`) is a value;
  - **documented by AWS**: twenty or forty characters that end in `EXAMPLE` or
    `EXAMPLEKEY`;
- a call (`get_token()`, `env::var("X")?;`), an index (`env["X"]`) or a chain
  of names (`self.token`, `config::TOKEN`);
- the value of a name of a cursor of pagination (`next_page_token`,
  `nextToken`, `prev_page_token`, `continuation_token`, `pagination_token`,
  `cursor_token`): the text a server gives back to ask for the next page. A
  bare `page_token` is not on the list: it is also the name of a Facebook page
  access token, so it stays a secret;
- a quoted word of a locale file: the name is in quotes too (`"password":
  "Contraseña"`, `"forgot_password": "Forgot?"`), and the value is one word of
  letters, the first a capital and the rest lower case, at most 24 letters, with
  one `?` or `!` at its end allowed. `"password": "Contraseña1"`,
  `"password": "sunshine"`, `"password": "SunShine"` and `password = "Sunshine"`
  (a name not in quotes) are values;
- a quoted value of fewer than eight characters under a name that ends in
  `token` or `api_key`: `let token = "abc123";` is a test, and no token is that
  short. A short value under `password`, `secret` and the rest is still found.

The shapes judge a stand-in, not a secret: a value that is none of them is found
whatever it looks like beside its name (`api_key=F4keApiKey0123456789abcdef`).

**A quoted value** has no space in it, as written. **An unquoted one** is a
secret when the name is tied to it with `=` and no space (`password=value`, the
way an environment file, a query and a connection string write it), when it has
a digit in it (`password: hunter22`), which a word of code does not, or when it
ends in `=` (a base64 padding, as a Kubernetes secret is written). A `,`, `;`,
`:`, `.`, `)`, quote or backtick at the end of an unquoted value is judged
without, and covered with it.

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

Reading is for recognising a secret; where one ends is decided on the text as it
was written. The rows for a password in an address run over the written text
too, so a `%2F` in a password is not the `/` that ends it and a `%40` in a user
name is not the `@`; the read text is run as well, which finds an address
written in escapes as a whole. A name assigned a value ends its value on the
written text (see above).

## What is safe on purpose

These are Safe, and each has a row in the tests:

- Hashes, UUIDs, commit SHAs, base64 fixtures and encoded data, minified
  JavaScript, a lockfile's integrity hashes (`sha512-…`) and checksums: no row
  reads a run for its shape alone.
- A page of source: `password: String`, `let token = self.token`,
  `max_tokens=100000`, `password_hash`, a call that fetches a password, a chain
  of identifiers as long as a Discord token, the labels of a locale file
  (`"password": "Contraseña"`), a pagination cursor, `let token = "abc123";`.
- Stand-ins for a secret that a document writes on purpose, by the shapes of
  [a name assigned a value](#a-name-assigned-a-value): `ghp_` and `AKIA`
  followed by one repeated character, a value that ends in `EXAMPLE`, a
  `${TOKEN}`, `<password>`, `YOUR_TOKEN_HERE`, `REPLACE_ME`, `DEFAULT_TOKEN`,
  `changeme`, `dummy_password`, `api_key=api_key`, `sk-...`, `[REDACTED]`,
  helm's `existingSecret: my-secret-2`. Each key row
  (the JWT and the Slack webhook apart) requires the last 32 characters after
  the provider's fixed prefix (`sk_live_`, `glpat-`) to have six different ones at
  least: a placeholder is not random and a key is,
  and a key that is random in its front and repeats at its end is still one.
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
- A JWT-shaped text whose signature is `signature` is Safe (a signature is
  empty, for `none`, or at least sixteen characters); one with a sixteen-letter
  word there is found.
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
- **A value equal to its name is Safe, one that holds it is not**: `password=PASSWORD`
  is a stand-in, `password=MyPassword!` is a value. The equality rule cannot tell
  a stand-in written with a prefix or a suffix from a password.
- **A word that holds the name's** (`password=Password1`, `secret=mysecret2`,
  helm's `existingSecret: my-secret-2`) is a value and is found, even when it
  is the name of a secret in a cluster and no password. It is Safe only as the
  whole name: `password=PASSWORD`.
- **A closing bracket ends the value of a name that is inside brackets**
  (`[password=F4kePass9]word]`, `f(password=F4kePass9)word)`): a bracket is not
  escaped by anything, so the part after it is not covered. A quote that closes
  a string is read as the string reads it: `\"` and `''` are part of the value.
- **A `&` before something that reads as another pair** ends a value
  (`SECRET=F4kePa&ss9=word` covers `F4kePa`).
- **A block of key on one line with spaces** for its line ends is not read.
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
- `tests/review.rs`: the rows of a reviewer's probe, every kind of key in the
  dress it comes in, and the text of a code base that looks like a secret.
- `tests/entropy.rs`, `tests/names.rs` and `tests/robust.rs`.
