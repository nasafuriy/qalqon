# Contributing to Qalqon

New templates are the most valuable contribution, and the easiest place to start.

## The bar for a template

**It has to be accurate enough to leave switched on in CI.**

A rule that fires on correct configuration is worse than no rule at all: someone adds
`-id` to skip it, then someone disables the whole scan, and the tool stops protecting
anything. When you have to choose, prefer missing a case over inventing one.

Concretely, every template must:

- Fire on the fixture you add to `testdata/vulnerable/`
- Stay silent on the fixture you add to `testdata/clean/`
- Carry a `description` explaining *why* it matters, not just what matched
- Carry a `remediation` telling the reader what to do instead
- Carry at least one tag, so `-tags` can select it

The test suite enforces all five: `TestEveryFileTemplateFiresOnTheVulnerableTree` fails
if your rule never fires anywhere, and `TestCleanFixturesProduceNoFindings` fails if it
fires where it should not.

## Adding one

1. Pick the right file in `templates/`, or create a new one for a new technology.
   Several templates share a file, separated by `---`.

2. Write the rule:

```yaml
id: nginx-weak-tls-protocols        # lowercase, hyphens, unique
info:
  name: Obsolete TLS versions enabled
  severity: high                     # info | low | medium | high | critical
  description: >-
    SSLv2, SSLv3, TLS 1.0 and TLS 1.1 all carry known protocol-level
    weaknesses, and browsers already refuse them.
  remediation: 'Use: ssl_protocols TLSv1.2 TLSv1.3;'
  reference:
    - https://ssl-config.mozilla.org/
  tags: [nginx, tls, crypto]

files:
  - nginx.conf
  - "*.conf"

matchers:
  - type: regex
    patterns:
      - '(?im)^\s*ssl_protocols[^;]*\bSSLv[23]\b'
```

3. Add a fixture to **both** trees, then run:

```bash
go test ./...
go build -o qalqon ./cmd/qalqon
./qalqon scan testdata/vulnerable -id your-template-id
./qalqon scan testdata/clean          # must print nothing
```

4. Update the expectation map in `scan_test.go` so the new finding is asserted.

## Things that catch people out

**Go regexes are RE2 — there is no lookahead or lookbehind.** `(?!...)` and `(?<=...)`
will not compile. Express the rule positively instead. If you cannot, the check probably
needs a real parser rather than a pattern, and it may not belong here.

**A negated character class matches newlines.** `[^;]*` will happily run past the end of
the line and match something several lines down, which is how a `listen_addresses` in a
`postgresql.conf` once reported a missing nginx HSTS header. When the directive is
line-oriented, write `[^;\n]*`.

**Broad file globs need a context matcher.** `*.yaml` matches half a repository. Gate the
rule on something that proves the file is what you think it is:

```yaml
condition: and
matchers:
  - type: regex
    context: true          # must match, but is never the reported line
    patterns:
      - '(?im)^\s*kind:\s*Deployment\b'
  - type: regex
    patterns:
      - '(?im)^\s*privileged:\s*true\b'
```

**Broad rules need a prefilter.** A plain substring test runs before the regexes and
skips the file entirely when it cannot match:

```yaml
prefilter: [AKIA, ASIA]
```

Every literal must be implied by something the template *positively* requires. Never
derive one from an `absent` matcher — that inverts the logic and the rule silently stops
firing.

**Ignore references, flag literals.** `POSTGRES_PASSWORD: ${DB_PASSWORD}` is correct
configuration. Patterns that match credentials should exclude values starting with `$`
or `{`:

```
'(?im)^\s*POSTGRES_PASSWORD\s*[:=]\s*[^\s${][^\s]*'
```

**Use `once: true`** when the rule is about the file as a whole, so a five-line `.env`
does not produce five identical findings.

## Fixtures and fake credentials

`testdata/vulnerable/` deliberately contains bad configuration. Keep it obviously fake:

- Use `AKIAIOSFODNN7EXAMPLE`, the key from the AWS documentation
- Use a PEM header with placeholder text, never a generated key
- Suffix dummy values with `fixture` so nobody mistakes them for real

Never commit a real credential to test a rule, even a revoked one.

## Code changes

```bash
go vet ./...
go test -race ./...
```

The engine is deliberately small. Before adding a matcher type, check whether the rule
can be written with `regex`, `word` and `absent` plus `context` — most can, and every
new concept is one more thing a template author has to learn.

## Reporting a false positive

Open an issue with the smallest file that triggers it and the template id. False
positives are treated as bugs, not preferences.

## Licence

By contributing you agree that your work is released under the [MIT Licence](LICENSE).
