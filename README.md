<div align="center">

# Qalqon

**Find the configuration mistake before it ships.**

A single Go binary that scans a repository for insecure Docker, Compose, Kubernetes,
Helm, Terraform, CloudFormation, Ansible, GitHub Actions, GitLab CI, nginx, Apache,
Caddy, Traefik, HAProxy, Envoy, sshd, systemd, PHP, PostgreSQL, MySQL, MongoDB and
Redis configuration — and for credentials that should never have been committed. It can
also check the security headers and TLS posture of hosts you run, and look up the
versions in your dependency manifests against the public vulnerability database.

[![Go Reference](https://img.shields.io/badge/go-1.22%2B-00ADD8.svg)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Single binary](https://img.shields.io/badge/install-one%20binary-brightgreen.svg)](#install)
[![Templates](https://img.shields.io/badge/templates-204-informational.svg)](templates/)

<img src="docs/demo-scan.png" alt="qalqon scanning a project and reporting seven findings across a Dockerfile, a compose file and a workflow" width="880">

</div>

---

Every finding names the file and line, shows the text that matched, and tells you what
to do instead. The exit code is `1`, so CI stops. Every finding at high severity or
above also comes with the deterministic change that ends it — shown as a diff by
default, written only when you pass `-apply`.

## Why another scanner

There are excellent, thorough tools in this space — `trivy`, `checkov`, `kics`. They
scan far more than Qalqon does. Qalqon is built around three choices they did not make:

- **One binary, no configuration.** Download it and run `qalqon .`. There is no config
  file to write, no policy language to learn, no container to pull, no Python
  environment to solve.
- **Templates you can write during a code review.** A rule is a short YAML document:
  which files, what pattern. If you hit a mistake twice, writing the rule that catches
  it the third time takes about two minutes.
- **Findings you can act on.** Every template must carry a remediation line, enforced
  by the test suite. A finding that does not tell you what to do is noise.

If you need exhaustive compliance coverage, use one of the others. If you want a fast
check that runs on every commit and that your team will actually keep enabled, that is
what this is for.

### Windows is a first-class platform

Not "works on Windows too". Three concrete meanings:

- **Line endings are folded at read time.** Almost every Windows checkout is CRLF;
  without folding, `$`-anchored patterns and one-line captures behave differently from
  the same file committed with LF, which is how a rule quietly turns off. A CRLF fixture
  tree proves finding parity byte for byte.
- **Case-insensitive file globs.** `Dockerfile` and `dockerfile` are the same file on
  Windows, so a pattern that matches only one spelling is a rule that never fires for
  half the team. Glob matching follows the filesystem's own rule.
- **`~` expands.** Neither the PowerShell pass-through nor the standard library does it
  on Windows, so `qalqon ~/infra` and `qalqon ~\infra` both resolve from
  `%USERPROFILE%`.

## Install

```bash
go install github.com/nasafuriy/qalqon/cmd/qalqon@latest
```

Or download a binary for your platform from [Releases](https://github.com/nasafuriy/qalqon/releases)
and put it on your `PATH`. There is nothing else to install — the template library is
compiled into the binary, so it works with no network access.

## Use

```bash
qalqon .                                # scan the working tree
qalqon scan ./infra -severity high,critical
qalqon scan . -tags docker,kubernetes
qalqon scan . -fail-on high             # only fail CI on high and above
qalqon scan . -fix                      # show the change that ends each finding; writes nothing
qalqon report . -framework cis-docker -html report.html
qalqon host                             # audit the machine this runs on
qalqon target example.com               # headers, cookies and TLS of a host you run
qalqon deps .                           # known CVEs in your manifests (the one network call)
qalqon history .                        # secrets in commits, not only in files
qalqon templates                        # list every rule that would run
```

Useful flags:

| Flag | What it does |
|---|---|
| `-severity LIST` | only run rules at these severities |
| `-min-severity S` | drop everything below `S` |
| `-tags LIST` | select by technology: `docker`, `k8s`, `nginx`, `secret`, … |
| `-id LIST` | run named rules only |
| `-exclude GLOB` | skip paths |
| `-t DIR` | add your own template directory |
| `-no-builtin` | run only your templates |
| `-c N` | worker count, defaults to one per core |
| `-fail-on S` | severity that makes the exit code `1` (default `low`, `none` disables) |
| `-fix` | show the declared fix of each finding as a unified diff; writes nothing |
| `-apply` | with `-fix`: back up, write, verify by re-scan, roll back on miss |

## Checking a live host

`qalqon target` reads the security headers, cookie flags and TLS state of a running
service:

<img src="docs/demo-target.png" alt="qalqon target reporting five header findings against a live site" width="880">

```bash
qalqon target example.com                    # bare host is treated as https
qalqon target -l my-domains.txt              # one per line
qalqon target https://a.example https://b.example -json
qalqon target example.com -tls-versions       # also ask which TLS versions it accepts
qalqon target example.com -cve                # check the versions it discloses
```

**Scope, deliberately.** Each target gets exactly one ordinary GET — the same request a
browser makes when you type the address. There is no path guessing, no payloads, no
authentication attempts, and concurrency is capped at ten. That is enough to audit your
own infrastructure and not enough to be useful against anyone else's. **Only probe hosts
you operate or are authorised to test.**

Rules address the response by part:

| Part | Contains |
|---|---|
| `header` | the status line plus one `Name: value` line per header |
| `body` | the response body, up to `-max-body` |
| `status` | the status code |
| `url` | the final URL after redirects |
| `tls` | negotiated version, cipher, and certificate facts |

The `tls` part is rendered as text so a pattern can match it, with the date arithmetic
already done:

```
version: TLS 1.3
cipher: TLS_AES_128_GCM_SHA256
forward_secrecy: true
issuer: E5
not_after: 2026-11-02T09:14:00Z
validity_days: 90
days_remaining: 81
expired: false
expires_within_30d: false
self_signed: false
hostname_mismatch: false
key_bits: 256
```

When the certificate fails verification the probe retries without it, so a broken chain
is reported rather than turning into a connection error you have to debug by hand.

### Which versions the server *accepts*

A handshake tells you the best version both sides could agree on — not the worst the
server would allow. A host that speaks TLS 1.3 to your browser may still complete a
TLS 1.0 handshake for anyone who asks, and that is the version an attacker asks for.

`-tls-versions` asks for each version in turn, one handshake each, and adds the answer
to the `tls` part:

```
versions_checked: true
supports_tls10: true
supports_tls11: true
supports_tls12: true
supports_tls13: true
weakest_version: TLS 1.0
accepts_obsolete_tls: true
```

It is off by default because it costs four extra handshakes per host. Nothing is sent
beyond the handshake itself, and the certificate is not verified during the sweep —
the question is which protocol the server agrees to speak, and a self-signed
certificate answers that as well as a valid one.

The probe also offers the obsolete cipher suites deliberately. Go has been removing
RSA key exchange, 3DES and RC4 from what a client offers, which is right for a browser
and wrong for a scanner: a server that speaks nothing else would answer "handshake
failure", and the report would say the host was unreachable instead of saying it has
no forward secrecy. Secure suites are offered first, so a server that honours client
preference still gets the good one.

### Versions a host discloses about itself

Most servers name their software and version in `Server` or `X-Powered-By`. `-cve`
reads that claim and says what is published about it — whether upstream still fixes
that release at all, and which landmark advisories name it:

```console
$ qalqon target http://legacy.internal -cve
  header    critical service-known-vulnerability   CVE-2021-40438: Apache httpd 2.2.14 is in the affected range
             Server: Apache/2.2.14 (Unix)
             → Upgrade Apache httpd to 2.4.49 or later — the 2.2 branch is no longer
               maintained, so upgrading within it would leave the rest unfixed. A banner
               is a claim, not a measurement…
```

**Read this one with the caveat attached.** A banner is a claim, not a measurement. It
can be edited or proxied away, and — the part that matters more — distributions
backport security fixes without touching the version string, so a Debian nginx
reporting 1.10.3 may carry years of patches upstream never put in a 1.10.3 release. So
nothing here says *you are vulnerable*. It says *this version is in the published
affected range*, which is the same inference an attacker draws from the same header,
and every finding carries the caveat in its remediation line.

That uncertainty is why the flag is off by default: the report you get without it is
meant to be true without qualification.

Two kinds of finding come out of it:

| Finding | Says |
|---|---|
| `service-end-of-life` | upstream has stopped fixing this release entirely |
| `service-known-vulnerability` | a published advisory names this version |

The end-of-life boundaries are set conservatively — at a branch that is clearly dead,
not at the newest release — because "upstream abandoned this line" survives a backport
and "you are missing last month's patch" does not. Advice never points inside a dead
branch: an Apache 2.2.14 host is told to move to 2.4, not to 2.2.20.

Covered: nginx (and openresty), Apache httpd, PHP, Express, gunicorn, Werkzeug, IIS,
Tomcat and lighttpd. The tables live in [internal/service/known.go](internal/service/known.go)
and carry the date they were last reviewed, because a version table goes stale
silently, which is the worst way for a security tool to be wrong.

The best fix for most of these is the one the remediation mentions last: stop sending
the version at all. `server_tokens off` in nginx, `ServerTokens Prod` in Apache,
`expose_php = Off` in PHP.

## Auditing the machine it runs on

`qalqon host` inspects the local machine — registry defence settings, firewall and
Defender state, remote access, service definitions with quoting problems, autorun
entries, listening ports, and on Linux and macOS the `/proc/sys` parity subset:

```console
$ qalqon host
qalqon · 32 probes · 61 findings in 1.8s

listener-on-wildcard
                    high     tcp listen on 0.0.0.0:3389
                    → Restrict RDP to a specific interface or remove the binding; host
                      audit found it reachable on every interface.

2 findings   1 critical · 1 high
```

It is strictly read-only — probes change nothing, and there is no fix path from `host`
in this version. Recommendations are printed like any other finding.

Useful flags:

```bash
qalqon host -facts     # print the raw probed facts and stop, before rules run
qalqon host -probe firewall,defender
qalqon host -json -o audit.json
```

Probes that need administrator rights on a non-elevated process are skipped and named,
so an audit is never quietly narrower than it looks.

## Fixing findings safely

Fifty of the file rules declare the deterministic change that ends their finding — the
directive to flip, the line to delete, the port to bind to loopback. `-fix` shows it
without touching anything:

```console
$ qalqon scan . -fix
docker-compose.yml  — would change (dry run, nothing written):
--- a
+++ b
@@
-    privileged: true
+    privileged: false
```

`-apply` is the explicit second half, and it refuses to exist without `-fix`:

```bash
qalqon scan . -fix -apply
```

The contract `-fix`/`-apply` keeps, deliberately:

- every changed file is backed up to `.qalqon-backups/<timestamp>/` before anything is
  written;
- the originating rule is re-run against the new content — if it still fires, the fix
  did not end the finding and the file is rolled back immediately;
- `.git` directories, binaries, oversized files and files this process cannot write are
  refused by name rather than skipped silently;
- Windows line endings survive the round trip, and inserts take the indentation of the
  line they follow, so the diff looks like it was written by someone who edits the file
  for a living.

Rules that would need a value the tool cannot invent — the real password, the real
pinned version — carry no fix on purpose: a fabricated value is a broken file, not a fix.

## Scoring a scan against a framework

`qalqon report` turns an ordinary scan into a checklist against a published framework:

```console
$ qalqon report . -framework cis-docker -html report.html
compliance · CIS Docker Engine Benchmark (static, build-time subset)
score 82% — 11 pass, 2 fail, 3 review

FAIL  C6  Ensure no container service runs privileged
        compose-privileged-container → docker-compose.yml:4 · Service runs privileged
        rules: compose-privileged-container
```

Three mappings ship inside the binary — `cis-docker`, `cis-kubernetes` and `pci-dss` —
covering only what a scan of a configuration tree can honestly evidence. A control is:

| Status | Means |
|---|---|
| `FAIL` | at least one of its rules fired on this tree |
| `PASS` | every rule ran on a file it applies to and stayed quiet |
| `REVIEW` | the tree contains nothing the rules apply to — a repo with no nginx is not rewarded for it |

Reviewed controls stay out of the score, so absence of evidence never reads as
compliance. A failed control exits `1`, so the report drops into CI unchanged. `-json`
prints the assessment; `-html` writes a standalone report with no assets and no scripts.

## Checking dependencies

Configuration is only half of it. Most of the vulnerabilities a project actually ships
arrive through its dependencies, so `qalqon deps` reads the manifests and asks
[osv.dev](https://osv.dev) what is known about the versions it finds:

```console
$ qalqon deps .
qalqon · 6 dependencies · 3 manifests in 4.2s

go.mod
  6         high     CVE-2022-32149 Denial of service via crafted Accept-Language header
             golang.org/x/text@0.3.0
             → Upgrade golang.org/x/text to 0.3.8 or later.

60 findings   7 critical · 22 high · 24 medium · 5 low · 2 info
```

| Manifest | Ecosystem |
|---|---|
| `go.mod` | Go |
| `package-lock.json` | npm (lockfile v1, v2 and v3) |
| `requirements.txt` | PyPI, `==` pins only |
| `Cargo.lock` | crates.io |
| `composer.lock` | Packagist |

Three things are worth knowing about how it reports:

- **One flaw, one line.** An issue usually has two records — the ecosystem advisory
  (`GHSA-…`) and the language's own database (`GO-…`, `PYSEC-…`). They alias to the same
  CVE, so they are merged, keeping whichever half carries a severity.
- **One severity scale.** Where a CVSS vector exists the base score is calculated rather
  than the label trusted, so "moderate" from one database and "medium" from another do
  not sort differently.
- **`-list` needs no network.** It prints what the manifests declare and stops, which is
  also how this repository tests the parsers without depending on someone else's uptime.

This is the one command that makes a network request. Scanning configuration stays
entirely offline, because it can; a vulnerability database cannot, since the answer
changes daily and no useful copy of it fits in a binary.

## Secrets in the history

Deleting a credential in a later commit does not remove it. It is still in the
history, still in every clone, and still readable through the forge's API — so a scan
of the working tree reports nothing to someone who believes they cleaned it up.

```console
$ qalqon scan .
No findings.

$ qalqon history .
qalqon · 21 templates · 3 commits in 42ms

config.env
  501a4d06  critical aws-access-key-id  AWS access key id in source
             AKIAIOSFODNN7EXAMPLE
             → Disable the key in IAM now, then rotate it. The value is in the history
               and in every clone, so rewriting the commit does not undo the exposure:
               rotate it first.

1 finding   1 critical
```

The position column carries the commit that introduced the value, and the JSON output
adds the author and date alongside it.

Only the secret rules run by default. A configuration rule judges a file as it stands,
and a diff hunk is not that file, so running those over history produces mostly noise;
`-all-rules` overrides this when you want it anyway. A value that survives many commits
is reported once, against the commit that introduced it, rather than once per commit
that carried it forward.

## In CI

Qalqon emits SARIF, so findings land in the GitHub **Security** tab and appear as inline
annotations on pull requests:

```yaml
name: Config audit
on: [push, pull_request]

permissions:
  contents: read
  security-events: write

jobs:
  qalqon:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install qalqon
        run: go install github.com/nasafuriy/qalqon/cmd/qalqon@latest

      - name: Scan
        run: qalqon scan . -sarif -o qalqon.sarif -fail-on none

      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: qalqon.sarif
```

`-fail-on none` lets the upload step run even when findings exist; the Security tab
becomes the place they are triaged. Drop that flag if you would rather fail the build.

## Writing a template

A template is one YAML document. Several can share a file, separated by `---`.

```yaml
id: docker-missing-user
info:
  name: Image runs as root
  severity: high            # info | low | medium | high | critical
  description: >-
    The Dockerfile never switches to an unprivileged user, so the container
    process runs as root.
  remediation: Add a non-root USER before the final CMD or ENTRYPOINT.
  tags: [docker, container, privilege]

files:                       # globs; a pattern with "/" matches the path
  - Dockerfile
  - "*.dockerfile"

condition: and               # how the matchers combine: and (default) | or
matchers:
  - type: regex
    context: true            # must match, but is not the reported location
    patterns:
      - '(?im)^\s*FROM\s+\S+'
  - type: absent             # fires when the pattern is NOT in the file
    patterns:
      - '(?im)^\s*USER\s+\S+'
```

Three matcher types cover almost everything:

| Type | Fires when |
|---|---|
| `regex` | a pattern is found |
| `word` | a literal string is found |
| `absent` | a pattern is **not** found anywhere in the file |

A rule for `qalqon target` sets `type: http`, drops `files`, and gives each matcher a
`part`:

```yaml
id: http-missing-hsts
type: http
info:
  name: HSTS header not sent
  severity: medium
  description: Without HSTS a browser will still try plain HTTP on the next visit.
  remediation: 'Send: Strict-Transport-Security: max-age=31536000; includeSubDomains'
  tags: [http, headers, tls]

condition: and
matchers:
  - part: url
    context: true
    patterns: ['^https://']
  - part: header
    type: absent
    patterns: ['(?im)^strict-transport-security:']
```

Other fields worth knowing:

- `context: true` on a matcher — it gates the rule but never becomes the reported line.
  Use it for "this really is a Kubernetes manifest" checks.
- `once: true` on a template — report one finding per file, for rules about the file as
  a whole.
- `prefilter: [AKIA, ASIA]` — literal strings, any of which must appear before the
  regexes run at all. This is the difference between a fast scan and a slow one on broad
  rules. Every literal must be implied by something the template positively requires.

Patterns are Go [RE2](https://github.com/google/re2/wiki/Syntax): **no lookahead or
lookbehind**. Write them positively.

Check your work:

```bash
qalqon validate ./my-templates
qalqon scan ./testdata -t ./my-templates -no-builtin
```

## Coverage

204 templates: 149 that read files, 23 that read a live HTTP response, and 32 that read
probed facts about the machine. Fifty of the file rules declare a safe automatic fix.

| Area | Covered by |
|---|---|
| Containers | Dockerfile, Compose |
| Orchestration | Kubernetes workloads, RBAC, Ingress, Helm charts and values |
| Infrastructure as code | Terraform (AWS, GCP, Azure), CloudFormation, Ansible |
| CI | GitHub Actions, GitLab CI |
| Web and proxies | nginx, Apache, Caddy, Traefik, HAProxy, Envoy |
| Databases | PostgreSQL, MySQL/MariaDB, MongoDB, Redis |
| Hosts | sshd, systemd, PHP, plus Windows defence settings and `/proc/sys` hardening |
| Credentials | private keys, AWS, GCP, Stripe, Slack, JWTs, provider tokens, connection strings |
| Frameworks | cis-docker, cis-kubernetes, pci-dss checklists scored by `qalqon report` |
| Fixes | 50 rules declare the deterministic change that ends their finding (`-fix`, `-apply`) |

`qalqon templates` prints the current list with severities and tags.

## Performance

Measured over the Go standard library source tree, warm page cache, on a 32-core
Windows machine:

| | |
|---|---|
| Files walked | 10,382 |
| Files read | 7,307 (65.8 MB) |
| File templates | 149 |
| **Wall time** | **1.3 s** |
| Single worker (`-c 1`) | 4.3 s |

Two things keep that flat as the library grows. Files are only read when a template's
file globs already matched the name, so most of a tree is skipped without touching the
disk. Then `prefilter` rules a template out with a plain substring search before any
regex runs, which is why tripling the rule count cost about 20% rather than tripling the
time.

## Development

```bash
go test ./...              # unit tests plus fixture scans
go build ./cmd/qalqon
qalqon scan testdata/vulnerable    # should report findings
qalqon scan testdata/clean         # must report none
qalqon report testdata/clean -framework cis-docker   # must exit 0
```

The `testdata/clean` tree is the false-positive guard, and it matters more than the
detection test: a scanner that cries wolf gets switched off, and then it protects
nothing. Every new template needs a case in both trees.

CI also asserts the release behaviours that go stale quietly: every declared fix is
applied to its fixture and the rule must go quiet, the `host` family fires on its
fixtures on the runner's own platform, and the clean fixtures must exit clean with
every method. Run `go test ./internal/fix/ -v` for the fix engine's own suite.

## Contributing

New templates are the most useful thing you can add — see [CONTRIBUTING.md](CONTRIBUTING.md).
The bar is that the rule must be accurate enough to leave on in CI.

## Licence

[MIT](LICENSE).
