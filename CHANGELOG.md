# Changelog

Notable changes are described here. Older pre-changelog releases are listed
with the version they published.

## v2.0.0

The Windows release, and the one where findings started to carry their own
resolutions.

### New

- **Windows is a first-class platform.** Line endings are folded CRLF→LF once at
  read time, file globs match case-insensitively the way a Windows filesystem
  does, and a leading `~` in a path argument expands to `%USERPROFILE%`. A CRLF
  fixture tree asserts finding parity with LF content, and CI runs the whole
  suite on windows-latest plus a gofmt gate.
- **`qalqon host`** audits the machine the binary runs on, strictly read-only.
  On Windows: registry defence settings, `net accounts`, BitLocker state,
  listening sockets (`netstat -ano`), and service definitions with unquoted or
  user-writable binary paths. On Linux and macOS: the `/proc/sys` parity subset
  (ASLR, kernel pointer leaks, unprivileged BPF and user namespaces, ptrace
  scope, dmesg). `-facts` prints the raw probed facts and stops; probes that
  need administrator rights are skipped and named, never silently absent. Old
  PowerShell command history is also swept for credentials, by running the
  secret file rules over it.
- **`-fix` / `-apply`.** Fifty file rules declare the deterministic change that
  ends their finding. `-fix` shows every one as a unified diff and writes
  nothing; `-apply` backs each file up to `.qalqon-backups/<timestamp>/`,
  writes, re-runs the originating rule to verify, and rolls back immediately
  anything that did not end its finding. CRLF files keep their endings;
  inserts inherit the matched line's indentation; binaries, oversized files and
  paths outside the scan root are refused by name.
- **`qalqon report`.** Scores an ordinary scan against a published framework —
  `cis-docker`, `cis-kubernetes`, `pci-dss`, all compiled in. Controls report
  PASS, FAIL or REVIEW (nothing in the tree applies to them); reviewed controls
  are excluded from the score, and a failed control exits `1`. `-html` writes a
  standalone report, `-json` emits the assessment.

### Rules

- 33 more templates across Windows host hardening, POSIX `/proc/sys` hardening,
  and a split of the Apache "server tokens or signature" rule into two rules
  with one deterministic fix each. 204 templates now: 149 file, 23 http,
  32 host.
- Every host rule is fixture-covered by its own committed probe output, and the
  clean fixtures must stay at zero — both enforced by the test suite on every
  platform CI supports.

### Template format

- `fix:` blocks are new and **additive**: existing templates and external
  template directories keep working unchanged. Ops are `replace`, `insert-after`,
  `insert-before`, `delete-line` (file rules) and `registry-set` (host rules,
  reserved for a future release). `find` patterns compile under the same RE2
  engine as matchers, which is what lets the engine verify by re-running the
  rule.

### Still true

- One binary, no configuration file, and scanning stays 100% offline.
  `qalqon deps` remains the only command that touches the network, because a
  vulnerability database cannot be embedded.

## v0.2.0

- `qalqon target` — security headers, cookie flags and TLS state of hosts you
  run, with opt-in `-tls-versions` and `-cve` checks, offline secret scanning of
  commit history via `qalqon history`, and dependency CVE lookups via
  `qalqon deps` against osv.dev.
- SARIF output, exit-code discipline, multi-OS CI.

## v0.1.0

- First release: one binary, YAML template library over local files.
