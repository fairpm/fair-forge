# 🔎 deep-filescan.sh

> Scans file contents for malicious code patterns and MIME integrity anomalies.

**TL;DR:** Catches active threats: reverse shells, crypto miners, obfuscated eval chains, PHP webshells, data exfiltration code, and files disguised as a different type.

---

## 🎯 Purpose

A package can pass checksum verification and CVE scanning while still containing injected malicious code. CVE scanning catches *known vulnerable versions of declared packages*; it does not catch hand-written PHP webshells or obfuscated reverse shell scripts added to a plugin's source tree. `deep-filescan.sh` closes this gap with static pattern analysis.

---

## 🔧 Options

| Flag | Description |
|---|---|
| `-s, --silent` | Suppress progress messages |
| `-j, --json` | Output results in JSON format |
| `-sj, -js` | Silent + JSON (pipe-friendly) |
| `-v, --verbose` | Show phase status, per-finding detail, and hygiene breakdown |
| `-o, --output-dir D` | Write JSON output to directory |
| `--meta-base DIR` | Base directory for meta output (default: `./meta`) |
| `--no-file` | Output JSON to stdout only; do not write file |
| `--no-size-limit` | Disable the 10 MB per-file skip threshold for pattern scanning |
| `--write-json F` | Write JSON results to file F (used by `run-filescans.sh`) |
| `--version` | Print version and exit |

---

## 🚨 What It Detects

### Pattern checks (on text/code files)

| Category | Severity | Example patterns |
|---|---|---|
| Reverse shells | CRITICAL | `bash -i >& /dev/tcp/`, `nc -e /bin/sh`, `python socket dup2`, `socat EXEC:` |
| Crypto miners | CRITICAL | CoinHive, `xmrig`, `stratum+tcp://`, CryptoNight, cryptoloot |
| Code obfuscation | HIGH | `eval(base64_decode(...))`, `fromCharCode` chains >80 chars, hex chains ≥8 bytes, `gzinflate(base64_decode...)` |
| Data exfiltration | HIGH | `curl --data @`, `wget --post-file`, `fetch` + POST + `document.cookie` |
| PHP webshells | MEDIUM | `system($_GET[...])`, `shell_exec($_POST[...])`, `passthru`, `assert($_{REQUEST})`, `create_function` + user input |

### Integrity checks (all files)

| Check | What it catches |
|---|---|
| MIME type mismatch | A `.jpg` with MIME `text/x-php`; a `.png` that is `application/zip` |
| Executable in data directory | PHP/script MIME inside `images/`, `uploads/`, `assets/` |
| Embedded code in binary | PHP tags or shell markers inside otherwise binary data |

### Size limit

Files over **10 MB** are skipped for pattern and embedded-code scanning (MIME check still runs). Use `--no-size-limit` to override. The size limit exists to keep scan times predictable on large minified bundles.

---

## 📤 Output

**File:** `meta/<clean-name>/<clean-name>.content-scan.json`  
**Root key:** `content_scan`

```jsonc
{
  "content_scan": {
    "toolkit_version":       "1.0.0",
    "timestamp":             "...",
    "files_checked":         87,
    "files_pattern_scanned": 60,
    "files_size_skipped":    0,
    "summary": {
      "total_issues": 1,
      "critical": 1,
      "patterns": { "reverse_shells": 1, "crypto_miners": 0, ... },
      "integrity": { "mime_mismatches": { "total": 0 }, ... }
    },
    "risk_contribution": 500,
    "findings": [
      {
        "severity": "CRITICAL",
        "type":     "reverse_shell",
        "file":     "includes/helper.php",
        "line":     42,
        "match":    "bash -i >& /dev/tcp/..."
      }
    ]
  }
}
```

**Risk contribution:** Scales with finding count and severity. A single CRITICAL finding contributes 500 points.

---

## 💡 Examples

```bash
# Scan a directory
./deep-filescan.sh ./packages/akismet.5.3/

# Scan a single file
./deep-filescan.sh ./packages/akismet.5.3/includes/helper.php

# Include large files (slower)
./deep-filescan.sh --no-size-limit ./packages/large-package/

# Silent JSON
./deep-filescan.sh -sj ./packages/akismet.5.3/ \
  | jq '.content_scan.summary.total_issues'
```

---

## ⚠️ Known Limitations

- Pattern matching is signature-based. Novel or custom obfuscation techniques will not be detected.
- Base64-encoded PHP eval is a common pattern in *legitimate* plugin code (e.g., licence key encoding). All `eval(base64_decode(...))` matches are flagged for review — context determines whether they are malicious.
- MIME detection depends on the `file` command. Some file types are ambiguous or platform-dependent.

---

<sub>Scripts licensed MIT · Documentation [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) · © Package Profiler Contributors</sub>
