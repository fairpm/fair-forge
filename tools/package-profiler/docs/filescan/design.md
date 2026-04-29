# 🧠 Filescan Suite — Design Document

> Design rationale, threat model, and performance characteristics for the Filescan Suite.

---

## 🎯 Objectives

The Filescan Suite operates on an extracted package directory and provides three complementary lenses on its contents:

1. **Structural inventory** — understand what the package actually ships, independent of what it declares
2. **Static threat detection** — catch malicious code patterns before the package is installed or executed
3. **Permission hardening** — identify permission configurations that could be exploited post-installation

All three are intentionally non-destructive by default. The suite never modifies the target unless `--fix` is explicitly passed to `permission-check.sh` or `run-filescans.sh`.

---

## 🔐 Threat Model

### Structural inventory (file-stats)

**What it reveals:** The file-type distribution exposes anomalies. A plugin claiming to be a contact form should not contain hundreds of binary executables or nested archives. The best-practice file check reveals whether the package follows ecosystem conventions for discoverability, licensing, and maintainability.

**What it does not catch:** File type is determined by extension for statistics. Mismatched extensions (a PHP file named `.jpg`) are caught by deep-filescan, not file-stats.

### Malicious pattern detection (deep-filescan)

**Threat categories:**

| Category | Severity | What it catches |
|---|---|---|
| Reverse shells | CRITICAL | Bash/netcat/Python/Ruby/PHP socket-exec patterns |
| Crypto miners | CRITICAL | CoinHive, XMRig, stratum protocol references, CryptoNight |
| Code obfuscation | HIGH | `eval(base64_decode(...))`, `fromCharCode` chains, hex chains, `gzinflate(base64_decode(...))` |
| Data exfiltration | HIGH | `curl --data @file`, `wget --post-file`, fetch+cookie POST |
| PHP webshells | MEDIUM | `system($_GET[...])`, `shell_exec($_POST[...])`, `passthru`, `proc_open`, `assert` with user input |

**MIME integrity:**

| Check | Rationale |
|---|---|
| Extension vs. MIME mismatch | A `.jpg` with MIME type `text/x-php` is a disguised PHP file |
| Executable in data location | A PHP file inside an images/ or uploads/ directory |
| Embedded code in binary | PHP or script markers inside otherwise binary files |

**Size limit:** Files over 10 MB are excluded from pattern and embedded-code scanning (MIME check still runs). This prevents the scanner from hanging on large minified bundles or media files. Override with `--no-size-limit`.

**Why static analysis only:** This suite does not execute code. Static pattern matching has a false-positive rate — not every base64-decoded eval is malicious. Findings are signals for human review, not automated verdicts.

### Permission audit (permission-check)

**Threat categories and risk weights:**

| Issue | Severity | Risk weight |
|---|---|---|
| World-writable file | Critical | ×10 per file |
| World-writable directory | Critical | ×15 per dir |
| Missing sticky bit on world-writable dir | Critical | ×20 |
| Privilege escalation (SUID/SGID) | Critical | ×20 |
| Permission inversion (dir less accessible than contents) | Critical | ×30 |
| External symlink | Critical | ×25 |
| Sensitive file exposure | Critical | ×25 |
| Internal symlink | Other | ×5 |
| Dangling symlink | Other | ×10 |
| Unnecessary execute bit on data file | Other | ×3 |
| Orphaned ownership | Other | ×10 |
| Deploy artefact | Other | ×8 |

The risk score is a straight sum of weights — no credit is given for hardened files, because doing so would mask genuine issues and make scores non-comparable across packages.

**--fix behaviour:** Removes world-writable permissions, adds sticky bits to world-writable directories, strips execute bits from data files (images, fonts, documents), and restricts access to sensitive files (`.env`, `.htpasswd`, etc.). All fixes are logged. The script reports failures when a fix cannot be applied (e.g., insufficient privileges).

---

## ⚙️ Performance

| Script | Typical runtime | Scaling factor |
|---|---|---|
| `file-stats.sh` | 1–5 s | File count |
| `deep-filescan.sh` | 5–60 s | File count × average file size |
| `permission-check.sh` | 1–10 s | File count |

`deep-filescan.sh` is the bottleneck. Pattern matching runs `grep -f` across all eligible files in one pass (not per-file), which scales well to large packages. The 10 MB size limit prevents outlier files from dominating scan time. For single large files, use `--no-size-limit` explicitly.

`run-filescans.sh` runs all three scripts sequentially (not in parallel) to avoid I/O contention on the target directory.

---

## ⚠️ Known Limitations

- Pattern detection is signature-based. Novel or custom-obfuscated malware may not match any pattern.
- MIME type detection relies on the `file` command. Some MIME types are ambiguous or platform-dependent.
- The best-practice check in file-stats is a presence check only — it confirms the file exists but does not validate its contents.
- Permission checks run as the current user. SUID/SGID detection requires the current user to be able to read file metadata. In containers running as root, all permission checks will still run correctly.

---

<sub>Scripts licensed MIT · Documentation [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) · © Package Profiler Contributors</sub>
