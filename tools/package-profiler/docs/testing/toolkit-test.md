# 🧪 SBOM Toolkit Test Suite

> `toolkit-test.sh` — comprehensive self-contained test suite for the SBOM Toolkit scripts.

---

## Overview

`toolkit-test.sh` validates the correctness of all SBOM Toolkit analysis scripts through a battery of functional tests with generated fixtures. It is self-contained: all fixture files are created at startup using only standard tools — no network access and no pre-existing package archives are required.

The suite exercises argument validation, JSON output structure, risk scoring, edge cases, and output file permissions. It does not test the full pipeline controller (`sbom-toolkit.sh`), as that would require Syft and Grype; instead it targets the scripts that can be tested meaningfully offline.

---

## Running the Suite

```bash
# Run all tests
bash toolkit-test.sh

# Dry run — verify fixtures can be created and scripts found, then exit
bash toolkit-test.sh --dry-run

# Run only specific sections (by number)
bash toolkit-test.sh --only 1        # checksum-verify only
bash toolkit-test.sh --only 3,4      # license-check and dependency-audit

# Verbose output — show each assert result
bash toolkit-test.sh --verbose
```

Exit code: `0` = all tests passed · `1` = one or more failures · `2` = setup error

---

## Test Sections

### Section 1 — `checksum-verify.sh`

**Fixtures:** A synthetic WordPress plugin zip with `readme.txt` containing `=== Plugin Name ===` headers; a WordPress core zip with `wp-includes/version.php`; a non-WordPress zip with RST-style headers.

| Test group | What is verified |
|---|---|
| Arg errors | No args → exit 2; missing file → exit 2 |
| WP plugin identity detection | `package_identity.ecosystem == "wordpress"`, correct name and version extracted from `readme.txt` |
| WP core identity detection | Core detected as `wordpress` ecosystem, version from `wp-includes/version.php` |
| RST headers false positive | Non-WordPress zip with RST headers does **not** get detected as `wordpress` |
| File write and permissions | Output file is created with `664` permissions; no absolute paths in JSON |
| `--extract` behaviour | `extraction.directory_name` contains basename only, not full path |
| `--skip` mode | Exits 0; status is `skipped`; checksums still calculated |

---

### Section 2 — `sbom-discover.sh`

**Fixtures:** A zip with no embedded SBOM; a directory containing a minimal valid SPDX JSON file.

| Test group | What is verified |
|---|---|
| Arg errors | No args → exit 2 |
| Archive with no SBOM | Exit 0 or 1 (not 2); status reflects no SBOM found |
| Directory with SPDX fixture | `status == "sbom_found"`; `valid_sboms[0].path` is non-empty |
| File write and permissions | Output file created at `664` |

---

### Section 3 — `license-check.sh`

**Fixtures:** Synthetic SPDX JSON SBOMs with specific license combinations: SSPL (GPL-incompatible), MIT/Apache-2.0 mix (permissive), clean GPL-2.0-only, SPDX OR expression (`MIT OR Apache-2.0`).

| Test group | What is verified |
|---|---|
| Arg errors | No args → exit 2; missing file → exit 2 |
| SSPL causes exit 1 | `gpl_compatible == false`; `summary.gpl_incompatible >= 1` |
| SPDX OR expressions | Least-restrictive interpretation applied; MIT chosen over Apache |
| Clean SBOM exits 0 | `status == "clean"`; `risk_contribution == 0` |
| `--require-gpl-compat` | Exit 1 when SSPL present; exit 0 when absent |
| `--allow-unknown` | Unknown license identifier does not trigger exit 1 |
| File write and permissions | Output at `664`; no absolute paths |

---

### Section 4 — `dependency-audit.sh`

**Fixtures:** Synthetic CycloneDX SBOMs: a clean SBOM with well-known packages; an SBOM with a near-typosquat (`1odash` for `lodash`, distance 1); an SBOM with packages triggering suspicious pattern rules.

| Test group | What is verified |
|---|---|
| Arg errors | No args → exit 2; missing file → exit 2 |
| Clean SBOM exits 0 | `summary.total_issues == 0`; `risk_contribution == 0` |
| Typosquat detection | Distance-1 match flagged; `findings[0].type == "typosquatting"` |
| `--max-distance 1` | Same typosquat still caught at distance 1 |
| `--skip-typosquat` | Typosquat finding suppressed; exit 0 for that input |
| `--skip-suspicious` | Suspicious pattern finding suppressed |
| Risk contribution scaling | Typosquat risk = 400; two findings = ≥ 800 |

---

### Section 5 — `sbom-compare.sh`

**Fixtures:** Two minimal CycloneDX SBOMs — one with packages A+B, one with packages B+C (so: A removed, C added, B in both).

| Test group | What is verified |
|---|---|
| Arg errors | No args → exit 2; `--compare` without file → exit 2 |
| Added/removed detection | `summary.added == 1`; `summary.removed == 1` |
| Same package not in findings | Package B appears in `same`, not `changed` |
| Exit code | Exit 1 when differences found; exit 0 when identical |
| `--manifest` mode | Manifest-format diff produces findings with correct types |
| File write and permissions | Output at `664` |

---

### Section 6 — `provenance-verify.sh`

**Fixtures:** A synthetic WordPress plugin zip with valid `readme.txt`; a synthetic SLSA provenance JSON with trusted builder and valid structure; a malformed provenance JSON; a provenance JSON with untrusted builder.

| Test group | What is verified |
|---|---|
| Arg errors | No args → exit 2 |
| WP mode without network | With `--skip` or offline fixture, produces output with WP identity |
| SLSA format validation | Valid provenance → `checks` contains `slsa_format: passed` |
| Untrusted builder | Builder not in trust list → finding with `builder_trusted: failed` |
| Malformed provenance | Parse error reported in issues; exit 1 |
| `--package-type internal` | `public_verification_skipped == true`; lower base risk |
| Risk contribution range | `risk_contribution` is a non-negative integer |

---

## Fixture Design

All fixtures are created in a temporary directory at test startup (`mktemp -d`) and cleaned up on exit via a `trap`. Fixtures use the minimum content needed to satisfy the parsing logic in each script — they do not need to be valid real-world packages.

### Why self-contained fixtures?

- No network access required — tests can run in CI without outbound connections
- Deterministic — fixture content is controlled, so test assertions are reliable
- Fast — no archive downloads; fixture creation takes < 1 second

### Adding new tests

1. Add fixture creation to `create_fixtures()` at the top of the script
2. Add a new `section "N. script-name.sh"` block with `echo` labels and `assert_*` calls
3. Use the existing assertion helpers:
   - `assert_exit N $? "description"` — check exit code
   - `assert_json FILE '.jq.path' "expected" "description"` — check JSON field value
   - `assert_json_nonempty FILE '.jq.path' "description"` — check field is non-empty
   - `assert_no_abspath FILE "description"` — verify no absolute paths in JSON
   - `assert_perms FILE "664" "description"` — check file permissions

---

## Expected Output

```
=== Package Profiler — Toolkit Test Suite ===
Running 6 sections, N assertions

──── 1. checksum-verify.sh ────────────────────────────
  [arg errors]
  PASS  no args → exit 2
  PASS  missing file → exit 2
  [WP plugin identity detection from readme.txt]
  PASS  plugin: --skip exits 0
  PASS  plugin: ecosystem is wordpress
  ...

══════════════════════════════════════════════════════
  Results: N passed, 0 failed, 0 skipped (N total)
══════════════════════════════════════════════════════
```

If any test fails, the section, test name, expected value, and actual value are reported, and the exit code is 1.

---

## Known Limitations

- `sbom-gen.sh`, `vuln-scan.sh`, and `sbom-toolkit.sh` are not tested because they require Syft and Grype. Integration testing of the full pipeline requires those tools to be installed.
- Network-dependent behaviour (API lookups in `checksum-verify.sh` and `provenance-verify.sh`) is tested in offline mode only. The `--skip` flag and mock fixtures cover the code paths that don't require network, but actual API response parsing is not validated by this suite.
- `slsa-attest.sh` is not included in the current suite. Adding tests for it is tracked as a future improvement (the script's meta-json dependency makes fixture construction more involved).

---

<sub>Scripts licensed MIT · Documentation [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) · © Package Profiler Contributors</sub>
