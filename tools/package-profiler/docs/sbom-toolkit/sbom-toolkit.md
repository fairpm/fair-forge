# 🎛️ sbom-toolkit.sh

> **Controller script** — orchestrates the full SBOM Toolkit pipeline, aggregates results into `meta.json`, and applies CI gate thresholds.

**TL;DR:** Point this at a package archive and it runs everything automatically: checksum, SBOM generation, CVE scan, license check, supply chain audit, provenance verification, and SLSA attestation.

---

## 📋 Overview

`sbom-toolkit.sh` is the entry point for the SBOM Toolkit. It:

1. Discovers which peer scripts are available
2. Runs Wave 1 scripts in parallel (checksum, SBOM discovery, SBOM generation)
3. Runs Wave 2 scripts in parallel using Wave 1 outputs (vuln scan, license, audit, provenance, compare)
4. Runs Wave 3 sequentially (SLSA attestation)
5. Aggregates all scan JSONs into a single `<name>.meta.json`
6. Evaluates CI gate thresholds and sets exit code accordingly

Individual scripts can be skipped with `--skip-*` flags. The controller handles missing peer scripts gracefully (skip with log message rather than fail).

---

## 🔧 Options

### Basic

| Flag | Description |
|---|---|
| `-h, --help` | Show help and exit |
| `-s, --silent` | Suppress progress messages |
| `-j, --json` | JSON output to stdout (meta JSON) |
| `-sj, -js` | Silent + JSON (pipe-friendly) |
| `-v, --verbose` | Show per-job detail |
| `--version` | Print version and exit |
| `--dry-run` | Print what would run; do not execute |
| `--keep-intermediate` | Retain individual scan JSON files alongside meta.json |
| `--no-log` | Do not write `run.log` |
| `-o, --output-dir DIR` | Base directory for all output (default: `./meta`) |

### Package identity

| Flag | Description |
|---|---|
| `--ecosystem TYPE` | Ecosystem for license defaults: `wordpress` \| `packagist` \| `npm` \| `pypi` \| `github` \| `file` |
| `--source-type TYPE` | Archive source type for checksum API: same values as `--ecosystem` |
| `--wp-plugin SLUG` | WordPress plugin slug (enables WP-specific checks in checksum and provenance) |
| `--wp-version VERSION` | WordPress plugin version |

### Source and build context

| Flag | Description |
|---|---|
| `--source-repo URL` | Source repository URL (forwarded to provenance-verify and slsa-attest) |
| `--source-commit SHA` | Source commit hash |
| `--source-ref REF` | Git ref (e.g. `refs/tags/v1.2.3`) |
| `--build-trigger TYPE` | Build trigger: `push` \| `tag` \| `manual` \| `schedule` \| `api` |
| `--build-id ID` | CI run ID or build reference |
| `--package-type TYPE` | Package context for provenance risk scoring: `public` (default) \| `internal` \| `prerelease` \| `custom` |

### SLSA attestation

| Flag | Description |
|---|---|
| `--slsa-level N` | SLSA level to assert: 0–3 (default: 0) |
| `--builder-id URI` | Builder identity URI (required for SLSA L1+) |
| `--policy-uri URI` | Policy URI (required for SLSA L1+) |
| `--disclaimer-uri URI` | Observer disclaimer URI |

### SBOM comparison (optional)

| Flag | Description |
|---|---|
| `--compare FILE` | Compare generated SBOM against a baseline SBOM file |
| `--manifest FILE` | Compare generated SBOM against a package manifest file |

### CI gate options

| Flag | Description |
|---|---|
| `--fail-on-risk N` | Exit 1 if total risk score ≥ N |
| `--fail-on-severity SEV` | Exit 1 if any finding at `CRITICAL` or `HIGH` severity |
| `--require-gpl-compat` | Exit 1 if any license is not GPL-compatible |
| `--allow-license-unknown` | Do not fail on unknown license identifiers |

### Skip options

| Flag | Skips |
|---|---|
| `--skip-checksum` | checksum-verify |
| `--skip-discover` | sbom-discover |
| `--skip-sbom-gen` | sbom-gen (use if SBOM already exists) |
| `--skip-vuln` | vuln-scan |
| `--skip-license` | license-check |
| `--skip-audit` | dependency-audit |
| `--skip-provenance` | provenance-verify |
| `--skip-compare` | sbom-compare |
| `--skip-slsa` | slsa-attest |

---

## 📁 Output Structure

```
meta/<clean-name>/
  <n>.spdx.json                      SPDX 2.3 SBOM
  <n>.cdx.json                       CycloneDX 1.5 SBOM
  <n>.meta.json                      Aggregated toolkit results  ← primary output
  <n>.slsa-L<n>.provenance.json      SLSA attestation
  run.log                            Full execution log
  (individual scan JSONs if --keep-intermediate)
```

The `clean-name` is derived from the target filename with archive extensions stripped and non-alphanumeric characters replaced by hyphens (e.g., `akismet.5.3.zip` → `akismet.5.3`).

### meta.json structure

```jsonc
{
  "run": {
    "id":            "uuid",
    "toolkit_version": "1.0.0",
    "timestamp":     "ISO-8601",
    "target":        "akismet.5.3.zip",
    "clean_name":    "akismet.5.3",
    "options":       { ... }
  },
  "risk_summary": {
    "total_risk":  142,
    "risk_level":  "LOW",      // CRITICAL | HIGH | MEDIUM | LOW
    "components": {
      "checksum":  0,
      "provenance": 100,
      "vuln":      42,
      "license":   0,
      "audit":     0
    }
  },
  "ci_gate": {
    "triggered":  false,
    "reasons":    []
  },
  "crypto_verification":     { ... },   // from checksum-verify
  "provenance_verification": { ... },   // from provenance-verify
  "vulnerability_scan":      { ... },   // from vuln-scan (CycloneDX + risk_assessment)
  "license_compliance":      { ... },   // from license-check
  "dependency_audit":        { ... },   // from dependency-audit
  "sbom_discovery":          { ... },   // from sbom-discover
  "sbom_comparison":         { ... },   // from sbom-compare (if run)
  "slsa_attestation":        { ... }    // from slsa-attest assessment file
}
```

---

## 💡 Examples

### WordPress plugin, full pipeline

```bash
./sbom-toolkit.sh \
  --ecosystem wordpress \
  --wp-plugin akismet --wp-version 5.3 \
  akismet.5.3.zip
```

### WordPress plugin with CI gates and SLSA

```bash
./sbom-toolkit.sh \
  --ecosystem wordpress \
  --wp-plugin akismet --wp-version 5.3 \
  --require-gpl-compat \
  --fail-on-risk 500 \
  --fail-on-severity HIGH \
  --builder-id https://github.com/actions/runner \
  --policy-uri  https://your-org.example/package-policy \
  --slsa-level 2 \
  akismet.5.3.zip
```

### Internal package (skip public registry checks)

```bash
./sbom-toolkit.sh \
  --package-type internal \
  --source-repo git.your-org.example/team/lib \
  --skip-provenance \
  internal-lib-2.0.tar.gz
```

### Using an existing SBOM (skip Syft generation)

```bash
./sbom-toolkit.sh \
  --skip-sbom-gen \
  --ecosystem npm \
  ./my-package/
```

### Compare against a previous version's SBOM

```bash
./sbom-toolkit.sh \
  --compare ./meta/akismet.5.2/akismet.5.2.cdx.json \
  --ecosystem wordpress \
  --wp-plugin akismet --wp-version 5.3 \
  akismet.5.3.zip
```

### Dry run — see what would execute

```bash
./sbom-toolkit.sh --dry-run \
  --ecosystem wordpress \
  --wp-plugin akismet --wp-version 5.3 \
  akismet.5.3.zip
```

### Read the risk score in a pipeline

```bash
./sbom-toolkit.sh -sj akismet.5.3.zip \
  | jq '.risk_summary.total_risk'
```

---

## 🚦 Exit Codes

| Code | Meaning |
|---|---|
| 0 | All checks passed; CI gates not triggered |
| 1 | Issues found, or a CI gate (`--fail-on-risk`, `--fail-on-severity`) was triggered |
| 2 | Execution error (missing argument, script not found, unexpected failure) |

---

## ⚠️ Known Limitations

- `sbom-toolkit.sh` discovers peer scripts by resolving `$(dirname "${BASH_SOURCE[0]}")`. Symlinks to the controller work as long as the peer scripts are in the same physical directory as the resolved symlink target.
- Wave 2 provenance-verify is skipped automatically if neither `--wp-plugin` nor `--source-repo` is provided, to avoid a misleading 300-point base risk penalty. Pass `--skip-provenance` explicitly to suppress the advisory message.
- The SLSA attestation is an observer report — it cannot make guarantees about the build environment the toolkit did not witness. See [slsa-attest.md](slsa-attest.md).

---

<sub>Scripts licensed MIT · Documentation [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) · © Package Profiler Contributors</sub>
