# 🏗️ Architecture

> **TL;DR:** Package Profiler is two sets of independent scripts unified by a shared output convention: every script writes a root-keyed JSON file, and the controller aggregates them into one `meta.json`. Scripts can run standalone or be orchestrated by the controllers.

---

## 🎯 Design Objectives

1. **Composable** — every script works standalone. The controllers (`sbom-toolkit.sh`, `run-filescans.sh`) add orchestration, not capability.
2. **Auditable** — all findings are machine-readable JSON with stable root keys. The meta.json is a single document that captures the full scan state.
3. **CI-friendly** — exit codes are consistent (0 = pass, 1 = issues found, 2 = execution error) across all scripts. Silent+JSON mode (`-sj`) allows piping without log noise.
4. **Non-destructive** — scripts never modify the target. `permission-check.sh` with `--fix` is the only exception, and it requires the flag to be explicit.
5. **Offline-capable** — most analysis runs without network access. Only checksum API lookups and Grype database updates require connectivity.

---

## 📐 The Two Sets

```
Package Archive / Directory
         │
         ├─── SBOM Toolkit ─────────────────────────────────────────────┐
         │    (archive-level: identity, integrity, risk, compliance)    │
         │                                                              │
         │    sbom-toolkit.sh                                           │
         │      Wave 1 ──── checksum-verify  sbom-discover  sbom-gen  │
         │      Wave 2 ──── vuln-scan  license-check  dep-audit       │
         │                   provenance-verify  sbom-compare           │
         │      Wave 3 ──── slsa-attest ──► meta.json                 │
         │                                                              │
         └──────────────────────────────────────────────────────────────┘
         │
         ├─── Filescan Suite ───────────────────────────────────────────┐
         │    (directory-level: structure, content, permissions)        │
         │                                                              │
         │    run-filescans.sh                                          │
         │      Always ──── file-stats  permission-check               │
         │      --deep  ──── deep-filescan                             │
         │      ──► merged filescan JSON                               │
         │                                                              │
         └──────────────────────────────────────────────────────────────┘
```

The two sets are complementary. The SBOM Toolkit works from the archive (what it declares it is); the Filescan Suite works from the extracted directory (what it actually contains). Running both gives the most complete picture.

---

## 🌊 SBOM Toolkit Pipeline

### Wave design

The pipeline runs in three waves. Wave 1 and 2 jobs execute in parallel (background subshells, one job per script); Wave 3 is sequential because it depends on Wave 2 outputs.

```
Wave 1 (parallel)
  checksum-verify  ─── verifies the archive is what it claims; optionally extracts it
  sbom-discover    ─── looks for embedded SBOMs or manifest files
  sbom-gen         ─── generates SPDX + CycloneDX SBOMs using Syft

Wave 2 (parallel, uses Wave 1 outputs)
  vuln-scan        ─── CVE scan of the CycloneDX SBOM (Grype)
  license-check    ─── SPDX license compliance of the SPDX SBOM
  dependency-audit ─── typosquat + confusion pattern detection (CycloneDX)
  provenance-verify─── upstream source and provenance validation
  sbom-compare     ─── diff against a baseline SBOM or manifest

Wave 3 (sequential)
  slsa-attest      ─── generates SLSA v1.0 in-toto attestation
  aggregate_meta   ─── merges all scan JSONs into <name>.meta.json
  evaluate_gates   ─── applies CI gate thresholds; sets exit code
```

### Data flow

Each Wave 2 script reads the output of one or more Wave 1 scripts. The expected file paths follow a deterministic naming convention:

```
meta/<clean-name>/
  <clean-name>.checksum.json    ← from checksum-verify
  <clean-name>.spdx.json        ← from sbom-gen (also used by license-check)
  <clean-name>.cdx.json         ← from sbom-gen (also used by vuln-scan, dep-audit)
  <clean-name>.discover.json    ← from sbom-discover
  <clean-name>.vuln.json        ← from vuln-scan
  <clean-name>.license.json     ← from license-check
  <clean-name>.deps-audit.json  ← from dependency-audit
  <clean-name>.provenance.json  ← from provenance-verify
  <clean-name>.compare.json     ← from sbom-compare
  <clean-name>.slsa-L<n>.provenance.json  ← from slsa-attest
  <clean-name>.meta.json        ← aggregated by sbom-toolkit
  run.log                       ← full execution log
```

### Name sanitisation

All scripts apply the same `sanitize_name()` function to produce a filesystem-safe `clean-name` from the target path. The function strips archive extensions, replaces non-alphanumeric characters with hyphens, and collapses repeated hyphens. **This function is duplicated verbatim in every script that writes output files** — a deliberate choice to keep each script self-contained. Changes must be propagated to all copies; see [Maintenance Guide](maintenance.md).

---

## 📄 JSON Output Convention

Every script that produces JSON output follows this structure:

```json
{
  "<root_key>": {
    "timestamp":       "ISO-8601 UTC",
    "toolkit_version": "1.0.0",
    "status":          "verified | issues_found | clean | ...",
    "risk_contribution": 0,
    "...": "script-specific fields",
    "issues": [],
    "findings": []
  }
}
```

### Root key registry

| Script | Root key |
|---|---|
| `checksum-verify.sh` | `crypto_verification` |
| `provenance-verify.sh` | `provenance_verification` |
| `vuln-scan.sh` | CycloneDX SBOM + `risk_assessment` block |
| `license-check.sh` | `license_compliance` |
| `dependency-audit.sh` | `dependency_audit` |
| `sbom-compare.sh` | `sbom_comparison` |
| `file-stats.sh` | `file_statistics` |
| `deep-filescan.sh` | `content_scan` |
| `permission-check.sh` | `permission_audit` |
| `slsa-attest.sh` | `slsa_attestation` (assessment file) |

See [JSON Schema](json-schema.md) for full field definitions.

---

## 🔢 Risk Score Model

The toolkit aggregates a `total_risk` score from the `risk_contribution` of each scan section. This is a dimensionless number in arbitrary units — it is not a CVSS score.

| Contribution | Source | How it's calculated |
|---|---|---|
| `checksum` | checksum-verify | 0 if verified; 500 if mismatch; 50 if no reference found |
| `provenance` | provenance-verify | Starts at 300 for public packages; reduced by 50–100 per verification factor satisfied |
| `vuln` | vuln-scan | CVSS sum per severity × weight (Critical×100, High×25, Medium×5, Low×1, Negligible×0.1) |
| `license` | license-check | 100 per GPL-incompatible; 200 per AGPL; 50 per unknown |
| `audit` | dependency-audit | 400 per typosquat; 500 per confusion finding |

The thresholds that map `total_risk` to a `risk_level` label are set in `sbom-toolkit.sh` and described in [maintenance.md](maintenance.md).

---

## 🔌 Extension Points

### Adding a new ecosystem (checksum-verify)

`checksum-verify.sh` contains a `lookup_<ecosystem>()` function for each supported source. Add a new function following the same pattern, then add its name to the source-type case statement and the auto-detect logic. See [Maintenance Guide](maintenance.md).

### Adding a new file category (file-stats)

`file-stats.sh` uses an associative array `CATEGORIES` that maps file extensions to category names. Add extensions to existing categories or create a new entry. Corresponding changes may be needed in `deep-filescan.sh`'s exclusion list. See [Maintenance Guide](maintenance.md).

### Adding new malicious patterns (deep-filescan)

Pattern arrays in `deep-filescan.sh` are grouped by threat type (reverse shells, crypto miners, obfuscation, etc.). Append new regex patterns to the appropriate array. Consider whether the pattern warrants a new severity classification. See [Maintenance Guide](maintenance.md).

---

## 🔐 Security Model

### What the suite can and cannot do

**Can detect:**
- Known CVEs in declared dependencies (via Grype + NVD/GHSA)
- Archive tampering (checksum mismatch against upstream API)
- Provenance gaps (missing or unverifiable source attestation)
- License compliance violations
- Typosquatting and dependency confusion patterns
- Malicious code patterns in source files (static analysis only)
- Dangerous filesystem permissions

**Cannot detect:**
- Zero-day vulnerabilities not yet in the CVE database
- Semantic/logic malware that doesn't match known patterns
- Malicious code injected after Grype last scanned the ecosystem
- Supply chain compromises in the upstream registry itself (if the registry serves a malicious file with matching checksums)
- Runtime behaviour

### Trust model

The suite treats the upstream ecosystem API (WordPress.org, Packagist, npm, PyPI) as the authoritative reference for checksums. If the registry itself has been compromised, a matching checksum does not imply safety — it implies the downloaded file matches what the registry is currently serving. The SLSA attestation explicitly documents this limitation via an observer disclaimer.

---

<sub>© Package Profiler Contributors · Documentation licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)</sub>
