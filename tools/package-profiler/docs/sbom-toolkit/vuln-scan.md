# 🛡️ vuln-scan.sh

> Scans a CycloneDX SBOM for known CVEs using Grype and produces a CVSS-weighted risk score.

**TL;DR:** The primary risk signal for a package. A single critical CVE in a dependency can produce a score of 1000+; a score below 100 means the dependency tree is in reasonable shape by known-vuln standards.

---

## 🎯 Purpose

Known vulnerabilities in third-party dependencies are the most common and most measurable supply chain risk. `vuln-scan.sh` runs Grype against a CycloneDX SBOM to identify every dependency with a CVE match in NVD, GHSA, OSV, or other Grype-supported databases, then converts the raw CVE list into a single risk score that can drive CI gate decisions.

The **risk score** is preferable to raw CVE counts as a gate because severity distribution matters: 50 low-severity CVEs are less urgent than one critical one.

---

## 🔧 Options

| Flag | Description |
|---|---|
| `-h, --help` | Show help and exit |
| `-s, --silent` | Suppress progress messages |
| `-j, --json` | JSON output to stdout |
| `-sj, -js` | Silent + JSON (pipe-friendly) |
| `-v, --verbose` | Show additional detail |
| `-f, --format FORMAT` | Output format: `merged` (default) \| `grype-only` \| `summary` \| `risk` |
| `-t, --timeout SECONDS` | Grype scan timeout (default: 300) |
| `-o, --output-dir DIR` | Directory for output file |
| `--no-file` | Output to stdout only; do not write file |
| `--no-risk` | Skip risk score calculation (faster; no `vuln-scan-risk.jq` required) |
| `--version` | Print version and exit |

### Output formats

| Format | Contents |
|---|---|
| `merged` | Full CycloneDX SBOM with embedded vulnerability data + `risk_assessment` block |
| `grype-only` | Raw Grype JSON output (no SBOM merging) |
| `summary` | Condensed human-readable vulnerability summary |
| `risk` | Risk score block only — suitable for CI gate scripts |

---

## ⚠️ Required peer file

`vuln-scan-risk.jq` must be in the **same directory** as `vuln-scan.sh`. The two files are distributed together and cannot be separated. The script exits with code 2 if the `.jq` file is missing.

---

## 📊 Risk Scoring

Risk scoring is handled by `vuln-scan-risk.jq`, which applies CVSS-weighted scoring to the Grype output.

### CVSS preference order

For each CVE, the CVSS base score is selected in this order: v3.1 → v3.0 → v2.0 → first available. This preference reflects the improved scoring methodology in later CVSS versions.

### Weights

| Severity | CVSS range | Weight |
|---|---|---|
| Critical | 9.0–10.0 | ×100 |
| High | 7.0–8.9 | ×25 |
| Medium | 4.0–6.9 | ×5 |
| Low | 0.1–3.9 | ×1 |
| Negligible | — | ×0.1 |

`weighted_risk = Σ (cvss_score × weight)` for all matched CVEs

### Risk level thresholds

| `weighted_risk` | Level | Meaning |
|---|---|---|
| ≥ 1000 | CRITICAL | Immediate action required |
| ≥ 500 | HIGH | Remediate soon |
| ≥ 100 | MEDIUM | Plan remediation |
| < 100 | LOW | Monitor for updates |

*These thresholds are set in `sbom-toolkit.sh`. See [Maintenance Guide](../developer/maintenance.md) for how to adjust them.*

---

## 📤 Output

**File:** `meta/<clean-name>/<clean-name>.vuln.json`

The output is a **CycloneDX 1.5 SBOM** with an appended `risk_assessment` block (not part of the CycloneDX spec — treated as an extension):

```jsonc
{
  "bomFormat":   "CycloneDX",
  "specVersion": "1.5",
  "metadata":    { ... },
  "components":  [ ... ],
  "vulnerabilities": [
    {
      "id":       "CVE-2024-12345",
      "severity": "HIGH",
      "cvss":     { "version": "3.1", "score": 8.1 },
      "artifact": { "name": "some-dep", "version": "1.0.0" }
    }
  ],
  "risk_assessment": {
    "weighted_risk":   202,
    "cvss_critical":   0,
    "cvss_high":       8.1,
    "cvss_medium":     0,
    "cvss_low":        0,
    "cvss_negligible": 0,
    "vuln_counts": {
      "critical": 0, "high": 1, "medium": 0,
      "low": 0, "negligible": 0, "unknown": 0, "total": 1
    },
    "scoring_notes": {
      "method":         "cvss_weighted",
      "cvss_version":   "3.1_preferred",
      "unscored_vulns": 0,
      "weights":        "Critical×100 High×25 Medium×5 Low×1 Negligible×0.1"
    }
  }
}
```

---

## 💡 Examples

```bash
# Basic scan
./vuln-scan.sh akismet.5.3.cdx.json

# Risk score only (CI gate)
./vuln-scan.sh -f risk akismet.5.3.cdx.json

# Silent JSON for piping
./vuln-scan.sh -sj akismet.5.3.cdx.json \
  | jq '.risk_assessment.weighted_risk'

# Longer timeout for large SBOMs
./vuln-scan.sh --timeout 600 large-package.cdx.json

# Skip risk scoring (faster, raw Grype output only)
./vuln-scan.sh --no-risk -f grype-only akismet.5.3.cdx.json
```

---

## ⚠️ Known Limitations

- Grype matches CVEs against components as declared in the SBOM. Vendored code or dynamically loaded dependencies that Syft didn't catalogue will not be scanned.
- The Grype database must be updated periodically to reflect new CVE disclosures. Run `grype db update` to refresh. CVEs published after the last database update will not appear.
- CVSS scores are from the NVD or GHSA database entry. Some CVEs lack a CVSS score; these are counted in `unscored_vulns` but contribute 0 to `weighted_risk`.
- `weighted_risk` is a dimensionless score, not a probability or percentage. Do not compare scores between packages with very different dependency counts.

---

<sub>Scripts licensed MIT · Documentation [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) · © Package Profiler Contributors</sub>
