# 🕵️ dependency-audit.sh

> Detects supply chain attack patterns in a package's dependency graph: typosquatting, dependency confusion, and suspicious package characteristics.

**TL;DR:** Catches the case where a dependency isn't a CVE risk but *is* a substitution attack — a malicious package masquerading as a legitimate one by name proximity or namespace collision.

---

## 🎯 Purpose

CVE scanning catches vulnerabilities in known packages. Supply chain attacks use *different* packages — ones that look like legitimate dependencies but aren't. `dependency-audit.sh` runs three independent heuristic checks on every package in an SBOM:

1. **Typosquatting** — Is this package name suspiciously close to a well-known legitimate package?
2. **Dependency confusion** — Could this internal package name be hijacked via a public registry?
3. **Suspicious patterns** — Does this package have characteristics associated with malicious packages (install scripts, unusual versioning, known-bad name patterns)?

These are heuristics, not definitive verdicts. Every finding should be reviewed by a human.

---

## 🔧 Options

| Flag | Description |
|---|---|
| `-h, --help` | Show help and exit |
| `-s, --silent` | Suppress progress messages |
| `-j, --json` | JSON output to stdout |
| `-sj, -js` | Silent + JSON (pipe-friendly) |
| `-v, --verbose` | Show per-package detail |
| `-o, --output-dir DIR` | Directory for output file |
| `--meta-base DIR` | Base directory for meta output (default: `./meta`) |
| `--no-file` | Output JSON to stdout only; do not write file |
| `--skip-typosquat` | Skip typosquatting detection |
| `--skip-confusion` | Skip dependency confusion detection |
| `--skip-suspicious` | Skip suspicious pattern detection |
| `--max-distance N` | Levenshtein distance threshold for typosquat (default: 2) |
| `--version` | Print version and exit |

---

## 🔍 Detection Methods

### Typosquatting (Levenshtein distance)

Compares each dependency name to a curated list of well-known packages in the same ecosystem using the Wagner–Fischer dynamic programming algorithm (true Levenshtein distance). Any name within `--max-distance` of a well-known package is flagged.

**Distance 1** catches: single insertion, deletion, or substitution (`lodash` → `1odash`)  
**Distance 2** catches: transpositions and two-character edits (`lodash` → `lodahs`) — the default

Trade-off: distance 2 increases false positives for short package names. Use `--max-distance 1` for stricter (lower false positive) mode.

### Dependency confusion

Identifies dependencies whose names match the pattern of internal/private packages (e.g., scoped npm packages with internal prefixes, or Composer packages with vendor names not present on public Packagist) that could be hijacked if published to a public registry with a higher version number.

### Suspicious patterns

Flags packages with:
- Post-install or pre-install scripts (common attack vector)
- Unusual or suspicious version strings (e.g., `9.9.9` appearing as a first release)
- Names matching known-bad pattern families from public threat intelligence

---

## 📤 Output

**File:** `meta/<clean-name>/<clean-name>.deps-audit.json`  
**Root key:** `dependency_audit`

```jsonc
{
  "dependency_audit": {
    "timestamp":       "...",
    "toolkit_version": "1.0.0",
    "scan_status":     "issues_found",
    "summary": {
      "typosquatting":        1,
      "dependency_confusion": 0,
      "suspicious_packages":  0,
      "total_issues":         1
    },
    "checks_performed": {
      "typosquatting":          true,
      "dependency_confusion":   true,
      "suspicious_patterns":    true,
      "typosquat_max_distance": 2,
      "typosquat_method":       "levenshtein_wagner_fischer"
    },
    "risk_contribution": 400,
    "findings": [
      {
        "type":           "typosquatting",
        "severity":       "HIGH",
        "package":        "1odash",
        "closest_match":  "lodash",
        "distance":       1,
        "ecosystem":      "npm",
        "recommendation": "Verify this is not a typosquatting attempt"
      }
    ]
  }
}
```

**Risk contribution:** 400 per typosquatting finding · 500 per dependency confusion finding · 200 per suspicious pattern finding

---

## 💡 Examples

```bash
# Full audit
./dependency-audit.sh akismet.5.3.cdx.json

# Typosquat only, strict mode
./dependency-audit.sh \
  --skip-confusion --skip-suspicious \
  --max-distance 1 \
  akismet.5.3.cdx.json

# Silent JSON
./dependency-audit.sh -sj akismet.5.3.cdx.json \
  | jq '.dependency_audit.summary'
```

---

## ⚠️ Known Limitations

- The well-known package list used for typosquatting is curated and may not include all popular packages in all ecosystems. Novel packages may produce false positives.
- Dependency confusion detection is heuristic and depends on naming conventions that vary by organisation. Not all internal packages follow detectable patterns.
- Results are heuristics — all findings require human review before action.

---

<sub>Scripts licensed MIT · Documentation [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) · © Package Profiler Contributors</sub>
