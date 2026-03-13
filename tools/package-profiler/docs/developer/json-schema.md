# 📐 JSON Output Schema

> Complete field-level reference for all JSON outputs produced by Package Profiler scripts.

**TL;DR:** Every script writes a single root-keyed JSON file. `sbom-toolkit.sh` merges them into `meta.json`. All root keys, required fields, and enums are documented here.

---

## 📋 Conventions

- **Root key:** Every script's output is wrapped in a single top-level object key (e.g., `"crypto_verification": { ... }`). This allows safe merging without field collisions.
- **Timestamps:** ISO-8601 UTC (`"2025-11-14T09:12:00Z"`)
- **`toolkit_version`:** Semantic version string (`"1.0.0"`)
- **`risk_contribution`:** Dimensionless integer ≥ 0. Higher = more risk. Not a CVSS score; not comparable across scripts.
- **`status`:** Script-specific string enum. Always present. Values documented per section below.
- **Absent fields:** Optional fields are omitted (not set to `null`) when not applicable.

---

## 🔐 `crypto_verification`

Produced by `checksum-verify.sh`.

```jsonc
{
  "crypto_verification": {
    // ── Identity ──────────────────────────────────────────────
    "target":           "akismet.5.3.zip",          // string — input file or path
    "timestamp":        "2025-11-14T09:12:00Z",     // string — ISO-8601
    "toolkit_version":  "1.0.0",                    // string

    "package_identity": {
      "name":      "akismet",                       // string | null
      "version":   "5.3",                           // string | null
      "ecosystem": "wordpress",                     // enum — see below
      "vendor":    "Automattic"                     // string | null
    },

    // ── Checksums ─────────────────────────────────────────────
    "calculated_checksums": {
      "sha256": "a1b2c3...",     // string (hex) | null
      "sha384": "aabbcc...",     // string (hex) | "unavailable"
      "sha512": "unavailable"   // string (hex) | "unavailable"
    },

    // ── Verification result ───────────────────────────────────
    "verification": {
      "status":          "verified",   // enum: verified | mismatch | not_found | skipped | api_error
      "verified":        true,         // boolean
      "checksum_source": "wordpress_api",  // string — which API provided the reference
      "reference_sha256": "a1b2c3...",    // string | null
      "reference_sha512": null,           // string | null
      "api_download_url": "https://...",  // string | null
      "checks": [
        { "algorithm": "SHA256", "status": "matched" }  // status: matched | mismatched | skipped
      ]
    },

    // ── Extraction ────────────────────────────────────────────
    "extraction": {
      "performed":      true,             // boolean
      "directory_name": "akismet",        // string | null — basename only, no absolute path
      "path":           "./packages/..."  // string | null
    },

    "risk_contribution": 0,   // 0=verified, 50=no_reference, 500=mismatch
    "issues": []              // array of issue objects (see common issue envelope)
  }
}
```

**`ecosystem` enum:** `wordpress` | `packagist` | `npm` | `pypi` | `github` | `file`

---

## 🔏 `provenance_verification`

Produced by `provenance-verify.sh`.

```jsonc
{
  "provenance_verification": {
    "status":          "verified",    // enum: verified | partial | unverified | skipped | error
    "package_type":    "wordpress",   // enum: public | internal | prerelease | custom | wordpress
    "slsa_level":      2,             // integer 0-3 | null
    "timestamp":       "...",
    "toolkit_version": "1.0.0",
    "mode":            "wordpress",   // enum: wordpress | github | slsa | auto | none

    "public_verification_skipped": false,   // boolean — true for internal/prerelease

    "artifact": {
      "name": "akismet.5.3.zip"   // string
    },

    "verification_summary": {
      "provenance_found":  true,    // boolean
      "provenance_valid":  true,
      "source_verified":   true,
      "builder_trusted":   true,
      "wp_files_verified": false
    },

    "risk_contribution": 100,   // integer — see design doc for calculation
    "risk_context": {
      "base_risk":           300,   // integer — starting value for package_type
      "adjustments_applied": 200,   // integer — total reduction from verified factors
      "note":                "Full verification expected"
    },

    // ── Per-check results ─────────────────────────────────────
    "checks": [
      {
        "check":   "slsa_format",       // string — check identifier
        "status":  "passed",            // enum: passed | failed | skipped | warning
        "type":    "https://slsa.dev/provenance/v1"  // optional detail
      }
      // Additional check objects per mode
    ],

    "issues": []
  }
}
```

---

## 🛡️ `vulnerability_scan` (vuln-scan.sh)

The output is a **CycloneDX 1.5** document with a non-spec `risk_assessment` extension block. Only the extension block is documented here; the CycloneDX schema covers the rest.

```jsonc
{
  // Standard CycloneDX 1.5 fields (bomFormat, specVersion, metadata, components, vulnerabilities)
  // ...

  // ── Package Profiler extension ────────────────────────────
  "risk_assessment": {
    "weighted_risk":   202,          // number — CVSS-weighted sum
    "cvss_critical":   0,            // number — sum of CVSS scores for Critical
    "cvss_high":       8.1,          // number
    "cvss_medium":     0,
    "cvss_low":        0,
    "cvss_negligible": 0,
    "vuln_counts": {
      "critical":    0,              // integer counts per severity
      "high":        1,
      "medium":      0,
      "low":         0,
      "negligible":  0,
      "unknown":     0,
      "total":       1
    },
    "scoring_notes": {
      "method":         "cvss_weighted",        // string
      "cvss_version":   "3.1_preferred",        // string
      "unscored_vulns": 0,                       // integer — CVEs with no CVSS score
      "weights":        "Critical×100 High×25 Medium×5 Low×1 Negligible×0.1"
    }
  }
}
```

---

## 📜 `license_compliance`

Produced by `license-check.sh`.

```jsonc
{
  "license_compliance": {
    "status":          "clean",        // enum: clean | issues_found | error
    "gpl_compatible":  true,           // boolean
    "timestamp":       "...",
    "toolkit_version": "1.0.0",
    "sbom_source": {
      "file":      "akismet.5.3.spdx.json",
      "format":    "spdx",             // enum: spdx | cyclonedx
      "ecosystem": "wordpress"
    },
    "root_package": {
      "license":          "GPL-2.0-or-later",
      "license_category": "strong_copyleft",   // enum — see categories below
      "license_source":   "spdx_declared"
    },
    "summary": {
      "total":            12,
      "permissive":        8,
      "weak_copyleft":     2,
      "strong_copyleft":   1,
      "gpl_incompatible":  0,
      "proprietary":       0,
      "unknown":           0
    },
    "policy": {
      "require_gpl_compat": true,    // boolean
      "fail_on_unknown":    true     // boolean
    },
    "risk_contribution": 0,
    "issues": [],
    "packages": [
      {
        "name":       "some/package",
        "version":    "2.1.0",
        "license":    "MIT",
        "category":   "permissive",   // enum — license category
        "compatible": true            // boolean — GPL-compatible
      }
    ]
  }
}
```

**License category enum:** `permissive` | `weak_copyleft` | `strong_copyleft` | `gpl_incompatible` | `proprietary` | `unknown`

---

## 🕵️ `dependency_audit`

Produced by `dependency-audit.sh`.

```jsonc
{
  "dependency_audit": {
    "timestamp":       "...",
    "toolkit_version": "1.0.0",
    "sbom_source":     "akismet.5.3.cdx.json",
    "scan_status":     "clean",     // enum: clean | issues_found | error
    "findings_count":  0,
    "summary": {
      "typosquatting":        0,
      "dependency_confusion": 0,
      "suspicious_packages":  0,
      "total_issues":         0
    },
    "checks_performed": {
      "typosquatting":          true,
      "dependency_confusion":   true,
      "suspicious_patterns":    true,
      "typosquat_max_distance": 2,
      "typosquat_method":       "levenshtein_wagner_fischer"
    },
    "risk_contribution": 0,
    "findings": [
      {
        "type":          "typosquatting",     // enum: typosquatting | dependency_confusion | suspicious
        "severity":      "HIGH",              // enum: CRITICAL | HIGH | MEDIUM | LOW
        "package":       "1odash",
        "closest_match": "lodash",
        "distance":      1,
        "ecosystem":     "npm",
        "recommendation": "Verify this is not a typosquatting attempt"
      }
    ]
  }
}
```

---

## 🔄 `sbom_comparison`

Produced by `sbom-compare.sh`.

```jsonc
{
  "sbom_comparison": {
    "timestamp":       "...",
    "toolkit_version": "1.0.0",
    "mode":            "sbom",         // enum: sbom | manifest
    "files": {
      "primary":       "akismet.5.3.cdx.json",
      "baseline":      "akismet.5.2.cdx.json",
      "baseline_type": "sbom"          // enum: sbom | manifest
    },
    "package_counts": { "primary": 14, "baseline": 13 },
    "summary": {
      "added":               2,
      "removed":             1,
      "changed":             1,
      "same":               10,
      "manifest_only":       0,
      "total_differences":   4,
      "report_manifest_only": false
    },
    "risk_delta": {
      "direction":    "increased",     // enum: increased | decreased | unchanged | unknown
      "added_risk":   50,
      "removed_risk": 0
    },
    "findings": [
      {
        "type":    "added",             // enum: added | removed | changed | manifest_only
        "package": "new-dep",
        "version": "1.0.0"
      },
      {
        "type":    "changed",
        "package": "shared-dep",
        "from":    "2.0.0",
        "to":      "2.1.0"
      }
    ]
  }
}
```

---

## 📊 `file_statistics`

Produced by `file-stats.sh`. No `risk_contribution` — informational only.

```jsonc
{
  "file_statistics": {
    "target_directory": "akismet",
    "scan_type":        "file_statistics",
    "toolkit_version":  "1.0.0",
    "timestamp":        "...",
    "elapsed_seconds":  2,
    "totals": {
      "files":              87,
      "lines":              14203,
      "bytes":              412800,
      "empty_files":        2,
      "hidden_files":       0,
      "hidden_directories": 0,
      "minified_files":     4,
      "minified_bytes":     98304
    },
    "categories": [
      {
        "category": "code",     // string — see file-stats.md for full list
        "files":    42,
        "lines":    9800,
        "bytes":    280000
      }
    ],
    "best_practices": {
      "checked": 11,
      "found":   6,
      "missing": 5,
      "items": [
        {
          "key":     "readme",                  // string — file type key
          "label":   "README.md / README.txt",  // string — human-readable
          "present": true,                       // boolean
          "path":    "README.md"                 // string | null — found path
        }
      ]
    }
  }
}
```

---

## 🔎 `content_scan`

Produced by `deep-filescan.sh`.

```jsonc
{
  "content_scan": {
    "target_directory":      "akismet",
    "scan_type":             "content_scan",
    "toolkit_version":       "1.0.0",
    "timestamp":             "...",
    "elapsed_seconds":       4,
    "files_checked":         87,
    "files_pattern_scanned": 60,
    "files_size_skipped":    0,
    "summary": {
      "total_issues": 0,
      "critical": 0, "high": 0, "medium": 0, "low": 0,
      "patterns": {
        "reverse_shells": 0, "crypto_miners": 0,
        "obfuscation":    0, "data_exfiltration": 0, "webshell": 0
      },
      "integrity": {
        "mime_mismatches": { "total": 0, "critical": 0, "high": 0, "low": 0 },
        "deceptive_extensions": 0,
        "embedded_code":   { "total": 0, "critical": 0, "high": 0 }
      }
    },
    "risk_contribution": 0,
    "findings": [
      {
        "severity": "CRITICAL",                 // enum: CRITICAL | HIGH | MEDIUM | LOW
        "type":     "reverse_shell",            // enum — pattern category
        "file":     "includes/helper.php",
        "line":     42,
        "match":    "bash -i >& /dev/tcp/..."  // truncated match context
      }
    ]
  }
}
```

**`type` enum (patterns):** `reverse_shell` | `crypto_miner` | `obfuscation` | `data_exfil` | `webshell`  
**`type` enum (integrity):** `mime_mismatch` | `deceptive_extension` | `embedded_code`

---

## 🔒 `permission_audit`

Produced by `permission-check.sh`.

```jsonc
{
  "permission_audit": {
    "target_directory": "akismet",
    "scan_type":        "permission_audit",
    "toolkit_version":  "1.0.0",
    "timestamp":        "...",
    "elapsed_seconds":  1,
    "fix_mode":         false,
    "summary": {
      "items_checked":            87,
      "total_issues":              1,
      "total_directories":        12,
      "passed_directories":       12,
      "total_files":              75,
      "passed_files":             74,
      "writable_files":            0,
      "writable_directories":      0,
      "missing_sticky_bit":        0,
      "symlinks": {
        "total": 0, "external": 0, "dangling": 0, "internal": 0
      },
      "privilege_escalation":      0,
      "permission_inversions":     0,
      "unnecessary_exec":          1,
      "sensitive_exposure":        0,
      "orphaned_ownership":        0,
      "deploy_artifacts":          0,
      "secure_permissions":       74,
      "fixed":                    false,
      "failed":                    0
    },
    "risk_contribution": 3,
    "risk_detail": {
      "critical_floor": 0,   // integer — from world-writable, SUID, etc.
      "other_risk":     3    // integer — from exec bits, symlinks, etc.
    },
    "findings": [
      {
        "severity":    "LOW",                 // enum: CRITICAL | HIGH | MEDIUM | LOW
        "type":        "unnecessary_exec",    // string — issue type
        "status":      "found",               // enum: found | fixed | failed | skipped
        "permissions": "-rwxr-xr-x",
        "file_path":   "assets/banner.png"   // string — relative path
      }
    ]
  }
}
```

**Finding `type` enum:** `world-writable_file` | `world-writable_dir` | `missing_sticky_bit` | `privilege_escalation` | `permission_inversion` | `external_symlink` | `sensitive_exposure` | `internal_symlink` | `dangling_symlink` | `unnecessary_exec` | `orphaned_ownership` | `deploy_artifact`

---

## 📋 `slsa_attestation`

The `slsa_attestation` key in `meta.json` comes from the **assessment file** (`<n>.slsa-assessment.json`), not the attestation itself. The full in-toto statement is in `<n>.slsa-L<N>.provenance.json`.

```jsonc
{
  "slsa_attestation": {
    "highest_satisfied": 0,          // integer 0-3
    "target_level":      1,          // integer 0-3 — requested level
    "levels": {
      "l0": {
        "satisfied": true,
        "requirements": {
          "provenance_exists":   { "met": true,  "note": "Observer-generated SLSA document produced" },
          "artifact_digest":     { "met": true,  "note": "SHA-256 digest calculated" },
          "observer_disclaimer": { "met": true,  "note": "Disclaimer embedded in provenance document" }
        }
      },
      "l1": {
        "satisfied": false,
        "requirements": {
          "builder_id_declared": {
            "met":          false,
            "value":        null,
            "missing_flag": "--builder-id",
            "description":  "Non-placeholder builder identity URI"
          },
          "policy_uri_declared": {
            "met":          false,
            "value":        null,
            "missing_flag": "--policy-uri"
          }
        }
      }
    },
    "remediation": [
      "Pass --builder-id with the builder URI to satisfy L1"
    ]
  }
}
```

---

## 🗂️ meta.json — Aggregated Output

Produced by `sbom-toolkit.sh`. Contains all of the above under their respective root keys, plus a `run` header and `risk_summary`.

```jsonc
{
  "run": {
    "id":              "uuid-v4",
    "toolkit_version": "1.0.0",
    "timestamp":       "...",
    "target":          "akismet.5.3.zip",
    "clean_name":      "akismet.5.3",
    "options": { ... }          // resolved option values for this run
  },
  "risk_summary": {
    "total_risk":  142,
    "risk_level":  "LOW",       // enum: CRITICAL | HIGH | MEDIUM | LOW
    "components": {
      "checksum":   0,
      "provenance": 100,
      "vuln":       42,
      "license":    0,
      "audit":      0
    }
  },
  "ci_gate": {
    "triggered": false,
    "reasons":   []             // array of strings — which gates fired
  },
  "crypto_verification":     { ... },
  "provenance_verification": { ... },
  "vulnerability_scan":      { ... },
  "license_compliance":      { ... },
  "dependency_audit":        { ... },
  "sbom_discovery":          { ... },
  "sbom_comparison":         { ... },   // present only if sbom-compare ran
  "slsa_attestation":        { ... }
}
```

**`risk_level` thresholds:**

| `total_risk` | `risk_level` |
|---|---|
| ≥ 1000 | `CRITICAL` |
| ≥ 500 | `HIGH` |
| ≥ 100 | `MEDIUM` |
| < 100 | `LOW` |

---

> **Note:** A formal JSON Schema (draft-07) document covering all root keys, required vs optional fields, and enum values is planned for a future release once the schema stabilises through a full release cycle.

---

<sub>Scripts licensed MIT · Documentation [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) · © Package Profiler Contributors</sub>
