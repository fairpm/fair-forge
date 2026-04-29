# 🧠 SBOM Toolkit — Design Document

> Design rationale, security model, and CI/CD integration requirements for the SBOM Toolkit script set.

---

## 🎯 Objectives

The SBOM Toolkit is built around a single core requirement: **provide a reproducible, auditable verdict on whether a package is safe to introduce into a codebase**, using only the package archive as input and standard open-source tooling.

Secondary objectives:

- **Zero lock-in** — all output is standard JSON (SPDX, CycloneDX, or schema-documented custom format). No proprietary formats, no cloud dependencies.
- **CI-native** — exit codes are consistent and meaningful; every script supports silent+JSON mode for pipeline integration; the controller provides CI gate flags.
- **Composable** — every script is independently useful. The pipeline is an orchestration convenience, not a requirement.
- **Auditable** — the `meta.json` captures the full scan state at a point in time, including tool version, timestamp, and all findings. It can be stored as an artefact alongside the package it describes.

---

## 🔐 Security Model

### What the toolkit verifies

| Check | Threat detected | Confidence |
|---|---|---|
| Checksum vs. upstream API | Tampered download, corrupted archive | High — API is the authoritative source |
| CVE scan (Grype) | Known vulnerabilities in declared dependencies | High for NVD/GHSA-catalogued CVEs; zero for zero-days |
| License compliance | License violations, GPL-incompatible dependencies | High for SPDX-declared licenses; low for unlicensed code |
| Typosquatting detection | Malicious packages with near-identical names | Medium — Levenshtein distance heuristic; false positives possible |
| Dependency confusion | Internal package names resolvable on public registries | Medium — name-based heuristic |
| Provenance verification | Unverifiable build origin | Medium — depends on upstream attestation quality |
| SLSA attestation (observer) | Documents what the toolkit could and could not verify | Informational; not a trust guarantee |

### Trust boundaries

The toolkit treats the **upstream ecosystem API** as the authoritative reference for checksums. This means:

- A matching checksum confirms the downloaded file is identical to what the registry currently serves.
- It does **not** confirm the registry itself has not been compromised.
- It does **not** confirm the upstream source code is free of malicious logic.

The SLSA attestation explicitly records this limitation via an observer disclaimer. See [slsa-attest.md](slsa-attest.md).

### What the toolkit cannot detect

- Zero-day CVEs not yet catalogued in NVD or GHSA
- Semantic malware (malicious logic with no syntactic signature)
- Compromised upstream registries serving tampered packages with matching checksums
- Runtime behaviour
- Vulnerabilities in code the package ships but which Syft/Grype doesn't classify as components

---

## ⚙️ How Each Check Meets Its Objective

### checksum-verify.sh
**Objective:** Confirm the archive is byte-for-byte identical to the upstream-published version.

**How:** Calculates SHA-256, SHA-384, and SHA-512 of the local file. Queries the ecosystem API for the reference checksum (WordPress.org, Packagist, npm, PyPI, GitHub releases). If the API provides per-file checksums (WordPress.org `/plugin-checksums/` endpoint), also verifies individual files inside the extracted archive.

**Why SHA-256 as the primary:** SHA-256 is the universal baseline — all supported ecosystems publish it. SHA-384 and SHA-512 add defence-in-depth but are treated as advisory. SHA-1 is noted if present but not used for verification given its collision weakness.

**Performance:** Single network request per algorithm with a 15-second timeout. Runs in Wave 1 in parallel with sbom-gen and sbom-discover.

### sbom-gen.sh
**Objective:** Produce a machine-readable inventory of all components in the package.

**How:** Delegates to Syft, which performs static analysis of the archive or directory to enumerate components from package manifests (composer.json, package.json, requirements.txt, etc.) and embedded metadata. Outputs both SPDX 2.3 (for license-check) and CycloneDX 1.5 (for vuln-scan, dependency-audit).

**Why two formats:** SPDX has richer license expression support; CycloneDX is better supported by Grype's vulnerability matching. Downstream scripts each use the format most appropriate to their task.

### sbom-discover.sh
**Objective:** Identify packages that already ship their own SBOM or manifest files.

**How:** Searches the archive or directory for SPDX JSON, CycloneDX JSON/XML, and standard manifest formats (composer.lock, yarn.lock, requirements.txt, etc.) up to a configurable depth. Validates found SBOMs structurally (required fields, format version).

**Why this matters:** If a package ships its own SBOM, a risk assessment can be performed without running Syft — important for packages where Syft's manifest parsing may miss components (e.g., vendored code without a manifest).

### vuln-scan.sh
**Objective:** Identify known CVEs in the package's dependency tree.

**How:** Runs Grype against the CycloneDX SBOM. Grype queries its locally cached CVE database (NVD, GHSA, OSV, and others). Results are enriched with CVSS-weighted risk scoring via `vuln-scan-risk.jq`.

**Risk scoring rationale:** Raw CVE counts are a poor CI gate signal — one critical vulnerability matters more than ten low ones. The CVSS-weighted formula (Critical×100, High×25, Medium×5, Low×1, Negligible×0.1) reflects this, and its thresholds (≥1000 = CRITICAL, ≥500 = HIGH, etc.) are calibrated to avoid alert fatigue on typical package scans while reliably flagging genuinely dangerous dependency trees. *These thresholds are tunable — see [Maintenance Guide](../developer/maintenance.md).*

### license-check.sh
**Objective:** Identify license compliance violations.

**How:** Parses SPDX license expressions from the SPDX SBOM. Classifies each component into permissive, weak-copyleft, strong-copyleft, GPL-incompatible, proprietary, or unknown. Applies configurable policy (require GPL-compat, fail-on-unknown).

**Why GPL-compatibility matters for WordPress plugins:** The WordPress core is GPL-2.0-or-later. Plugins that include GPL-incompatible libraries (e.g., SSPL, Commons-Clause) may violate the WordPress.org distribution policy and create legal exposure.

### dependency-audit.sh
**Objective:** Detect supply chain attack patterns in the dependency graph.

**How:** Three independent checks:
1. **Typosquatting** — Levenshtein distance comparison of each dependency name against a list of well-known packages in the same ecosystem. Matches within distance 2 are flagged.
2. **Dependency confusion** — Identifies internal package names (private registry markers, internal naming conventions) that are also resolvable on public registries.
3. **Suspicious patterns** — Flags packages with install scripts, unusual version strings, or names matching known-malicious pattern families.

**False positive rate:** Typosquatting detection at distance 2 has a moderate false positive rate for short package names. Distance 1 is more precise but may miss intentional misspellings. The threshold is configurable via `--max-distance`.

### provenance-verify.sh
**Objective:** Confirm the package was built from the claimed source.

**How:** Mode-dependent:
- `wordpress` — validates the plugin exists on WordPress.org API, version matches, and optionally verifies per-file checksums against the `/plugin-checksums/` endpoint.
- `auto` — validates the source repository exists on GitHub, the claimed commit hash exists in that repository, and (if a SLSA provenance file is provided) validates the attestation format, builder trust, and artifact digest.

**Why base risk is high for unverified public packages:** Unverified provenance on a public package is a meaningful gap — it means the package could have been built from an unreviewed fork or from modified sources. The base risk of 300 (public) / 150 (custom) / 100 (internal/prerelease) encodes this expectation.

### slsa-attest.sh
**Objective:** Produce a portable, verifiable record of what the toolkit was able to confirm about this package.

**How:** Generates a SLSA v1.0 in-toto provenance statement. Level assessment (L0–L3) is based on what context was provided and verified during the scan. An observer disclaimer is always embedded because the toolkit did not witness the build process itself.

**CI/CD requirement:** For SLSA L1 and above, `--builder-id` and `--policy-uri` must be provided. These should reference stable URIs that describe the build system and review policy in use.

---

## 🔄 CI/CD Pipeline Integration

### Exit code contract

All scripts follow a consistent three-value exit code contract:

| Code | Meaning |
|---|---|
| 0 | Success — all checks passed or no issues found |
| 1 | Issues found — at least one finding, or a CI gate was triggered |
| 2 | Execution error — missing dependency, bad argument, or unexpected failure |

This allows pipelines to distinguish "this package has issues" (exit 1, investigate) from "the scan itself failed" (exit 2, fix the pipeline).

### Parallel execution

Wave 1 and Wave 2 scripts run as background subshells managed by the controller. Each job writes its output to the shared `meta/` directory and logs to `run.log`. The controller waits for all Wave 2 jobs before proceeding to Wave 3.

### Silent+JSON mode

All scripts support `-sj` (silent + JSON output to stdout). This makes them pipeable without log noise:

```bash
./checksum-verify.sh -sj akismet.5.3.zip \
  | jq '.crypto_verification.risk_contribution'
```

### Performance targets

| Wave | Typical runtime | Bottleneck |
|---|---|---|
| Wave 1 | 5–30 s | Syft scan time (varies with archive size and dependency count) |
| Wave 2 | 15–120 s | Grype CVE database scan |
| Wave 3 | 1–5 s | Meta aggregation and attestation signing |

The Grype database is cached locally after the first run. Subsequent scans on the same host are faster. Consider warming the cache in CI by running `grype db update` in a setup step.

---

## ⚠️ Known Limitations

- Grype only scans components that Syft identifies. Vendored code without a manifest, or code embedded via `require` without a package declaration, may not be catalogued.
- License detection relies on SPDX-declared identifiers in the SBOM. Unlicensed code is reported as `unknown` but its actual license is not inferred.
- Typosquatting detection compares against a static list of well-known packages. Novel packages and ecosystem-specific naming conventions may not be covered.
- Provenance verification requires either a WordPress plugin slug/version, a GitHub source repository URL, or an existing SLSA provenance file. Without at least one, the script skips with a warning rather than penalising the risk score.
- The toolkit cannot verify the integrity of Syft or Grype themselves. In high-assurance environments, verify the tool binaries independently.

---

<sub>Scripts licensed MIT · Documentation [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) · © Package Profiler Contributors</sub>
