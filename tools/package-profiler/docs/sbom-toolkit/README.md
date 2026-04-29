# 🔬 SBOM Toolkit

> **TL;DR:** The SBOM Toolkit takes a package archive and tells you whether it is what it claims to be, what vulnerabilities it carries, and whether its license and supply chain are acceptable — in a single automated pipeline.

---

## 🎯 What This Set Does

The SBOM Toolkit evaluates a software package from the outside in, working from the archive file alone. It answers five questions:

1. **Is the archive authentic?** (`checksum-verify`) — Does the download match what the upstream source published?
2. **What is in it?** (`sbom-gen`, `sbom-discover`) — A complete Software Bill of Materials of every declared dependency.
3. **Is it safe?** (`vuln-scan`) — Are any known CVEs present in its dependencies?
4. **Is it compliant?** (`license-check`, `dependency-audit`) — Are the licenses acceptable, and are there any supply chain attack patterns?
5. **Can we trust the build?** (`provenance-verify`, `slsa-attest`) — Does the package have verifiable provenance, and can an attestation be generated?

All findings are aggregated into a single `meta.json` with a composite risk score and optional CI gate.

---

## 🌊 Pipeline Overview

```
Wave 1 (parallel)
  ├─ checksum-verify  — hash the archive; verify against ecosystem API
  ├─ sbom-discover    — find any embedded SBOMs or manifests already inside the archive
  └─ sbom-gen         — generate SPDX 2.3 + CycloneDX 1.5 SBOMs with Syft

Wave 2 (parallel, uses Wave 1 output)
  ├─ vuln-scan        — CVE scan of the CycloneDX SBOM via Grype
  ├─ license-check    — SPDX license compliance analysis
  ├─ dependency-audit — typosquat + dependency confusion detection
  ├─ provenance-verify — upstream source / SLSA provenance validation
  └─ sbom-compare     — diff against a baseline SBOM or manifest (optional)

Wave 3 (sequential)
  └─ slsa-attest      — SLSA v1.0 in-toto attestation → meta.json → CI gates
```

---

## 📄 Script Index

| Script | Purpose | Document |
|---|---|---|
| **`sbom-toolkit.sh`** | Controller — orchestrates all scripts; produces `meta.json` | [sbom-toolkit.md](sbom-toolkit.md) |
| `sbom-gen.sh` | Generates SPDX and CycloneDX SBOMs using Syft | [sbom-gen.md](sbom-gen.md) |
| `sbom-discover.sh` | Locates embedded SBOMs and package manifests | [sbom-discover.md](sbom-discover.md) |
| `checksum-verify.sh` | Verifies archive checksums against ecosystem APIs | [checksum-verify.md](checksum-verify.md) |
| `vuln-scan.sh` | CVE scan with CVSS-weighted risk scoring | [vuln-scan.md](vuln-scan.md) |
| `license-check.sh` | SPDX license compliance and GPL-compatibility check | [license-check.md](license-check.md) |
| `dependency-audit.sh` | Supply chain attack detection (typosquat, confusion) | [dependency-audit.md](dependency-audit.md) |
| `provenance-verify.sh` | Upstream provenance and SLSA attestation validation | [provenance-verify.md](provenance-verify.md) |
| `slsa-attest.sh` | Generates SLSA v1.0 in-toto provenance attestation | [slsa-attest.md](slsa-attest.md) |
| `sbom-compare.sh` | Diffs two SBOMs or an SBOM against a manifest | [sbom-compare.md](sbom-compare.md) |

---

## 🛠️ Design & Architecture

- [Design document](design.md) — objectives, security model, CI/CD requirements
- [Architecture overview](../developer/architecture.md) — wave pipeline, data flow, extension points
- [Maintenance guide](../developer/maintenance.md) — tuning thresholds, adding ecosystems

---

## ⚡ Quick Example

```bash
# Full pipeline for a WordPress plugin
./sbom-toolkit.sh \
  --ecosystem wordpress \
  --wp-plugin akismet --wp-version 5.3 \
  --fail-on-risk 500 --fail-on-severity HIGH \
  --require-gpl-compat \
  akismet.5.3.zip

# Exit 0 = all gates passed
# Exit 1 = gate triggered or issues found
# Exit 2 = execution error
```

---

<sub>Scripts licensed MIT · Documentation [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) · © Package Profiler Contributors</sub>
