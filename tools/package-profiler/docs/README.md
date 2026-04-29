# 📦 Package Profiler

> **Automated security analysis and provenance tracking for third-party packages.**

Package Profiler is a suite of Bash scripts that evaluates the safety, integrity, and compliance of software packages before they enter your codebase. It generates Software Bills of Materials (SBOMs), scans for known vulnerabilities, verifies checksums and provenance, audits licenses and supply chain patterns, and produces a signed SLSA attestation — all from a single command.

---

## 🗺️ Quick Map

| I want to… | Go to |
|---|---|
| Run my first scan | [Getting Started →](developer/getting-started.md) |
| Install dependencies | [Installation →](INSTALL.md) |
| Understand what the suite does | [Architecture →](developer/architecture.md) |
| Scan a package automatically | [sbom-toolkit.sh →](sbom-toolkit/sbom-toolkit.md) |
| Scan files and permissions | [run-filescans.sh →](filescan/run-filescans.md) |
| Understand the JSON output | [JSON Schema →](developer/json-schema.md) |
| Extend or maintain the suite | [Maintenance Guide →](developer/maintenance.md) |

---

## 🧰 The Two Script Sets

Package Profiler is organised into two complementary toolsets that work together to evaluate a package from the outside in.

### 🔬 SBOM Toolkit — Identity, Integrity & Risk

The SBOM Toolkit answers: *Is this package what it claims to be, and is it safe to use?*

It generates a Bill of Materials from the package archive, checks every declared component for known CVEs, verifies the download matches what the upstream source published, audits licenses for compliance, and looks for supply chain attack patterns. Results are aggregated into a single `meta.json` and optionally wrapped in a SLSA provenance attestation.

**Scripts:** `sbom-toolkit.sh` (controller) · `sbom-gen.sh` · `sbom-discover.sh` · `checksum-verify.sh` · `vuln-scan.sh` · `license-check.sh` · `dependency-audit.sh` · `provenance-verify.sh` · `slsa-attest.sh` · `sbom-compare.sh`

→ [SBOM Toolkit documentation](sbom-toolkit/README.md)

---

### 🗂️ Filescan Suite — Structure, Content & Permissions

The Filescan Suite answers: *What is actually inside this package, and is anything suspicious?*

It catalogues every file by type, scans source code and data files for malicious patterns (reverse shells, crypto miners, obfuscated code, webshells, MIME mismatches), and audits filesystem permissions for privilege escalation vectors. It operates on the extracted package directory rather than the archive.

**Scripts:** `run-filescans.sh` (controller) · `file-stats.sh` · `deep-filescan.sh` · `permission-check.sh`

→ [Filescan Suite documentation](filescan/README.md)

---

## 📋 All Documents

### Getting Started & Reference
| Document | Description |
|---|---|
| [INSTALL.md](INSTALL.md) | System dependencies, tool versions, and install instructions |
| [developer/getting-started.md](developer/getting-started.md) | First scan walkthrough, common patterns, CI/CD integration |
| [developer/architecture.md](developer/architecture.md) | Design rationale, wave pipeline, data flow, extension points |
| [developer/json-schema.md](developer/json-schema.md) | Full JSON output schema for all scripts |
| [developer/maintenance.md](developer/maintenance.md) | Tuning thresholds, adding ecosystems, keeping scripts in sync |

### SBOM Toolkit
| Document | Description |
|---|---|
| [sbom-toolkit/README.md](sbom-toolkit/README.md) | Set overview, pipeline stages, and script index |
| [sbom-toolkit/design.md](sbom-toolkit/design.md) | Design doc: objectives, security model, CI/CD requirements |
| [sbom-toolkit/sbom-toolkit.md](sbom-toolkit/sbom-toolkit.md) | Controller: flags, pipeline, output structure, CI gates |
| [sbom-toolkit/sbom-gen.md](sbom-toolkit/sbom-gen.md) | SBOM generation with Syft |
| [sbom-toolkit/sbom-discover.md](sbom-toolkit/sbom-discover.md) | Embedded SBOM and manifest discovery |
| [sbom-toolkit/checksum-verify.md](sbom-toolkit/checksum-verify.md) | Checksum verification with ecosystem API lookup |
| [sbom-toolkit/vuln-scan.md](sbom-toolkit/vuln-scan.md) | Vulnerability scanning and CVSS risk scoring |
| [sbom-toolkit/license-check.md](sbom-toolkit/license-check.md) | SPDX license compliance analysis |
| [sbom-toolkit/dependency-audit.md](sbom-toolkit/dependency-audit.md) | Supply chain attack detection |
| [sbom-toolkit/provenance-verify.md](sbom-toolkit/provenance-verify.md) | SLSA provenance and source verification |
| [sbom-toolkit/slsa-attest.md](sbom-toolkit/slsa-attest.md) | SLSA v1.0 attestation generation |
| [sbom-toolkit/sbom-compare.md](sbom-toolkit/sbom-compare.md) | SBOM-to-SBOM and SBOM-to-manifest diff |

### Filescan Suite
| Document | Description |
|---|---|
| [filescan/README.md](filescan/README.md) | Set overview and script index |
| [filescan/design.md](filescan/design.md) | Design doc: objectives, threat model, performance |
| [filescan/run-filescans.md](filescan/run-filescans.md) | Controller: orchestration, merged output, options |
| [filescan/file-stats.md](filescan/file-stats.md) | File type statistics and best-practice checks |
| [filescan/deep-filescan.md](filescan/deep-filescan.md) | Malicious pattern and MIME integrity scanning |
| [filescan/permission-check.md](filescan/permission-check.md) | Permission audit and auto-remediation |

### Testing
| Document | Description |
|---|---|
| [testing/toolkit-test.md](testing/toolkit-test.md) | SBOM Toolkit test suite: coverage, fixtures, expected results |
| [testing/filescan-test.md](testing/filescan-test.md) | Filescan Suite test suite: coverage, fixtures, expected results |

---

## ⚡ Sixty-Second Start

```bash
# Install dependencies (see INSTALL.md for full details)
brew install syft grype jq curl          # macOS
# apt install jq curl && install syft/grype from GitHub releases  # Linux

# Clone or extract the suite, then run a full scan
./sbom-toolkit.sh --ecosystem wordpress \
  --wp-plugin akismet --wp-version 5.3 \
  --fail-on-risk 500 \
  akismet.5.3.zip

# Results land in ./meta/akismet.5.3/
#   akismet.5.3.meta.json   — aggregated results
#   akismet.5.3.spdx.json   — SPDX SBOM
#   akismet.5.3.cdx.json    — CycloneDX SBOM
#   run.log                 — full execution log
```

---

## 📜 Licences

- **Scripts:** MIT — see `LICENSE` in the repository root
- **Documentation:** [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)

---

<sub>© Package Profiler Contributors · Documentation licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)</sub>
