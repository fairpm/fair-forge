# 🚀 Getting Started

> **TL;DR:** Point `sbom-toolkit.sh` at a package archive and it handles the rest — SBOM, CVE scan, checksum, license, provenance, and attestation in one command. For extracted directories, use `run-filescans.sh` to scan file contents and permissions.

See [INSTALL.md](../INSTALL.md) before proceeding if you haven't installed dependencies yet.

---

## 1️⃣ Your First Scan

### WordPress plugin (most common use case)

```bash
./sbom-toolkit.sh \
  --ecosystem wordpress \
  --wp-plugin contact-form-7 \
  --wp-version 5.9.3 \
  contact-form-7.5.9.3.zip
```

This runs the full pipeline: checksum verification against the WordPress.org API, SBOM generation, vulnerability scan, license compliance check, supply chain audit, provenance verification against the WP.org API, and a SLSA observer attestation.

Results land in `./meta/contact-form-7.5.9.3/`:

```
contact-form-7.5.9.3.spdx.json          SPDX 2.3 SBOM
contact-form-7.5.9.3.cdx.json           CycloneDX 1.5 SBOM
contact-form-7.5.9.3.meta.json          Aggregated results
contact-form-7.5.9.3.slsa-L0.provenance.json  SLSA attestation
run.log                                  Full execution log
```

### Composer/Packagist package

```bash
./sbom-toolkit.sh \
  --ecosystem packagist \
  --source-repo github.com/guzzlehttp/guzzle \
  guzzle-7.8.0.zip
```

### npm package

```bash
./sbom-toolkit.sh --ecosystem npm lodash-4.17.21.tgz
```

### Local directory (no archive)

```bash
./sbom-toolkit.sh --ecosystem wordpress ./my-plugin-directory/
```

---

## 2️⃣ Reading the Results

The `meta.json` file is the primary output. Open it in any JSON viewer. Key fields:

```jsonc
{
  "risk_summary": {
    "total_risk":   142,          // sum of all weighted risk contributions
    "risk_level":   "LOW",        // CRITICAL | HIGH | MEDIUM | LOW
    "components": {
      "checksum":   0,            // 0 = verified, >0 = mismatch or no data
      "provenance": 100,          // 0 = verified, higher = less certain
      "vuln":       42,           // CVSS-weighted vulnerability risk
      "license":    0,            // 0 = compliant
      "audit":      0             // 0 = no supply chain concerns
    }
  }
}
```

Risk levels:

| Score | Level | Meaning |
|---|---|---|
| ≥ 1000 | CRITICAL | Immediate action required |
| ≥ 500 | HIGH | Remediate soon |
| ≥ 100 | MEDIUM | Plan remediation |
| < 100 | LOW | Monitor for updates |

---

## 3️⃣ Scanning Extracted Files

Once a package is extracted (automatically if you pass `--extract` to `checksum-verify.sh`, or manually), scan its internals:

```bash
./run-filescans.sh ./packages/contact-form-7.5.9.3/
```

Add `--deep` to include content pattern scanning (reverse shells, crypto miners, obfuscation):

```bash
./run-filescans.sh --deep ./packages/contact-form-7.5.9.3/
```

Results go to `./meta/contact-form-7.5.9.3/` alongside the SBOM toolkit output.

---

## 4️⃣ CI/CD Integration

### Basic gate

Fail the pipeline if risk is too high or any HIGH-severity CVE is found:

```bash
./sbom-toolkit.sh \
  --ecosystem wordpress \
  --wp-plugin akismet --wp-version 5.3 \
  --fail-on-risk 500 \
  --fail-on-severity HIGH \
  akismet.5.3.zip

# Exit code: 0 = pass, 1 = gate triggered or issues found, 2 = error
```

### With SLSA attestation (CI-aware)

```bash
./sbom-toolkit.sh \
  --ecosystem wordpress \
  --wp-plugin akismet --wp-version 5.3 \
  --fail-on-risk 500 \
  --fail-on-severity HIGH \
  --require-gpl-compat \
  --builder-id  "https://github.com/actions/runner" \
  --policy-uri  "https://your-org.example/policies/package-review" \
  --slsa-level  2 \
  --source-commit "${{ github.sha }}" \
  akismet.5.3.zip
```

### GitHub Actions example

```yaml
name: Package Audit

on:
  workflow_dispatch:
    inputs:
      plugin:
        description: 'WordPress plugin slug'
        required: true
      version:
        description: 'Plugin version'
        required: true

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install dependencies
        run: |
          sudo apt-get install -y jq curl file unzip
          curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
            | sudo sh -s -- -b /usr/local/bin
          curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
            | sudo sh -s -- -b /usr/local/bin

      - name: Download plugin
        run: |
          curl -L "https://downloads.wordpress.org/plugin/${{ inputs.plugin }}.${{ inputs.version }}.zip" \
            -o plugin.zip

      - name: Run Package Profiler
        run: |
          chmod +x ./package-profiler/*.sh
          ./package-profiler/sbom-toolkit.sh \
            --ecosystem wordpress \
            --wp-plugin "${{ inputs.plugin }}" \
            --wp-version "${{ inputs.version }}" \
            --fail-on-risk 500 \
            --fail-on-severity HIGH \
            --require-gpl-compat \
            --builder-id "https://github.com/actions/runner" \
            --policy-uri  "https://your-org.example/package-policy" \
            --slsa-level  1 \
            plugin.zip

      - name: Upload results
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: package-profiler-results
          path: meta/
```

---

## 5️⃣ Running Individual Scripts

Every script can be run standalone. Common patterns:

```bash
# Just verify a checksum (no SBOM needed)
./checksum-verify.sh --source-type wordpress akismet.5.3.zip

# Just scan an existing SBOM for CVEs
./vuln-scan.sh akismet.5.3.cdx.json

# Just check licenses in an SBOM
./license-check.sh --require-gpl-compat akismet.5.3.spdx.json

# Just scan file permissions in a directory
./permission-check.sh ./packages/akismet.5.3/

# Just get file type statistics
./file-stats.sh ./packages/akismet.5.3/

# Silent JSON output — pipe-friendly
./checksum-verify.sh -sj akismet.5.3.zip | jq '.crypto_verification.risk_contribution'
```

---

## 6️⃣ Internal / Pre-Release Packages

For packages not on public registries, tell the tools to adjust their expectations:

```bash
# Internal package — no public registry verification expected
./sbom-toolkit.sh \
  --package-type internal \
  --source-repo "git.your-org.example/team/package" \
  --skip-provenance \
  internal-library-2.0.tar.gz

# Pre-release — not yet published
./sbom-toolkit.sh \
  --package-type prerelease \
  --source-repo "github.com/your-org/package" \
  --source-commit "abc123def456" \
  package-2.0.0-beta.1.zip
```

---

## 7️⃣ What to Do With the Results

| Finding | Recommended action |
|---|---|
| `risk_level: CRITICAL` or HIGH CVEs | Do not install. Seek an alternative or patched version. |
| `risk_level: HIGH` | Assess each CVE individually. Check for mitigating controls. |
| Checksum mismatch | **Do not install.** The archive differs from what the upstream published. Possible tampering or corrupted download. |
| Provenance unverified | Acceptable for internal/prerelease packages. For public packages, investigate the source. |
| GPL-incompatible license | Review before including in GPL-licensed projects. |
| Typosquatting or dependency confusion | Verify the package identity against the intended package. Check for substitution attacks. |
| Malicious patterns (deep-filescan) | **Do not install.** Report to the package registry. |
| World-writable files | Review before deployment; web-accessible world-writable files are a significant risk. |

---

<sub>© Package Profiler Contributors · Documentation licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)</sub>
