# 🔏 provenance-verify.sh

> Verifies the provenance of a package by validating it against upstream source records, checking SLSA attestation files, and assessing build origin confidence.

**TL;DR:** Answers "did this package come from where it claims?" — by checking the upstream registry, verifying source commits, or validating a SLSA provenance attestation.

---

## 🎯 Purpose

A package can pass checksum verification (the file matches what the registry serves) while still having weak provenance (the registry is serving something that wasn't built from the claimed source). `provenance-verify.sh` adds a second layer of verification by checking the build *origin*:

- For WordPress plugins: does this version exist on WordPress.org, and do the per-file checksums match?
- For GitHub-hosted packages: does the source repository and commit exist?
- For packages with SLSA attestations: is the attestation format valid, the builder trusted, and the artifact digest correct?

---

## 🔧 Options

| Flag | Description |
|---|---|
| `-s, --silent` | Suppress progress messages |
| `-j, --json` | JSON output to stdout |
| `-sj, -js` | Silent + JSON |
| `-v, --verbose` | Show additional detail |
| `-o, --output-dir DIR` | Directory for output file |
| `--meta-base DIR` | Base directory for meta output (default: `./meta`) |
| `--no-file` | Output JSON to stdout only; do not write file |
| `--mode MODE` | Verification mode: `auto` \| `wordpress` \| `slsa` \| `github` (default: `auto`) |
| `--wp-plugin SLUG` | WordPress plugin slug |
| `--wp-version VERSION` | WordPress plugin version |
| `--source-repo URL` | Source repository URL |
| `--source-commit SHA` | Expected source commit hash |
| `--provenance FILE` | SLSA provenance attestation file to validate |
| `--checksum-json FILE` | Path to checksum JSON from checksum-verify (enables cross-check) |
| `--extracted-dir DIR` | Path to extracted plugin directory |
| `--package-type TYPE` | `public` (default) \| `internal` \| `prerelease` \| `custom` |
| `--check-svn` | Also check WordPress SVN tag existence |
| `--version` | Print version and exit |

---

## 🔍 Verification Modes

### `wordpress` (triggered by `--wp-plugin`)

1. Queries the WordPress.org API to confirm the plugin exists and the claimed version is published
2. Verifies the download URL for the version matches the expected pattern
3. If `--extracted-dir` or `--checksum-json` is provided, verifies per-file checksums against the WordPress.org `/plugin-checksums/` endpoint
4. Optionally checks the SVN tag exists for the version (`--check-svn`)

### `github` / `auto` (triggered by `--source-repo`)

1. Verifies the repository exists on GitHub via the API
2. If `--source-commit` is provided, confirms the commit exists in that repository
3. Falls back to `none` mode if no context is available (skips without penalty when run via sbom-toolkit)

### `slsa` (triggered by `--provenance FILE`)

1. Parses the provenance file and validates the `predicateType` URI
2. Checks the builder identity against a trusted builder list (GitHub Actions, GitLab CI, CircleCI)
3. Verifies the source URI and commit hash match declared values
4. Cross-checks the artifact SHA-256 digest against the provenance `subject[0].digest`
5. Notes whether the provenance is signed and whether hermetic build is declared

---

## 📊 Risk Contribution

Risk starts at a base value determined by `--package-type` and is reduced for each verification factor satisfied:

| Package type | Base risk | Rationale |
|---|---|---|
| `public` | 300 | Full verification is expected and available |
| `custom` | 150 | Modified public package; partial verification expected |
| `internal` | 100 | Not on public registries; verification not applicable |
| `prerelease` | 100 | Not yet published; public verification not yet available |

Each successfully verified check (source confirmed, commit verified, provenance valid, builder trusted, files verified) reduces the risk contribution by 50–100 points.

---

## 📤 Output

**File:** `meta/<clean-name>/<clean-name>.provenance.json`  
**Root key:** `provenance_verification`

Key fields: `status`, `package_type`, `mode`, `verification_summary`, `risk_contribution`, `risk_context`, `checks[]`, `issues[]`

---

## 💡 Examples

```bash
# WordPress plugin
./provenance-verify.sh \
  --mode wordpress \
  --wp-plugin akismet --wp-version 5.3 \
  --extracted-dir ./packages/akismet.5.3 \
  akismet.5.3.zip

# Validate a SLSA attestation file
./provenance-verify.sh \
  --mode slsa \
  --provenance akismet.5.3.slsa-L2.provenance.json \
  akismet.5.3.zip

# GitHub-hosted package
./provenance-verify.sh \
  --source-repo github.com/guzzlehttp/guzzle \
  --source-commit abc123 \
  guzzle-7.8.0.zip

# Internal package (no penalty for missing public verification)
./provenance-verify.sh \
  --package-type internal \
  internal-lib-2.0.tar.gz
```

---

## ⚠️ Known Limitations

- Without `--wp-plugin`, `--source-repo`, or `--provenance`, the script detects no verification context and is skipped by `sbom-toolkit.sh` to avoid a misleading base risk penalty.
- GitHub API requests are rate-limited (60/hr unauthenticated). Set `GITHUB_TOKEN` environment variable to raise the limit to 5,000/hr.
- SLSA attestation signature verification is not performed — only structural and content validation. Cryptographic signature verification requires `cosign` or equivalent tooling beyond this script's scope.
- The trusted builder list is hardcoded. Adding new trusted builders requires editing the script. See [Maintenance Guide](../developer/maintenance.md).

---

<sub>Scripts licensed MIT · Documentation [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) · © Package Profiler Contributors</sub>
