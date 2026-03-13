# 🔄 sbom-compare.sh

> Compares two SBOMs or an SBOM against a package manifest — detecting added, removed, and version-changed dependencies, and optionally reporting risk score deltas.

---

## 🎯 Purpose

Version updates change dependency trees. `sbom-compare.sh` makes those changes explicit by diffing the current SBOM against a reference — either a previous version's SBOM or the project's package manifest. This is particularly useful for:

- **Version upgrade reviews:** What new dependencies did the update introduce? Did any existing ones change?
- **SBOM-to-manifest drift:** Are there packages in the SBOM not declared in the manifest (vendored code, hidden dependencies)?
- **Risk delta:** Did the update make the risk score better or worse?

---

## 🔧 Options

| Flag | Description |
|---|---|
| `-s, --silent` | Suppress progress messages |
| `-j, --json` | JSON output to stdout |
| `-sj, -js` | Silent + JSON |
| `-v, --verbose` | Show per-package diff detail |
| `-o, --output-dir DIR` | Directory for output file |
| `--meta-base DIR` | Base directory for meta output (default: `./meta`) |
| `--no-file` | Output JSON to stdout only; do not write file |
| `--compare FILE` | Compare two SBOMs (detect added/removed/changed) |
| `--manifest FILE` | Compare SBOM against a manifest file |
| `--report-manifest-only` | Also flag packages present in the manifest but absent from the SBOM |
| `--version` | Print version and exit |

---

## 🔍 Comparison Modes

### `--compare FILE` (SBOM vs. SBOM)

Detects:
- **Added** packages — in the primary SBOM but not the baseline
- **Removed** packages — in the baseline but not the primary
- **Changed** packages — present in both but with different versions
- **Risk delta** — if both SBOMs carry embedded vulnerability data, reports the net change in weighted risk

### `--manifest FILE` (SBOM vs. manifest)

Detects:
- **Undeclared** packages — in the SBOM but not the manifest (vendored, generated, or hidden dependencies)
- **Missing** packages — in the manifest but not the SBOM (if `--report-manifest-only` is set)
- **Version drift** — declared version differs between manifest and SBOM

Supported manifest formats: `composer.lock`, `package.json`, `yarn.lock`, `requirements.txt`, `go.sum`, `Gemfile.lock`

---

## 📤 Output

**File:** `meta/<clean-name>/<clean-name>.compare.json`  
**Root key:** `sbom_comparison`  
**Exit code:** 0 = no differences, 1 = differences found, 2 = execution error

---

## 💡 Examples

```bash
# Compare two SBOM versions
./sbom-compare.sh \
  --compare ./meta/akismet.5.2/akismet.5.2.cdx.json \
  ./meta/akismet.5.3/akismet.5.3.cdx.json

# Compare SBOM against composer manifest
./sbom-compare.sh \
  --manifest composer.lock \
  akismet.5.3.cdx.json

# Also flag packages only in the manifest
./sbom-compare.sh \
  --manifest composer.lock \
  --report-manifest-only \
  akismet.5.3.cdx.json

# Silent JSON for piping
./sbom-compare.sh -sj \
  --compare ./baseline.cdx.json \
  akismet.5.3.cdx.json | jq '.sbom_comparison.summary'
```

---

## ⚠️ Known Limitations

- Package matching is by name and ecosystem. Packages that change names between versions will appear as add+remove rather than rename.
- Risk delta calculation requires both SBOMs to carry embedded `risk_assessment` blocks (i.e., both must have been processed by `vuln-scan.sh`).
- Manifest format support is limited to the formats listed above. Formats not in this list will cause execution error (exit 2).

---

<sub>Scripts licensed MIT · Documentation [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) · © Package Profiler Contributors</sub>
