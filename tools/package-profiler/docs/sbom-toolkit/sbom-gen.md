# 📦 sbom-gen.sh

> Generates SPDX 2.3 and CycloneDX 1.5 SBOMs from a package archive or directory using Syft, with provenance metadata.

---

## 🎯 Purpose

An SBOM (Software Bill of Materials) is a machine-readable inventory of every component in a package. Without one, downstream tools (vuln-scan, license-check, dependency-audit) have nothing to analyse. `sbom-gen.sh` produces both SPDX and CycloneDX formats because each is optimised for different consumers: SPDX has richer license expression support; CycloneDX is better supported by Grype.

---

## 🔧 Options

| Flag | Description |
|---|---|
| `-s, --silent` | Suppress progress messages |
| `-j, --json` | JSON output (provenance block) to stdout |
| `-sj, -js` | Silent + JSON |
| `-v, --verbose` | Show additional detail |
| `-f, --format FORMAT` | `spdx` \| `cyclonedx` \| `both` (default: `both`) |
| `-t, --timeout SECONDS` | Syft scan timeout (default: 120) |
| `-o, --output-dir DIR` | Directory for output files |
| `--no-files` | Output to stdout only; do not write files |
| `--no-provenance` | Skip provenance metadata collection |
| `--version` | Print version and exit |

---

## 📤 Output

| File | Format |
|---|---|
| `<n>.spdx.json` | SPDX 2.3 JSON |
| `<n>.cdx.json` | CycloneDX 1.5 JSON |

Both files include provenance metadata (tool name/version, scan timestamp, source details) in their respective metadata sections. The JSON output (via `-j`) is a provenance summary block, not the full SBOM.

---

## 💡 Examples

```bash
# Generate both formats
./sbom-gen.sh akismet.5.3.zip

# CycloneDX only, long timeout for large packages
./sbom-gen.sh -f cyclonedx --timeout 300 large-package.zip

# From an extracted directory
./sbom-gen.sh ./packages/akismet.5.3/

# Skip if SBOMs already exist
./sbom-toolkit.sh --skip-sbom-gen ...
```

---

## ⚠️ Known Limitations

- Syft identifies components from manifest files and lock files. Vendored dependencies copied without a manifest entry will not appear in the SBOM.
- Scan time scales with the number of files and depth of the dependency graph. Set `--timeout` appropriately for large packages.

---

<sub>Scripts licensed MIT · Documentation [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) · © Package Profiler Contributors</sub>
