# 🔍 sbom-discover.sh

> Searches a package archive or directory for embedded SBOM files and package manifests, and validates any SBOMs it finds structurally.

---

## 🎯 Purpose

Some packages ship their own SBOM or lock file. Discovering these before running Syft can:
- Confirm the vendor's own declared dependency inventory
- Provide an alternative source for vuln-scan if Syft cannot generate a complete SBOM
- Identify whether the package already participates in a supply chain transparency ecosystem

`sbom-discover.sh` searches for SPDX JSON, CycloneDX JSON/XML, and common manifest formats (composer.lock, yarn.lock, requirements.txt, go.sum, etc.), then validates any found SBOMs for format compliance.

---

## 🔧 Options

| Flag | Description |
|---|---|
| `-s, --silent` | Suppress progress messages |
| `-j, --json` | JSON output to stdout |
| `-sj, -js` | Silent + JSON |
| `-v, --verbose` | Show per-file detail |
| `-o, --output-dir DIR` | Directory for output file |
| `--meta-base DIR` | Base directory for meta output (default: `./meta`) |
| `--no-file` | Output JSON to stdout only; do not write file |
| `--max-depth N` | Maximum directory search depth (default: 8) |
| `--version` | Print version and exit |

---

## 📤 Output

**File:** `meta/<clean-name>/<clean-name>.discover.json`  
**Root key:** `sbom_discovery`

Key fields include `status` (`sbom_found` | `manifest_only` | `not_found`), `valid_sboms[]` (path, format, component count), and `manifests[]` (path, type).

---

## 💡 Examples

```bash
# Search an archive
./sbom-discover.sh akismet.5.3.zip

# Search an extracted directory
./sbom-discover.sh ./packages/akismet.5.3/

# Limit search depth
./sbom-discover.sh --max-depth 3 ./packages/akismet.5.3/
```

---

## ⚠️ Known Limitations

- Archives are searched by listing contents without full extraction. Nested archives are not recursively searched.
- Structural validation checks required fields and format version; it does not verify that the SBOM accurately describes the package contents.

---

<sub>Scripts licensed MIT · Documentation [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) · © Package Profiler Contributors</sub>
