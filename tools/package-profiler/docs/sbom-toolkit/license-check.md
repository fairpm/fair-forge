# 📜 license-check.sh

> Analyses SPDX license declarations in an SBOM, classifies every component by license type, and flags compliance violations.

**TL;DR:** For WordPress plugins, the GPL-compatibility check is the key gate. An Apache-2.0 or AGPL dependency in a GPL-2.0 plugin is a distribution violation.

---

## 🎯 Purpose

License compliance is a legal requirement, not just a best practice. `license-check.sh` parses SPDX license expressions from an SBOM and evaluates them against a policy:

- Which licenses are present?
- Are any GPL-incompatible?
- Are there unknown licenses that may require manual review?

The script understands SPDX expression syntax including `OR`, `AND`, and `WITH` operators. For `OR` expressions it applies the least-restrictive interpretation (best case for compliance).

### Why GPL-compatibility matters for WordPress

WordPress core is licensed GPL-2.0-or-later. Plugins distributed via WordPress.org must be GPL-compatible. Libraries with GPL-incompatible licenses (SSPL-1.0, Commons-Clause, EUPL-1.1 in some configurations) cannot legally be distributed as part of a GPL plugin.

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
| `--require-gpl-compat` | Exit 1 when any license is not GPL-compatible |
| `--allow-unknown` | Do not fail on unrecognised license identifiers |
| `--ecosystem TYPE` | Ecosystem context for license defaults: `wordpress` \| `packagist` \| `npm` \| `pypi` \| `github` \| `file` |
| `--version` | Print version and exit |

---

## 📂 License Categories

| Category | Examples |
|---|---|
| Permissive | MIT, BSD-2-Clause, BSD-3-Clause, Apache-2.0, ISC |
| Weak copyleft | LGPL-2.1, LGPL-3.0, MPL-2.0, EUPL-1.2 |
| Strong copyleft | GPL-2.0, GPL-3.0, AGPL-3.0 |
| GPL-incompatible | SSPL-1.0, Commons-Clause, EUPL-1.1 (some configs) |
| Proprietary | Commercial, all-rights-reserved |
| Unknown | Not a recognised SPDX identifier |

> Note: AGPL-3.0 is GPL-compatible but may have additional network use implications. It is classified as strong copyleft, not GPL-incompatible, but flagged separately in verbose output.

---

## 📤 Output

**File:** `meta/<clean-name>/<clean-name>.license.json`  
**Root key:** `license_compliance`

```jsonc
{
  "license_compliance": {
    "status":          "issues_found",
    "gpl_compatible":  false,
    "timestamp":       "...",
    "toolkit_version": "1.0.0",
    "summary": {
      "total":            12,
      "permissive":        8,
      "weak_copyleft":     2,
      "strong_copyleft":   1,
      "gpl_incompatible":  1,
      "proprietary":       0,
      "unknown":           0
    },
    "risk_contribution": 100,
    "issues": [ ... ],
    "packages": [ ... ]
  }
}
```

**Risk contribution:** 100 per GPL-incompatible license · 200 per AGPL · 50 per unknown license (unless `--allow-unknown`)

---

## 💡 Examples

```bash
# Basic scan
./license-check.sh akismet.5.3.spdx.json

# Fail CI if GPL-incompatible dependency found
./license-check.sh --require-gpl-compat akismet.5.3.spdx.json

# WordPress ecosystem context
./license-check.sh --ecosystem wordpress --require-gpl-compat akismet.5.3.spdx.json

# Silent JSON
./license-check.sh -sj akismet.5.3.spdx.json \
  | jq '.license_compliance.gpl_compatible'
```

---

## ⚠️ Known Limitations

- License detection relies entirely on SPDX identifiers declared in the SBOM. If Syft could not determine the license for a component, it will appear as `NOASSERTION` or `unknown`.
- SPDX `OR` expressions are resolved as least-restrictive. This is the legally correct interpretation (the recipient may choose the more permissive option) but may not reflect actual usage.
- The GPL-incompatibility classification covers common cases; edge cases in EUPL or OSL licensing require legal review beyond what this script can provide.

---

<sub>Scripts licensed MIT · Documentation [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) · © Package Profiler Contributors</sub>
