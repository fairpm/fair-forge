# 📊 file-stats.sh

> Catalogues every file in a directory by type, counts lines and bytes per category, and checks for standard governance and best-practice files.

---

## 🎯 Purpose

Before examining file contents, it helps to understand the package's structure at a glance: how many source files, how much code, what types of assets, and whether standard project files are present. `file-stats.sh` answers these structural questions and flags anything that looks anomalous — for example, a "form plugin" with 200 binary executables.

The best-practice check is also useful as a package quality signal: packages that include a README, LICENSE, CHANGELOG, and SECURITY policy are more transparent and easier to audit.

---

## 🔧 Options

| Flag | Description |
|---|---|
| `-h, --help` | Show help and exit |
| `-s, --silent` | Suppress progress messages |
| `-j, --json` | Output results in JSON format |
| `-sj, -js` | Silent + JSON (pipe-friendly) |
| `-v, --verbose` | Show per-extension breakdown within categories |
| `-o, --output-dir D` | Write JSON output to directory |
| `--meta-base DIR` | Base directory for meta output (default: `./meta`) |
| `--no-file` | Output JSON to stdout only; do not write file |
| `--write-json F` | Write JSON results to file F (used by `run-filescans.sh`) |
| `--version` | Print version and exit |

---

## 📂 File Categories

Files are classified by extension into these categories:

| Category | Extensions (examples) |
|---|---|
| **code** | `php`, `js`, `ts`, `jsx`, `tsx`, `py`, `rb`, `java`, `go`, `rs`, `sh` and 40+ more |
| **web** | `html`, `htm`, `css`, `scss`, `sass`, `svg` |
| **markup** | `md`, `rst`, `txt`, `json`, `yaml`, `toml`, `xml` |
| **config** | `ini`, `conf`, `env`, `gitignore`, `editorconfig`, `.htaccess` and similar |
| **data** | `csv`, `sql`, `graphql`, `geojson` |
| **images** | `jpg`, `png`, `gif`, `svg`, `webp`, `ico` |
| **fonts** | `woff`, `woff2`, `ttf`, `otf`, `eot` |
| **media** | `mp4`, `mp3`, `webm`, `wav` |
| **archives** | `zip`, `tar`, `gz`, `bz2`, `7z` |
| **binaries** | `exe`, `dll`, `so`, `dylib`, `elf`, `wasm` |
| **secrets** | `.pem`, `.key`, `.p12`, `.pfx`, `.crt` (flagged when found) |
| **other** | Everything else |

Hidden files (dotfiles) and minified files are counted separately in `totals`.

---

## ✅ Best-Practice File Check

The script checks for these governance files at the package root:

| Key | Files checked |
|---|---|
| `readme` | `README.md`, `README.txt`, `README` |
| `license` | `LICENSE`, `LICENSE.md`, `LICENSE.txt`, `COPYING` |
| `security` | `SECURITY.md`, `SECURITY.txt` |
| `contributing` | `CONTRIBUTING.md`, `CONTRIBUTING.txt` |
| `changelog` | `CHANGELOG.md`, `CHANGELOG.txt`, `CHANGES.md`, `HISTORY.md` |
| `code_of_conduct` | `CODE_OF_CONDUCT.md` |
| `notice` | `NOTICE`, `NOTICE.md` |
| `maintainers` | `MAINTAINERS`, `MAINTAINERS.md` |
| `governance` | `GOVERNANCE.md` |
| `codeowners` | `CODEOWNERS` (root or `.github/`) |
| `sbom` | Any `.cdx.json`, `.spdx`, or `sbom.json` |

---

## 📤 Output

**File:** `meta/<clean-name>/<clean-name>.file-stats.json`  
**Root key:** `file_statistics`

No `risk_contribution` field — this scan is informational only. Unusual file type distributions are surfaced as data, not as a risk score. Human review determines whether the distribution is appropriate.

```jsonc
{
  "file_statistics": {
    "target_directory": "akismet",
    "toolkit_version":  "1.0.0",
    "timestamp":        "...",
    "totals": {
      "files":          87,
      "lines":          14203,
      "bytes":          412800,
      "minified_files": 4,
      "hidden_files":   0
    },
    "categories": [
      { "category": "code", "files": 42, "lines": 9800, "bytes": 280000 }
    ],
    "best_practices": {
      "checked": 11,
      "found":   6,
      "missing": 5,
      "items": [ ... ]
    }
  }
}
```

---

## 💡 Examples

```bash
# Basic scan
./file-stats.sh ./packages/akismet.5.3/

# Per-extension breakdown
./file-stats.sh --verbose ./packages/akismet.5.3/

# Silent JSON
./file-stats.sh -sj ./packages/akismet.5.3/ \
  | jq '.file_statistics.totals'
```

---

<sub>Scripts licensed MIT · Documentation [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) · © Package Profiler Contributors</sub>
