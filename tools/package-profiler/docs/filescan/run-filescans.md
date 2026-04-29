# 🎛️ run-filescans.sh

> Controller script — runs `file-stats.sh`, `permission-check.sh`, and optionally `deep-filescan.sh` against a directory, and produces a merged JSON output.

---

## 🎯 Purpose

`run-filescans.sh` orchestrates the three Filescan Suite scripts into a single command. It passes flags through to the appropriate subscripts, collects their JSON outputs, and merges them into one document under a `scans` wrapper for convenient downstream processing.

---

## 🔧 Options

| Flag | Description |
|---|---|
| `-h, --help` | Show help and exit |
| `-s, --silent` | Suppress progress messages |
| `-j, --json` | Output merged results in JSON format |
| `-sj, -js` | Silent + JSON (pipe-friendly) |
| `-v, --verbose` | Pass verbose mode through to all sub-scripts |
| `-f, --fix` | Pass `--fix` to `permission-check.sh` |
| `--deep` | Enable `deep-filescan.sh` (content and MIME scan) |
| `-o, --output-dir DIR` | Write merged JSON output to directory |
| `--meta-base DIR` | Base directory for output (default: `./meta`) |
| `--no-file` | Output JSON to stdout only; do not write file |
| `--version` | Print version and exit |

---

## 📁 Output Structure

```
meta/<clean-name>/
  <clean-name>.meta.json        merged output  ← primary output
  <clean-name>.perms.json       from permission-check (if --keep-intermediate)
  <clean-name>.file-stats.json  from file-stats (if --keep-intermediate)
  <clean-name>.content-scan.json from deep-filescan (if --keep-intermediate)
```

### Merged JSON structure

```jsonc
{
  "scan_suite":   "filescan",
  "toolkit_version": "1.0.0",
  "timestamp":    "ISO-8601",
  "target":       "./packages/akismet.5.3",
  "scans": {
    "file_statistics": { ... },   // from file-stats.sh
    "permission_audit": { ... },  // from permission-check.sh
    "content_scan":     { ... }   // from deep-filescan.sh (if --deep)
  },
  "risk_summary": {
    "total":      10,
    "permissions": 10,
    "content":    0
  }
}
```

---

## 💡 Examples

```bash
# Basic scan (stats + permissions)
./run-filescans.sh ./packages/akismet.5.3/

# Full scan including content patterns
./run-filescans.sh --deep ./packages/akismet.5.3/

# Auto-fix dangerous permissions
./run-filescans.sh --fix ./packages/akismet.5.3/

# Full scan with fix + verbose
./run-filescans.sh --deep --fix --verbose ./packages/akismet.5.3/

# Silent JSON for piping
./run-filescans.sh -sj ./packages/akismet.5.3/ \
  | jq '.risk_summary'
```

---

## ⚠️ Known Limitations

- Scripts run sequentially. For large packages, `deep-filescan.sh` may take a minute or more.
- The `--fix` flag modifies the target directory. Always operate on a copy when `--fix` is used in a non-destructive review workflow.

---

<sub>Scripts licensed MIT · Documentation [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) · © Package Profiler Contributors</sub>
