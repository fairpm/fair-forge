# 🔒 permission-check.sh

> Audits filesystem permissions in a package directory, detecting world-writable files, SUID/SGID binaries, dangerous symlinks, sensitive file exposure, and other privilege-escalation vectors — with optional auto-remediation.

---

## 🎯 Purpose

Dangerous permissions are often introduced silently: a build system that copies files without preserving permission bits, a vendor package with world-writable directories, or a data file that gained an execute bit during packaging. `permission-check.sh` surfaces these before the package reaches production.

For web-deployed packages (WordPress plugins, web apps), world-writable files and missing sticky bits on world-writable directories are particularly dangerous — they allow any web process to modify or overwrite package files.

---

## 🔧 Options

| Flag | Description |
|---|---|
| `-h, --help` | Show help and exit |
| `-s, --silent` | Suppress output (exit code only) |
| `-j, --json` | Output results in JSON format |
| `-sj, -js` | Silent + JSON (pipe-friendly) |
| `-v, --verbose` | Verbose output (list every finding) |
| `-f, --fix` | Fix issues: remove world-writable perms, add sticky bits, strip exec from data files, restrict sensitive files |
| `-o, --output-dir D` | Write JSON output to directory |
| `--meta-base DIR` | Base directory for meta output (default: `./meta`) |
| `--no-file` | Output JSON to stdout only; do not write file |
| `--write-json F` | Write JSON results to file F (used by `run-filescans.sh`) |
| `--version` | Print version and exit |

---

## 🔍 What It Checks

### Critical issues

| Issue | Why it matters |
|---|---|
| **World-writable file** (`o+w`) | Any process can modify this file — a web shell could be injected |
| **World-writable directory** | Any user can create, rename, or delete files in this directory |
| **Missing sticky bit** on world-writable dir | Without `+t`, any user can delete others' files in the directory |
| **SUID/SGID binary** | Runs with elevated privileges regardless of calling user |
| **Permission inversion** | Directory is less accessible than files it contains (usually a sign of a packaging error) |
| **External symlink** | Symlink points outside the package directory — may expose host filesystem paths |
| **Sensitive file exposure** | `.env`, `.htpasswd`, `.pem`, `.key`, `credentials.*` readable by others |

### Non-critical issues

| Issue | Notes |
|---|---|
| Internal symlink | Symlink within the package — usually fine, flagged for review |
| Dangling symlink | Target does not exist |
| Unnecessary execute bit | A `.png` or `.css` with execute permission |
| Orphaned ownership | File owned by UID/GID not present in the system |
| Deploy artefact | `.DS_Store`, `Thumbs.db`, editor temp files — shouldn't ship |

---

## 📊 Risk Scoring

```
critical_risk = (world-writable files × 10) + (world-writable dirs × 15)
              + (missing sticky bits × 20)
              + (privilege escalation × 20) + (permission inversions × 30)
              + (external symlinks × 25) + (sensitive files × 25)

other_risk    = (internal symlinks × 5) + (dangling symlinks × 10)
              + (unnecessary exec × 3) + (orphaned ownership × 10)
              + (deploy artefacts × 8)

total = critical_risk + other_risk
```

Hardened files (correctly locked-down sensitive files) are reported as informational but do not reduce the score — they narrow real-world risk, but crediting them would mask genuine issues and make scores non-comparable.

---

## 🛠️ --fix Behaviour

When `--fix` is passed, the script attempts to remediate each finding it can:

| Finding | Fix applied |
|---|---|
| World-writable file | `chmod o-w` |
| World-writable directory | `chmod o-w` |
| Missing sticky bit | `chmod +t` |
| Data file with execute bit | `chmod a-x` (images, fonts, CSS, etc.) |
| Sensitive file readable by other | `chmod o-r` |

Fixes are logged. Failures (e.g., insufficient privileges) are reported as `[FAIL]` in the output and JSON. SUID/SGID and permission inversions are flagged but not auto-remediated — they require a human decision.

---

## 📤 Output

**File:** `meta/<clean-name>/<clean-name>.perms.json`  
**Root key:** `permission_audit`

```jsonc
{
  "permission_audit": {
    "target_directory": "akismet",
    "toolkit_version":  "1.0.0",
    "timestamp":        "...",
    "fix_mode":         false,
    "summary": {
      "items_checked":        87,
      "total_issues":         1,
      "writable_files":       0,
      "unnecessary_exec":     1
    },
    "risk_contribution": 3,
    "risk_detail": {
      "critical_floor": 0,
      "other_risk":     3
    },
    "findings": [
      {
        "severity":    "LOW",
        "type":        "unnecessary_exec",
        "permissions": "-rwxr-xr-x",
        "file_path":   "assets/banner.png"
      }
    ]
  }
}
```

---

## 💡 Examples

```bash
# Basic audit
./permission-check.sh ./packages/akismet.5.3/

# Verbose — list every finding
./permission-check.sh --verbose ./packages/akismet.5.3/

# Audit and fix
./permission-check.sh --fix ./packages/akismet.5.3/

# Silent JSON for piping
./permission-check.sh -sj ./packages/akismet.5.3/ \
  | jq '.permission_audit.risk_contribution'
```

---

## ⚠️ Known Limitations

- `--fix` requires the script to be run with sufficient privileges to modify the target files. In a read-only or container environment, fixes will fail gracefully.
- SUID/SGID detection on Linux requires access to the file metadata. In some container environments or with certain filesystem mounts, this may not be available.
- Permission checks are a snapshot in time. A deployment step that changes permissions after scanning will not be caught.

---

<sub>Scripts licensed MIT · Documentation [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) · © Package Profiler Contributors</sub>
