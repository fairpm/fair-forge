# 🗂️ Filescan Suite

> **TL;DR:** The Filescan Suite opens the package and looks inside — cataloguing every file by type, scanning source code for malicious patterns, and auditing filesystem permissions for privilege escalation vectors.

---

## 🎯 What This Set Does

The SBOM Toolkit works from the archive. The Filescan Suite works from the *extracted* directory — examining what the package actually contains at the file level, not just what it declares.

It answers three questions:

1. **What is in here, by file type?** (`file-stats`) — How many PHP, JS, CSS, image, binary, and archive files? Are standard governance files (README, LICENSE, CHANGELOG) present?
2. **Is there anything dangerous in the source code?** (`deep-filescan`) — Patterns matching reverse shells, crypto miners, code obfuscation, data exfiltration, and PHP webshells. MIME type integrity checks (a `.jpg` that is actually a PHP file). Embedded code in data files.
3. **Are the permissions safe?** (`permission-check`) — World-writable files, SUID/SGID binaries, missing sticky bits on world-writable directories, external symlinks, sensitive file exposure.

---

## 📄 Script Index

| Script | Purpose | Document |
|---|---|---|
| **`run-filescans.sh`** | Controller — orchestrates all three scripts; produces merged JSON | [run-filescans.md](run-filescans.md) |
| `file-stats.sh` | File type statistics, line/byte counts, best-practice file check | [file-stats.md](file-stats.md) |
| `deep-filescan.sh` | Malicious pattern detection and MIME integrity analysis | [deep-filescan.md](deep-filescan.md) |
| `permission-check.sh` | Permission audit with optional auto-remediation | [permission-check.md](permission-check.md) |

---

## ⚡ Quick Example

```bash
# Scan an extracted package directory (permissions + file stats only)
./run-filescans.sh ./packages/akismet.5.3/

# Add content scanning (slower; examines file contents)
./run-filescans.sh --deep ./packages/akismet.5.3/

# Auto-fix dangerous permissions
./run-filescans.sh --fix ./packages/akismet.5.3/
```

---

## 🛠️ Design & Architecture

- [Design document](design.md) — threat model, performance considerations, detection methodology

---

<sub>Scripts licensed MIT · Documentation [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) · © Package Profiler Contributors</sub>
