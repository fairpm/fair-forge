
# SBOM Analyzer

A robust Bash utility that scans directories for Software Bill of Materials (SBOM) sources (such as `package-lock.json` or existing SBOM files), generates standardized SBOMs on-the-fly using **Syft**, and performs a deep variance analysis against a baseline if multiple SBOMs are found. It identifies added, removed, and version-shifted packages while intelligently filtering out development dependencies to reduce noise.

## 🚀 Features

* **Auto-Discovery:** Recursively finds SBOM-compatible files (default depth: 6), skipping `node_modules` and hidden directories for speed.
* **Intelligent Baseline:** Automatically sorts found files by depth, prioritizing files with `*bom*`, `*spdx*`, `*cyclonedx*, and `*json*` in the file name. The highest-priority file is selected as the "Source of Truth" baseline for comparisons.
* **Noise Reduction:** Identifies and omits `devDependencies` from the comparison report to focus on production risks.
* **Security Hardened:** Includes timeouts, relative path masking (privacy), and secure filename handling to prevent injection attacks on the script itself.
* **CI/CD Ready:** Offers a `--json` flag for machine-parsable output for build pipelines.

## 🛠️ Dependencies

- jq 1.6+
- Syft v0.60.0+
- Grype 
- `bash`,
- `awk`, `sed`, `grep`, `basename`, `dirname`, `mktemp`, `realpath`, which are all standard with the `coreutils` package.
- External HTTP access is required for Grype only to retrieve the vulnerability database. This must be done manually for an air-gapped environment. Syft does not require an external connection except when scanning an external Docker file.

This script relies on standard Unix utilities and two specific tools: **Syft** and **jq**.

### Required Tools

| Tool | Purpose | Installation (macOS) | Installation (Ubuntu/Debian) |
| --- | --- | --- | --- |
| **Syft** | Generating SBOMs from lockfiles | `brew install syft` | `curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh |
| **jq** | Processing JSON data | `brew install jq` | `sudo apt-get install jq` |
| **awk** | Text processing & diffing | Pre-installed | Pre-installed |
| **timeout** | Anti-DoS security | Pre-installed | `sudo apt-get install coreutils` |

* Obviously, adapt the install commands for your package installer on other Linux distros or if not using `apt`.

## 📥 Installation

1. Ensure dependencies are met.
2. Save the script to your selected directory.
3. Make it executable:

```bash
chmod +x analyze-sbom.sh

```

## 💻 Usage

### Basic Syntax

```bash
./analyze-sbom.sh [DIRECTORY] [OPTIONS]

```

*If no directory is provided, it defaults to the current directory (`.`).*

### Options & Flags

| Flag | Long Flag | Description |
| --- | --- | --- |
| `-v` | `--verbose` | **Detailed Mode:** Lists the specific names of added, removed, or changed packages. |
| `-j` | `--json` | **JSON Output:** Outputs raw JSON for piping into other tools. Suppresses all log messages. |
| `-n` | `--no-diff` | **Discovery Only:** Finds potential SBOMs but skips the comparison step. |
| `-d` | `--depth INT` | **Search Depth:** How deep to search for files (Default: 6). |
| `-f` | `--filter TYPE` | **Filter:** Limit analysis to specific package types (e.g., `npm`, `python`, `binary`). |
| `-h` | `--help` | **Help:** Displays usage information. |

## 🔍 Examples

### 1. Drift Check

Compare all lockfiles in the current directory against the highest-priority baseline.

```bash
./analyze-sbom.sh

```

### 2. Verbose Audit

See exactly *which* library versions have changed.

```bash
./analyze-sbom.sh ./backend --verbose

```

*Output snippet:*

```text
  Variances: [+] 0 new, [-] 0 removed, [Δ] 1 version changes
      [Δ] react: 17.0.2 ➔ 18.2.0

```

### 3. CI/CD Integration (JSON)

Generate a JSON report to fail a build if drift is detected.

```bash
./analyze-sbom.sh --json > sbom-report.json

```

### 4. Deep Search

If your `package-lock.json` is deeply nested (_e.g._, inside a monorepo structure).

```bash
./analyze-sbom.sh --depth 8

```

## ⚙️  How It Works

1. **Discovery:** The script runs `find` to locate files matching `*bom*` or `*.json`. It deliberately prunes (ignores) `node_modules`, `.git`, `dist`, and `.venv` to ensure performance.
2. **Baseline Selection:** When multiple SBOM files are found, list is sorted by priority, calculated as (1) the depth it is found in the directory tree (_e.g._, 0 in the target-root directory, 1 for the first subdirectory, and so on). If the filename includes any the SBOM-indicators (`spdx`, `cyclonedx`, `bom`), 0.5 is subtracted from its depth score. The highest-priority file will have the lowest number, becoming the Baseline to which any other files are compared.
3. **Parsing:**
* Each file is passed to `syft` to generate a standardized JSON SBOM.
* `jq` filters out artifacts marked as `dev: true` or having a `dev` property.

4. **Comparison:**
* `awk` compares the production dependencies of the Target vs. the Baseline.
* It calculates **Additions** (in Target, not Baseline), **Removals** (in Baseline, not Target), and **Version Shifts**.



## 🛡️ Security Notes

* **Read-Only:** This script is read-only; it does not modify your lockfiles or project structure.
* **Privacy:** Output paths are relative to the execution directory. Absolute system paths (_e.g._, `/home/user/...`) are masked.
* **Timeouts:** Parsing operations are capped at 30 seconds per file to prevent "Zip bomb" or "JSON bomb" denial-of-service scenarios.


## License

These scripts are licensed under the MIT License.

Documentation **CC BY 4.0** https://creativecommons.org/licenses/by/4.0/

