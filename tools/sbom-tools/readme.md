# 📦 SBOM Tools

A set of production-hardened Bash utilities for generating Software Bill of Materials (SBOMs) and performing vulnerability scanning. These scripts are designed for CI/CD environments, emphasizing error handling, input sanitization, and automated cleanup.

**The Scripts:**
1. SBOM Generator     -- Generates SPDX & CycloneDX SBOMs from a target directory or archive
2. SBOM Analyzer      -- Finds & Analyzes SBOMs within a target directory
3. SBOM CVE Scanner   -- Scans packages listed in an SBOM for known CVEs

## 📥 Installation

### 🛠️ Dependencies

Ensure the following tools are installed in your environment (local or CI runner):
- jq 1.6+          -- used for JSON processing
- Syft v0.60.0+    -- used for SBOM Generation
- Grype            -- used for vulerability scanning of SBOM content
- `bash`, with support for `sed`, `grep`, `basename`, `dirname`, `mktemp`, `realpath`, `timeout` (standard with `coreutils`)
- External HTTP access is required for Grype to retrieve the vulnerability database. In air-gapped environments, this step must be done manually. Syft does not require an external connection except when scanning an external Docker file.

#### 📥 Install Dependencies

**Ubuntu/Debian:** `sudo apt-get update && sudo apt-get install -y jq`

If necessary: `sudo apt-get install coreutils` (Should be pre-installed)

(Adjust to suit your distro or package manager if not apt; _e.g._, `yum`, `rpm`, _etc._)

Install Syft & Grype from their repos:

`curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin`

`curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin`

**macOS, using Homebrew:** `brew install jq syft grype`

### 📥 Install the SBOM Scripts

1. Save the scripts to a working directory (unless you're adding them to your PATH).
2. Make them executable:

```bash
chmod +x sbom-gen.sh analyze-sbom.sh vuln-scan.sh

```




## 🚀 SBOM Generator

`sbom-gen.sh`

**Purpose:** Generates standardized SBOMs from a source target (Docker image, directory, or archive) using **Syft**.
**Outputs:** Automatically creates two `.json files` for SBOMs in both `SPDX` and `CycloneDX` formats.
**Safety:**  Sanitizes filenames, enforces relative paths for privacy, and includes timeouts to prevent stalls.

This script will generate two `.json` SBOM files (one SPDX and one CyclondDX format) from a target directory or archive of a type supported by Syft, including `.zip`, `.tar`, `.tar.gz`, `.7z`, `.tgz`, `.xz`, and others, or from Docker images. The script sanitizes filenames, enforces relative paths for privacy, and includes timeouts to prevent stalls.

Usage: `./sbom-gen.sh {target}`










## 🚀 Vulnerability Check

`vulncheck-sbom.sh`

This script will review a provided SBOM and check the listed packages against a current vulnerability database. The script is recommended to be run on a CycloneDX SBOM, but will work equally with other standard SBOM formats. The script will output an updated SBOM including vulnerability information, with a file name based on the target input, _e.g._, `sbom-vulns-{target}.cyclonedx.json`.

Usage: `./vulncheck-sbom.sh sbom-{target}.cyclonedx.json`

Note: in an air-gapped environment, the Grype DB must be imported manually or the script will fail.

Import the database manually with `grype db import`

## License: MIT














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




















### 2. `vuln-scan.sh` SBOM CVE Scanner

**Purpose:** Consumes an existing SBOM and scans it for vulnerabilities using **Grype**.

* **Outputs:** A unified JSON SBOM file containing the original SBOM merged with the vulnerability report.
* **Safety:** Redacts internal tool paths (_e.g._, `.cache/grype`) to prevent information leakage and validates JSON integrity before saving.



## 💻 Usage

### Generating SBOMs

Run the generator against a local directory, supported archive (`.zip`, `.tar.gz`, _etc._), or Docker image.

```bash
./sbom-gen.sh <TARGET>

```

**Examples:**

```bash
# Scan a local directory
./sbom-gen.sh ./app-source

# Scan a Docker image
./sbom-gen.sh nginx:latest

```

**Environment Variables:**
You can pass flags directly to Syft using `SYFT_ARGS`:

```bash
# Scan only the squash filesystem of an image
SYFT_ARGS='--scope squash' ./sbom-gen.sh alpine:latest

```

**Output:**
The script creates two files in the current directory:

* `sbom-<sanitized_name>.spdx.json`
* `sbom-<sanitized_name>.cyclonedx.json`

---

### Scanning SBOM for Vulnerable Packages

Give the scanner a valid SBOM as its target file to scan.

```bash
./vuln-scan.sh <INPUT_SBOM_FILE>

```

**Example:**

```bash
./vuln-scan.sh sbom-nginx_latest.spdx.json

```

**Output:**

* Creates: `sbom-vulns-<sanitized_name>.json`
* This file contains the full SBOM **plus** a new top-level `vulnerabilities` object containing the Grype findings.

## 🛡️ Security & Hardening Features

These scripts include several protections suitable for enterprise pipelines:

1. **Write Verification:** Both scripts explicitly check if the current directory is writable before wasting CPU cycles on scanning.
2. **Anti-DoS Timeouts:**
* `syft` is capped at **60s**.
* `grype` is capped at **120s** (to allow for database updates).


3. **Privacy Scrubbing:**
* **Generator:** Forces relative path scanning to prevent leaking absolute server paths (e.g., `/home/jenkins/workspace`).
* **Scanner:** Redacts internal Grype cache paths from the final JSON report.


4. **Atomic Writes:** Results are written to temporary files first and only moved to the final filename upon successful completion and validation.
5. **Strict Cleanup:** A `trap` function ensures temporary files are deleted regardless of whether the script succeeds, fails, or is terminated by `CTRL+C`.


## License

These scripts are licensed under the MIT License.

Documentation **CC BY 4.0** https://creativecommons.org/licenses/by/4.0/
