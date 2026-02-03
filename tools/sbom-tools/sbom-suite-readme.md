# SBOM Tooling Suite

A set of production-hardened Bash utilities for generating Software Bill of Materials (SBOMs) and performing vulnerability scanning. These scripts are designed for CI/CD environments, emphasizing error handling, input sanitization, and automated cleanup.

## 📦 The Scripts

### 1. `sbom-gen.sh` SBOM Generator

**Purpose:** Generates standardized SBOMs from a source target (Docker image, directory, or archive) using **Syft**.

* **Outputs:** Automatically creates both `SPDX` and `CycloneDX` formats.
* **Safety:** Sanitizes filenames, enforces relative paths for privacy, and includes timeouts to prevent stalls.

### 2. `vuln-scan.sh` SBOM CVE Scanner

**Purpose:** Consumes an existing SBOM and scans it for vulnerabilities using **Grype**.

* **Outputs:** A unified JSON SBOM file containing the original SBOM merged with the vulnerability report.
* **Safety:** Redacts internal tool paths (_e.g._, `.cache/grype`) to prevent information leakage and validates JSON integrity before saving.

## 🛠️ Script Dependencies

Ensure the following tools are installed in your environment (local or CI runner):

| Tool | Purpose | Installation (macOS) | Installation (Ubuntu/Debian) |
| --- | --- | --- | --- |
| **Syft** | SBOM Generation | `brew install syft` | `curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh |
| **Grype** | Vulnerability Scanning | `brew install grype` | `curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh |
| **jq** | JSON Processing | `brew install jq` | `sudo apt-get install jq` |
| **timeout** | Anti-DoS Safety | Pre-installed | `sudo apt-get install coreutils` |

## 📥 Installation

1. Ensure dependencies are met.
2. Save the scripts to a working directory (unless you're adding them to your PATH).
3. Make them executable:

```bash
chmod +x sbom-gen.sh vuln-scan.sh

```

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
