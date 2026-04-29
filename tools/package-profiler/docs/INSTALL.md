# 🔧 Installation & Dependencies

> **TL;DR:** Install `syft`, `grype`, `jq`, and `curl`. Everything else is standard Bash on any modern Linux or macOS system.

---

## 📋 Requirements at a Glance

| Tool | Required by | Minimum version | Notes |
|---|---|---|---|
| **Bash** | All scripts | 4.0+ | macOS ships Bash 3; upgrade via Homebrew |
| **jq** | All scripts | 1.6+ | JSON processing throughout |
| **curl** | checksum-verify, provenance-verify | Any recent | API lookups for upstream checksums |
| **Syft** | sbom-gen | 0.90+ | SBOM generation (Anchore) |
| **Grype** | vuln-scan | 0.65+ | CVE database scanning (Anchore) |
| **sha256sum** | checksum-verify, crypto-verify | coreutils | Standard on Linux; `gsha256sum` on macOS |
| **sha384sum** | checksum-verify | coreutils | Optional; noted as unavailable if absent |
| **sha512sum** | checksum-verify | coreutils | Optional; noted as unavailable if absent |
| **file** | deep-filescan | Any | MIME type detection |
| **unzip** | checksum-verify, provenance-verify | Any | Archive extraction |
| **tar** | checksum-verify, provenance-verify | Any | Archive extraction |

> **Filescan Suite only** (`run-filescans.sh`, `permission-check.sh`, `file-stats.sh`, `deep-filescan.sh`) requires only Bash, jq, and `file`. Syft and Grype are not needed.

---

## 🍺 macOS

```bash
# Homebrew is the easiest path
brew install bash jq curl syft grype

# Verify Bash version (must be 4+)
bash --version
# If still showing 3.x, add to your shell profile:
export PATH="/usr/local/bin:$PATH"    # Intel
export PATH="/opt/homebrew/bin:$PATH" # Apple Silicon

# sha256sum ships as gsha256sum on macOS — alias it
echo 'alias sha256sum="gsha256sum"' >> ~/.zshrc
echo 'alias sha384sum="gsha384sum"' >> ~/.zshrc
echo 'alias sha512sum="gsha512sum"' >> ~/.zshrc
source ~/.zshrc
```

---

## 🐧 Linux (Debian / Ubuntu)

```bash
# System packages
sudo apt-get update
sudo apt-get install -y bash jq curl file unzip tar coreutils

# Syft — from the official install script or GitHub releases
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Grype
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Verify
syft --version
grype --version
jq --version
```

## 🐧 Linux (RHEL / CentOS / Fedora)

```bash
sudo dnf install -y bash jq curl file unzip tar coreutils

# Syft and Grype as above (install scripts or GitHub releases)
```

---

## 🐳 Docker / CI

A minimal Dockerfile that satisfies all dependencies:

```dockerfile
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash jq curl file unzip tar ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Syft
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
    | sh -s -- -b /usr/local/bin

# Grype
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
    | sh -s -- -b /usr/local/bin

COPY *.sh *.jq /opt/package-profiler/
RUN chmod +x /opt/package-profiler/*.sh

WORKDIR /workspace
```

### GitHub Actions

```yaml
- name: Install Package Profiler dependencies
  run: |
    sudo apt-get install -y jq curl file unzip
    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sudo sh -s -- -b /usr/local/bin
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin
```

---

## ✅ Verify Your Installation

```bash
# Run this from the directory containing the scripts
bash toolkit-test.sh --dry-run    # SBOM Toolkit self-check
bash filescan-test.sh --dry-run   # Filescan Suite self-check
```

If either test suite reports missing dependencies, it will name the missing tool and suggest how to install it.

---

## 🔒 Network Requirements

The following outbound connections are made at runtime:

| Destination | Used by | Purpose |
|---|---|---|
| `api.wordpress.org` | checksum-verify, provenance-verify | Plugin checksum and version lookup |
| `downloads.wordpress.org` | checksum-verify | Reference download for checksum comparison |
| `repo.packagist.org` | checksum-verify, provenance-verify | Packagist dist hash lookup |
| `registry.npmjs.org` | checksum-verify | npm package dist.integrity |
| `pypi.org` | checksum-verify | PyPI release hash |
| `api.github.com` | provenance-verify | Repository and commit existence |
| `anchore.com` (grype DB) | vuln-scan | CVE database update |

All connections use HTTPS. `curl` is given a 15-second timeout per request. Scans work offline for most checks if the Grype CVE database is already cached; only checksum and provenance API lookups require network access.

---

## 🗂️ File Placement

All scripts must be in the same directory. `vuln-scan-risk.jq` is a required peer file for `vuln-scan.sh` and must be co-located with it — they cannot be separated.

```
package-profiler/
  sbom-toolkit.sh      ← main controller
  run-filescans.sh     ← filescan controller
  sbom-gen.sh
  sbom-discover.sh
  checksum-verify.sh
  vuln-scan.sh
  vuln-scan-risk.jq    ← required peer; must stay with vuln-scan.sh
  license-check.sh
  dependency-audit.sh
  provenance-verify.sh
  slsa-attest.sh
  sbom-compare.sh
  permission-check.sh
  file-stats.sh
  deep-filescan.sh
  toolkit-test.sh
  filescan-test.sh
```

Scripts locate their peers at runtime by resolving `$(dirname "${BASH_SOURCE[0]}")`. As long as all files stay together, you can symlink the controllers into your PATH.

---

<sub>© Package Profiler Contributors · Documentation licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)</sub>
