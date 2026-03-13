# 🔐 checksum-verify.sh

> Calculates SHA-256/384/512 checksums for a package archive, auto-detects its identity from embedded metadata, and verifies the checksums against the upstream ecosystem API.

**TL;DR:** Run this first. If the archive doesn't match what the registry published, nothing else matters — stop and investigate.

---

## 🎯 Purpose

A modified or corrupted archive is the most direct form of supply chain attack. `checksum-verify.sh` defends against this by:

1. Calculating cryptographic hashes of the local file
2. Auto-detecting the package identity (name, version, ecosystem) from embedded metadata
3. Querying the upstream registry API for its reference checksum
4. Comparing the two and reporting a clear pass/fail

For WordPress plugins, it additionally verifies individual file checksums inside the archive against the WordPress.org per-file endpoint — catching partial tampering that would survive a whole-archive hash match.

---

## 🔧 Options

| Flag | Description |
|---|---|
| `-h, --help` | Show help and exit |
| `-s, --silent` | Suppress progress messages |
| `-j, --json` | JSON output to stdout |
| `-sj, -js` | Silent + JSON (pipe-friendly) |
| `-v, --verbose` | Show additional detail |
| `-o, --output-dir DIR` | Directory for JSON output |
| `--meta-base DIR` | Base directory for meta output (default: `./meta`) |
| `--no-file` | Output JSON to stdout only; do not write file |
| `--skip` | Skip API verification; calculate hashes only |
| `--extract` | Extract archive to `./packages/<clean-name>/` |
| `--extract-dir DIR` | Extract to a specific directory (implies `--extract`) |
| `--packages-base DIR` | Base directory for extractions (default: `./packages`) |
| `--source-type TYPE` | Override auto-detected source type: `wordpress` \| `packagist` \| `npm` \| `pypi` \| `github` \| `file` |
| `--pkg-name NAME` | Pre-seed package name (fallback if auto-detection fails) |
| `--pkg-version VERSION` | Pre-seed package version (fallback if auto-detection fails) |
| `--sha256 HASH` | Expected SHA-256 (skips API lookup for this algorithm) |
| `--sha384 HASH` | Expected SHA-384 |
| `--sha512 HASH` | Expected SHA-512 |
| `--version` | Print version and exit |

---

## 🌐 Supported Ecosystems

| `--source-type` | API used | What is verified |
|---|---|---|
| `wordpress` | `api.wordpress.org` + `downloads.wordpress.org` | Whole-archive SHA-256; per-file checksums if extractable |
| `packagist` | `repo.packagist.org` | `dist.shasum` (SHA-1 noted; SHA-256 if available) |
| `npm` | `registry.npmjs.org` | `dist.integrity` (SHA-512 base64) |
| `pypi` | `pypi.org/pypi/<pkg>/<ver>/json` | `digests.sha256` per release file |
| `github` | GitHub releases API | SHA-256 of release asset |
| `file` | — | No API lookup; hashes calculated only |

### Auto-detection

If `--source-type` is not specified, the script reads metadata embedded in the archive:

- WordPress plugins: `readme.txt` with `=== Plugin Name ===` header
- WordPress core: `wp-includes/version.php`
- Composer: `composer.json` with `name` field
- npm: `package/package.json` with `name` and `version`
- PyPI: `.dist-info/METADATA`

Falls back to `file` mode if nothing is detected.

---

## 📤 Output

**File:** `meta/<clean-name>/<clean-name>.checksum.json`

**Root key:** `crypto_verification`

```jsonc
{
  "crypto_verification": {
    "target":           "akismet.5.3.zip",
    "timestamp":        "2025-11-14T09:12:00Z",
    "toolkit_version":  "1.0.0",
    "package_identity": {
      "name":      "akismet",
      "version":   "5.3",
      "ecosystem": "wordpress",
      "vendor":    "Automattic"
    },
    "calculated_checksums": {
      "sha256": "a1b2c3...",
      "sha384": "aabbcc...",
      "sha512": "unavailable"   // if sha512sum not installed
    },
    "verification": {
      "status":          "verified",   // verified | mismatch | not_found | skipped
      "verified":        true,
      "checksum_source": "wordpress_api",
      "reference_sha256": "a1b2c3...",
      "checks": [
        { "algorithm": "SHA256", "status": "matched" }
      ]
    },
    "extraction": {
      "performed":      true,
      "directory_name": "akismet",
      "path":           "./packages/akismet.5.3"
    },
    "risk_contribution": 0,
    "issues": []
  }
}
```

### Risk contribution values

| Situation | Risk |
|---|---|
| Checksum verified | 0 |
| No reference found (ecosystem not supported or API unavailable) | 50 |
| Checksum mismatch | 500 |
| Skipped (`--skip` flag) | 0 (not penalised) |

---

## 💡 Examples

```bash
# WordPress plugin — auto-detect identity and verify
./checksum-verify.sh akismet.5.3.zip

# WordPress plugin — explicit identity + extract
./checksum-verify.sh \
  --source-type wordpress \
  --wp-plugin akismet --wp-version 5.3 \
  --extract \
  akismet.5.3.zip

# npm package
./checksum-verify.sh --source-type npm lodash-4.17.21.tgz

# Hash only (no API lookup)
./checksum-verify.sh --skip akismet.5.3.zip

# Silent JSON — pipe to jq
./checksum-verify.sh -sj akismet.5.3.zip \
  | jq '.crypto_verification.verification.status'

# Pre-seed identity when auto-detection would fail
./checksum-verify.sh \
  --source-type wordpress \
  --pkg-name akismet --pkg-version 5.3 \
  my-renamed-archive.zip
```

---

## ⚠️ Known Limitations

- SHA-384 and SHA-512 require `sha384sum` / `sha512sum` to be installed. On macOS, these are provided by GNU coreutils (`brew install coreutils`). The script notes their absence rather than failing.
- Packagist distributes SHA-1 checksums for most releases; SHA-1 is noted in the output but not used as the primary verification algorithm given its collision weakness.
- Per-file WordPress checksum verification requires the plugin to be extractable as a zip and for the `/plugin-checksums/` endpoint to return data for the specific version. Older versions may not have per-file checksums available.
- Network requests time out after 15 seconds. On slow connections, the API lookup may fail and the script will report the checksum as unverifiable (risk: 50) rather than failing entirely.

---

<sub>Scripts licensed MIT · Documentation [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) · © Package Profiler Contributors</sub>
