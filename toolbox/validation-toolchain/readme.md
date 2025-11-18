# Validation Toolchain

This toolchain consists of tools for validating the various attributes of a package. Given a package with FAIR-formatted meta, the toolchain will generate metadata for use in assigning a trust score, including evaluation of whether a package (or release) should be accepted for FAIR federation and aggregation. The same tools are run on the package, regardless of its origin. Validation tools are run internally on the package itself, largely but not exclusively focused on security, compliance, and coding practices.

## Validation Tools

### 1. Package & File Integrity
- Confirm checksum accuracy
- Confirm package & metadata signature
- Unzip or unpack archive file
- Check for anything unpacked as world-writeable (octal --6 or --7)
- Check for presence of required & recommended files:
  - `readme.txt`
  - `readme.md`
  - `security.md`
  - `contributing.md`
  - `code-of-conduct.md`
  - license file (e.g., GPL)
- Append results to build-meta per spec

### 2. Static Checks: PHP Code Scan
- Same code-scanning checks as run for .org repo
- PHPCS scan using .org rules with FAIR additions:
  - PHP version min/max check
  - Core version min/max check
- Confirm no API keys or undisclosed affiliate links/codes
- Report only (may or may not violate guidelines):
  - http calls using wp_ functions, curl, php, or exec functions
  - Enqueued or hard-coded files from remote sources
- Append results to build-meta per spec

### 3. Malware Detection
- Scan for known exploits
- Heuristic malware scan
- Append results to build-meta per spec

### 4. Runtime Checks
- No unexpected filesystem modification
- No unexpected http calls
- No console errors
- No PHP errors or warnings
- Append results to build-meta per spec

### 5. Package Meta Validation
- Confirm required metadata is present and properly formatted
  - Publisher Contact
  - Support contact
  - Security contact
  - SBOM
- Append results to build-meta per spec

