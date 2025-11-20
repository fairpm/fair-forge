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
  - [Theme-Check](https://github.com/WordPress/theme-check/tree/master/checks)
  - [Plugin-Check](https://github.com/WordPress/plugin-check/tree/trunk)
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
- _e.g._, [DataDog GuardDog](https://github.com/DataDog/guarddog) CLI tool to Identify malicious PyPI and npm packages; includes GitHub actions
- Append results to build-meta per spec

### 4. AI Code Detection
- [AI Code Detector](https://www.code-detector.ai/detector) by [Span App](https://www.span.app/)
- [Botsniffer](https://github.com/oscarvalenzuelab/botsniffer)
- Append results to build-meta per spec
_(Relates to repo health: AI-generated code is less likely to be maintained unless it represents only a small percentage of the codebase.)_

### 5. Runtime Checks
- No unexpected filesystem modification
- No unexpected http calls
- No console errors
- No PHP errors or warnings
- Performance checks; _e.g._, [Code Profiler](https://wordpress.org/plugins/code-profiler/) / [Code Profiler](https://nintechnet.com/codeprofiler/)
- Append results to build-meta per spec

### 6. Compliance
- Confirm required metadata is present and properly formatted
  - Publisher Contact
  - Support contact
  - Security contact
- SBOM Validation
  - [ScanCode](https://github.com/aboutcode-org/scancode-toolkit) detects licenses, copyrights, dependencies to discover and inventory open source and third-party packages used.
  - [OSS Review Toolkit / ORT](https://github.com/oss-review-toolkit/ort) suite of tools to automate software compliance checks
- Append results to build-meta per spec

