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
  - [Plugin-Check GitHub Action](https://github.com/WordPress/plugin-check-action)
- PHPCS scan using .org rules with FAIR additions:
  - Plugin-Check / [phpcs-rulesets (XML)](https://github.com/WordPress/plugin-check/tree/trunk/phpcs-rulesets) & [Sniffs/CodeAanalysis](https://github.com/WordPress/plugin-check/tree/trunk/phpcs-sniffs/PluginCheck/Sniffs/CodeAnalysis)
  - [PHPCSStandards](https://github.com/PHPCSStandards)
  - [PHP_CodeSniffer](https://github.com/PHPCSStandards/PHP_CodeSniffer)
  - PHP version min/max check
  - Core version min/max check
  - [PHPCompatibility](https://github.com/PHPCompatibility)
    - [PHPCompatibility/PHPCompatibility](https://github.com/PHPCompatibility/PHPCompatibility) : PHP Compatibility check for PHP\_CodeSniffer (php 5.0 to current)
    - [PHPCompatibility/PHPCompatibilityWP](https://github.com/PHPCompatibility/PHPCompatibilityWP) : PHPCompatibility ruleset for WordPress projects
- Confirm no API keys or undisclosed affiliate links/codes
- [AboutCode · GitHub](https://github.com/aboutcode-org) Python CLI Tools, Apache & AGPL licensing
- Report only (may or may not violate guidelines):
  - http calls using wp_ functions, curl, php, or exec functions
  - Enqueued or hard-coded files from remote sources
- Append results to build-meta per spec

### 3. Malware Detection
- Scan for known exploits
- [aboutcode-org/vulnerablecode:](https://github.com/aboutcode-org/vulnerablecode) free and open vuln db
- Heuristic malware scan
- _e.g._, [DataDog GuardDog](https://github.com/DataDog/guarddog) CLI tool to Identify malicious PyPI and npm packages (no php); includes GitHub actions
- [MISP Open Source Threat Intelligence Platform & Open Standards For Threat Information Sharing](https://www.misp-project.org/)
  - [MISP Project · GitHub](https://github.com/misp) (Python 3, AGPL)
  - [MISP Modules Documentation](https://misp.github.io/misp-modules/)
  - [MISP Modules for expansion services, enrichment, import and export in MISP and other tools.](https://github.com/MISP/misp-modules) includes CVE lookups, DNS, domain tools, [IPinfo.io](https://ipinfo.io/developers) RBL lookup, EUPI Phishing Initiative, [Google Threat Intelligence](https://gtidocs.virustotal.com/reference/api-overview) and [VirusTotal](https://www.virustotal.com/gui/home/upload) APIs, [Have I Been Pwned](https://haveibeenpwned.com/), [IP Intelligence IPQS](https://www.ipqualityscore.com/), Socialscan, _etc_.
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
- Fuzz Testing:
  - [GitHub - nikic/PHP-Fuzzer: Experimental fuzzer for PHP libraries](https://github.com/nikic/PHP-Fuzzer)
  - [Phuzz Modular & Open-Source Coverage-Guided Web Application Fuzzer for PHP](https://github.com/gehaxelt/phuzz)
  - [WPGarlic: A proof-of-concept WordPress plugin fuzzer](https://github.com/kazet/wpgarlic)
- Performance checks; _e.g._, [Code Profiler](https://wordpress.org/plugins/code-profiler/) / [Code Profiler](https://nintechnet.com/codeprofiler/)
- Possible environment: [Katakate/k7](https://github.com/Katakate/k7) self-hosted infra for lightweight VM sandboxes to safely execute untrusted code
- Append results to build-meta per spec

### 6. Compliance
- Confirm required metadata is present and properly formatted
  - Publisher Contact
  - Support contact
  - Security contact
- SBOM Validation
  - [ScanCode](https://github.com/aboutcode-org/scancode-toolkit) detects licenses, copyrights, dependencies to discover and inventory open source and third-party packages used.
  - [OSS Review Toolkit / ORT](https://github.com/oss-review-toolkit/ort) suite of tools to automate software compliance checks; [Related Tools | OSS Review Toolkit](https://oss-review-toolkit.org/ort/docs/related-tools) (Bash script, GitHub action, GitLab pipeline, desktop app)
- Append results to build-meta per spec

