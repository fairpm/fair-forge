# Intrinsic Verification Toolchain

This toolchain consists of tools for verifying the various attributes of a package. Given a package with FAIR-formatted meta, the toolchain will generate metadata for use in assigning a trust score, including evaluation of whether a package (or release) should be accepted for FAIR federation and aggregation. The same tools are run on the package, regardless of its origin. Intrinsic verification tools are run internally on the package itself, largely but not exclusively focused on security, compliance, and coding practices.

## Intrinsic Verification Tools

### 1. Package Integrity
#### 1.1 Prepare Package for Analysis
- Confirm checksum accuracy (correct file, not corrupted)
- Confirm package & metadata signature (correct package & meta)
- Unzip or unpack archive file
#### 1.2 File Security
- Scan for anything unpacked as world-writeable
- Scan for mime-type mismatches
- Scan for binary files
- Scan for executable files
#### 1.3 Compliance & Best-Practice
- Check for presence of required & recommended files, case-insensitive `.txt` or `.md`:
  - `readme`
  - `security`
  - `contributing`
  - `code-of-conduct`
  - `license`

### 2. Package Meta Verification
- Confirm required meta fields are populated
- Confirm required metadata is present and properly formatted
  - Publisher Contact
  - Support contact
  - Security contact
- SBOM Verification
  - [ScanCode](https://github.com/aboutcode-org/scancode-toolkit) detects licenses, copyrights, dependencies to discover and inventory open source and third-party packages used.
  - [OSS Review Toolkit / ORT](https://github.com/oss-review-toolkit/ort) suite of tools to automate software compliance checks; [Related Tools | OSS Review Toolkit](https://oss-review-toolkit.org/ort/docs/related-tools) (Bash script, GitHub action, GitLab pipeline, desktop app)

### 3. SBOM Verification
- Scan for presence of SBOM files
- Parse SBOM(s) & compare if multiples present
- Run CVE check against dependencies

### 4. Static Checks: PHP Code Scan
- Similar code-scanning checks as run for .org repo with appropriate revisions for FAIR. _e.g._,
  - [Theme-Check](https://github.com/WordPress/theme-check/tree/master/checks)
  - [Plugin-Check](https://github.com/WordPress/plugin-check/tree/trunk)
  - [Plugin-Check GitHub Action](https://github.com/WordPress/plugin-check-action)
  - No use of `eval()` (same)
  - No code obfuscation tactics (same)
  - No direct database queries (same)
  - No embedded API keys or (undisclosed) affilliate links (similar)
  - .org ignores Update URIs that don't match a specific regex pattern (change/remove if present)
- PHPCS scan using .org rules with FAIR additions:
  - Security headers included
  - Plugin-Check / [phpcs-rulesets (XML)](https://github.com/WordPress/plugin-check/tree/trunk/phpcs-rulesets) & [Sniffs/CodeAanalysis](https://github.com/WordPress/plugin-check/tree/trunk/phpcs-sniffs/PluginCheck/Sniffs/CodeAnalysis)
  - [PHPCSStandards](https://github.com/PHPCSStandards)
  - [PHP_CodeSniffer](https://github.com/PHPCSStandards/PHP_CodeSniffer)
  - PHP version min/max check
  - Core version min/max check
  - [PHPCompatibility](https://github.com/PHPCompatibility)
    - [PHPCompatibility/PHPCompatibility](https://github.com/PHPCompatibility/PHPCompatibility) : PHP Compatibility check for PHP\_CodeSniffer (php 5.0 to current)
    - [PHPCompatibility/PHPCompatibilityWP](https://github.com/PHPCompatibility/PHPCompatibilityWP) : PHPCompatibility ruleset for WordPress projects
- Scan for dependencies / third-party libraries (verify against SBOM)
- No binaries present
- [AboutCode · GitHub](https://github.com/aboutcode-org) Python CLI Tools, Apache & AGPL licensing
- Flag / Report only (may or may not violate guidelines):
  - http calls using wp_ functions, curl, php, or exec functions
  - Enqueued or hard-coded files from remote sources: CDNs, Google fonts, _etc_. (possible GDPR implications)


### 5. Direct Malware Detection
- Scan for known exploits
- [aboutcode-org/vulnerablecode:](https://github.com/aboutcode-org/vulnerablecode) free and open vuln db
- Heuristic malware scan
- _e.g._, [DataDog GuardDog](https://github.com/DataDog/guarddog) CLI tool to Identify malicious PyPI and npm packages (no php); includes GitHub actions
- [MISP Open Source Threat Intelligence Platform & Open Standards For Threat Information Sharing](https://www.misp-project.org/)
  - [MISP Project · GitHub](https://github.com/misp) (Python 3, AGPL)
  - [MISP Modules Documentation](https://misp.github.io/misp-modules/)
  - [MISP Modules for expansion services, enrichment, import and export in MISP and other tools.](https://github.com/MISP/misp-modules) includes CVE lookups, DNS, domain tools, [IPinfo.io](https://ipinfo.io/developers) RBL lookup, EUPI Phishing Initiative, [Google Threat Intelligence](https://gtidocs.virustotal.com/reference/api-overview) and [VirusTotal](https://www.virustotal.com/gui/home/upload) APIs, [Have I Been Pwned](https://haveibeenpwned.com/), [IP Intelligence IPQS](https://www.ipqualityscore.com/), Socialscan, _etc_.


### 6. AI Code Detection
- [AI Code Detector](https://www.code-detector.ai/detector) by [Span App](https://www.span.app/)
- [Botsniffer](https://github.com/oscarvalenzuelab/botsniffer)
- Append results to fair-forge-meta per spec
_(Relates to repo health: AI-generated code is less likely to be maintained unless it represents only a small percentage of the codebase.)_


### 7. Runtime Checks
- Smoke Test, _e.g._, [PluginTests.com](https://plugintests.com/)
- No unexpected filesystem modifications
- No unexpected outbound http requests
- Flag outbound http requests to CDNs, Google fonts, _etc_. if not already logged from static scan
- No console errors
- No PHP errors or warnings in log
- Flag `deprecation` notices
- Flag `doing_it_wrong`
- Slow db queries
- Fuzz Testing:
  - [GitHub - nikic/PHP-Fuzzer: Experimental fuzzer for PHP libraries](https://github.com/nikic/PHP-Fuzzer)
  - [Phuzz Modular & Open-Source Coverage-Guided Web Application Fuzzer for PHP](https://github.com/gehaxelt/phuzz)
  - [WPGarlic: A proof-of-concept WordPress plugin fuzzer](https://github.com/kazet/wpgarlic)
- Performance checks; _e.g._, [Code Profiler](https://wordpress.org/plugins/code-profiler/) / [Code Profiler](https://nintechnet.com/codeprofiler/)
- Possible environments:
  - [Katakate/k7](https://github.com/Katakate/k7) self-hosted infra for lightweight VM sandboxes to safely execute untrusted code
  - [Playground CLI | WordPress Playground](https://wordpress.github.io/wordpress-playground/developers/local-development/wp-playground-cli/)
  - WP Playground, WASM; FAIR's self-hosted instance pending


### 8. Code Reference & Documentation Generator
Per Milana on our Slack discussion, [phpDocumentor](https://phpdoc.org/) ([on GitHub](https://github.com/phpDocumentor/phpDocumentor)) is used by .org to generate code reference, but the tool could do more.

> The most difficult and annoying part in writing docs is knowing what needs to be written, how, and where....
> I'd love to have a tool that would read annotations from DocBlock (a comment) and do the following:
> - Generates code reference (it's good, why not)
> - Generates changelog
> - Generates the structure for the Field guide
> - Creates GH isssues for docs that needs to be written, by docs type (dev note, end-user, how-to, guide, etc). Each type has own issue template and the tool knows which template to use. These templates should already exist (to create the standard of documenting open-source software) but should be possible for extending or completely overwriting.
> - Is easy to add to any project (not just WP) and can be up and running in 30 minutes.
> - Uses some kind of config file for easier abstraction.
> - Ideally, it scans through any language but for the start, PHP and JS would cover WordPress needs.
> 
> The idea is that every new code/feature needs to annotate for appropriate docs (this could be enforced with CI), and that annotation could be stripped off during packing distro process.

This can be helpful for FAIR's own releases, but could also be added as a FAIR Forge tool. Integrating with Beacon would allow it to create changelogs and documentation for each release, auto-publishing it to Beacon as a means of providing a minimum level of documentation for all FAIR-formatted packages.

