# Validation Toolchain

This toolchain consists of tools for validating the various attributes of a package. Given a package with FAIR-formatted meta, the toolchain will generate metadata for use in assigning a trust score, including evaluation of whether a package (or release) should be accepted for FAIR federation and aggregation. The same tools are run on the package, regardless of its origin. Validation tools are run internally on the package itself, largely but not exclusively focused on security, compliance, and coding practices.

## Validation Tools

### Checksum & Signature Validator
- Confirm checksum accuracy
- Confirm package & metadata signature

### Static Checks: PHPCS Code Scan
- Same code-scanning checks as run for .org repo
- PHP version min/max check

### Other Static Scans
- Safe file permissions
- No API keys or undisclosed affiliate links/codes

### Runtime Checks
- No unexpected filesystem modification
- No unexpected http calls

### Direct Malware Detection
- Scan for known exploits
- Heuristic malware scans

### SBOM Validation
- Confirm SBOM is present & properly formatted

### Package Metadata Validation
- Confirm required metadata is present and properly formatted

