# FAIR Forge Toolbox Documentation
<!-- TOC START -->
<!-- TOC END -->

This Document:
| Purpose          | Updated    | Status |
| ---------------- | ---------- | ------ |
| Project Overview | 2025-12-13 | Draft  |

The FAIR Forge Toolbox contains three toolchains. One of these is used to prepare non-FAIR packages for evaluation and federation, while the other two are used to check compliance, security, and code quality in order to create metadata for use in calculatng trust signals and evaluating the package's suitability for federation. The relationshp, function, and purpose of these toolchains are described and illustrated below, with build requirements shown as functional specifications in the subdirectories here.

**Terminology Note:** The words "validate" and "verify" (validation and verification) have a significant degree of semantic overlap in English. While there is a distinction between them in technical contexts, it is a nuanced one, and is not held consistently in a non-technical context, where the nuance may be reversed, or more commonly, ignored. In order to ensure these terms are properly understood and translated, the nuance between them is ignored here, and where the terms are used, explanations should be provided to clarify what is intended in context.

Within the documents, certains words may be intentionally capitalized to indicate they are defined terms within FAIR's usage.

## FAIR Forge's Technical Architecture

FAIR Forge is designed for modular use, with tools being run according to a configured request defining which results are being requested of the toolchain(s).

## FAIR Forge Toolchains

### Legacy Package Build

This toolchain is used to convert a Package mirrored from WordPress.org from its "legacy" format, rebuilding it in the format used by the FAIR Protocol. This step involves adding security headers to the plugin, identifying it by a DID, creating a metadata document, cryptographically signing the Package and the Metadata Document, and publishing checksums for both. An official SBOM is not required in the legacy format, and while FAIR does not certify it to be complete, an _observed_ SBOM will be generated listing what can be detected within the package. This repackaging process enables FAIR to mirror and federate it in the same standardized way as all other packages. The resulting Package can be consistently rebuilt and is presented as a "true" copy of the original, though it will no longer be a "bit-for-bit" copy.

### Intrinsic Verification

Intrinsic validation tools consist of checks that can be run internally, directly referencing the code. Static code scans, Package Meta Documment formatting checks, direct malware scans, and runtime checks in an isolated environment are examples of Intrinsic Validation tests forming a part of this toolchain. Detecting that an email address is present where required as contact information and that it is properly formatted with a recognized TLD might result in it being "valid" based on intrinsic checks. To ensure that the email address is actually _deliverable_ and is not a disposable one requires an external, or third-party check to make sure it is "valid".[^1]

[^1]: Note the term has different meanings when marking an email address as "valid", illustrating the need to avoid it as vague. In this context, it means both "properly formatted" and "deliverable". The second meaning requires the first be also true, but the first meaning does not require the second.

### Third-Party Verification

This toolchain is used to check various Attestations from the Package Metadata against third party, or external, sources to convirm thier accuracy and compile other information used in evaluating the Package and assigning a Trust Score. In addition to direct attestation checks, additional inferred checks are also done. For example, the domain hosting a package must exist and return a 200 result via https, which can be verified by direct checks. An inferred check that may also be done would be to check the domain for listings on common RBLs to assess its reputation. Third party verification by FAIR includes both types, and requires external verifications points rather than intrinsic ones.

### Forge Toolchains Diagram

<img width="634" height="692" alt="FAIR-Forge-Components" src="https://github.com/user-attachments/assets/5a928bfb-7789-4594-b489-4e7a912bdaca" />

### Utilities

Additional tools are considered for use in the Forge toolchain that are expected to have uses outside of Forge, either for standalone uses or for inclusion as a library or class in another project. The DID Manager is an example.

## Human Review

Some steps in the process of validating Packages, evaluating them for federation, and confirming a final Trust Score will require human review. Some of these may eventually be partly automated in the toolchains, however for a variety of reasons FAIR is choosing to begin these checks manually. We do not at this time envision removing a human review step from the process.

## Reference Standards & Specs for Attestations, Provenance, SBOMs
- [in-toto](https://in-toto.io/)
- [SLSA • Software attestations](https://slsa.dev/spec/v1.1/attestation-model) 
- [SLSA • Distributing provenance](https://slsa.dev/spec/v1.1/distributing-provenance)
- [The System Package Data Exchange™ (SPDX®)](https://spdx.dev/)



## License
This page is **CC BY 4.0** https://creativecommons.org/licenses/by/4.0/
