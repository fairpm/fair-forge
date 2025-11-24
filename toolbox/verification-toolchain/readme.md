# Verification Toolchain

This toolchain consists of tools for verifying the various attestations about a package. Given a package with FAIR-formatted meta, the toolchain will generate metadata for use in assigning a trust score, including evaluation of whether a package (or release) should be accepted for FAIR federation and aggregation. The same tools are run on the package, regardless of its origin. Verification tools are run to verify attestations against external sourcees.


## Verification Tools


### 1. Package Integrity
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
- Append results to fair-forge-meta per spec

### 2. DID & Domain Verification
- Verify DID Document
- Verify DNS for domain alias, if provided
- If MX record exists, verify DNS includes SPF, DMARC, DKIM
- Check domain reputation (e.g., [Spamhaus](https://www.spamhaus.org/domain-reputation/), [Cisco Talos](https://www.talosintelligence.com/reputation_center), [APIVoid](https://www.apivoid.com/api/domain-reputation/), _etc._)
- RBL check for domain
- Append results to fair-forge-meta per spec


### 3. Provenance & Attestation Checks
- Check for VDP
- CRA Compliance TBD
- License compatibility
  - [Open Definition Licenses API](https://opendefinition.org/licenses/api/)
  - [OSI Approved License API](https://opensource.org/blog/introducing-the-new-api-for-osi-approved-licenses)
  - Verify [GPL compatibility](https://www.gnu.org/licenses/license-list.html) (FSF List)
- Verify contact info
  - Verify email addresses are deliverable: roll our own or use APIs like (e.g.) [Verifalia](https://verifalia.com/developers), [Email Hippo](https://tools.emailhippo.com/), or [VerifyMail](https://verifymail.io/) 
  - Verify no disposable email addresses; roll our own or use APIs such as [Email Hippo](https://tools.emailhippo.com/Apps/Disposable_Email_Address_Detector) or [DeBounce](https://debounce.io/free-disposable-check-api/)
  - Verify URLS provided are live and contain the required contact information
- [WordPress Plugin Attestation](https://github.com/johnbillion/action-wordpress-plugin-attestation) Github action by John Blackbourn
- Append results to fair-forge-meta per spec


### 4. CVE Checks
- Check published CVE lists for package using available APIs
  - Patchstack API
  - [Snyk Vulnerability Database](https://security.snyk.io/)
  - [WPVulnerability Database API](https://www.wpvulnerability.com/) free API; Javier Casares & other contributors
  - [OpeCVE](https://www.opencve.io/) ([docs](https://docs.opencve.io/)) self-hosted or SaaS app to monitor CVEs
  - [Wordfence Intelligence](https://www.wordfence.com/products/wordfence-intelligence/) / [API Docs](https://www.wordfence.com/help/wordfence-intelligence/v2-accessing-and-consuming-the-vulnerability-data-feed/)
  - [Prototype CVE Labeller](https://github.com/fairpm/cve-labeller)
  - [WP-CLI Vulnerability Scanner (10Up)](https://github.com/10up/wpcli-vulnerability-scanner) (Supports [WPScan](https://wpscan.com/)/[WP Vuln DB](http://wpvulndb.com/), [Patchstack](https://patchstack.com/), [WordFence Intelligence](https://www.wordfence.com/threat-intel/)
- Check time from exposure to patch for past CVEs
- Append results to fair-forge-meta per spec


### 5. Repo Profiler
- 2FA enabled/required
- VDP listed
- Uses dependabot & plugin check actions
- Count number of contributors in past _n_ months
- Count number of commits/releases in past _n_ months
- Repo age
- Changelog for all releases
- https enforced _e.g._, [testssl.sh](https://github.com/span/testssl.sh) or curl, _etc._ and check port 80 is closed or redirected
- Append results to fair-forge-meta per spec


### 6. Label Application
- Apply labels inferred from package-meta & fair-forge-meta
- Apply subscribed third-party labels for the package
- Append results to fair-forge-meta per spec


