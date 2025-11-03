# Toolbox

See Also: https://github.com/fairpm/trust/blob/FAIR-Trust-Model/fair-trust-model/to-do.md

The AspireBuild Toolbox contains three toolchains. One of these is used to prepare non-FAIR packages for evaluation and federation, while the other two are used to check compliance, security, and code quality in order to create metadata for use in calculatng trust signals and evaluating the package's suitability for federation. These relationshp and function of these toolchains within FAIR may be illustrated as follows.

![AspireBuild-Components](https://github.com/user-attachments/assets/71e9749f-ceae-4b18-8a12-040196e0e6b1)<?xml version="1.0" encoding="UTF-8" standalone="no"?>


## List of prior art, possible sources, & related resources.

### Vuln Check
- [WP-CLI vulnerability scanner](https://github.com/10up/wpcli-vulnerability-scanner) (GitHub) 10up/wpcli-vulnerability-scanner: WP-CLI command for checking installed plugins and themes for vulnerabilities | works with [WPScan](https://wpscan.com), [Patchstack](https://patchstack.com/) and [Wordfence Intelligence](https://www.wordfence.com/threat-intel/) to check reported vulnerabilities [wpvulndb.com](http://wpvulndb.com) = [wpscan.com](http://wpscan.com)
### Code Scanning
- **.org:** [WordPress/theme-check](https://github.com/WordPress/theme-check/tree/master/checks) (GitHub)
- **.org:** [WordPress/plugin-check](https://github.com/WordPress/plugin-check/tree/trunk) (GitHub) Plugin Check plugin from the WordPress Performance and Plugins Team.
- **.org:** [WordPress/plugin-check-action](https://github.com/WordPress/plugin-check-action) (GitHub) Test your WordPress plugin with Plugin Check as a GH Action
- [ScanCode](https://github.com/aboutcode-org/scancode-toolkit) (GitHub - aboutcode-org/scancode-toolkit) detects licenses, copyrights, dependencies to discover and inventory open source and third-party packages used.
- [oss-review-toolkit/ort](https://github.com/oss-review-toolkit/ort) (GitHub) suite of tools to automate software compliance checks
- [Tern (tern-tools/tern)](https://github.com/tern-tools/tern) (GitHub) is a software composition analysis tool and Python library that generates a Software Bill of Materials for container images and Dockerfiles. The SBOM that Tern generates will give you a layer-by-layer view of what's inside your container in a variety of formats including human-readable, JSON, HTML, SPDX and more.
- [DataDog GuardDog](https://github.com/DataDog/guarddog) - (GitHub) CLI tool to Identify malicious PyPI and npm packages; includes GitHub actions etc
### SBOMs
- [Software Transparency Foundation \| Open Source Knowledge Base](https://www.softwaretransparency.org/) 
- [SCANOSS SBOM Workbench](https://github.com/scanoss/sbom-workbench) (GitHub) The  graphical user interface to scan and audit your source code
- [SPDX – Linux Foundation Projects Site](https://spdx.dev/)
- [FossID Open Source Mastery](https://fossid.com/) 
- [WordPress Feature Project: Plugin Dependencies](https://github.com/WordPress/wp-plugin-dependencies) (GitHub)
- [Bomctl – Open Source Security Foundation](https://openssf.org/projects/bomctl/) 
- [Trustify](https://guac.sh/trustify/) 
### Other Scan / Build / Analyze Tools & Projects
- **.org:** [Performing Reviews – Make WordPress Plugins](https://make.wordpress.org/plugins/handbook/performing-reviews/)
- [OpenSSF Scorecard](https://scorecard.dev/) 
- [guac](https://guac.sh/guac/) = Graph for Understanding Artifact Composition
- [OpenCode Badge Program| openCode.de](https://opencode.de/en/knowledge/software-index/badges-en) 
### Standards & Specs for Attestations, Provenance, SBOMs
- [in-toto](https://in-toto.io/)
- [SLSA • Software attestations](https://slsa.dev/spec/v1.1/attestation-model) 
- [SLSA • Distributing provenance](https://slsa.dev/spec/v1.1/distributing-provenance)
### Runtime?
- [Code Profiler](https://wordpress.org/plugins/code-profiler/) WordPress Performance Profiling and Debugging Made Easy (WordPress.org)



