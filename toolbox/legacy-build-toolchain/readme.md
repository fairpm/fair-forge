# Legacy Build Toolchain

This toolchain consists of tools for taking a WordPress package (plugin or theme) from the legacy Subversion repository and (re)building it as a package formatted according to the FAIR protocol. The result will be a _true copy_ of the original package with properly formed metadata. Since the legacy WordPress respository requirement omits data required by the FAIR Protocol, some may be reasonably inferred or omitted if necessary.

## Legacy Build Tools

Received packages are presumed to have been verified by WordPress.org using [Plugin Check](https://github.com/WordPress/theme-check/tree/master/checks) or [Theme Check](https://github.com/WordPress/plugin-check/tree/trunk) processes from the Plugins Team or Themes Team. The intent is that they "inherit" trust from .org verification processes and can safely be mirrored. These packages will nevertheless be passed through other toolchains to perform more stringent checks.

### Step 1: File & Record Preparation
  - Unzip/decompress received archives if necessary
  - Scan for any DID advertised within the received package
  - If none, assign DID:PLC or DID:Web (TBD)
  - Create detailed DID record
  - Touch DID/package-meta
  - Touch DID/build-meta
  - Append json output to build-meta

### Step 2: File Permissions Fix
  - Check received/unpacked files for anything world-writable (octal - - 6 or - - 7)
  - Correct file permissions as needed
  - Append logged results as json to build-meta by DID

### Step 3: Supplied Meta & Readme Parser
  - (Approximately) Same parsing as is done on .org
  - Append FAIR-formatted json to package-meta & build-meta per spec

### Step 4: Contact Info Parser
  - Publisher contact
  - Security contact & VDP
    - Check supplied meta & available APIs, _e.g._, https://patchstack.com/database/api/v2/vdp/elementor
    - Create security.md if missing
  - Support channel
  - Append contact info to package-meta & build-meta per spec

### Step 5: Observed SBOM Generator
  - Code scan for dependencies & bundled libraries
  - Evaluate SBOM Generation tools for use or inspiration:
    - [Software Transparency Foundation](https://www.softwaretransparency.org/) | [OSSKB.org](https://www.softwaretransparency.org/osskb)
    - [SBOM Workbench](https://github.com/scanoss/sbom-workbench)
    - [FOSSID](https://fossid.com/)
    - [OpenSSF bomctl](https://openssf.org/projects/bomctl/) (LF Project)
    - [Guac](https://guac.sh/guac/) (LF Project)
    - [Guac Trustify](https://guac.sh/trustify/) (LF Project)
    - [The System Package Data Exchange (SPDX)](https://spdx.dev/) (LF Project)
    - [wp-plugin-dependencies](https://github.com/WordPress/wp-plugin-dependencies) (Contribs include @afragen & @cosdev) to parse a "Required Plugins" header; see [Feature Project: Plugin Dependencies](https://make.wordpress.org/core/2022/02/24/feature-project-plugin-dependencies/); if adopted, can scan headers for SBOM.
  - Create formatted SBOM (Likely [SPDX](https://spdx.dev/), possibly CycloneDX) _Important: SBOM will be tagged as _observed_ rather than authoritative since it's third-party generated_

### Step 6: Package Builder
  - Build meta with toolchain data
  - Generate checksums
  - Crypto sign package & meta documents
  - Append json results to build-meta
