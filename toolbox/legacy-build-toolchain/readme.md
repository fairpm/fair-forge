# Legacy Build Toolchain

This toolchain consists of tools for taking a WordPress package (plugin or theme) from the legacy Subversion repository and (re)building it as a package formatted according to the FAIR protocol. The result will be a _true copy_ of the original package with properly formed metadata. Since the legacy WordPress respository requirement omits data required by the FAIR Protocol, some may be reasonably inferred or omitted if necessary.

## Legacy Build Tools

Received packages are presumed to have been verified by WordPress.org using [Plugin Check](https://github.com/WordPress/theme-check/tree/master/checks) or [Theme Check](https://github.com/WordPress/plugin-check/tree/trunk) processes from the Plugins Team or Themes Team. The intent is that they "inherit" trust from .org verification processes and can safely be mirrored. These packages will nevertheless be passed through other toolchains to perform more stringent checks.

### Step 1: File Preparation
  - Unzip/decompress received archives if necessary
  - Check received/unpacked files for anything world-writable (octal - - 6 or - - 7)
  - Log result & correct file permissions as needed
  - Output logged results as json to new build-meta by DID

### Step 2: DID Check & Assign
  - Check for any DID advertised within the received package
  - If none, assign DID:PLC or DID:Web (TBD)
  - Create detailed DID record
  - Append json output to build-meta
  - Create (empty) FAIR-formatted (json) package-meta with DID

### Step 3: Supplied Meta & Readme Parser
  - Same parsing as is done on .or
  - Output FAIR-formatted json to package-meta

### Step 4: Contact Info Parser
  - Publisher contact
  - Security contact & VDP
    - Create security.md if missing
  - Support channel
  - Append contact info to package-meta & build-meta

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

## Package Metadata Mapping

### .org Requirements
#### [Plugin Readmes](https://developer.wordpress.org/plugins/wordpress-org/how-your-readme-txt-works/)
  - Plugin Name
  - Contributors (comma-separated list of wordpress.org usernames)
  - Tags (comma-separated list of 1-12 tags describing the plugin; only first 5 show, more than 12 detrimental to SEO)
  - Donate Link
  - License
  - License URI
  - Required WordPress version (minimum)
  - Tested up to (highest WP version tested)
  - Required PHP version (minimum)
  - Stable tag (latest stable subversion tag; default "trunk")
  - Short Description (2-3 sentences, 150 characters, no markup)
  - Long Description (full description, no character limit)
  - Installation (instruction)
  - FAQ
  - Screenshot(s)
  - Change Log (list changes by most recent)
  - Upgrade Notice (why user should upgrade, up to 300 characters)
Max readme.txt file size is 10k for .org
[Plugin Readme Generator](https://generatewp.com/plugin-readme/)

#### [Plugin Headers](https://developer.wordpress.org/plugins/plugin-basics/header-requirements/)
- Plugin Name
- Plugin URI
- Description (short)
- Version (current)
- Requires at least (minimum WP version)
- Requires PHP (minimum PHP version)
- Author (comma-separated if multiple)
- License
- License URI
- Text Domain
- Domain Path (used for locating translations)
- Network (if network activation is supported)
- Update URI (used for disambiguation of slugs, [per dev note](https://make.wordpress.org/core/2021/06/29/introducing-update-uri-plugin-header-in-wordpress-5-8/))
- Requires Plugins (comma-separated list of wp slugs) [per dev note](https://make.wordpress.org/core/2024/03/05/introducing-plugin-dependencies-in-wordpress-6-5/))


### [FAIR Metadata Document](https://github.com/fairpm/fair-protocol/blob/main/specification.md#metadata-document)

| Property | Required? | Constraints | In WP Meta? |
| -------- | --------- | ----------- | ----------- |
| id | yes | A valid DID. | no, can add |
| type | yes | A string that conforms to the rules of type. | no, can infer |
| license | yes | A string that conforms to the rules of license | yes |
| [authors](https://github.com/fairpm/fair-protocol/blob/main/specification.md#authors) | yes | A list that includes name with optional url and email |  yes |
| [security](https://github.com/fairpm/fair-protocol/blob/main/specification.md#security) | yes | A list that conforms to the rules of security |  no, can infer |
| [releases](https://github.com/fairpm/fair-protocol/blob/main/specification.md#releases) | yes | A formatted [Release Document](https://github.com/fairpm/fair-protocol/blob/main/specification.md#release-document) |  yes |
| [slug](https://github.com/fairpm/fair-protocol/blob/main/specification.md#slug) | no | A string that conforms to the rules of slug | yes |
| [name](https://github.com/fairpm/fair-protocol/blob/main/specification.md#name) | no | A string. |  yes |
| [description](https://github.com/fairpm/fair-protocol/blob/main/specification.md#description) | no | A string. | yes |
| keywords | no | A json list of strings, recommend up to 5 | yes, tags |
| [sections](https://github.com/fairpm/fair-protocol/blob/main/specification.md#sections) | no | A json map with defined keys for changelog, description, security; may include others | yes, yes, no |
| [_links](https://github.com/fairpm/fair-protocol/blob/main/specification.md#_links) | no | [HAL links](https://datatracker.ietf.org/doc/html/draft-kelly-json-hal-11), with [defined relationships](https://github.com/fairpm/fair-protocol/blob/main/specification.md#links-metadata) | - |

#### Release Document

| Property    | Required? | Constraints                                                          | In WP Meta? |
| ----------- | --------- | -------------------------------------------------------------------- | ----------- |
| version     | yes       | A string per [version](#property-version)  | yes |
| artifacts   | yes       | A json map per [artifacts](#property-artifacts) | no |
| provides    | no        | A json map per [provides](#property-provides)   | no, package type |
| requires    | no        | A json map per [requires](#property-requires)   | maybe, dependencies |
| suggests    | no        | A json map per [suggests](#property-suggests)   | no |
| auth        | no        | A json map per [auth](#property-auth) authentiation if required with type, hint, hint_url | no |
| _links      | no        | [HAL links][hal], with [defined relationships](#links-release); link to Repository Document & Metadata Document | no |

#### Repository Document

| Property    | Required? | Constraints                                                                    | In WP Meta? |
| ----------- | --------- | ------------------------------------------------------------------------------ | ----------- |
| name        | yes       | A string.                                                                      | no |
| maintainers | yes       | A json list per [maintainers](#property-repo-maintainers) (name, url, email) | yes, authors |
| security    | yes       | A json list per [security](#property-repo-security)       | no, infer |
| privacy     | yes       | A URL string; link to repo's privacy policy                                    | no |
| _links      | no        | [HAL links][hal], with [defined relationships](#links-repo)                    | no |


