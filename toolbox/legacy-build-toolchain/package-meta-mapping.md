# Package Metadata Mapping

## .org Requirements & Sources
### [Plugin Readmes](https://developer.wordpress.org/plugins/wordpress-org/how-your-readme-txt-works/)
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

### [Plugin Headers](https://developer.wordpress.org/plugins/plugin-basics/header-requirements/)
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


## FAIR Package Meta Requirements

See [FAIR Metadata Document specification](https://github.com/fairpm/fair-protocol/blob/main/specification.md#metadata-document)

| Property | Req'd | Constraints           | In WP Meta?   |
| -------- | ----- | --------------------- | ------------- |
| id       | yes   | A valid DID           | no, can add   |
| type     | yes   | string, package type. | no, can infer |
| [license](https://github.com/fairpm/fair-protocol/blob/main/specification.md#license) | yes | A string that conforms to the rules of license | yes |
| [authors](https://github.com/fairpm/fair-protocol/blob/main/specification.md#authors) | yes | A list that includes name with optional url and email |  yes |
| [security](https://github.com/fairpm/fair-protocol/blob/main/specification.md#security) | yes | A list that conforms to the rules of security |  no, can infer |
| [releases](https://github.com/fairpm/fair-protocol/blob/main/specification.md#releases) | yes | A formatted [Release Document](https://github.com/fairpm/fair-protocol/blob/main/specification.md#release-document) |  yes |
| [slug](https://github.com/fairpm/fair-protocol/blob/main/specification.md#slug) | no | A string that conforms to the rules of slug | yes |
| [name](https://github.com/fairpm/fair-protocol/blob/main/specification.md#name) | no | A string. |  yes |
| [description](https://github.com/fairpm/fair-protocol/blob/main/specification.md#description) | no | A string. | yes |
| keywords | no | A json list of strings, recommend up to 5 | yes, tags |
| [sections](https://github.com/fairpm/fair-protocol/blob/main/specification.md#sections) | no | A json map with defined keys for changelog, description, security; may include others | yes, yes, no |
| [_links](https://github.com/fairpm/fair-protocol/blob/main/specification.md#_links) | no | [HAL links](https://datatracker.ietf.org/doc/html/draft-kelly-json-hal-11), with [defined relationships](https://github.com/fairpm/fair-protocol/blob/main/specification.md#links-metadata) | - |




# Mapping: Create FAIR Metadata formats from Legacy Package Sources

## (Package) Metadata Document

| FAIR Meta   | Explicit?     | Source                              | FAIR Format        |
| ----------- | ------------- | ----------------------------------- | ------------------ |
| id          | Yes, Assigned | internally-generated                | DID:PLC or DID:Web |
| type        | Yes           | `wp-plugin` `wp-theme` or `wp-core` |  string            |
| license     | Infer/convert | readme.txt & plugin headers         | [SPDX License Expression](https://spdx.github.io/spdx-spec/v3.0.1/annexes/spdx-license-expressions/); the protocol doesn't call for a url or license file, but should be included; make this json instead? WP meta has License URI & should contain a file copy |
| authors     | Yes           | `contributors` in readme.txt & `authors` in plugin headers; extend via profiles.wordpress.org/[username] |
| security    | Yes           | Use author/contributor if individual, else WordPress.org url | json doc with author name, url, email if available; social media links; if Bluesky link available, add user's DID:PLC |
| releases    | Yes           | Change Log from readme.txt, SVN     | Release Document   |
| slug        | Yes           | .org Source                         |                    |
| name        | Yes           | `readme.txt` & plugin headers       |                    |
| [description](https://github.com/fairpm/fair-protocol/blob/main/specification.md#description) | Yes | short description from `readme.txt` | string |
| [keywords](https://github.com/fairpm/fair-protocol/blob/main/specification.md#keywords) | Yes | tags frome `readme.txt` | comma-separated list |
| [sections](https://github.com/fairpm/fair-protocol/blob/main/specification.md#sections) | Yes | (various) | [Sections Document](#sections-document) |
| _links      | no; infer?    |                                     |                    |


## DID Document

Refer to [DID Document](https://github.com/fairpm/fair-protocol/blob/main/specification.md#did-document) in the FAIR Protocol. The DID document should contain:
- `id` : DID:PLC or DID:Web
- `alsoKnownAs` : Domain Alias, if any
- `service` : id, endpoint, type
- `verificationMethod` : includes `publicKeyMultibase` key value

*Also added to [FAIR Forge Meta Document](toolbox/fair-forge-meta.md).


## Sections Document

| Key              | Data Source                         | Value, FAIR Format   |
| ---------------- | ----------------------------------- | -------------------- |
| `changelog`      | `readme.txt`                        | predefined           |
| `description`    | long descriptioon from `readme.txt` | predefined           |
| `security`       | security.md if available            | predefined           |
| `faq`            | `readme.txt`                        | extended             |
| `screenshots`    | `readme.txt`                        | extended             |
| `plugin_uri`     | plugin headers                      | extended             |
| `revenue_model`  | business model & donation link      | extended as json doc |


## Release Document

| Key            | Req'd | Constraints | Source                              | Value, FAIR Format                  |
| -------------- | ----- | ----------- | ----------------------------------- | ----------------------------------- |
| version        | yes   | string      | Current version from plugin headers | string                              |
| [artifacts](https://github.com/fairpm/fair-protocol/blob/main/specification.md#artifacts) | yes  | json map | scan release files? | [json object](#artifacts-json-object) |
| [provides](https://github.com/fairpm/fair-protocol/blob/main/specification.md#property-provides) | no* | json map | [package type](https://github.com/fairpm/fair-protocol/blob/main/specification.md#property-type) (wp-theme, wp-plugin)  | |
| [requires](https://github.com/fairpm/fair-protocol/blob/main/specification.md#property-requires) | no* | json object | `Requires Plugins` in plugin headers |
| suggests       | no*   | json map     |  may be available for themes        | same format as [requires](https://github.com/fairpm/fair-protocol/blob/main/specification.md#property-requires) |
| auth           | no*   | json map     |  n/a for legacy packages             | bool `false` |
| _links         | no*   |  [HAL links](https://datatracker.ietf.org/doc/html/draft-kelly-json-hal-11), with [defined relationships](https://github.com/fairpm/fair-protocol/blob/main/specification.md#links-metadata); links to Repository & Metadata Documents  |none; infer? | URLs for Repository & Meta Document |
| tested_to      | no*   | string       | `readme.txt`                        | string                              |
| min_php_ver    | no*   | string       | `readme.txt`                        | string                              |
| upgrade_notice | no*   | string       | `readme.txt`                        | string                              |
| multisite      | no*   | string       | plugin headers                      | bool                                |
| update_url     | yes   | string       | plugin headers                      | URL                                 |

*Populate for legacy .org packages if data is available.


## Repository Document

| Key            | Req'd | Constraints | Data Source                           | Value, FAIR Format                           |
| -------------- | ----- | ----------- | ------------------------------------- | -------------------------------------------- |
| name           | yes   | string      | Repository name, not package name     | `FAIR Package Mirror`                        |
| [maintainers](https://github.com/fairpm/fair-protocol/blob/main/specification.md#maintainers) | yes | json list (name, url, email) | generated | use `fair.pm` |
| security       | yes   | json list   | generated                             | `fair.pm`                                    |
| privacy        | yes   | URL string  | generated                             | `https://fair.pm/governance/privacy-policy/` |
| _links         | no*   | [HAL links](https://datatracker.ietf.org/doc/html/draft-kelly-json-hal-11) | generated | `fair.pm` |

*Populate for legacy .org packages.


## Revenue Model Document

*This is an extension to the FAIR Protocol specification and replaces the existing (optional) WordPress meta fields for `business model` and `donation link`.

**json format document** containing:
- one of: none, donation, freemium, paid-extensions, saas-subscription, commercial; default is none.
- Plugin Website URL
- long description; recommend feature comparison, donation appeal, SaaS
- payment info / gateway


## Artifacts JSON Object

All values are optional, but at least one must exist. Refer to [FAIR artifacts specification](https://github.com/fairpm/fair-protocol/blob/main/specification.md#artifacts).

| Key           | Source     | Value, FAIR Format |
| ------------- | ---------- | ------------------ |
| id            | n/a        |                    |
| content-type  | file scan? | MIME type          |
| requires-auth | n/a, false | bool               |
| url           | infer      | url for the asset  |
| signature     | generate   |                    |
| checksum      | generate   | sha256 or sha384   |


**Package Meta** --> autogenerated labels to be used for faceted search & sorting of paginated results

- multisite support
- date last updated
- date of first release
- package type
- author/maintainer
- license
- revenue model
- PHP max version (negative selector)

*Add to [FAIR Forge Meta Document](toolbox/fair-forge-meta.md) as `fair_forge_meta_labels`.

