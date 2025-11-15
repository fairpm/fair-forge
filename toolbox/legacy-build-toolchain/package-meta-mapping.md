
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


