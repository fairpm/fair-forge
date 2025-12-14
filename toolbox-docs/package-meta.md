# Package Metadata

This Document:
| Purpose      | Updated    | Status |
| ------------ | ---------- | ------ |
| Project Spec | 2025-12-1e | Draft  |

**Important:** this document contains extensions to the Package Metadata defined in the FAIR Protocol specification. Where this occurs, it will need to be resolved in the documentation, noting that some of it may be WordPress-specific and form part of the WordPress Extension to the FAIR Protocol rather than being reflected in the core protocol. It is _expected_ that the implementation described below will be subject to change during development of the Forge toolset.

Relevant sections of the [FAIR Protocol](https://github.com/fairpm/fair-protocol/tree/main) include:
- (Package) [Metadata Document](https://github.com/fairpm/fair-protocol/blob/main/specification.md#metadata-document)
- [JSON Schema for FAIR Package Metadata Document](https://github.com/fairpm/fair-protocol/blob/main/schemas/metadata.schema.json)
- [FAIR for WordPress Packages](https://github.com/fairpm/fair-protocol/blob/main/ext-wp.md) (WordPress-specific protocol extensions)

The JSON-formatted **Package Metadata document** is to be cryptographically signed by the publisher.

# Package Metadata Document

| Key             | Value                |
| --------------- | -------------------- |
| `id`            | DID                  |
| `type`          | string, package type |
| `license`       | SPDX format          |
| `authors`       | json                 |
| `security`      |                      |
| `releases`      | Release Document     |

> ## Release Document
> | Key              | Value             |
> | ---------------- | ----------------- |
> | `version`        | string            |
> | `artifacts`      | json object       |

>> ## Artifacts JSON Object
>> | Key             | Value             |
>> | --------------- | ----------------- |
>> | `id`            |                   |
>> | `content-type`  | MIME type         |
>> | `requires-auth` | bool              |
>> | `url`           | url string        |
>> | `signature`     |                   |
>> | `checksum`      |                   |

> | Key              | Value             |
> | ---------------- | ----------------- |
> | `provides`       | json map          |
> | `requires`       | json object       |
> | `suggests`       | json map          |
> | `auth`           | json map          |
> | `_links`         |                   |
> | `tested_to`      | string            |
> | `min_php_ver`    | string            |
> | `upgrade_notice` | string            |
> | `multisite`      | bool              |
> | `update_url`     | URL               |

| Key             | Value                |
| --------------- | -------------------- |
| `slug`          | string               |
| `name`          | string               |
| `description`   | string               |
| `keywords`      | comma-separated list |
| `sections`      | sections document    |

> ## Sections Document
> | Key           | Value                |
> | ------------- | -------------------- |
> | `changelog`   |                      |
> | `description` | long description     |
> | `security`    |                      |
> | `faq`         |                      |
> | `screenshots` |                      |
> | `plugin_uri`  |                      |
> | `revenue_model` | Revenue Model Doc  |

>> ## Revenue Model Document
>> | Key           | Value               |
>> | ------------- | ------------------- |
>> | `model`       | string              |
>> | `URL`         | URL string          |
>> | `description` | feature comparison  |
>> | `payments`    | info / gateway      |

| Key             | Value                |
| --------------- | -------------------- |
| `_links`        |                      |


## Repository Document

| Key             | Value                |
| --------------- | -------------------- |
| `name`          |                      |
| `maintainers`   |                      |
| `security`      |                      |
| `privacy`       |                      |
| `_links`        |                      |



# External Sources

## DID Document
The [DID Document](https://github.com/fairpm/fair-protocol/blob/main/specification.md#did-document) contains a URL for the Repository, from which the Package Metadata Document is retrieved.
| Key                  | Value                                                  |
| -------------------- | ------------------------------------------------------ |
| `id`                 | {The DID}                                              |
| `alsoKnownAs`        | {Domain Alias, if any}                                 |
| `service`            | `id:` #fairpm_repo<br>`endpoint:` https://repo-url.tld/package/something/<br>`type:` FairPackageManagementRepo |
| `verificationMethod` | `controller`<br>`id`<br>`publicKeyMultibase`<br>`type` |



## License

This page is **CC BY 4.0** https://creativecommons.org/licenses/by/4.0/

