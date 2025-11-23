# Package Meta

| Key             | Value                |
| --------------- | -------------------- |
| `id`            | DID Document         |

> ## DID Document
> | Key           | Value                |
> | ------------- | -------------------- |
> | `id`          | DID                  |
> | `alsoKnownAs` | Domain Alias         |
> | `service`     | id, endpoint, type   |
> | `verificationMethod` | includes `publicKeyMultibase` value |

| Key             | Value                |
| --------------- | -------------------- |
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

