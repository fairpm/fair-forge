# FAIR Forge Meta

This JSON metadata document is _separate_ from the publisher-provided (signed) **Package Meta**, and contains the meta collected by FAIR for use in evaluating the package to assign trust scores, approve for federation, apply labels, and catalogue the entry. 

| Key       | Req'd | Data Source                | Value, FAIR Format          |
| --------- | ----- | -------------------------- | --------------------------- |
| `id`      | yes   | package DID                | DID (cache DID document     |
| `package` | yes   | plugin slug                | package-forge-meta document |
| `release` | yes   | version from plugin header | release-forge-meta document  |


## Package Forge Meta Document

This JSON metadata document contains meta which relates to the package generally rather than to a specific release.

| Key                        | Req'd | Data Source                   | Value, FAIR Format                     |
| -------------------------- | ----- | ----------------------------- | -------------------------------------- |
| `domain_verification`      | no    | external dns validation       | json `domain-verification` document    |
| `provenance`               | no    | publisher attestations        | json document                          |
| `project_health`           | no    | generated                     | json `project-health` document         |
| `package_labels`           | no    | various labellers             | json list of appied labels             |
| `fair_forge_meta_labels`   | no    | various tools in AB toolchain | json list of labels from compiled meta |


### Domain Verification Document

This JSON metadata document contains verifications based on the package's domain name, if supplied

| Key                 | Req'd | Data Source             | Value, FAIR Format       |
| ------------------- | ----- | ----------------------- | ------------------------ |
| `domain_alias`      | no    | external dns validation | string with result       |
| `domain_reputation` | no    | external checks, APIs   | json list with results   |
| `domain_rbls`       | no    | external checks, APIs   | json list with results   |
| `dns_record`        | no    | external checks, APIs   | json list with results   |


### Project Health Document

This JSON metadata document contains compiled meta for assessing the overall health of the project and its application of best practices.

| Key                 | Req'd | Data Source                | Value, FAIR Format                           |
| ------------------- | ----- | -------------------------- | -------------------------------------------- |
| `repo_scan`         | no    | scan canonical repo        | json list                                    |
| `contributors`      | no    | scan canonical repo        | json list: contrib count & confirm contributing.md present |
| `release_history`   | no    |                            |                                              |
| `policy_check`      | no    |                            | json list: privacy policy, CoC, VDP          |
| `release_labels`    | no    | various labellers          | json list of release-specific labels applied |


## Release Forge Meta Document

This JSON metadata document contains meta wich relates to a specific release (version) of the package.

| Key                | Req'd | Data Source                | Value, FAIR Format                           |
| ------------------ | ----- | -------------------------- | -------------------------------------------- |
| `version`          | yes   | Plugin headers             | string                                       |
| `commit`           | no    | Repo                       | Repo's commit hash or id                     |
| `release_date`     | yes   | infer from svn?            | ISO formatted date string, YYYY-MM-DD        |
| `sbom`             | yes   |                            | [SPDX](https://spdx.dev/)-formatted SBOM     |
| `cve`              | no    | API requests               | cve label                                    |
| `wporg_scan`       | no    | .org scan tools            | results from scan tools                      |
| `php_version`      | no    | code scan                  | json list, min & max compatible php versions |
| `core_version`     | no    | package meta + code scan   | json list, min & max compatible wp core versions observale + requires & tested-to |
| `file_permissions` | no    | code scan                  | world-write octal permissions; corrected?    |
| `phpcs`            | no    | code scan                  | scan result as json document                 |
| `malware_scan`     | no    | code scan and/or API       | scan result as json document                 |
| `runtime`          | no    | runtime monitoring         | json [runtime forge meta document](#runtime-forge-meta-document) |


### Runtime Forge Meta Document

This JSON metadata document contains meta gleaned from runtime testing to ensure there is no unexpected filesystem or http activity. Tests are also run to confirm no excessive or slow database queries and to assess the package's overall effect on site performance.

| Key                | Req'd | Data Source                | Value, FAIR Format   |
| ------------------ | ----- | -------------------------- | -------------------- |
| `filesystem`       | no    | runtime monitoring tests   | results as json list |
| `http`             | no    | runtime monitoring tests   | results as json list |
| `db_queries`       | no    | runtime monitoring tests   | results as json list |
| `performance`      | no    | runtime monitoring tests   | results as json list |



