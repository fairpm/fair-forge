# FAIR Forge

## Requirements

* Nix, with flakes support.  I _highly_ recommend the [Determinate Systems installer](https://docs.determinate.systems/)
* Recommended: `direnv` (should be available on apt/brew/dnf/pacman/etc)

**Note:** Nix is required to develop fair-forge itself, but will not be required to run builders -- however, those will likely require a container runtime such as Docker.

## Quick Start

```
echo "use flake" > .envrc && direnv allow   # if using direnv
nix develop
```

## Immediate goals

1. convert legacy WordPress packages to FAIR-formatted packages & package-meta;
2. run automated code validation and perform external verifications on the code & attestations in the package meta.

Important: This project will use the MIT license. Any GPL (or similar) code *must* be in a separate repository as a standalone service for use by FAIR Forge, and not integrated with it.

## Work In Progress

Some vague notes below.  Things will take a more defined shape as we build out the tooling.

## General Principles

* glues together tools like git/gh/composer/phpcs/spdx, does not replace them
* Inspirations: Dist::Zilla, Gulp, Vite, Nix
* A collection of tools, not a single tool.  No one will use the whole thing.
* "`<whatever>` to tarball, tarball to `<whatever>`"
* Focus on attested reproducible builds
* Tools have minimal privileges, limited to only stdin/stdout where feasible
* Tools are selected, configured, and packaged together in a **builder**
    * environments are as hermetic as possible (containers or nix)
    * attestations are created for each tool's run
    * dispense capabilities to tools that need more than stdin/stdout
    * continuously reconcile input state to output state
    * All input and output state traces to a hash (file or parent dir hash)
    * validate all claims/attestations (e.g. hashes) on completion

## Potential Tools (old, needs update)

### Source Code Retrieval

* Fetch source tarball by a variety of addressing schemes
    * type+slug+version (resolved via AC)
    * DID (resolved directly)
    * source hash (encoded into filename on S3, verified on download)
    * composer package
    * github project (may use or maybe even require github cli app)
    * arbitrary git url
    * svn url (for legacy wordpress.org only)
* Unpack and validate tarball
    * validate checksums/signatures in manifest
    * validate source hash and version matches filename

### Building and Packaging

* Base quality checks, e.g. Plugin Checker (PCP)
* Security scanning, e.g. PatchStack
* SBOM generation, validation, scanning
* PLC DID generation

### Publishing

* Upload to cloud storage e.g. S3 with source hash filename
* Bump version tag and push tags
* Update PLC DID document

## Use Cases

### source code retrieval
* "Unpack wp-plugin:hello-dolly:1.0.1 into hello-dolly/"
* "Fetch tarball of gh:aspirepress/aspireupdate:latest"
* "Fetch tarball of hash dikl3hpv39qbxwjryrs2r4adqqkyv1pr"


### Packaging
* "rebuild the SBOM of the current package"
* "register a PLC DID for the current package"
* "run the default configured release process" (e.g. bump version, CI checks, SBOM, signing, upload)

