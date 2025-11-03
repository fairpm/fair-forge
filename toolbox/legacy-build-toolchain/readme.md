# Legacy Build Toolchain

This toolchain consists of tools for taking a WordPress package (plugin or theme) from the legacy Subversion repository and (re)building it as a package formatted according to the FAIR protocol specification. The result will be a true copy of the original package with properly formed metadata. Since the legacy WordPress respository requirement omits data required by the FAIR Protocol, some may be reasonably inferred, or omitted if necessary.

## Legacy Build Tools

### Supplied Meta & Readme Parser
  - Same as done on .org

### DID Assignment
  - May be DID:PLC or DID:Web (TBD)

### Observed SBOM Generator
  - Code scan for dependencies & bundled libraries
  - Create formatted SBOM
  - Important: SBOM will be tagged as _observed_ rather than authoritative since it's third-party generated

### Contact Info Parser
  - Publisher contact
  - Security contact
  - Support channel

### Packager
  - Build meta with toolchain data
  - Generate checksum
  - Crypto sign package & meta

