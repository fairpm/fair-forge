# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

FAIR Forge is a modular toolchain for building, validating, and federating WordPress (and eventually other) packages under the FAIR Protocol. It is a collection of composable tools — not a single monolith. The immediate focus is on static checks for WordPress plugins.

**License constraint:** This project uses MIT. Any GPL-licensed code must live in a separate repository and be consumed as an external service — it must not be integrated here.

## Repository Structure

```
tools/wordpress/
  shared/                        # Shared base classes used by all tools
  static-checks-contact-info/    # Checks publisher contact headers
  static-checks-support-info/    # Checks support information
  static-checks-security-info/   # Checks security contact headers
  static-checks-phpcs/           # Runs PHPCS on plugin code
  static-checks-php-min-max/     # Checks PHP version compatibility
toolbox-docs/                    # Architecture and specification docs
tools/sbom-tools/                # Shell scripts for SBOM generation/scanning
tools/sentinel-shell/            # Shell scripts for file integrity checks
```

Each tool under `tools/wordpress/` is a standalone Composer package with its own `composer.json`, `phpcs.xml`, `phpunit.xml.dist`, `src/`, `tests/`, and a CLI entry point in `bin/`.

## Architecture: Scanner + Result Pattern

Every WordPress static-check tool follows the same pattern:

1. **Scanner** (`*Scanner.php`) extends `AbstractToolScanner` from `fair-forge/shared`. Subclasses only implement `getToolName(): string` and `scanDirectory(string $directory): ToolResultInterface`. The base class handles URL download, ZIP extraction, and dispatch.

2. **Result** (`*Result.php`) extends `AbstractToolResult` from `fair-forge/shared`. Must implement `getToolName()`, `isSuccess()`, `getSummary()`, `getData()`, `getIssues()`, and `getMetadata()`. The base class assembles a standard JSON envelope automatically via `toArray()` / `toJson()` / `saveToFile()`.

3. **Standard JSON envelope** output by every tool:
   ```json
   {
     "schema_version": "1.0.0",
     "tool": "<slug>",
     "success": true,
     "summary": {},
     "data": {},
     "issues": [],
     "metadata": { "scanned_at": "ISO-8601" }
   }
   ```

`ScanTarget` accepts three input types: `Url`, `ZipFile`, or `Directory`. The scanner's `scan()` method dispatches accordingly.

Plugin metadata (headers, readme.txt) is parsed via `fairpm/did-manager` through the shared `PluginMetadataReader` class.

## Commands

Each tool and the shared package are developed independently. Run these from within the tool's directory after `composer install`.

```bash
# Install dependencies
composer install

# Run tests
composer test
# or directly:
vendor/bin/phpunit

# Run a single test file
vendor/bin/phpunit tests/ContactInfoScannerTest.php

# Lint
composer lint

# Lint + fix
composer lint:fix

# Lint + test together (where available)
composer check
```

## Adding a New WordPress Static-Check Tool

1. Create a new directory under `tools/wordpress/static-checks-<name>/`.
2. Set up `composer.json` with a path repository pointing to `../shared` and requiring `fair-forge/shared: @dev`.
3. Implement `<Name>Scanner extends AbstractToolScanner` — only `getToolName()` and `scanDirectory()` are required.
4. Implement `<Name>Result extends AbstractToolResult` — implement the six abstract methods; `toArray()` / `toJson()` / `saveToFile()` come for free.
5. Add a CLI entry point in `bin/` and register it in `composer.json` under `"bin"`.
6. Mirror the `phpcs.xml`, `phpunit.xml.dist`, and `scripts` block from an existing tool.
