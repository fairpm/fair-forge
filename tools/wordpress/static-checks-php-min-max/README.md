# PHP Version Compatibility Scanner

A PHP library and CLI tool for determining the minimum and maximum PHP version compatibility of PHP packages. Uses [PHPCompatibility](https://github.com/PHPCompatibility/PHPCompatibility) sniffs to detect version-specific features and syntax.

## Features

- **Determine minimum PHP version** - Find the lowest PHP version that runs without fatal errors
- **Determine maximum PHP version** - Confirm compatibility with the latest PHP versions
- **Scan from URL** - Download and scan ZIP files directly (e.g., WordPress.org plugins)
- **Scan local files** - Scan local ZIP files or directories
- **JSON output** - Structured results for CI/CD integration
- **Composer constraints** - Get suggested `composer.json` PHP version requirements

## How It Works

The scanner runs [PHPCompatibility](https://github.com/PHPCompatibility/PHPCompatibility) checks against each PHP version (5.2 through 8.4). A version "passes" if there are no fatal errors - warnings are noted but don't cause a version to fail.

The minimum version is the oldest PHP version that passes, and the maximum version is the newest that passes.

## Requirements

- PHP 8.1 or higher (to run the scanner)
- Composer
- Extensions: `curl` (required for downloading)

## Installation

```bash
cd fair-forge/tools/wordpress/static-checks-php-min-max
composer install
```

## CLI Usage

### Basic Usage

```bash
# Scan a plugin from WordPress.org
php bin/php-min-max https://downloads.wordpress.org/plugin/akismet.zip

# Scan a local ZIP file
php bin/php-min-max ./my-plugin.zip

# Scan a local directory
php bin/php-min-max ./src/

# Save results to a file
php bin/php-min-max https://example.com/plugin.zip --output=results.json
```

### Options

| Option | Description |
|--------|-------------|
| `--output=FILE` | Save JSON output to specified file |
| `--extensions=LIST` | Comma-separated list of file extensions (default: php) |
| `--insecure, -k` | Skip SSL certificate verification |
| `--quiet, -q` | Suppress progress messages (output only JSON) |
| `--help, -h` | Show help message |

### PHP Versions Checked

The scanner checks compatibility with:

`5.2, 5.3, 5.4, 5.5, 5.6, 7.0, 7.1, 7.2, 7.3, 7.4, 8.0, 8.1, 8.2, 8.3, 8.4`

### Example Output

```json
{
    "success": true,
    "compatibility": {
        "min_version": "7.4",
        "max_version": "8.4",
        "version_range": ">=7.4 <=8.4",
        "composer_constraint": "^7.4 || ^8.0"
    },
    "versions": {
        "passed": ["7.4", "8.0", "8.1", "8.2", "8.3", "8.4"],
        "failed": {
            "5.6": {"errors": 12, "warnings": 3},
            "7.0": {"errors": 5, "warnings": 1}
        },
        "warnings": {"7.4": 2}
    },
    "summary": {
        "success": true,
        "min_version": "7.4",
        "max_version": "8.4",
        "passed_count": 6,
        "failed_count": 9,
        "issue_count": 45
    },
    "issues": [
        {
            "file": "includes/functions.php",
            "line": 25,
            "type": "ERROR",
            "message": "Function array_key_first() is not present in PHP version 7.3 or earlier",
            "source": "PHPCompatibility.FunctionUse.NewFunctions.array_key_firstFound",
            "affectedVersions": ["5.6", "7.0", "7.1", "7.2", "7.3"]
        }
    ]
}
```

### Exit Codes

- `0` - Scan completed, package is compatible with at least one version
- `1` - Scan completed, package has no compatible versions
- `2` - Scan could not be completed due to an error

## Library Usage

### Basic Example

```php
<?php

require_once 'vendor/autoload.php';

use FairForge\Tools\PhpMinMax\CompatibilityScanner;

$scanner = new CompatibilityScanner();

// Scan from URL
$result = $scanner->scanFromUrl('https://downloads.wordpress.org/plugin/akismet.zip');

// Or scan a local directory
$result = $scanner->scanDirectory('./my-plugin/');

// Get results
echo "Min PHP: " . $result->minVersion . "\n";
echo "Max PHP: " . $result->maxVersion . "\n";
echo "Composer constraint: " . $result->getComposerConstraint() . "\n";

// Check specific version
if ($result->isVersionCompatible('8.0')) {
    echo "Compatible with PHP 8.0!\n";
}

// Get all issues
foreach ($result->issues as $issue) {
    echo "{$issue['file']}:{$issue['line']} - {$issue['message']}\n";
}

// Output as JSON
echo $result->toJson();
```

### Configuration

```php
$scanner = new CompatibilityScanner();

// Set file extensions to scan
$scanner->setExtensions(['php', 'inc']);

// Disable SSL verification (for self-signed certs)
$scanner->setSslVerify(false);
```

## Use Cases

1. **Plugin/Theme Development** - Verify your minimum PHP version requirement is accurate
2. **Dependency Auditing** - Check if packages will work on your target PHP version
3. **Upgrade Planning** - Identify what breaks when upgrading PHP
4. **CI/CD Integration** - Automatically verify compatibility in your pipeline

## Running Tests

```bash
composer test
```

## Credits

This tool uses [PHPCompatibility](https://github.com/PHPCompatibility/PHPCompatibility) for PHP version compatibility detection.

## License

MIT

