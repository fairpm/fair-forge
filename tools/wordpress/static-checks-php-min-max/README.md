# PHP Version Compatibility Scanner

A PHP library and CLI tool for determining the minimum and maximum PHP version compatibility of PHP packages. Uses [PHPCompatibility](https://github.com/PHPCompatibility/PHPCompatibility) sniffs to detect version-specific features and syntax. Returns results as JSON for easy integration with CI/CD pipelines and other tools.

## Features

- **Determine minimum PHP version** - Find the lowest PHP version that runs without fatal errors
- **Determine maximum PHP version** - Confirm compatibility with the latest PHP versions
- **Download and scan** ZIP files from URLs (e.g., wordpress.org, github)
- **Scan local ZIP files** or directories
- **JSON output** for easy parsing and integration
- **Use as library** in your PHP code or **CLI tool** from command line
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
| `--insecure, -k` | Skip SSL certificate verification (for self-signed certs) |
| `--quiet, -q` | Suppress progress messages (output only JSON) |
| `--help, -h` | Show help message |

### PHP Versions Checked

The scanner checks compatibility with:

`5.2, 5.3, 5.4, 5.5, 5.6, 7.0, 7.1, 7.2, 7.3, 7.4, 8.0, 8.1, 8.2, 8.3, 8.4`

### Examples

```bash
# Scan and save to file
php bin/php-min-max plugin.zip --output=compat.json

# Scan PHP and INC files
php bin/php-min-max plugin.zip --extensions=php,inc

# Quiet mode - only JSON output
php bin/php-min-max plugin.zip --quiet

# Skip SSL verification for self-signed certs
php bin/php-min-max https://internal.example.com/plugin.zip --insecure
```

### Exit Codes

- `0` - Scan completed, package is compatible with at least one version
- `1` - Scan completed, package has no compatible versions
- `2` - Scan could not be completed due to a processing error

## Library Usage

### Basic Example

```php
<?php

require_once 'vendor/autoload.php';

use FairForge\Tools\PhpMinMax\CompatibilityScanner;

$scanner = new CompatibilityScanner();

// Scan from URL
$result = $scanner->scanFromUrl('https://downloads.wordpress.org/plugin/akismet.zip');

// Or scan from local ZIP
$result = $scanner->scanFromZipFile('./my-plugin.zip');

// Or scan a directory
$result = $scanner->scanDirectory('./my-plugin');

// Get JSON output
echo $result->toJson();

// Or save to file
$result->saveToFile('results.json');
```

### Configuration

```php
$scanner = new CompatibilityScanner();

// Set file extensions to scan
$scanner->setExtensions(['php', 'inc']);

// Disable SSL verification (for development with self-signed certs)
$scanner->setSslVerify(false);

// Then scan
$result = $scanner->scanFromUrl($url);
```

### Working with Results

```php
$result = $scanner->scanFromUrl($url);

// Get version info
echo "Min PHP: {$result->minVersion}\n";
echo "Max PHP: {$result->maxVersion}\n";
echo "Range: {$result->getVersionRange()}\n";
echo "Composer: {$result->getComposerConstraint()}\n";

// Check for compatible versions
if ($result->hasPassingVersions()) {
    echo "Compatible with " . count($result->passedVersions) . " PHP versions\n";
}

// Check specific version compatibility
if ($result->isVersionCompatible('8.0')) {
    echo "Compatible with PHP 8.0!\n";
}

// Check for issues
if ($result->hasIssues()) {
    echo "Found {$result->getErrorCount()} errors\n";
    echo "Found {$result->getWarningCount()} warnings\n";
}

// Get summary
$summary = $result->getSummary();
print_r($summary);
// [
//     'success' => true,
//     'min_version' => '7.4',
//     'max_version' => '8.4',
//     'version_range' => '>=7.4 <=8.4',
//     'composer_constraint' => '^7.4 || ^8.0',
//     'passed_count' => 6,
//     'failed_count' => 9,
//     'issue_count' => 45,
// ]

// Get all issues
foreach ($result->issues as $issue) {
    echo "{$issue['file']}:{$issue['line']} - {$issue['message']}\n";
    echo "  Affects: " . implode(', ', $issue['affectedVersions']) . "\n";
}

// Get errors grouped by file
$errorsByFile = $result->getErrorsByFile();
foreach ($errorsByFile as $filePath => $errors) {
    echo "File: $filePath\n";
    foreach ($errors as $error) {
        echo "  Line {$error['line']}: {$error['message']}\n";
    }
}

// Access version details
echo "Passed versions: " . implode(', ', $result->passedVersions) . "\n";

foreach ($result->failedVersions as $version => $counts) {
    echo "PHP $version failed: {$counts['errors']} errors, {$counts['warnings']} warnings\n";
}

foreach ($result->warningVersions as $version => $warningCount) {
    echo "PHP $version passed with $warningCount warnings\n";
}
```

## JSON Output Format

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
            "5.2": {"errors": 45, "warnings": 12},
            "5.3": {"errors": 38, "warnings": 10},
            "5.4": {"errors": 32, "warnings": 8},
            "5.5": {"errors": 28, "warnings": 6},
            "5.6": {"errors": 20, "warnings": 5},
            "7.0": {"errors": 15, "warnings": 3},
            "7.1": {"errors": 10, "warnings": 2},
            "7.2": {"errors": 5, "warnings": 1},
            "7.3": {"errors": 2, "warnings": 0}
        },
        "warnings": {
            "7.4": 2,
            "8.0": 1
        }
    },
    "summary": {
        "success": true,
        "min_version": "7.4",
        "max_version": "8.4",
        "version_range": ">=7.4 <=8.4",
        "composer_constraint": "^7.4 || ^8.0",
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
            "affectedVersions": ["5.2", "5.3", "5.4", "5.5", "5.6", "7.0", "7.1", "7.2", "7.3"]
        },
        {
            "file": "includes/class-main.php",
            "line": 10,
            "type": "ERROR",
            "message": "Typed properties are not supported in PHP 7.3 or earlier",
            "source": "PHPCompatibility.Classes.NewTypedProperties.Found",
            "affectedVersions": ["5.2", "5.3", "5.4", "5.5", "5.6", "7.0", "7.1", "7.2", "7.3"]
        }
    ],
    "metadata": {
        "scanned_at": "2026-02-05T10:30:00+00:00",
        "php_versions_checked": ["5.2", "5.3", "5.4", "5.5", "5.6", "7.0", "7.1", "7.2", "7.3", "7.4", "8.0", "8.1", "8.2", "8.3", "8.4"]
    }
}
```

## Integration Examples

### GitHub Actions

```yaml
name: PHP Compatibility Check

on: [push, pull_request]

jobs:
  compatibility:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup PHP
        uses: shivammathur/setup-php@v2
        with:
          php-version: '8.3'
          
      - name: Install dependencies
        run: composer install
        
      - name: Check PHP version compatibility
        run: |
          php bin/php-min-max ./src --output=compat-results.json --quiet
          
          # Parse and validate minimum version
          MIN_VERSION=$(jq -r '.compatibility.min_version' compat-results.json)
          echo "Minimum PHP version: $MIN_VERSION"
          
          # Fail if minimum version is higher than expected
          if [[ "$MIN_VERSION" > "7.4" ]]; then
            echo "Error: Package requires PHP $MIN_VERSION but should support 7.4"
            exit 1
          fi

      - name: Upload compatibility results
        uses: actions/upload-artifact@v4
        with:
          name: php-compatibility-results
          path: compat-results.json
```
### In a WordPress Plugin

```php
// In your plugin's admin page - check compatibility of uploaded plugins
use FairForge\Tools\PhpMinMax\CompatibilityScanner;

$scanner = new CompatibilityScanner();

try {
    $result = $scanner->scanFromUrl($plugin_zip_url);
    
    // Get the current PHP version
    $current_php = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;
    
    if (!$result->isVersionCompatible($current_php)) {
        wp_admin_notice(
            sprintf(
                'This plugin is not compatible with your PHP version (%s). It requires PHP %s to %s.',
                $current_php,
                $result->minVersion,
                $result->maxVersion
            ),
            ['type' => 'error']
        );
    } elseif ($result->minVersion && version_compare($result->minVersion, '7.4', '<')) {
        wp_admin_notice(
            sprintf(
                'This plugin supports PHP %s which may have security issues. Consider updating the plugin.',
                $result->minVersion
            ),
            ['type' => 'warning']
        );
    } else {
        wp_admin_notice(
            sprintf('Plugin is compatible (PHP %s)', $result->getVersionRange()),
            ['type' => 'success']
        );
    }
} catch (RuntimeException $e) {
    wp_admin_notice('Failed to check compatibility: ' . $e->getMessage(), ['type' => 'error']);
}
```
### Pre-commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit

# Check PHP compatibility before committing
RESULT=$(php bin/php-min-max ./src --quiet 2>&1)
MIN_VERSION=$(echo "$RESULT" | jq -r '.compatibility.min_version')

if [ "$MIN_VERSION" != "null" ]; then
    EXPECTED="7.4"
    if [ "$(printf '%s\n' "$EXPECTED" "$MIN_VERSION" | sort -V | head -n1)" != "$EXPECTED" ]; then
        echo "Error: Code requires PHP $MIN_VERSION but minimum should be $EXPECTED"
        exit 1
    fi
fi

echo "PHP compatibility check passed (min: $MIN_VERSION)"
```

## Use Cases

1. **Plugin/Theme Development** - Verify your minimum PHP version requirement is accurate
2. **Dependency Auditing** - Check if packages will work on your target PHP version
3. **Upgrade Planning** - Identify what breaks when upgrading PHP
4. **CI/CD Integration** - Automatically verify compatibility in your pipeline
5. **Plugin Directory Submission** - Validate PHP version requirements before submitting

## Running Tests

```bash
composer test
```

## Running Code Quality Checks

```bash
# Run PHPCS
composer lint

# Run PHP-CS-Fixer
composer format:check

# Run all checks
composer check
```

## Credits

This tool uses [PHPCompatibility](https://github.com/PHPCompatibility/PHPCompatibility) for PHP version compatibility detection.

## License

MIT

