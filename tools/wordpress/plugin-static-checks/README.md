# WordPress Plugin PHPCS Scanner

A PHP library and CLI tool for scanning WordPress plugin ZIP files using PHPCS with WordPress coding standards. Returns results as JSON for easy integration with CI/CD pipelines and other tools.

## Features

- **Download and scan** plugin ZIP files from URLs (e.g., wordpress.org, github)
- **Scan local ZIP files** or directories
- **WordPress coding standards** built-in (WordPress, WordPress-Core, WordPress-Extra, WordPress-Docs)
- **JSON output** for easy parsing and integration
- **Use as library** in your PHP code or **CLI tool** from command line
- **Configurable** standards, severity, file extensions, and more

## Requirements

- PHP 8.1 or higher
- Composer
- Extensions: `curl` (required for downloading)

## Installation

```bash
cd fair-forge/tools/wordpress/plugin-static-checks
composer install
```

## CLI Usage

### Basic Usage

```bash
# Scan a plugin from WordPress.org
php bin/plugin-static-checks https://downloads.wordpress.org/plugin/akismet.zip

# Scan a local ZIP file
php bin/plugin-static-checks ./my-plugin.zip

# Save results to a file
php bin/plugin-static-checks https://example.com/plugin.zip --output=results.json
```

### Options

| Option | Description |
|--------|-------------|
| `--output=FILE` | Save JSON output to specified file |
| `--standard=NAME` | PHPCS standard to use (default: WordPress) |
| `--no-warnings` | Exclude warnings from output (show only errors) |
| `--severity=N` | Minimum severity level 1-10 (default: 1) |
| `--extensions=LIST` | Comma-separated list of file extensions (default: php) |
| `--insecure, -k` | Skip SSL certificate verification (for self-signed certs) |
| `--quiet, -q` | Suppress progress messages (output only JSON) |
| `--help, -h` | Show help message |

### Available Standards

- `WordPress` - Complete WordPress coding standards (default)
- `WordPress-Core` - Core WordPress coding standards only
- `WordPress-Extra` - Additional WordPress coding standards
- `WordPress-Docs` - Documentation standards

### Examples

```bash
# Scan with only errors (no warnings)
php bin/plugin-static-checks plugin.zip --no-warnings

# Use WordPress-Core standard
php bin/plugin-static-checks plugin.zip --standard=WordPress-Core

# Scan PHP and JavaScript files
php bin/plugin-static-checks plugin.zip --extensions=php,js

# Quiet mode - only JSON output, save to file
php bin/plugin-static-checks plugin.zip --quiet --output=results.json
```

### Exit Codes

- `0` - Scan completed successfully with no errors
- `1` - Scan completed but found errors
- `2` - Scan failed (invalid input, download error, etc.)

## Library Usage

### Basic Example

```php
<?php

require_once 'vendor/autoload.php';

use FairForge\Tools\WordPress\PluginStaticChecks\PluginScanner;

$scanner = new PluginScanner();

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
$scanner = new PluginScanner();

// Set the PHPCS standard
$scanner->setStandard('WordPress-Core');

// Exclude warnings (only errors)
$scanner->setIncludeWarnings(false);

// Set minimum severity level
$scanner->setSeverity(5);

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

// Check for issues
if ($result->hasErrors()) {
    echo "Found {$result->errorCount} errors\n";
}

if ($result->hasWarnings()) {
    echo "Found {$result->warningCount} warnings\n";
}

// Get summary
$summary = $result->getSummary();
print_r($summary);
// [
//     'success' => true,
//     'errors' => 10,
//     'warnings' => 25,
//     'fixable' => 15,
//     'files_scanned' => 5,
//     'standard' => 'WordPress',
// ]

// Get all errors
$errors = $result->getAllErrors();
foreach ($errors as $error) {
    echo "{$error['file']}:{$error['line']} - {$error['message']}\n";
}

// Get all warnings
$warnings = $result->getAllWarnings();

// Access raw file data
foreach ($result->files as $filePath => $fileData) {
    echo "File: $filePath\n";
    echo "  Errors: {$fileData['errors']}\n";
    echo "  Warnings: {$fileData['warnings']}\n";
}
```

## JSON Output Format

```json
{
    "success": true,
    "summary": {
        "success": true,
        "errors": 10,
        "warnings": 25,
        "fixable": 15,
        "files_scanned": 5,
        "standard": "WordPress"
    },
    "totals": {
        "errors": 10,
        "warnings": 25,
        "fixable": 15
    },
    "files": {
        "my-plugin/my-plugin.php": {
            "errors": 5,
            "warnings": 10,
            "messages": [
                {
                    "message": "Missing doc comment for function",
                    "source": "Squiz.Commenting.FunctionComment.Missing",
                    "severity": 5,
                    "fixable": false,
                    "type": "ERROR",
                    "line": 25,
                    "column": 1
                }
            ]
        }
    },
    "metadata": {
        "standard": "WordPress",
        "phpcs_exit_code": 1,
        "scanned_at": "2024-01-15T10:30:00+00:00"
    }
}
```

## Integration Examples

### GitHub Actions

```yaml
- name: Scan plugin
  run: |
    php bin/static-checks ./plugin.zip --output=phpcs-results.json --quiet
    if [ $? -eq 1 ]; then
      echo "PHPCS found errors"
      exit 1
    fi

- name: Upload results
  uses: actions/upload-artifact@v3
  with:
    name: phpcs-results
    path: phpcs-results.json
```

### In a WordPress Plugin

```php
// In your plugin's admin page
$scanner = new \FairForge\PhpCodeScan\PluginScanner();
$scanner->setStandard('WordPress-Extra');

try {
    $result = $scanner->scanFromUrl($plugin_zip_url);
    
    if ($result->hasErrors()) {
        wp_admin_notice(
            sprintf('Plugin has %d coding standard errors', $result->errorCount),
            ['type' => 'warning']
        );
    }
} catch (RuntimeException $e) {
    wp_admin_notice('Failed to scan plugin: ' . $e->getMessage(), ['type' => 'error']);
}
```

## License

GPL-2.0-or-later
