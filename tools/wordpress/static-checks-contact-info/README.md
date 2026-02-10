# WordPress Contact Info Scanner

A PHP library and CLI tool for checking WordPress plugins and themes for **publisher contact information**. Returns results as JSON for easy integration with CI/CD pipelines and other tools.

## Features

- **Check publisher headers** (Author, Author URI) in the main plugin/theme file comment block
- **Check project URI** (Plugin URI / Theme URI)
- **Require at least one email** address in publisher contact fields
- **Download and scan** ZIP files from URLs (e.g., wordpress.org, github)
- **Scan local ZIP files** or directories
- **JSON output** for easy parsing and integration
- **Use as library** in your PHP code or **CLI tool** from command line

## What It Checks

WordPress packages should include publisher contact information in their main file header.

### Publisher Contact in Main File

The main plugin file (`plugin-name.php`) or theme file (`style.css`) should contain `Author:` and `Author URI:` headers:

```php
<?php
/**
 * Plugin Name: My Plugin
 * Description: A great plugin
 * Version: 1.0.0
 * Author: John Doe
 * Author URI: mailto:john@johndoe.com
 * Plugin URI: https://example.com/my-plugin
 */
```

## Requirements

- PHP 8.1 or higher
- Composer
- Extensions: `curl` (required for downloading)

## Installation

```bash
cd fair-forge/tools/wordpress/static-checks-contact-info
composer install
```

## CLI Usage

### Basic Usage

```bash
# Scan a plugin from WordPress.org
php bin/contact-info https://downloads.wordpress.org/plugin/akismet.zip

# Scan a local ZIP file
php bin/contact-info ./my-plugin.zip

# Scan a local directory
php bin/contact-info ./my-plugin/

# Save results to a file
php bin/contact-info https://example.com/plugin.zip --output=results.json
```

### Options

| Option | Description |
|--------|-------------|
| `--output=FILE` | Save JSON output to specified file |
| `--insecure, -k` | Skip SSL certificate verification (for self-signed certs) |
| `--quiet, -q` | Suppress progress messages (output only JSON) |
| `--help, -h` | Show this help message |

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan passed — has publisher info and at least one email |
| `1` | Scan completed but found issues (missing info or no email) |
| `2` | Error — scan could not complete |

### Example Output

```json
{
  "schema_version": "1.0.0",
  "tool": "contact-info",
  "success": true,
  "summary": {
    "success": true,
    "passes": true,
    "has_publisher_name": true,
    "has_publisher_uri": true,
    "has_project_uri": true,
    "has_email": true,
    "issue_count": 0,
    "publisher_name": "John Doe",
    "publisher_uri": "mailto:john@johndoe.com",
    "package_type": "plugin"
  },
  "data": {
    "publisher": {
      "name": "John Doe",
      "uri": "mailto:john@johndoe.com",
      "file": "my-plugin.php"
    },
    "project": {
      "uri": "https://example.com/my-plugin"
    }
  },
  "issues": [],
  "metadata": {
    "package_type": "plugin",
    "scanned_directory": "/tmp/extracted/my-plugin"
  }
}
```

## Library Usage

### Basic Scanning

```php
use FairForge\Tools\ContactInfo\ContactInfoScanner;

$scanner = new ContactInfoScanner();

// Scan a directory
$result = $scanner->scanDirectory('/path/to/plugin');

// Scan a ZIP file
$result = $scanner->scanFromZipFile('/path/to/plugin.zip');

// Scan from URL
$result = $scanner->scanFromUrl('https://downloads.wordpress.org/plugin/akismet.zip');
```

### Working with Results

```php
// Check if scan passed
if ($result->passes()) {
    echo "Publisher contact info checks passed!\n";
}

// Get publisher info
echo "Publisher: " . $result->publisherName . "\n";
echo "Publisher URI: " . $result->publisherUri . "\n";
echo "Project URI: " . $result->projectUri . "\n";

// Check what's present
$result->hasPublisherInfo();   // true if Author or Author URI found
$result->hasProjectUri();      // true if Plugin URI / Theme URI found
$result->hasEmail();           // true if publisher URI contains an email address

// Get summary
$summary = $result->getSummary();

// Get JSON
$json = $result->toJson();

// Save to file
$result->saveToFile('results.json');
```

### Using ScanTarget

```php
use FairForge\Shared\ScanTarget;
use FairForge\Tools\ContactInfo\ContactInfoScanner;

$scanner = new ContactInfoScanner();

// From URL
$target = ScanTarget::fromUrl('https://example.com/plugin.zip');
$result = $scanner->scan($target);

// From ZIP file
$target = ScanTarget::fromZipFile('/path/to/plugin.zip');
$result = $scanner->scan($target);

// From directory
$target = ScanTarget::fromDirectory('/path/to/plugin');
$result = $scanner->scan($target);
```

## Development

```bash
# Install dependencies
composer install

# Run tests
composer test

# Run linter
composer lint

# Fix linting issues
composer lint:fix

# Run all checks
composer check
```

## Issues Detected

| Issue | Description |
|-------|-------------|
| Missing Author header | No `Author:` header in the main file comment block |
| Missing Author URI header | No `Author URI:` header in the main file comment block |
| No email address | No email address found in the publisher URI field |
| No main file | Could not identify the main plugin or theme file |

## Related Modules

- **[static-checks-support-info](../static-checks-support-info/)** — Checks for support contact information (Support header, SUPPORT.md)
- **[static-checks-security-info](../static-checks-security-info/)** — Checks for security contact information (Security header, security.md, security.txt)

## License

MIT

