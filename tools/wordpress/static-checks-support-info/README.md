# WordPress Support Info Scanner

A PHP library and CLI tool for checking WordPress plugins and themes for **support contact information**. Returns results as JSON for easy integration with CI/CD pipelines and other tools.

## Features

- **Check Support header** in the main plugin/theme file comment block
- **Detect SUPPORT.md** file with contact information
- **Verify consistency** between support contact sources
- **Require at least one email** address in support contact fields
- **Download and scan** ZIP files from URLs (e.g., wordpress.org, github)
- **Scan local ZIP files** or directories
- **JSON output** for easy parsing and integration
- **Use as library** in your PHP code or **CLI tool** from command line

## What It Checks

WordPress packages should include support contact information so users know where to get help.

### 1. Support Header in Main File

The main plugin file (`plugin-name.php`) or theme file (`style.css`) should contain a `Support:` header:

```php
<?php
/**
 * Plugin Name: My Plugin
 * Description: A great plugin
 * Version: 1.0.0
 * Author: John Doe
 * Support: support@example.com
 */
```

Or with a URL:

```php
/**
 * Plugin Name: My Plugin
 * Support: https://example.com/support
 */
```

### 2. SUPPORT.md File

A `SUPPORT.md` file in the root directory with contact information:

```markdown
# Support

For help with this plugin, please contact support@example.com.
```

## Requirements

- PHP 8.1 or higher
- Composer
- Extensions: `curl` (required for downloading)

## Installation

```bash
cd fair-forge/tools/wordpress/static-checks-support-info
composer install
```

## CLI Usage

### Basic Usage

```bash
# Scan a plugin from WordPress.org
php bin/support-info https://downloads.wordpress.org/plugin/akismet.zip

# Scan a local ZIP file
php bin/support-info ./my-plugin.zip

# Scan a local directory
php bin/support-info ./my-plugin/

# Save results to a file
php bin/support-info https://example.com/plugin.zip --output=results.json
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
| `0` | Scan passed — has Support header, at least one email, and contacts are consistent |
| `1` | Scan completed but found issues (missing info, no email, or inconsistent) |
| `2` | Error — scan could not complete |

### Example Output

```json
{
  "schema_version": "1.0.0",
  "tool": "support-info",
  "success": true,
  "summary": {
    "success": true,
    "passes": true,
    "has_support_header": true,
    "has_support_md": true,
    "has_email": true,
    "is_consistent": true,
    "issue_count": 0,
    "primary_support_contact": "support@example.com",
    "package_type": "plugin"
  },
  "data": {
    "support": {
      "header": {
        "found": true,
        "contact": "support@example.com",
        "file": "my-plugin.php"
      },
      "support_md": {
        "exists": true,
        "contact": "support@example.com"
      }
    },
    "consistency": {
      "is_consistent": true,
      "primary_support_contact": "support@example.com"
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
use FairForge\Tools\SupportInfo\SupportInfoScanner;

$scanner = new SupportInfoScanner();

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
    echo "Support contact checks passed!\n";
}

// Get support info
echo "Support header: " . ($result->supportHeaderContact ?? 'None') . "\n";
echo "SUPPORT.md contact: " . ($result->supportMdContact ?? 'None') . "\n";
echo "Primary contact: " . ($result->getPrimarySupportInfo() ?? 'None') . "\n";

// Check what's present
$result->hasSupportHeader();   // true if Support: header found
$result->hasSupportFile();     // true if SUPPORT.md exists
$result->hasSupportInfo();     // true if any support info found
$result->hasEmail();           // true if any field contains an email address

// Consistency
echo "Consistent: " . ($result->isConsistent ? 'Yes' : 'No') . "\n";

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
use FairForge\Tools\SupportInfo\SupportInfoScanner;

$scanner = new SupportInfoScanner();

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
| Missing Support header | No `Support:` header in the main file comment block |
| No SUPPORT.md file | No `SUPPORT.md` file found in the package root |
| SUPPORT.md no contact | `SUPPORT.md` exists but no contact info could be extracted |
| Inconsistent contacts | Support contacts in header and file don't match |
| No email address | No email address found in any support contact field |
| No main file | Could not identify the main plugin or theme file |

## Related Modules

- **[static-checks-contact-info](../static-checks-contact-info/)** — Checks for publisher contact information (Author, Author URI, Plugin/Theme URI)
- **[static-checks-security-info](../static-checks-security-info/)** — Checks for security contact information (Security header, security.md, security.txt)

## License

MIT
