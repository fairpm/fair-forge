# WordPress Security Header Scanner

A PHP library and CLI tool for checking WordPress plugins and themes for security contact information. Returns results as JSON for easy integration with CI/CD pipelines and other tools.

## Features

- **Check security headers** in the main plugin/theme file comment block
- **Detect security files** (security.md, security.txt)
- **Verify consistency** between all security contact sources
- **Download and scan** ZIP files from URLs (e.g., wordpress.org, github)
- **Scan local ZIP files** or directories
- **JSON output** for easy parsing and integration
- **Use as library** in your PHP code or **CLI tool** from command line

## What It Checks

WordPress packages should include security contact information in multiple locations:

### 1. Security Header in Main File

The main plugin file (`plugin-name.php`) or theme file (`style.css`) should contain a `Security:` header:

```php
<?php
/**
 * Plugin Name: My Plugin
 * Description: A great plugin
 * Version: 1.0.0
 * Author: Your Name
 * Security: security@example.com
 */
```

Or with a URL:

```php
/**
 * Plugin Name: My Plugin
 * Security: https://example.com/security
 */
```

### 2. security.md File

A `SECURITY.md` file in the root directory with contact information:

```markdown
# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities to security@example.com.
```

### 3. security.txt File

A `security.txt` file following [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116):

```
Contact: security@example.com
Expires: 2030-01-01T00:00:00.000Z
```

## Requirements

- PHP 8.1 or higher
- Composer
- Extensions: `curl` (required for downloading)

## Installation

```bash
cd fair-forge/tools/wordpress/static-checks-security-header
composer install
```

## CLI Usage

### Basic Usage

```bash
# Scan a plugin from WordPress.org
php bin/security-header https://downloads.wordpress.org/plugin/akismet.zip

# Scan a local ZIP file
php bin/security-header ./my-plugin.zip

# Scan a local directory
php bin/security-header ./my-plugin/

# Save results to a file
php bin/security-header https://example.com/plugin.zip --output=results.json
```

### Options

| Option | Description |
|--------|-------------|
| `--output=FILE` | Save JSON output to specified file |
| `--insecure, -k` | Skip SSL certificate verification (for self-signed certs) |
| `--quiet, -q` | Suppress progress messages (output only JSON) |
| `--help, -h` | Show help message |

### Examples

```bash
# Scan and save to file
php bin/security-header plugin.zip --output=security.json

# Quiet mode - only JSON output
php bin/security-header plugin.zip --quiet

# Skip SSL verification for self-signed certs
php bin/security-header https://internal.example.com/plugin.zip --insecure
```

### Exit Codes

- `0` - Scan passed (has security header and all contacts are consistent)
- `1` - Scan completed but found issues (missing header or inconsistent contacts)
- `2` - Scan could not be completed due to a processing error

## Library Usage

### Basic Example

```php
<?php

require_once 'vendor/autoload.php';

use FairForge\Tools\SecurityHeader\SecurityScanner;

$scanner = new SecurityScanner();

// Scan from URL
$result = $scanner->scanFromUrl('https://downloads.wordpress.org/plugin/akismet.zip');

// Or scan from local ZIP
$result = $scanner->scanFromZipFile('./my-plugin.zip');

// Or scan a directory
$result = $scanner->scanDirectory('./my-plugin');

// Check if it passes
if ($result->passes()) {
    echo "Security check passed!\n";
} else {
    echo "Security check failed.\n";
}

// Get JSON output
echo $result->toJson();

// Or save to file
$result->saveToFile('results.json');
```

### Configuration

```php
$scanner = new SecurityScanner();

// Disable SSL verification (for development with self-signed certs)
$scanner->setSslVerify(false);

// Then scan
$result = $scanner->scanFromUrl($url);
```

### Working with Results

```php
$result = $scanner->scanFromUrl($url);

// Check what was found
echo "Has security header: " . ($result->hasSecurityHeader() ? 'Yes' : 'No') . "\n";
echo "Has security.md: " . ($result->hasSecurityMd ? 'Yes' : 'No') . "\n";
echo "Has security.txt: " . ($result->hasSecurityTxt ? 'Yes' : 'No') . "\n";
echo "Is consistent: " . ($result->isConsistent ? 'Yes' : 'No') . "\n";

// Get contact information
echo "Header contact: " . ($result->headerContact ?? 'None') . "\n";
echo "Header file: " . ($result->headerFile ?? 'None') . "\n";
echo "Primary contact: " . ($result->getPrimaryContact() ?? 'None') . "\n";

// Check for issues
if ($result->hasIssues()) {
    echo "Issues found:\n";
    foreach ($result->issues as $issue) {
        echo "  - $issue\n";
    }
}

// Get summary
$summary = $result->getSummary();
print_r($summary);
// [
//     'success' => true,
//     'passes' => true,
//     'has_header' => true,
//     'has_security_md' => true,
//     'has_security_txt' => false,
//     'is_consistent' => true,
//     'issue_count' => 0,
//     'primary_contact' => 'security@example.com',
//     'package_type' => 'plugin',
// ]

// Check package type
echo "Package type: " . ($result->packageType ?? 'unknown') . "\n";
```

## JSON Output Format

```json
{
    "success": true,
    "header": {
        "found": true,
        "contact": "security@example.com",
        "file": "my-plugin.php"
    },
    "files": {
        "security_md": {
            "exists": true,
            "contact": "security@example.com"
        },
        "security_txt": {
            "exists": true,
            "contact": "security@example.com"
        }
    },
    "consistency": {
        "is_consistent": true,
        "primary_contact": "security@example.com"
    },
    "summary": {
        "success": true,
        "passes": true,
        "has_header": true,
        "has_security_md": true,
        "has_security_txt": true,
        "is_consistent": true,
        "issue_count": 0,
        "primary_contact": "security@example.com",
        "package_type": "plugin"
    },
    "issues": [],
    "metadata": {
        "scanned_at": "2026-02-05T10:30:00+00:00",
        "package_type": "plugin",
        "scanned_directory": "/tmp/extracted/my-plugin"
    }
}
```

## Integration Examples

### GitHub Actions

```yaml
name: Security Header Check

on: [push, pull_request]

jobs:
  security-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup PHP
        uses: shivammathur/setup-php@v2
        with:
          php-version: '8.3'
          
      - name: Install dependencies
        run: composer install
        
      - name: Check security header
        run: |
          php bin/security-header ./ --output=security-results.json --quiet
          
          # Check if it passes
          PASSES=$(jq -r '.summary.passes' security-results.json)
          if [ "$PASSES" != "true" ]; then
            echo "Security header check failed!"
            jq '.issues' security-results.json
            exit 1
          fi
          
          echo "Security header check passed!"

      - name: Upload results
        uses: actions/upload-artifact@v4
        with:
          name: security-results
          path: security-results.json
```

### In a WordPress Plugin Review Tool

```php
use FairForge\Tools\SecurityHeader\SecurityScanner;

$scanner = new SecurityScanner();

try {
    $result = $scanner->scanFromUrl($plugin_zip_url);
    
    if (!$result->passes()) {
        $issues = $result->issues;
        
        if (!$result->hasSecurityHeader()) {
            wp_admin_notice(
                'Plugin is missing a Security header in the main file.',
                ['type' => 'error']
            );
        }
        
        if (!$result->isConsistent) {
            wp_admin_notice(
                'Plugin has inconsistent security contact information.',
                ['type' => 'warning']
            );
        }
    } else {
        wp_admin_notice(
            sprintf('Security contact: %s', $result->getPrimaryContact()),
            ['type' => 'success']
        );
    }
} catch (RuntimeException $e) {
    wp_admin_notice('Failed to check security: ' . $e->getMessage(), ['type' => 'error']);
}
```

## Use Cases

1. **Plugin/Theme Development** - Ensure security contact information is properly added
2. **Plugin Directory Submission** - Validate before submitting to WordPress.org
3. **Security Auditing** - Check third-party plugins for security contact info
4. **CI/CD Integration** - Automatically verify security headers in your pipeline
5. **Plugin Review** - Check plugins before installation

## Running Tests

```bash
composer test
```

## Running Code Quality Checks

```bash
# Run PHPCS
composer lint

# Fix PHPCS issues
composer lint:fix

# Run all checks
composer check
```

## License

MIT

