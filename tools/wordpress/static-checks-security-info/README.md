# WordPress Security Info Scanner

A PHP library and CLI tool for checking WordPress plugins and themes for **security contact information**. Returns results as JSON for easy integration with CI/CD pipelines and other tools.

## Features

- **Check Security header** in the main plugin/theme file comment block
- **Detect security files** (security.md, security.txt)
- **Parse readme.txt** for a `== Security ==` section via `fairpm/did-manager`
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

### 4. readme.txt Security Section

A `== Security ==` section inside `readme.txt`:

```
=== My Plugin ===
Contributors: johndoe
Tags: test
Requires at least: 5.0
Stable tag: 1.0

== Description ==
A great plugin.

== Security ==
Report security issues to security@example.com.
```

The readme.txt is parsed using `fairpm/did-manager`'s `ReadmeParser`.
Custom sections like `== Security ==` are extracted automatically.

## Requirements

- PHP 8.1 or higher
- Composer
- Extensions: `curl` (required for downloading)

## Installation

```bash
cd fair-forge/tools/wordpress/static-checks-security-info
composer install
```

## CLI Usage

### Basic Usage

```bash
# Scan a plugin from WordPress.org
php bin/security-info https://downloads.wordpress.org/plugin/akismet.zip

# Scan a local ZIP file
php bin/security-info ./my-plugin.zip

# Scan a local directory
php bin/security-info ./my-plugin/

# Save results to a file
php bin/security-info https://example.com/plugin.zip --output=results.json
```

### Options

| Option | Description |
|--------|-------------|
| `--output=FILE` | Save JSON output to specified file |
| `--insecure, -k` | Skip SSL certificate verification (for self-signed certs) |
| `--quiet, -q` | Suppress progress messages (output only JSON) |
| `--help, -h` | Show help message |

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan passed — has Security header and all contacts are consistent |
| `1` | Scan completed but found issues (missing header or inconsistent contacts) |
| `2` | Error — scan could not complete |

### Example Output

```json
{
  "schema_version": "1.0.0",
  "tool": "security-info",
  "success": true,
  "summary": {
    "success": true,
    "passes": true,
    "has_header": true,
    "has_security_md": true,
    "has_security_txt": true,
    "has_readme_security_section": true,
    "is_consistent": true,
    "issue_count": 0,
    "primary_contact": "security@example.com",
    "package_type": "plugin"
  },
  "data": {
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
      },
      "readme_txt": {
        "has_security_section": true,
        "contact": "security@example.com"
      }
    },
    "consistency": {
      "is_consistent": true,
      "primary_contact": "security@example.com"
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
use FairForge\Tools\SecurityInfo\SecurityScanner;

$scanner = new SecurityScanner();

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
    echo "Security check passed!\n";
}

// Get security info
echo "Has security header: " . ($result->hasSecurityHeader() ? 'Yes' : 'No') . "\n";
echo "Has security.md: " . ($result->hasSecurityMd ? 'Yes' : 'No') . "\n";
echo "Has security.txt: " . ($result->hasSecurityTxt ? 'Yes' : 'No') . "\n";
echo "Has readme.txt security: " . ($result->hasReadmeSecuritySection() ? 'Yes' : 'No') . "\n";
echo "Is consistent: " . ($result->isConsistent ? 'Yes' : 'No') . "\n";

// Get contact information
echo "Header contact: " . ($result->headerContact ?? 'None') . "\n";
echo "readme.txt contact: " . ($result->readmeSecurityContact ?? 'None') . "\n";
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

// Get JSON
$json = $result->toJson();

// Save to file
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

### Using ScanTarget

```php
use FairForge\Shared\ScanTarget;
use FairForge\Tools\SecurityInfo\SecurityScanner;

$scanner = new SecurityScanner();

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
| Missing Security header | No `Security:` header in the main file comment block |
| No security files | No `security.md` or `security.txt` file found |
| security.md no contact | `security.md` exists but no contact info could be extracted |
| security.txt no Contact | `security.txt` exists but no `Contact:` field found |
| Inconsistent contacts | Security contacts in header and files don't match |
| No main file | Could not identify the main plugin or theme file |

## Related Modules

- **[static-checks-contact-info](../static-checks-contact-info/)** — Checks for publisher contact information (Author, Author URI, Plugin/Theme URI)
- **[static-checks-support-info](../static-checks-support-info/)** — Checks for support contact information (Support header, SUPPORT.md)

## License

MIT
