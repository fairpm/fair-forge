<?php

declare(strict_types=1);

namespace FairForge\Tools\SecurityHeader;

use FairForge\Shared\ZipHandler;
use RuntimeException;

/**
 * WordPress Security Header Scanner.
 *
 * Scans WordPress plugins and themes for security contact headers and files.
 *
 * Checks for:
 * - Security: header in the main plugin/theme file comment block
 * - security.md file
 * - security.txt file
 * - Consistency between all sources
 */
class SecurityScanner
{
    /**
     * Pattern to match Security header in a comment block.
     * Matches: Security: email@example.com or Security: https://example.com/security
     */
    private const SECURITY_HEADER_PATTERN = '/^\s*\*?\s*Security:\s*(.+?)\s*$/mi';

    /**
     * Pattern to extract contact from security.txt (RFC 9116 format).
     * Matches: Contact: email or Contact: https://...
     */
    private const SECURITY_TXT_CONTACT_PATTERN = '/^Contact:\s*(.+?)\s*$/mi';

    /**
     * Common plugin header patterns to identify the main file.
     */
    private const PLUGIN_HEADER_PATTERN = '/^\s*\*?\s*Plugin Name:\s*.+/mi';

    /**
     * Common theme header patterns to identify style.css.
     */
    private const THEME_HEADER_PATTERN = '/^\s*Theme Name:\s*.+/mi';

    /** ZIP handler instance. */
    private ZipHandler $zipHandler;

    /**
     * Create a new SecurityScanner instance.
     */
    public function __construct(?ZipHandler $zipHandler = null)
    {
        $this->zipHandler = $zipHandler ?? new ZipHandler();
    }

    /**
     * Get the ZIP handler.
     */
    public function getZipHandler(): ZipHandler
    {
        return $this->zipHandler;
    }

    /**
     * Check if SSL verification is enabled.
     */
    public function getSslVerify(): bool
    {
        return $this->zipHandler->getSslVerify();
    }

    /**
     * Set whether to verify SSL certificates.
     */
    public function setSslVerify(bool $verify): self
    {
        $this->zipHandler->setSslVerify($verify);

        return $this;
    }

    /**
     * Scan from a URL.
     *
     * @param string $url The URL to the ZIP file
     *
     * @throws RuntimeException If download or extraction fails
     */
    public function scanFromUrl(string $url): SecurityResult
    {
        $tempDir = $this->zipHandler->downloadAndExtract($url);

        try {
            return $this->scanDirectory($tempDir);
        } finally {
            $this->zipHandler->removeDirectory($tempDir);
        }
    }

    /**
     * Scan from a local ZIP file.
     *
     * @param string $zipPath Path to the ZIP file
     *
     * @throws RuntimeException If extraction fails
     */
    public function scanFromZipFile(string $zipPath): SecurityResult
    {
        $tempDir = $this->zipHandler->extract($zipPath);

        try {
            return $this->scanDirectory($tempDir);
        } finally {
            $this->zipHandler->removeDirectory($tempDir);
        }
    }

    /**
     * Scan a directory for security headers and files.
     *
     * @param string $directory Path to the directory
     */
    public function scanDirectory(string $directory): SecurityResult
    {
        $directory = rtrim($directory, '/\\');

        if (!is_dir($directory)) {
            return new SecurityResult(
                success: false,
                headerContact: null,
                headerFile: null,
                hasSecurityMd: false,
                securityMdContact: null,
                hasSecurityTxt: false,
                securityTxtContact: null,
                isConsistent: false,
                issues: ['Directory does not exist: ' . $directory],
                scannedDirectory: $directory,
                parseError: 'Directory not found',
            );
        }

        // Find the actual package directory (might be nested)
        $packageDir = $this->findPackageDirectory($directory);

        // Detect package type and find main file
        $mainFileInfo = $this->findMainFile($packageDir);
        $packageType = $mainFileInfo['type'];
        $mainFile = $mainFileInfo['file'];

        // Extract security header from main file
        $headerContact = null;
        $headerFile = null;
        if ($mainFile !== null) {
            $headerContact = $this->extractSecurityHeader($mainFile);
            if ($headerContact !== null) {
                $headerFile = $this->getRelativePath($packageDir, $mainFile);
            }
        }

        // Check for security files
        $securityMdInfo = $this->findSecurityMd($packageDir);
        $securityTxtInfo = $this->findSecurityTxt($packageDir);

        // Gather all contacts for consistency check
        $contacts = [];
        if ($headerContact !== null) {
            $contacts['header'] = $this->normalizeContact($headerContact);
        }
        if ($securityMdInfo['contact'] !== null) {
            $contacts['security.md'] = $this->normalizeContact($securityMdInfo['contact']);
        }
        if ($securityTxtInfo['contact'] !== null) {
            $contacts['security.txt'] = $this->normalizeContact($securityTxtInfo['contact']);
        }

        // Check consistency
        $isConsistent = $this->checkConsistency($contacts);

        // Gather issues
        $issues = $this->gatherIssues(
            $headerContact,
            $mainFile,
            $securityMdInfo,
            $securityTxtInfo,
            $isConsistent,
            $contacts,
            $packageType,
        );

        return new SecurityResult(
            success: true,
            headerContact: $headerContact,
            headerFile: $headerFile,
            hasSecurityMd: $securityMdInfo['exists'],
            securityMdContact: $securityMdInfo['contact'],
            hasSecurityTxt: $securityTxtInfo['exists'],
            securityTxtContact: $securityTxtInfo['contact'],
            isConsistent: $isConsistent,
            issues: $issues,
            scannedDirectory: $packageDir,
            packageType: $packageType,
        );
    }

    /**
     * Find the actual package directory (handles nested directories in ZIPs).
     */
    private function findPackageDirectory(string $directory): string
    {
        // Check if there's exactly one subdirectory (common for ZIP extracts)
        $items = array_diff(scandir($directory) ?: [], ['.', '..']);

        if (count($items) === 1) {
            $singleItem = $directory . '/' . reset($items);
            if (is_dir($singleItem)) {
                return $singleItem;
            }
        }

        return $directory;
    }

    /**
     * Find the main plugin or theme file.
     *
     * @return array{type: string|null, file: string|null}
     */
    private function findMainFile(string $directory): array
    {
        // First check for theme (style.css in root)
        $styleCss = $directory . '/style.css';
        if (file_exists($styleCss)) {
            $content = file_get_contents($styleCss);
            if ($content !== false && preg_match(self::THEME_HEADER_PATTERN, $content)) {
                return ['type' => 'theme', 'file' => $styleCss];
            }
        }

        // Look for plugin files
        $pluginFiles = $this->findPluginFiles($directory);

        // First, check for a file with the same name as the directory
        $dirName = basename($directory);
        $expectedFile = $directory . '/' . $dirName . '.php';
        if (in_array($expectedFile, $pluginFiles, true)) {
            return ['type' => 'plugin', 'file' => $expectedFile];
        }

        // Otherwise, return the first plugin file found
        if (!empty($pluginFiles)) {
            return ['type' => 'plugin', 'file' => $pluginFiles[0]];
        }

        return ['type' => null, 'file' => null];
    }

    /**
     * Find all PHP files with plugin headers in the root directory.
     *
     * @return string[]
     */
    private function findPluginFiles(string $directory): array
    {
        $pluginFiles = [];
        $files = glob($directory . '/*.php') ?: [];

        foreach ($files as $file) {
            $content = file_get_contents($file);
            if ($content === false) {
                continue;
            }

            // Check if it has a plugin header
            if (preg_match(self::PLUGIN_HEADER_PATTERN, $content)) {
                $pluginFiles[] = $file;
            }
        }

        return $pluginFiles;
    }

    /**
     * Extract Security header from a PHP file.
     */
    private function extractSecurityHeader(string $filePath): ?string
    {
        $content = file_get_contents($filePath);
        if ($content === false) {
            return null;
        }

        // Find the opening comment block (plugin/theme header)
        if (!preg_match('/\/\*\*?.*?\*\//s', $content, $matches)) {
            return null;
        }

        $commentBlock = $matches[0];

        if (preg_match(self::SECURITY_HEADER_PATTERN, $commentBlock, $matches)) {
            return trim($matches[1]);
        }

        return null;
    }

    /**
     * Find and parse security.md file.
     *
     * @return array{exists: bool, contact: string|null, path: string|null}
     */
    private function findSecurityMd(string $directory): array
    {
        $possibleNames = ['SECURITY.md', 'security.md', 'Security.md'];

        foreach ($possibleNames as $name) {
            $path = $directory . '/' . $name;
            if (file_exists($path)) {
                $contact = $this->extractContactFromMarkdown($path);
                return ['exists' => true, 'contact' => $contact, 'path' => $path];
            }
        }

        return ['exists' => false, 'contact' => null, 'path' => null];
    }

    /**
     * Find and parse security.txt file.
     *
     * @return array{exists: bool, contact: string|null, path: string|null}
     */
    private function findSecurityTxt(string $directory): array
    {
        // Check common locations
        $possiblePaths = [
            $directory . '/security.txt',
            $directory . '/SECURITY.txt',
            $directory . '/.well-known/security.txt',
        ];

        foreach ($possiblePaths as $path) {
            if (file_exists($path)) {
                $contact = $this->extractContactFromSecurityTxt($path);
                return ['exists' => true, 'contact' => $contact, 'path' => $path];
            }
        }

        return ['exists' => false, 'contact' => null, 'path' => null];
    }

    /**
     * Extract contact information from a markdown security file.
     */
    private function extractContactFromMarkdown(string $filePath): ?string
    {
        $content = file_get_contents($filePath);
        if ($content === false) {
            return null;
        }

        // Look for email addresses
        if (preg_match('/[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}/', $content, $matches)) {
            return $matches[0];
        }

        // Look for URLs with security-related paths
        if (preg_match('/https?:\/\/[^\s\)]+(?:security|report|vulnerability)[^\s\)]*/i', $content, $matches)) {
            return $matches[0];
        }

        // Look for any URL
        if (preg_match('/https?:\/\/[^\s\)]+/', $content, $matches)) {
            return $matches[0];
        }

        return null;
    }

    /**
     * Extract contact from security.txt (RFC 9116 format).
     */
    private function extractContactFromSecurityTxt(string $filePath): ?string
    {
        $content = file_get_contents($filePath);
        if ($content === false) {
            return null;
        }

        if (preg_match(self::SECURITY_TXT_CONTACT_PATTERN, $content, $matches)) {
            return trim($matches[1]);
        }

        return null;
    }

    /**
     * Normalize a contact string for comparison.
     */
    private function normalizeContact(string $contact): string
    {
        // Lowercase
        $normalized = strtolower(trim($contact));

        // Remove mailto: prefix
        $normalized = preg_replace('/^mailto:/i', '', $normalized) ?? $normalized;

        // Remove trailing slashes from URLs
        $normalized = rtrim($normalized, '/');

        return $normalized;
    }

    /**
     * Check if all contacts are consistent.
     *
     * @param array<string, string> $contacts
     */
    private function checkConsistency(array $contacts): bool
    {
        if (count($contacts) <= 1) {
            return true;
        }

        $uniqueContacts = array_unique(array_values($contacts));

        return count($uniqueContacts) === 1;
    }

    /**
     * Gather issues based on the scan results.
     *
     * @param array{exists: bool, contact: string|null, path: string|null} $securityMdInfo
     * @param array{exists: bool, contact: string|null, path: string|null} $securityTxtInfo
     * @param array<string, string> $contacts
     * @return string[]
     */
    private function gatherIssues(
        ?string $headerContact,
        ?string $mainFile,
        array $securityMdInfo,
        array $securityTxtInfo,
        bool $isConsistent,
        array $contacts,
        ?string $packageType,
    ): array {
        $issues = [];

        if ($mainFile === null) {
            $issues[] = 'Could not identify the main plugin or theme file';
        } elseif ($headerContact === null) {
            $issues[] = 'Missing Security header in the main file comment block';
        }

        if (!$securityMdInfo['exists'] && !$securityTxtInfo['exists']) {
            $issues[] = 'No security.md or security.txt file found';
        }

        if ($securityMdInfo['exists'] && $securityMdInfo['contact'] === null) {
            $issues[] = 'security.md exists but no contact information could be extracted';
        }

        if ($securityTxtInfo['exists'] && $securityTxtInfo['contact'] === null) {
            $issues[] = 'security.txt exists but no Contact field found';
        }

        if (!$isConsistent && count($contacts) > 1) {
            $contactList = [];
            foreach ($contacts as $source => $contact) {
                $contactList[] = "$source: $contact";
            }
            $issues[] = 'Inconsistent security contacts: ' . implode(', ', $contactList);
        }

        return $issues;
    }

    /**
     * Get relative path from base directory.
     */
    private function getRelativePath(string $baseDir, string $fullPath): string
    {
        $baseDir = rtrim($baseDir, '/\\') . '/';
        if (str_starts_with($fullPath, $baseDir)) {
            return substr($fullPath, strlen($baseDir));
        }

        return basename($fullPath);
    }
}
