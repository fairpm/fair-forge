<?php

declare(strict_types=1);

namespace FairForge\Tools\SecurityInfo;

use FairForge\Shared\AbstractToolScanner;
use FairForge\Shared\PluginMetadataReader;

/**
 * WordPress Security Info Scanner.
 *
 * Scans WordPress plugins for security contact headers and files using the
 * fairpm/did-manager PluginHeaderParser and ReadmeParser via the shared
 * PluginMetadataReader.
 *
 * Checks for:
 * - Security: header in the main plugin file comment block
 * - security.md file
 * - security.txt file
 * - Security section in readme.txt
 * - Consistency between all sources
 */
class SecurityScanner extends AbstractToolScanner
{
    /**
     * Pattern to extract contact from security.txt (RFC 9116 format).
     * Matches: Contact: email or Contact: https://...
     */
    private const SECURITY_TXT_CONTACT_PATTERN = '/^Contact:\s*(.+?)\s*$/mi';

    private PluginMetadataReader $metadataReader;

    public function __construct(
        ?\FairForge\Shared\ZipHandler $zipHandler = null,
        ?PluginMetadataReader $metadataReader = null,
    ) {
        parent::__construct($zipHandler);
        $this->metadataReader = $metadataReader ?? new PluginMetadataReader();
    }

    /**
     * {@inheritDoc}
     */
    public function getToolName(): string
    {
        return 'security-info';
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

        // Use the did-manager parser to find the main file and parse headers
        $mainFile = $this->metadataReader->findMainFile($packageDir);
        $packageType = $mainFile !== null ? 'plugin' : null;

        // Extract security header from parsed data
        $headerContact = null;
        $headerFile = null;
        if ($mainFile !== null) {
            $headers = $this->metadataReader->parseFile($mainFile);
            $headerContact = $headers['security'] ?? null;

            if ($headerContact !== null) {
                $headerFile = $this->getRelativePath($packageDir, $mainFile);
            }
        }

        // Check for security files
        $securityMdInfo = $this->findSecurityMd($packageDir);
        $securityTxtInfo = $this->findSecurityTxt($packageDir);

        // Parse readme.txt for a security section
        $readmeData = $this->metadataReader->parseReadme($packageDir);
        $readmeSecuritySection = $readmeData['sections']['security'] ?? null;
        $readmeSecurityContact = null;
        if ($readmeSecuritySection !== null) {
            $readmeSecurityContact = $this->extractContactFromText($readmeSecuritySection);
        }

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
        if ($readmeSecurityContact !== null) {
            $contacts['readme.txt'] = $this->normalizeContact($readmeSecurityContact);
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
            readmeSecurityContact: $readmeSecurityContact,
        );
    }

    /**
     * Find the actual package directory (handles nested directories in ZIPs).
     */
    private function findPackageDirectory(string $directory): string
    {
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

        return $this->extractContactFromText($content);
    }

    /**
     * Extract contact information (email or URL) from a text string.
     */
    private function extractContactFromText(string $content): ?string
    {
        if (preg_match('/[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}/', $content, $matches)) {
            return $matches[0];
        }

        if (preg_match('/https?:\/\/[^\s\)]+(?:security|report|vulnerability)[^\s\)]*/i', $content, $matches)) {
            return $matches[0];
        }

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
        $normalized = strtolower(trim($contact));
        $normalized = preg_replace('/^mailto:/i', '', $normalized) ?? $normalized;
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
    ): array {
        $issues = [];

        if ($mainFile === null) {
            $issues[] = 'Could not identify the main plugin file';
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
