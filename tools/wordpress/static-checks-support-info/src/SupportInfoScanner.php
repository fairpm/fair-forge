<?php

declare(strict_types=1);

namespace FairForge\Tools\SupportInfo;

use FairForge\Shared\AbstractToolScanner;
use FairForge\Shared\PluginMetadataReader;

/**
 * WordPress Support Info Scanner.
 *
 * Scans WordPress plugins for support contact information using the
 * fairpm/did-manager PluginHeaderParser and ReadmeParser via the shared
 * PluginMetadataReader.
 *
 * Checks for:
 * - Support: header in the main plugin file comment block
 * - SUPPORT.md file with contact information
 * - Support section in readme.txt
 * - Consistency between support contact sources
 */
class SupportInfoScanner extends AbstractToolScanner
{
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
        return 'support-info';
    }

    /**
     * Scan a directory for support contact information.
     *
     * @param string $directory Path to the directory
     */
    public function scanDirectory(string $directory): SupportInfoResult
    {
        $directory = rtrim($directory, '/\\');

        if (!is_dir($directory)) {
            return new SupportInfoResult(
                success: false,
                supportHeaderContact: null,
                headerFile: null,
                hasSupportMd: false,
                supportMdContact: null,
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

        // Extract support header from parsed data
        $supportHeaderContact = null;
        $headerFile = null;

        if ($mainFile !== null) {
            $headers = $this->metadataReader->parseFile($mainFile);
            $supportHeaderContact = $headers['support'] ?? null;

            if ($supportHeaderContact !== null) {
                $headerFile = $this->getRelativePath($packageDir, $mainFile);
            }
        }

        // Check for support files
        $supportMdInfo = $this->findSupportMd($packageDir);

        // Parse readme.txt for support section
        $readmeData = $this->metadataReader->parseReadme($packageDir);
        $readmeSupportSection = $readmeData['sections']['support'] ?? null;
        $readmeSupportContact = null;
        if ($readmeSupportSection !== null) {
            $readmeSupportContact = $this->extractContactFromText($readmeSupportSection);
        }

        // Gather support contacts for consistency check
        $supportContacts = [];
        if ($supportHeaderContact !== null) {
            $supportContacts['header'] = $this->normalizeContact($supportHeaderContact);
        }
        if ($supportMdInfo['contact'] !== null) {
            $supportContacts['support.md'] = $this->normalizeContact($supportMdInfo['contact']);
        }
        if ($readmeSupportContact !== null) {
            $supportContacts['readme.txt'] = $this->normalizeContact($readmeSupportContact);
        }

        // Check consistency
        $isConsistent = $this->checkConsistency($supportContacts);

        // Gather issues
        $issues = $this->gatherIssues(
            $supportHeaderContact,
            $mainFile,
            $supportMdInfo,
            $isConsistent,
            $supportContacts,
            $readmeSupportContact,
        );

        return new SupportInfoResult(
            success: true,
            supportHeaderContact: $supportHeaderContact,
            headerFile: $headerFile,
            hasSupportMd: $supportMdInfo['exists'],
            supportMdContact: $supportMdInfo['contact'],
            isConsistent: $isConsistent,
            issues: $issues,
            scannedDirectory: $packageDir,
            packageType: $packageType,
            readmeSupportContact: $readmeSupportContact,
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
     * Find and parse SUPPORT.md file.
     *
     * @return array{exists: bool, contact: string|null, path: string|null}
     */
    private function findSupportMd(string $directory): array
    {
        $possibleNames = ['SUPPORT.md', 'support.md', 'Support.md'];

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
     * Extract contact information from a markdown file.
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
        // Look for email addresses
        if (preg_match('/[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}/', $content, $matches)) {
            return $matches[0];
        }

        // Look for URLs with support-related paths
        if (preg_match('/https?:\/\/[^\s\)]+(?:support|help|contact|forum)[^\s\)]*/i', $content, $matches)) {
            return $matches[0];
        }

        // Look for any URL
        if (preg_match('/https?:\/\/[^\s\)]+/', $content, $matches)) {
            return $matches[0];
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
     * @param array{exists: bool, contact: string|null, path: string|null} $supportMdInfo
     * @param array<string, string> $supportContacts
     * @return string[]
     */
    private function gatherIssues(
        ?string $supportHeaderContact,
        ?string $mainFile,
        array $supportMdInfo,
        bool $isConsistent,
        array $supportContacts,
        ?string $readmeSupportContact,
    ): array {
        $issues = [];

        if ($mainFile === null) {
            $issues[] = 'Could not identify the main plugin file';
        } elseif ($supportHeaderContact === null) {
            $issues[] = 'Missing Support header in the main file comment block';
        }

        if (!$supportMdInfo['exists']) {
            $issues[] = 'No SUPPORT.md file found';
        }

        if ($supportMdInfo['exists'] && $supportMdInfo['contact'] === null) {
            $issues[] = 'SUPPORT.md exists but no contact information could be extracted';
        }

        if (!$isConsistent && count($supportContacts) > 1) {
            $contactList = [];
            foreach ($supportContacts as $source => $contact) {
                $contactList[] = "$source: $contact";
            }
            $issues[] = 'Inconsistent support contacts: ' . implode(', ', $contactList);
        }

        // Check that at least one field contains an email address
        $hasEmail = false;
        $emailFields = [$supportHeaderContact, $supportMdInfo['contact'], $readmeSupportContact];
        foreach ($emailFields as $value) {
            if ($value !== null && preg_match('/[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}/', $value)) {
                $hasEmail = true;
                break;
            }
        }
        if (!$hasEmail) {
            $issues[] = 'No email address found in any support contact field';
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
