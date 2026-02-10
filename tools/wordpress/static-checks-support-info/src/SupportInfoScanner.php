<?php

declare(strict_types=1);

namespace FairForge\Tools\SupportInfo;

use FairForge\Shared\AbstractToolScanner;
use FairForge\Shared\ZipHandler;

/**
 * WordPress Support Info Scanner.
 *
 * Scans WordPress plugins and themes for support contact information.
 *
 * Checks for:
 * - Support: header in the main plugin/theme file comment block (support contact)
 * - SUPPORT.md file with contact information
 * - Consistency between support contact sources
 */
class SupportInfoScanner extends AbstractToolScanner
{
    /**
     * Pattern to match Support header in a comment block.
     * Matches: Support: support@example.com or Support: https://example.com/support
     */
    private const SUPPORT_HEADER_PATTERN = '/^\s*\*?\s*Support:\s*(.+?)\s*$/mi';

    /**
     * Common plugin header patterns to identify the main file.
     */
    private const PLUGIN_HEADER_PATTERN = '/^\s*\*?\s*Plugin Name:\s*.+/mi';

    /**
     * Common theme header patterns to identify style.css.
     */
    private const THEME_HEADER_PATTERN = '/^\s*Theme Name:\s*.+/mi';

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

        // Detect package type and find main file
        $mainFileInfo = $this->findMainFile($packageDir);
        $packageType = $mainFileInfo['type'];
        $mainFile = $mainFileInfo['file'];

        // Extract support header from main file
        $supportHeaderContact = null;
        $headerFile = null;

        if ($mainFile !== null) {
            $supportHeaderContact = $this->extractSupportHeader($mainFile, $packageType);

            if ($supportHeaderContact !== null) {
                $headerFile = $this->getRelativePath($packageDir, $mainFile);
            }
        }

        // Check for support files
        $supportMdInfo = $this->findSupportMd($packageDir);

        // Gather support contacts for consistency check
        $supportContacts = [];
        if ($supportHeaderContact !== null) {
            $supportContacts['header'] = $this->normalizeContact($supportHeaderContact);
        }
        if ($supportMdInfo['contact'] !== null) {
            $supportContacts['support.md'] = $this->normalizeContact($supportMdInfo['contact']);
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
            $packageType,
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
     * Extract Support header from a file.
     */
    private function extractSupportHeader(string $filePath, ?string $packageType): ?string
    {
        $content = file_get_contents($filePath);
        if ($content === false) {
            return null;
        }

        // Find the comment block that contains the Plugin Name / Theme Name header.
        // Some plugins (e.g. Akismet) have a docblock before the actual plugin
        // header, so we cannot just grab the first comment block.
        $headerPattern = $packageType === 'theme'
            ? self::THEME_HEADER_PATTERN
            : self::PLUGIN_HEADER_PATTERN;

        if (!preg_match_all('/\/\*\*?.*?\*\//s', $content, $allBlocks)) {
            return null;
        }

        $commentBlock = null;
        foreach ($allBlocks[0] as $block) {
            if (preg_match($headerPattern, $block)) {
                $commentBlock = $block;
                break;
            }
        }

        if ($commentBlock === null) {
            return null;
        }

        if (preg_match(self::SUPPORT_HEADER_PATTERN, $commentBlock, $matches)) {
            return trim($matches[1]);
        }

        return null;
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
        ?string $packageType,
    ): array {
        $issues = [];

        if ($mainFile === null) {
            $issues[] = 'Could not identify the main plugin or theme file';
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
        $emailFields = [$supportHeaderContact, $supportMdInfo['contact']];
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
