<?php

declare(strict_types=1);

namespace FairForge\Tools\ContactInfo;

use FairForge\Shared\AbstractToolScanner;
use FairForge\Shared\PluginMetadataReader;

/**
 * WordPress Contact Info Scanner.
 *
 * Scans WordPress plugins for publisher contact information using the
 * fairpm/did-manager PluginHeaderParser and ReadmeParser via the shared
 * PluginMetadataReader.
 *
 * Checks for:
 * - Author: header (publisher name)
 * - Author URI: header (publisher URL)
 * - Plugin URI: header (project URL)
 * - readme.txt contributors and donate link as supplementary sources
 */
class ContactInfoScanner extends AbstractToolScanner
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
        return 'contact-info';
    }

    /**
     * Scan a directory for publisher contact information headers.
     *
     * @param string $directory Path to the directory
     */
    public function scanDirectory(string $directory): ContactInfoResult
    {
        $directory = rtrim($directory, '/\\');

        if (!is_dir($directory)) {
            return new ContactInfoResult(
                success: false,
                publisherName: null,
                publisherUri: null,
                projectUri: null,
                headerFile: null,
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

        // Extract headers from the parsed data
        $publisherName = null;
        $publisherUri = null;
        $projectUri = null;
        $headerFile = null;

        if ($mainFile !== null) {
            $headers = $this->metadataReader->parseFile($mainFile);
            $publisherName = $headers['author'] ?? null;
            $publisherUri = $headers['author_uri'] ?? null;
            $projectUri = $headers['plugin_uri'] ?? null;

            if ($publisherName !== null || $publisherUri !== null) {
                $headerFile = $this->getRelativePath($packageDir, $mainFile);
            }
        }

        // Parse readme.txt for supplementary contributor and donate info
        $readmeData = $this->metadataReader->parseReadme($packageDir);
        $readmeContributors = $readmeData['header']['contributors'] ?? [];
        $readmeDonateLink = $readmeData['header']['donate_link'] ?? null;

        // Gather issues
        $issues = $this->gatherIssues(
            $publisherName,
            $publisherUri,
            $mainFile,
            $readmeContributors,
            $readmeDonateLink,
        );

        return new ContactInfoResult(
            success: true,
            publisherName: $publisherName,
            publisherUri: $publisherUri,
            projectUri: $projectUri,
            headerFile: $headerFile,
            issues: $issues,
            scannedDirectory: $packageDir,
            packageType: $packageType,
            readmeContributors: $readmeContributors,
            readmeDonateLink: $readmeDonateLink,
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
     * Gather issues based on the scan results.
     *
     * @param string[] $readmeContributors
     * @return string[]
     */
    private function gatherIssues(
        ?string $publisherName,
        ?string $publisherUri,
        ?string $mainFile,
        array $readmeContributors,
        ?string $readmeDonateLink,
    ): array {
        $issues = [];

        if ($mainFile === null) {
            $issues[] = 'Could not identify the main plugin file';
        } else {
            if ($publisherName === null) {
                $issues[] = 'Missing Author header in the main file comment block';
            }

            if ($publisherUri === null) {
                $issues[] = 'Missing Author URI header in the main file comment block';
            }
        }

        if (empty($readmeContributors)) {
            $issues[] = 'No contributors listed in readme.txt';
        }

        // Check that at least one field contains an email address
        $hasEmail = false;
        $emailFields = [$publisherUri, $readmeDonateLink];
        foreach ($emailFields as $value) {
            if ($value !== null && preg_match('/[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}/', $value)) {
                $hasEmail = true;
                break;
            }
        }
        if (!$hasEmail) {
            $issues[] = 'No email address found in any contact field';
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
