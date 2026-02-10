<?php

declare(strict_types=1);

namespace FairForge\Tools\ContactInfo;

use FairForge\Shared\AbstractToolResult;

/**
 * Represents the result of a contact info scan.
 *
 * Holds information about:
 * - Publisher contact (Author, Author URI) in the main plugin file
 * - Project URI (Plugin URI)
 * - readme.txt contributors and donate link
 */
class ContactInfoResult extends AbstractToolResult
{
    /**
     * @param bool $success Whether the scan completed successfully
     * @param string|null $publisherName Publisher name from the Author: header
     * @param string|null $publisherUri Publisher URL from the Author URI: header
     * @param string|null $projectUri Project URL from Plugin URI: / Theme URI: header
     * @param string|null $headerFile The file where the headers were found
     * @param string[] $issues List of issues/warnings found
     * @param string $scannedDirectory The directory that was scanned
     * @param string|null $packageType 'plugin' if detected
     * @param string|null $parseError Parse error message if any
     * @param string[] $readmeContributors Contributors listed in readme.txt
     * @param string|null $readmeDonateLink Donate link from readme.txt
     */
    public function __construct(
        public readonly bool $success,
        public readonly ?string $publisherName,
        public readonly ?string $publisherUri,
        public readonly ?string $projectUri,
        public readonly ?string $headerFile,
        public readonly array $issues,
        public readonly string $scannedDirectory,
        public readonly ?string $packageType = null,
        public readonly ?string $parseError = null,
        public readonly array $readmeContributors = [],
        public readonly ?string $readmeDonateLink = null,
    ) {
    }

    /**
     * Check if readme.txt has contributors listed.
     */
    public function hasReadmeContributors(): bool
    {
        return !empty($this->readmeContributors);
    }

    /**
     * Check if readme.txt has a donate link.
     */
    public function hasReadmeDonateLink(): bool
    {
        return $this->readmeDonateLink !== null;
    }

    /**
     * Check if publisher information was found (name or URI).
     */
    public function hasPublisherInfo(): bool
    {
        return $this->publisherName !== null || $this->publisherUri !== null;
    }

    /**
     * Check if a project URI was found.
     */
    public function hasProjectUri(): bool
    {
        return $this->projectUri !== null;
    }

    /**
     * Check if at least one email address is present in any contact field.
     */
    public function hasEmail(): bool
    {
        $fields = [
            $this->publisherUri,
            $this->readmeDonateLink,
        ];

        foreach ($fields as $value) {
            if ($value !== null && preg_match('/[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}/', $value)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if there are any issues.
     */
    public function hasIssues(): bool
    {
        return !empty($this->issues);
    }

    /**
     * Check if the result passes (has publisher info and at least one email).
     */
    public function passes(): bool
    {
        return $this->success
            && $this->hasPublisherInfo()
            && $this->hasEmail();
    }

    /**
     * Get a summary of the scan.
     *
     * @return array{
     *     success: bool,
     *     passes: bool,
     *     has_publisher_name: bool,
     *     has_publisher_uri: bool,
     *     has_project_uri: bool,
     *     has_email: bool,
     *     issue_count: int,
     *     publisher_name: string|null,
     *     publisher_uri: string|null,
     *     package_type: string|null
     * }
     */
    public function getSummary(): array
    {
        return [
            'success' => $this->success,
            'passes' => $this->passes(),
            'has_publisher_name' => $this->publisherName !== null,
            'has_publisher_uri' => $this->publisherUri !== null,
            'has_project_uri' => $this->hasProjectUri(),
            'has_email' => $this->hasEmail(),
            'has_readme_contributors' => $this->hasReadmeContributors(),
            'has_readme_donate_link' => $this->hasReadmeDonateLink(),
            'issue_count' => count($this->issues),
            'publisher_name' => $this->publisherName,
            'publisher_uri' => $this->publisherUri,
            'package_type' => $this->packageType,
        ];
    }

    // ------------------------------------------------------------------
    // ToolResultInterface / AbstractToolResult implementations
    // ------------------------------------------------------------------

    /**
     * {@inheritDoc}
     */
    public function getToolName(): string
    {
        return 'contact-info';
    }

    /**
     * {@inheritDoc}
     */
    public function isSuccess(): bool
    {
        return $this->success;
    }

    /**
     * Detailed scan data (publisher info).
     *
     * @return array<string, mixed>
     */
    public function getData(): array
    {
        return [
            'publisher' => [
                'name' => $this->publisherName,
                'uri' => $this->publisherUri,
                'file' => $this->headerFile,
            ],
            'project' => [
                'uri' => $this->projectUri,
            ],
            'readme' => [
                'contributors' => $this->readmeContributors,
                'donate_link' => $this->readmeDonateLink,
            ],
        ];
    }

    /**
     * {@inheritDoc}
     */
    public function getIssues(): array
    {
        return $this->issues;
    }

    /**
     * {@inheritDoc}
     */
    public function getMetadata(): array
    {
        return [
            'package_type' => $this->packageType,
            'scanned_directory' => $this->scannedDirectory,
        ];
    }
}
