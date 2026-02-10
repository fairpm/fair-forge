<?php

declare(strict_types=1);

namespace FairForge\Tools\ContactInfo;

use FairForge\Shared\AbstractToolResult;

/**
 * Represents the result of a contact info scan.
 *
 * Holds information about:
 * - Publisher contact (Author, Author URI) in the main plugin/theme file
 * - Project URI (Plugin URI / Theme URI)
 * - Support contact from the main file header and SUPPORT.md
 * - Consistency between support contact sources
 */
class ContactInfoResult extends AbstractToolResult
{
    /**
     * @param bool $success Whether the scan completed successfully
     * @param string|null $publisherName Publisher name from the Author: header
     * @param string|null $publisherUri Publisher URL from the Author URI: header
     * @param string|null $projectUri Project URL from Plugin URI: / Theme URI: header
     * @param string|null $supportHeaderContact Support contact from the Support: header (email or URL)
     * @param string|null $headerFile The file where the headers were found
     * @param bool $hasSupportMd Whether SUPPORT.md file exists
     * @param string|null $supportMdContact Contact info extracted from SUPPORT.md
     * @param bool $isConsistent Whether all present support contacts are consistent
     * @param string[] $issues List of issues/warnings found
     * @param string $scannedDirectory The directory that was scanned
     * @param string|null $packageType 'plugin' or 'theme' if detected
     * @param string|null $parseError Parse error message if any
     */
    public function __construct(
        public readonly bool $success,
        public readonly ?string $publisherName,
        public readonly ?string $publisherUri,
        public readonly ?string $projectUri,
        public readonly ?string $supportHeaderContact,
        public readonly ?string $headerFile,
        public readonly bool $hasSupportMd,
        public readonly ?string $supportMdContact,
        public readonly bool $isConsistent,
        public readonly array $issues,
        public readonly string $scannedDirectory,
        public readonly ?string $packageType = null,
        public readonly ?string $parseError = null,
    ) {
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
     * Check if a support header was found in the main file.
     */
    public function hasSupportHeader(): bool
    {
        return $this->supportHeaderContact !== null;
    }

    /**
     * Check if any support file exists (SUPPORT.md).
     */
    public function hasSupportFile(): bool
    {
        return $this->hasSupportMd;
    }

    /**
     * Check if support information is present (header or file).
     */
    public function hasSupportInfo(): bool
    {
        return $this->hasSupportHeader() || $this->hasSupportFile();
    }

    /**
     * Check if any contact information is present (publisher or support).
     */
    public function hasContactInfo(): bool
    {
        return $this->hasPublisherInfo() || $this->hasSupportInfo();
    }

    /**
     * Check if at least one email address is present in any contact field.
     */
    public function hasEmail(): bool
    {
        $fields = [
            $this->supportHeaderContact,
            $this->supportMdContact,
            $this->publisherUri,
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
     * Get the primary support contact (from header, then file).
     */

    public function getPrimarySupportContact(): ?string
    {
        return $this->supportHeaderContact
            ?? $this->supportMdContact;
    }

    /**
     * Check if the result passes (has publisher info, at least one email, and support contacts are consistent).
     */
    public function passes(): bool
    {
        return $this->success
            && $this->hasPublisherInfo()
            && $this->hasEmail()
            && $this->isConsistent;
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
     *     has_support_header: bool,
     *     has_support_md: bool,
     *     has_email: bool,
     *     is_consistent: bool,
     *     issue_count: int,
     *     publisher_name: string|null,
     *     publisher_uri: string|null,
     *     primary_support_contact: string|null,
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
            'has_support_header' => $this->hasSupportHeader(),
            'has_support_md' => $this->hasSupportMd,
            'has_email' => $this->hasEmail(),
            'is_consistent' => $this->isConsistent,
            'issue_count' => count($this->issues),
            'publisher_name' => $this->publisherName,
            'publisher_uri' => $this->publisherUri,
            'primary_support_contact' => $this->getPrimarySupportContact(),
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
     * Detailed scan data (publisher info, support info, consistency).
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
            'support' => [
                'header' => [
                    'found' => $this->hasSupportHeader(),
                    'contact' => $this->supportHeaderContact,
                ],
                'support_md' => [
                    'exists' => $this->hasSupportMd,
                    'contact' => $this->supportMdContact,
                ],
            ],
            'consistency' => [
                'is_consistent' => $this->isConsistent,
                'primary_support_contact' => $this->getPrimarySupportContact(),
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
