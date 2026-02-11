<?php

declare(strict_types=1);

namespace FairForge\Tools\SupportInfo;

use FairForge\Shared\AbstractToolResult;

/**
 * Represents the result of a support contact scan.
 *
 * Holds information about:
 * - Support contact from the main file header (Support: header)
 * - SUPPORT.md file contact information
 * - Support section from readme.txt
 * - Consistency between support contact sources
 */
class SupportInfoResult extends AbstractToolResult
{
    /**
     * @param bool $success Whether the scan completed successfully
     * @param string|null $supportHeaderContact Support contact from the Support: header (email or URL)
     * @param string|null $headerFile The file where the header was found
     * @param bool $hasSupportMd Whether SUPPORT.md file exists
     * @param string|null $supportMdContact Contact info extracted from SUPPORT.md
     * @param bool $isConsistent Whether all present support contacts are consistent
     * @param string[] $issues List of issues/warnings found
     * @param string $scannedDirectory The directory that was scanned
     * @param string|null $packageType 'plugin' if detected
     * @param string|null $parseError Parse error message if any
     * @param string|null $readmeSupportContact Support contact extracted from readme.txt support section
     */
    public function __construct(
        public readonly bool $success,
        public readonly ?string $supportHeaderContact,
        public readonly ?string $headerFile,
        public readonly bool $hasSupportMd,
        public readonly ?string $supportMdContact,
        public readonly bool $isConsistent,
        public readonly array $issues,
        public readonly string $scannedDirectory,
        public readonly ?string $packageType = null,
        public readonly ?string $parseError = null,
        public readonly ?string $readmeSupportContact = null,
    ) {
    }

    /**
     * Check if a support header was found in the main file.
     */
    public function hasSupportHeader(): bool
    {
        return $this->supportHeaderContact !== null;
    }

    /**
     * Check if SUPPORT.md file exists.
     */
    public function hasSupportFile(): bool
    {
        return $this->hasSupportMd;
    }

    /**
     * Check if support information is present (header, file, or readme section).
     */
    public function hasSupportInfo(): bool
    {
        return $this->hasSupportHeader() || $this->hasSupportFile() || $this->hasReadmeSupportSection();
    }

    /**
     * Check if readme.txt has a support section with contact info.
     */
    public function hasReadmeSupportSection(): bool
    {
        return $this->readmeSupportContact !== null;
    }

    /**
     * Check if at least one email address is present in any support contact field.
     */
    public function hasEmail(): bool
    {
        $fields = [
            $this->supportHeaderContact,
            $this->supportMdContact,
            $this->readmeSupportContact,
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
    public function getPrimarySupportInfo(): ?string
    {
        return $this->supportHeaderContact
            ?? $this->supportMdContact
            ?? $this->readmeSupportContact;
    }

    /**
     * Check if the result passes (has support header, at least one email, and contacts are consistent).
     */
    public function passes(): bool
    {
        return $this->success
            && $this->hasSupportHeader()
            && $this->hasEmail()
            && $this->isConsistent;
    }

    /**
     * Get a summary of the scan.
     *
     * @return array{
     *     success: bool,
     *     passes: bool,
     *     has_support_header: bool,
     *     has_support_md: bool,
     *     has_email: bool,
     *     is_consistent: bool,
     *     issue_count: int,
     *     primary_support_contact: string|null,
     *     package_type: string|null
     * }
     */
    public function getSummary(): array
    {
        return [
            'success' => $this->success,
            'passes' => $this->passes(),
            'has_support_header' => $this->hasSupportHeader(),
            'has_support_md' => $this->hasSupportMd,
            'has_readme_support_section' => $this->hasReadmeSupportSection(),
            'has_email' => $this->hasEmail(),
            'is_consistent' => $this->isConsistent,
            'issue_count' => count($this->issues),
            'primary_support_contact' => $this->getPrimarySupportInfo(),
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
        return 'support-info';
    }

    /**
     * {@inheritDoc}
     */
    public function isSuccess(): bool
    {
        return $this->success;
    }

    /**
     * Detailed scan data (support info, consistency).
     *
     * @return array<string, mixed>
     */
    public function getData(): array
    {
        return [
            'support' => [
                'header' => [
                    'found' => $this->hasSupportHeader(),
                    'contact' => $this->supportHeaderContact,
                    'file' => $this->headerFile,
                ],
                'support_md' => [
                    'exists' => $this->hasSupportMd,
                    'contact' => $this->supportMdContact,
                ],
                'readme_txt' => [
                    'has_support_section' => $this->hasReadmeSupportSection(),
                    'contact' => $this->readmeSupportContact,
                ],
            ],
            'consistency' => [
                'is_consistent' => $this->isConsistent,
                'primary_support_contact' => $this->getPrimarySupportInfo(),
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
