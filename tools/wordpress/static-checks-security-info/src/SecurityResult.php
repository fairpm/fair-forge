<?php

declare(strict_types=1);

namespace FairForge\Tools\SecurityInfo;

use FairForge\Shared\AbstractToolResult;

/**
 * Represents the result of a security header scan.
 *
 * Holds information about:
 * - Security header in the main plugin/theme file
 * - Presence and content of security.md and security.txt files
 * - Consistency between the header and files
 */
class SecurityResult extends AbstractToolResult
{
    /**
     * @param bool $success Whether the scan completed successfully
     * @param string|null $headerContact Security contact from the main file header (email or URL)
     * @param string|null $headerFile The file where the header was found
     * @param bool $hasSecurityMd Whether security.md file exists
     * @param string|null $securityMdContact Contact info extracted from security.md
     * @param bool $hasSecurityTxt Whether security.txt file exists
     * @param string|null $securityTxtContact Contact info extracted from security.txt
     * @param bool $isConsistent Whether all present security info is consistent
     * @param string[] $issues List of issues/warnings found
     * @param string $scannedDirectory The directory that was scanned
     * @param string|null $packageType 'plugin' or 'theme' if detected
     * @param string|null $parseError Parse error message if any
     */
    public function __construct(
        public readonly bool $success,
        public readonly ?string $headerContact,
        public readonly ?string $headerFile,
        public readonly bool $hasSecurityMd,
        public readonly ?string $securityMdContact,
        public readonly bool $hasSecurityTxt,
        public readonly ?string $securityTxtContact,
        public readonly bool $isConsistent,
        public readonly array $issues,
        public readonly string $scannedDirectory,
        public readonly ?string $packageType = null,
        public readonly ?string $parseError = null,
    ) {
    }

    /**
     * Check if a security header was found in the main file.
     */
    public function hasSecurityHeader(): bool
    {
        return $this->headerContact !== null;
    }

    /**
     * Check if any security file exists (security.md or security.txt).
     */
    public function hasSecurityFile(): bool
    {
        return $this->hasSecurityMd || $this->hasSecurityTxt;
    }

    /**
     * Check if security information is present (header or file).
     */
    public function hasSecurityInfo(): bool
    {
        return $this->hasSecurityHeader() || $this->hasSecurityFile();
    }

    /**
     * Check if there are any issues.
     */
    public function hasIssues(): bool
    {
        return !empty($this->issues);
    }

    /**
     * Get the primary security contact (from header, then files).
     */
    public function getPrimaryContact(): ?string
    {
        return $this->headerContact
            ?? $this->securityMdContact
            ?? $this->securityTxtContact;
    }

    /**
     * Check if the result passes (has header and is consistent).
     */
    public function passes(): bool
    {
        return $this->success
            && $this->hasSecurityHeader()
            && $this->isConsistent;
    }

    /**
     * Get a summary of the scan.
     *
     * @return array{
     *     success: bool,
     *     passes: bool,
     *     has_header: bool,
     *     has_security_md: bool,
     *     has_security_txt: bool,
     *     is_consistent: bool,
     *     issue_count: int,
     *     primary_contact: string|null,
     *     package_type: string|null
     * }
     */
    public function getSummary(): array
    {
        return [
            'success' => $this->success,
            'passes' => $this->passes(),
            'has_header' => $this->hasSecurityHeader(),
            'has_security_md' => $this->hasSecurityMd,
            'has_security_txt' => $this->hasSecurityTxt,
            'is_consistent' => $this->isConsistent,
            'issue_count' => count($this->issues),
            'primary_contact' => $this->getPrimaryContact(),
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
        return 'security-info';
    }

    /**
     * {@inheritDoc}
     */
    public function isSuccess(): bool
    {
        return $this->success;
    }

    /**
     * Detailed scan data (header info, file info, consistency).
     *
     * @return array<string, mixed>
     */
    public function getData(): array
    {
        return [
            'header' => [
                'found' => $this->hasSecurityHeader(),
                'contact' => $this->headerContact,
                'file' => $this->headerFile,
            ],
            'files' => [
                'security_md' => [
                    'exists' => $this->hasSecurityMd,
                    'contact' => $this->securityMdContact,
                ],
                'security_txt' => [
                    'exists' => $this->hasSecurityTxt,
                    'contact' => $this->securityTxtContact,
                ],
            ],
            'consistency' => [
                'is_consistent' => $this->isConsistent,
                'primary_contact' => $this->getPrimaryContact(),
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
