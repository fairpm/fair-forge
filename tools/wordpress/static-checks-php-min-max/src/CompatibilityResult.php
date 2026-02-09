<?php

declare(strict_types=1);

namespace FairForge\Tools\PhpMinMax;

use FairForge\Shared\AbstractToolResult;

/**
 * Represents the result of a PHP version compatibility scan.
 */
class CompatibilityResult extends AbstractToolResult
{
    /**
     * @param bool $success Whether the scan completed successfully
     * @param string|null $minVersion Minimum PHP version that passes (no fatal errors)
     * @param string|null $maxVersion Maximum PHP version that passes (no fatal errors)
     * @param string[] $passedVersions All PHP versions that pass (no errors)
     * @param array<string, array{errors: int, warnings: int}> $failedVersions Versions that failed with error counts
     * @param array<string, int> $warningVersions Versions that passed but have warnings
     * @param array<array{file: string, line: int, type: string, message: string, source: string, affectedVersions: string[]}> $issues All compatibility issues found
     * @param string $scannedDirectory The directory that was scanned
     * @param string|null $parseError Parse error message if any
     */
    public function __construct(
        public readonly bool $success,
        public readonly ?string $minVersion,
        public readonly ?string $maxVersion,
        public readonly array $passedVersions,
        public readonly array $failedVersions,
        public readonly array $warningVersions,
        public readonly array $issues,
        public readonly string $scannedDirectory,
        public readonly ?string $parseError = null,
    ) {
    }

    /**
     * Check if any versions passed.
     */
    public function hasPassingVersions(): bool
    {
        return !empty($this->passedVersions);
    }

    /**
     * Check if there are any compatibility issues.
     */
    public function hasIssues(): bool
    {
        return !empty($this->issues);
    }

    /**
     * Get count of errors-only issues.
     */
    public function getErrorCount(): int
    {
        return count(array_filter($this->issues, fn($i) => $i['type'] === 'ERROR'));
    }

    /**
     * Get count of warning-only issues.
     */
    public function getWarningCount(): int
    {
        return count(array_filter($this->issues, fn($i) => $i['type'] === 'WARNING'));
    }

    /**
     * Check if a specific PHP version is compatible (no errors).
     */
    public function isVersionCompatible(string $version): bool
    {
        return in_array($version, $this->passedVersions, true);
    }

    /**
     * Get the recommended version range string (e.g., ">=7.4 <=8.4").
     */
    public function getVersionRange(): ?string
    {
        if ($this->minVersion === null || $this->maxVersion === null) {
            return null;
        }

        if ($this->minVersion === $this->maxVersion) {
            return "={$this->minVersion}";
        }

        return ">={$this->minVersion} <={$this->maxVersion}";
    }

    /**
     * Get composer-compatible version constraint string.
     */
    public function getComposerConstraint(): ?string
    {
        if ($this->minVersion === null || $this->maxVersion === null) {
            return null;
        }

        if ($this->minVersion === $this->maxVersion) {
            return "~{$this->minVersion}.0";
        }

        // Convert to composer format: ^7.4 || ^8.0
        // For ranges like 7.4-8.4, we need to figure out major version spans
        $minParts = explode('.', $this->minVersion);
        $maxParts = explode('.', $this->maxVersion);
        $minMajor = (int) $minParts[0];
        $maxMajor = (int) $maxParts[0];

        if ($minMajor === $maxMajor) {
            return ">={$this->minVersion}";
        }

        // Multiple major versions, use OR format
        $constraints = [];
        for ($major = $minMajor; $major <= $maxMajor; $major++) {
            if ($major === $minMajor) {
                $constraints[] = "^{$this->minVersion}";
            } else {
                $constraints[] = "^{$major}.0";
            }
        }

        return implode(' || ', $constraints);
    }

    /**
     * Get all error issues grouped by file.
     *
     * @return array<string, array<array{line: int, message: string, source: string, affectedVersions: string[]}>>
     */
    public function getErrorsByFile(): array
    {
        $byFile = [];
        foreach ($this->issues as $issue) {
            if ($issue['type'] !== 'ERROR') {
                continue;
            }
            $file = $issue['file'];
            if (!isset($byFile[$file])) {
                $byFile[$file] = [];
            }
            $byFile[$file][] = [
                'line' => $issue['line'],
                'message' => $issue['message'],
                'source' => $issue['source'],
                'affectedVersions' => $issue['affectedVersions'],
            ];
        }
        return $byFile;
    }

    /**
     * Get a summary of the scan.
     *
     * @return array{success: bool, min_version: string|null, max_version: string|null, version_range: string|null, passed_count: int, failed_count: int, issue_count: int}
     */
    public function getSummary(): array
    {
        return [
            'success' => $this->success,
            'min_version' => $this->minVersion,
            'max_version' => $this->maxVersion,
            'version_range' => $this->getVersionRange(),
            'composer_constraint' => $this->getComposerConstraint(),
            'passed_count' => count($this->passedVersions),
            'failed_count' => count($this->failedVersions),
            'issue_count' => count($this->issues),
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
        return 'php-min-max';
    }

    /**
     * {@inheritDoc}
     */
    public function isSuccess(): bool
    {
        return $this->success;
    }

    /**
     * Detailed compatibility data (version ranges, per-version results).
     *
     * @return array<string, mixed>
     */
    public function getData(): array
    {
        return [
            'compatibility' => [
                'min_version' => $this->minVersion,
                'max_version' => $this->maxVersion,
                'version_range' => $this->getVersionRange(),
                'composer_constraint' => $this->getComposerConstraint(),
            ],
            'versions' => [
                'passed' => $this->passedVersions,
                'failed' => $this->failedVersions,
                'warnings' => $this->warningVersions,
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
            'php_versions_checked' => CompatibilityScanner::PHP_VERSIONS,
            'scanned_directory' => $this->scannedDirectory,
        ];
    }
}
