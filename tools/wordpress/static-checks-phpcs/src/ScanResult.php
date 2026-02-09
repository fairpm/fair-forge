<?php

declare(strict_types=1);

namespace FairForge\Tools\PhpcsStaticChecks;

use FairForge\Shared\AbstractToolResult;

/**
 * Represents the result of a PHPCS scan.
 */
class ScanResult extends AbstractToolResult
{
    /**
     * @param bool $success Whether the scan completed successfully
     * @param int $errorCount Total number of errors found
     * @param int $warningCount Total number of warnings found
     * @param array<string, array{errors: int, warnings: int, messages: array}> $files Files with issues
     * @param array{errors: int, warnings: int, fixable: int} $totals Summary totals
     * @param string $scannedDirectory The directory that was scanned
     * @param string $standard The PHPCS standard used
     * @param int $phpcsExitCode The PHPCS exit code
     * @param string|null $rawOutput Raw output if parsing failed
     * @param string|null $parseError Parse error message if any
     */
    public function __construct(
        public readonly bool $success,
        public readonly int $errorCount,
        public readonly int $warningCount,
        public readonly array $files,
        public readonly array $totals,
        public readonly string $scannedDirectory,
        public readonly string $standard,
        public readonly int $phpcsExitCode,
        public readonly ?string $rawOutput = null,
        public readonly ?string $parseError = null,
    ) {
    }

    /**
     * Check if any errors were found.
     */
    public function hasErrors(): bool
    {
        return $this->errorCount > 0;
    }

    /**
     * Check if any warnings were found.
     */
    public function hasWarnings(): bool
    {
        return $this->warningCount > 0;
    }

    /**
     * Check if any issues (errors or warnings) were found.
     */
    public function hasIssues(): bool
    {
        return $this->hasErrors() || $this->hasWarnings();
    }

    /**
     * Get the number of files with issues.
     */
    public function getFileCount(): int
    {
        return count($this->files);
    }

    /**
     * Get all error messages across all files.
     *
     * @return array<array{
     *     file: string,
     *     line: int,
     *     column: int,
     *     message: string,
     *     source: string,
     *     severity: int,
     *     fixable: bool
     * }>
     */
    public function getAllErrors(): array
    {
        return $this->getMessagesByType('ERROR');
    }

    /**
     * Get all warning messages across all files.
     *
     * @return array<array{
     *     file: string,
     *     line: int,
     *     column: int,
     *     message: string,
     *     source: string,
     *     severity: int,
     *     fixable: bool
     * }>
     */
    public function getAllWarnings(): array
    {
        return $this->getMessagesByType('WARNING');
    }

    /**
     * Get a summary of the scan.
     *
     * @return array{success: bool, errors: int, warnings: int, fixable: int, files_scanned: int, standard: string}
     */
    public function getSummary(): array
    {
        return [
            'success' => $this->success,
            'errors' => $this->errorCount,
            'warnings' => $this->warningCount,
            'fixable' => $this->totals['fixable'] ?? 0,
            'files_scanned' => $this->getFileCount(),
            'standard' => $this->standard,
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
        return 'phpcs';
    }

    /**
     * {@inheritDoc}
     */
    public function isSuccess(): bool
    {
        return $this->success;
    }

    /**
     * Detailed scan data (totals, files, and optional raw output).
     *
     * @return array<string, mixed>
     */
    public function getData(): array
    {
        $data = [
            'totals' => $this->totals,
            'files' => $this->files,
        ];

        if ($this->parseError !== null) {
            $data['parse_error'] = $this->parseError;
        }

        if ($this->rawOutput !== null) {
            $data['raw_output'] = $this->rawOutput;
        }

        return $data;
    }

    /**
     * {@inheritDoc}
     */
    public function getIssues(): array
    {
        $issues = [];

        foreach ($this->files as $filePath => $fileData) {
            if (!isset($fileData['messages'])) {
                continue;
            }

            foreach ($fileData['messages'] as $message) {
                $issues[] = [
                    'file' => $filePath,
                    'line' => $message['line'] ?? 0,
                    'column' => $message['column'] ?? 0,
                    'type' => $message['type'] ?? 'ERROR',
                    'message' => $message['message'] ?? '',
                    'source' => $message['source'] ?? '',
                    'severity' => $message['severity'] ?? 0,
                    'fixable' => $message['fixable'] ?? false,
                ];
            }
        }

        return $issues;
    }

    /**
     * {@inheritDoc}
     */
    public function getMetadata(): array
    {
        return [
            'standard' => $this->standard,
            'phpcs_exit_code' => $this->phpcsExitCode,
            'scanned_directory' => $this->scannedDirectory,
        ];
    }

    /**
     * Get messages filtered by type.
     *
     * @param string $type 'ERROR' or 'WARNING'
     *
     * @return array<array{
     *     file: string,
     *     line: int,
     *     column: int,
     *     message: string,
     *     source: string,
     *     severity: int,
     *     fixable: bool
     * }>
     */
    private function getMessagesByType(string $type): array
    {
        $messages = [];

        foreach ($this->files as $filePath => $fileData) {
            if (!isset($fileData['messages'])) {
                continue;
            }

            foreach ($fileData['messages'] as $message) {
                if (($message['type'] ?? '') === $type) {
                    $messages[] = [
                        'file' => $filePath,
                        'line' => $message['line'] ?? 0,
                        'column' => $message['column'] ?? 0,
                        'message' => $message['message'] ?? '',
                        'source' => $message['source'] ?? '',
                        'severity' => $message['severity'] ?? 0,
                        'fixable' => $message['fixable'] ?? false,
                    ];
                }
            }
        }

        return $messages;
    }
}
