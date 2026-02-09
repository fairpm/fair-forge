<?php

declare(strict_types=1);

namespace FairForge\Tools\PhpMinMax;

use FairForge\Shared\AbstractToolScanner;
use RuntimeException;

/**
 * PHP Version Compatibility Scanner using PHPCompatibility.
 *
 * Scans PHP code to determine minimum and maximum PHP version compatibility.
 * Uses PHPCompatibility sniffs to detect version-specific features.
 */
class CompatibilityScanner extends AbstractToolScanner
{
    /**
     * All PHP versions to check for compatibility.
     * Ordered from oldest to newest.
     */
    public const PHP_VERSIONS = [
        '5.2', '5.3', '5.4', '5.5', '5.6',
        '7.0', '7.1', '7.2', '7.3', '7.4',
        '8.0', '8.1', '8.2', '8.3', '8.4',
    ];

    /**
     * File extensions to scan.
     *
     * @var string[]
     */
    private array $extensions = ['php'];

    /**
     * Get the tool name identifier.
     */
    public function getToolName(): string
    {
        return 'php-min-max';
    }

    /**
     * Get file extensions being scanned.
     *
     * @return string[]
     */
    public function getExtensions(): array
    {
        return $this->extensions;
    }

    /**
     * Set file extensions to scan.
     *
     * @param string[] $extensions
     */
    public function setExtensions(array $extensions): self
    {
        $this->extensions = $extensions;

        return $this;
    }

    /**
     * Scan a local directory for PHP version compatibility.
     *
     * @param string $directory The directory to scan
     *
     * @throws RuntimeException If the scan fails
     */
    public function scanDirectory(string $directory): CompatibilityResult
    {
        if (!is_dir($directory)) {
            throw new RuntimeException("Directory not found: {$directory}");
        }

        $phpcsPath = $this->findPhpcs();

        // Run PHPCompatibility scan for each version
        $versionResults = [];
        foreach (self::PHP_VERSIONS as $version) {
            $versionResults[$version] = $this->runPhpcsForVersion($phpcsPath, $directory, $version);
        }

        return $this->analyzeResults($versionResults, $directory);
    }

    /**
     * Find the PHPCS executable.
     *
     * @throws RuntimeException If phpcs is not found
     */
    private function findPhpcs(): string
    {
        // Check in vendor/bin first (Composer installation)
        $vendorBin = dirname(__DIR__) . '/vendor/bin/phpcs';

        if (file_exists($vendorBin)) {
            return $vendorBin;
        }

        // Windows variant
        $vendorBinBat = dirname(__DIR__) . '/vendor/bin/phpcs.bat';

        if (file_exists($vendorBinBat)) {
            return $vendorBinBat;
        }

        // Check system PATH
        $command = PHP_OS_FAMILY === 'Windows' ? 'where phpcs' : 'which phpcs';
        $output = [];
        $returnCode = 0;
        exec($command, $output, $returnCode);

        if ($returnCode === 0 && !empty($output[0])) {
            return trim($output[0]);
        }

        throw new RuntimeException(
            'PHPCS not found. Install via: composer require --dev squizlabs/php_codesniffer'
        );
    }

    /**
     * Run PHPCS with PHPCompatibility for a specific PHP version.
     *
     * @param string $phpcsPath Path to phpcs executable
     * @param string $directory Directory to scan
     * @param string $version PHP version to check (e.g., "7.4")
     *
     * @return array{errors: int, warnings: int, issues: array<array{file: string, line: int, type: string, message: string, source: string}>}
     */
    private function runPhpcsForVersion(string $phpcsPath, string $directory, string $version): array
    {
        $args = [
            escapeshellarg($phpcsPath),
            '--standard=PHPCompatibility',
            '--runtime-set', 'testVersion', $version,
            '--report=json',
            '--extensions=' . implode(',', $this->extensions),
            escapeshellarg($directory),
            '2>&1',
        ];

        $command = implode(' ', $args);

        $output = [];
        $returnCode = 0;
        exec($command, $output, $returnCode);

        $jsonOutput = implode("\n", $output);
        $data = @json_decode($jsonOutput, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            // Return parse error as a special case
            return [
                'errors' => 0,
                'warnings' => 0,
                'issues' => [],
                'parseError' => 'Failed to parse PHPCS output: ' . json_last_error_msg(),
                'rawOutput' => $jsonOutput,
            ];
        }

        $errors = $data['totals']['errors'] ?? 0;
        $warnings = $data['totals']['warnings'] ?? 0;
        $issues = [];

        if (isset($data['files']) && is_array($data['files'])) {
            foreach ($data['files'] as $filePath => $fileData) {
                $relativePath = str_replace($directory . DIRECTORY_SEPARATOR, '', $filePath);
                $relativePath = str_replace($directory . '/', '', $relativePath);

                foreach ($fileData['messages'] ?? [] as $message) {
                    $issues[] = [
                        'file' => $relativePath,
                        'line' => $message['line'] ?? 0,
                        'type' => $message['type'] ?? 'ERROR',
                        'message' => $message['message'] ?? '',
                        'source' => $message['source'] ?? '',
                    ];
                }
            }
        }

        return [
            'errors' => $errors,
            'warnings' => $warnings,
            'issues' => $issues,
        ];
    }

    /**
     * Analyze results from all version scans to determine min/max compatibility.
     *
     * @param array<string, array{errors: int, warnings: int, issues: array}> $versionResults
     * @param string $directory The scanned directory
     */
    private function analyzeResults(array $versionResults, string $directory): CompatibilityResult
    {
        $passedVersions = [];
        $failedVersions = [];
        $warningVersions = [];
        $allIssues = [];

        foreach ($versionResults as $version => $result) {
            $hasErrors = ($result['errors'] ?? 0) > 0;
            $hasWarnings = ($result['warnings'] ?? 0) > 0;

            if (!$hasErrors) {
                $passedVersions[] = $version;
                if ($hasWarnings) {
                    $warningVersions[$version] = $result['warnings'];
                }
            } else {
                $failedVersions[$version] = [
                    'errors' => $result['errors'],
                    'warnings' => $result['warnings'],
                ];
            }

            // Collect unique issues with version context
            foreach ($result['issues'] ?? [] as $issue) {
                $key = $issue['file'] . ':' . $issue['line'] . ':' . $issue['source'];
                if (!isset($allIssues[$key])) {
                    $allIssues[$key] = $issue;
                    $allIssues[$key]['affectedVersions'] = [];
                }
                $allIssues[$key]['affectedVersions'][] = $version;
            }
        }

        // Determine min/max versions
        $minVersion = null;
        $maxVersion = null;

        if (!empty($passedVersions)) {
            // Sort passed versions to find the actual min and max
            usort($passedVersions, fn($a, $b) => version_compare($a, $b));
            $minVersion = $passedVersions[0];
            $maxVersion = $passedVersions[count($passedVersions) - 1];
        }

        return new CompatibilityResult(
            success: true,
            minVersion: $minVersion,
            maxVersion: $maxVersion,
            passedVersions: $passedVersions,
            failedVersions: $failedVersions,
            warningVersions: $warningVersions,
            issues: array_values($allIssues),
            scannedDirectory: $directory
        );
    }
}
