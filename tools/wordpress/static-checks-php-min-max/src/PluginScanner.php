<?php

declare(strict_types=1);

namespace FairForge\Tools\WordPress\PluginStaticChecks;

use RuntimeException;

/**
 * WordPress Plugin ZIP Scanner using PHPCS.
 *
 * Scans the contents of a WordPress plugin ZIP file using WordPress PHPCS rules
 * and returns results as JSON.
 *
 * Usage as library:
 *   $scanner = new PluginScanner();
 *   $result = $scanner->scanFromUrl('https://example.com/plugin.zip');
 *   echo json_encode($result, JSON_PRETTY_PRINT);
 *
 * Usage from CLI:
 *   php bin/static-checks https://example.com/plugin.zip
 */
class PluginScanner
{
    /** PHPCS standard to use for scanning. */
    private string $standard = 'WordPress';

    /**
     * File extensions to scan.
     *
     * @var string[]
     */
    private array $extensions = ['php'];

    /** Whether to include warnings in the output. */
    private bool $includeWarnings = true;

    /** PHPCS severity level (1-10). */
    private int $severity = 1;

    /**
     * Additional PHPCS arguments.
     *
     * @var string[]
     */
    private array $additionalArgs = [];

    /** ZIP handler instance. */
    private ZipHandler $zipHandler;

    /**
     * Create a new PluginScanner instance.
     */
    public function __construct(?ZipHandler $zipHandler = null)
    {
        $this->zipHandler = $zipHandler ?? new ZipHandler();
    }

    /**
     * Get the ZIP handler.
     */
    public function getZipHandler(): ZipHandler
    {
        return $this->zipHandler;
    }

    /**
     * Get the PHPCS standard being used.
     */
    public function getStandard(): string
    {
        return $this->standard;
    }

    /**
     * Set the PHPCS standard to use.
     *
     * @param string $standard The standard name (e.g., 'WordPress', 'WordPress-Core', 'WordPress-Extra')
     */
    public function setStandard(string $standard): self
    {
        $this->standard = $standard;

        return $this;
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
     * Check if warnings are included.
     */
    public function getIncludeWarnings(): bool
    {
        return $this->includeWarnings;
    }

    /**
     * Set whether to include warnings in output.
     */
    public function setIncludeWarnings(bool $include): self
    {
        $this->includeWarnings = $include;

        return $this;
    }

    /**
     * Get the severity level.
     */
    public function getSeverity(): int
    {
        return $this->severity;
    }

    /**
     * Set the PHPCS severity level (1-10).
     */
    public function setSeverity(int $severity): self
    {
        $this->severity = max(1, min(10, $severity));

        return $this;
    }

    /**
     * Add additional PHPCS arguments.
     *
     * @param string[] $args
     */
    public function setAdditionalArgs(array $args): self
    {
        $this->additionalArgs = $args;

        return $this;
    }

    /**
     * Check if SSL verification is enabled.
     */
    public function getSslVerify(): bool
    {
        return $this->zipHandler->getSslVerify();
    }

    /**
     * Set whether to verify SSL certificates.
     *
     * Warning: Disabling SSL verification is insecure and should only be used
     * in development environments with self-signed certificates.
     */
    public function setSslVerify(bool $verify): self
    {
        $this->zipHandler->setSslVerify($verify);

        return $this;
    }

    /**
     * Scan a WordPress plugin from a URL.
     *
     * @param string $url The URL to the plugin ZIP file
     *
     * @throws RuntimeException If download or extraction fails
     *
     * @return ScanResult The scan results
     */
    public function scanFromUrl(string $url): ScanResult
    {
        $extractDir = $this->zipHandler->downloadAndExtract($url);

        try {
            return $this->scanDirectory($extractDir);
        } finally {
            $this->zipHandler->removeDirectory($extractDir);
        }
    }

    /**
     * Scan a WordPress plugin from a local ZIP file.
     *
     * @param string $zipPath Path to the local ZIP file
     *
     * @throws RuntimeException If extraction fails
     *
     * @return ScanResult The scan results
     */
    public function scanFromZipFile(string $zipPath): ScanResult
    {
        if (!file_exists($zipPath)) {
            throw new RuntimeException("ZIP file not found: {$zipPath}");
        }

        $extractDir = $this->zipHandler->extract($zipPath);

        try {
            return $this->scanDirectory($extractDir);
        } finally {
            $this->zipHandler->removeDirectory($extractDir);
        }
    }

    /**
     * Scan a local directory.
     *
     * @param string $directory The directory to scan
     *
     * @throws RuntimeException If the scan fails
     *
     * @return ScanResult The scan results
     */
    public function scanDirectory(string $directory): ScanResult
    {
        if (!is_dir($directory)) {
            throw new RuntimeException("Directory not found: {$directory}");
        }

        $phpcsPath = $this->findPhpcs();
        $result = $this->runPhpcs($phpcsPath, $directory);

        return $this->parsePhpcsOutput($result, $directory);
    }

    /**
     * Find the PHPCS executable.
     *
     * @throws RuntimeException If phpcs is not found
     *
     * @return string Path to phpcs
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
     * Run PHPCS on a directory.
     *
     * @param string $phpcsPath Path to phpcs executable
     * @param string $directory Directory to scan
     *
     * @return array{output: string, exitCode: int} The command output and exit code
     */
    private function runPhpcs(string $phpcsPath, string $directory): array
    {
        $args = [
            escapeshellarg($phpcsPath),
            '--standard=' . escapeshellarg($this->standard),
            '--report=json',
            '--extensions=' . implode(',', $this->extensions),
            '--severity=' . $this->severity,
        ];

        if (!$this->includeWarnings) {
            $args[] = '-n'; // No warnings
        }

        foreach ($this->additionalArgs as $arg) {
            $args[] = escapeshellarg($arg);
        }

        $args[] = escapeshellarg($directory);

        $command = implode(' ', $args);

        $output = [];
        $returnCode = 0;

        // Redirect stderr to stdout for full error capture
        $command .= ' 2>&1';

        exec($command, $output, $returnCode);

        return [
            'output' => implode("\n", $output),
            'exitCode' => $returnCode,
        ];
    }

    /**
     * Parse PHPCS JSON output into a ScanResult.
     *
     * @param array{output: string, exitCode: int} $result The PHPCS output
     * @param string $scannedDirectory The directory that was scanned
     *
     * @return ScanResult The parsed results
     */
    private function parsePhpcsOutput(array $result, string $scannedDirectory): ScanResult
    {
        $output = $result['output'];
        $exitCode = $result['exitCode'];

        // Try to parse JSON output
        $data = @json_decode($output, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            // If JSON parsing fails, return an error result
            return new ScanResult(
                success: false,
                errorCount: 0,
                warningCount: 0,
                files: [],
                totals: ['errors' => 0, 'warnings' => 0, 'fixable' => 0],
                scannedDirectory: $scannedDirectory,
                standard: $this->standard,
                phpcsExitCode: $exitCode,
                rawOutput: $output,
                parseError: 'Failed to parse PHPCS output: ' . json_last_error_msg()
            );
        }

        // Normalize file paths (remove temp directory prefix)
        $files = [];
        $totalErrors = 0;
        $totalWarnings = 0;
        $totalFixable = 0;

        if (isset($data['files']) && is_array($data['files'])) {
            foreach ($data['files'] as $filePath => $fileData) {
                // Create relative path from scanned directory
                $relativePath = str_replace($scannedDirectory . DIRECTORY_SEPARATOR, '', $filePath);
                $relativePath = str_replace($scannedDirectory . '/', '', $relativePath);

                $files[$relativePath] = $fileData;

                $totalErrors += $fileData['errors'] ?? 0;
                $totalWarnings += $fileData['warnings'] ?? 0;

                // Count fixable issues
                if (isset($fileData['messages'])) {
                    foreach ($fileData['messages'] as $message) {
                        if (!empty($message['fixable'])) {
                            $totalFixable++;
                        }
                    }
                }
            }
        }

        return new ScanResult(
            success: true,
            errorCount: $data['totals']['errors'] ?? $totalErrors,
            warningCount: $data['totals']['warnings'] ?? $totalWarnings,
            files: $files,
            totals: [
                'errors' => $data['totals']['errors'] ?? $totalErrors,
                'warnings' => $data['totals']['warnings'] ?? $totalWarnings,
                'fixable' => $data['totals']['fixable'] ?? $totalFixable,
            ],
            scannedDirectory: $scannedDirectory,
            standard: $this->standard,
            phpcsExitCode: $exitCode,
            rawOutput: null,
            parseError: null
        );
    }
}
