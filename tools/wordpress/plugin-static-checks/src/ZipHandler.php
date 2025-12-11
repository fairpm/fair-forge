<?php

declare(strict_types=1);

namespace FairForge\Tools\WordPress\PluginStaticChecks;

use PhpZip\Exception\ZipException;
use PhpZip\ZipFile;
use RuntimeException;

/**
 * Handles ZIP file operations including downloading, verification, and extraction.
 */
class ZipHandler
{
    /** Whether to verify SSL certificates when downloading. */
    private bool $sslVerify = true;

    /** User agent string for HTTP requests. */
    private string $userAgent = 'FairForge-StaticChecks/1.0';

    /** Connection timeout in seconds. */
    private int $connectTimeout = 30;

    /** Transfer timeout in seconds. */
    private int $timeout = 120;

    /** Maximum number of redirects to follow. */
    private int $maxRedirects = 5;

    /**
     * Get SSL verification setting.
     */
    public function getSslVerify(): bool
    {
        return $this->sslVerify;
    }

    /**
     * Set whether to verify SSL certificates.
     */
    public function setSslVerify(bool $verify): self
    {
        $this->sslVerify = $verify;

        return $this;
    }

    /**
     * Get the user agent string.
     */
    public function getUserAgent(): string
    {
        return $this->userAgent;
    }

    /**
     * Set the user agent string.
     */
    public function setUserAgent(string $userAgent): self
    {
        $this->userAgent = $userAgent;

        return $this;
    }

    /**
     * Get the connection timeout.
     */
    public function getConnectTimeout(): int
    {
        return $this->connectTimeout;
    }

    /**
     * Set the connection timeout in seconds.
     */
    public function setConnectTimeout(int $seconds): self
    {
        $this->connectTimeout = $seconds;

        return $this;
    }

    /**
     * Get the transfer timeout.
     */
    public function getTimeout(): int
    {
        return $this->timeout;
    }

    /**
     * Set the transfer timeout in seconds.
     */
    public function setTimeout(int $seconds): self
    {
        $this->timeout = $seconds;

        return $this;
    }

    /**
     * Download a ZIP file from a URL.
     *
     * @param string $url The URL to download from
     *
     * @throws RuntimeException If download fails
     *
     * @return string Path to the downloaded temporary file
     */
    public function download(string $url): string
    {
        $tempFile = tempnam(sys_get_temp_dir(), 'static_checks_') . '.zip';

        $ch = curl_init();

        if ($ch === false) {
            throw new RuntimeException('Failed to initialize cURL');
        }

        $fp = fopen($tempFile, 'wb');

        if ($fp === false) {
            curl_close($ch);

            throw new RuntimeException("Failed to create temporary file: {$tempFile}");
        }

        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_FILE => $fp,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => $this->maxRedirects,
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_CONNECTTIMEOUT => $this->connectTimeout,
            CURLOPT_USERAGENT => $this->userAgent,
            CURLOPT_HTTPHEADER => [
                'Accept: application/zip,application/octet-stream,*/*',
            ],
            CURLOPT_SSL_VERIFYPEER => $this->sslVerify,
            CURLOPT_SSL_VERIFYHOST => $this->sslVerify ? 2 : 0,
            CURLOPT_FAILONERROR => true,
        ]);

        $success = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        $errno = curl_errno($ch);

        curl_close($ch);
        fclose($fp);

        if ($success === false || $errno !== 0) {
            @unlink($tempFile);

            throw new RuntimeException(
                "Failed to download ZIP from {$url}: cURL error ({$errno}): {$error}"
            );
        }

        if ($httpCode >= 400) {
            @unlink($tempFile);

            throw new RuntimeException(
                "Failed to download ZIP from {$url}: HTTP {$httpCode}"
            );
        }

        // Verify it's a valid ZIP
        if (!$this->isValidZip($tempFile)) {
            @unlink($tempFile);

            throw new RuntimeException('Downloaded file is not a valid ZIP archive');
        }

        return $tempFile;
    }

    /**
     * Verify that a file is a valid ZIP archive.
     *
     * @param string $filePath Path to the file to verify
     *
     * @return bool True if the file is a valid ZIP archive
     */
    public function isValidZip(string $filePath): bool
    {
        if (!file_exists($filePath)) {
            return false;
        }

        try {
            $zip = new ZipFile();
            $zip->openFile($filePath);
            $zip->close();

            return true;
        } catch (ZipException $e) {
            return false;
        }
    }

    /**
     * Extract a ZIP file to a directory.
     *
     * @param string $zipPath Path to the ZIP file
     * @param string|null $extractDir Directory to extract to (null for temp directory)
     *
     * @throws RuntimeException If extraction fails
     *
     * @return string Path to the extraction directory
     */
    public function extract(string $zipPath, ?string $extractDir = null): string
    {
        if (!file_exists($zipPath)) {
            throw new RuntimeException("ZIP file not found: {$zipPath}");
        }

        if ($extractDir === null) {
            $extractDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'static_checks_' . uniqid();
        }

        if (!is_dir($extractDir) && !mkdir($extractDir, 0o755, true)) {
            throw new RuntimeException("Failed to create extraction directory: {$extractDir}");
        }

        try {
            $zip = new ZipFile();
            $zip->openFile($zipPath);
            $zip->extractTo($extractDir);
            $zip->close();

            return $extractDir;
        } catch (ZipException $e) {
            $this->removeDirectory($extractDir);

            throw new RuntimeException('Failed to extract ZIP file: ' . $e->getMessage());
        }
    }

    /**
     * Download and extract a ZIP file from a URL.
     *
     * @param string $url The URL to download from
     * @param string|null $extractDir Directory to extract to (null for temp directory)
     *
     * @throws RuntimeException If download or extraction fails
     *
     * @return string Path to the extraction directory
     */
    public function downloadAndExtract(string $url, ?string $extractDir = null): string
    {
        $zipPath = $this->download($url);

        try {
            return $this->extract($zipPath, $extractDir);
        } finally {
            @unlink($zipPath);
        }
    }

    /**
     * List contents of a ZIP file.
     *
     * @param string $zipPath Path to the ZIP file
     *
     * @throws RuntimeException If the ZIP file cannot be read
     *
     * @return array<string> List of file paths in the archive
     */
    public function listContents(string $zipPath): array
    {
        if (!file_exists($zipPath)) {
            throw new RuntimeException("ZIP file not found: {$zipPath}");
        }

        try {
            $zip = new ZipFile();
            $zip->openFile($zipPath);
            $entries = $zip->getListFiles();
            $zip->close();

            return $entries;
        } catch (ZipException $e) {
            throw new RuntimeException('Failed to list ZIP contents: ' . $e->getMessage());
        }
    }

    /**
     * Recursively remove a directory and its contents.
     *
     * @param string $dir The directory to remove
     */
    public function removeDirectory(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }

        $items = scandir($dir);

        if ($items === false) {
            return;
        }

        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }

            $path = $dir . DIRECTORY_SEPARATOR . $item;

            if (is_dir($path)) {
                $this->removeDirectory($path);
            } else {
                @unlink($path);
            }
        }

        @rmdir($dir);
    }

    /**
     * Create a temporary directory.
     *
     * @param string $prefix Prefix for the directory name
     *
     * @throws RuntimeException If the directory cannot be created
     *
     * @return string Path to the created directory
     */
    public function createTempDirectory(string $prefix = 'static_checks_'): string
    {
        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . $prefix . uniqid();

        if (!mkdir($dir, 0o755, true)) {
            throw new RuntimeException("Failed to create temporary directory: {$dir}");
        }

        return $dir;
    }
}
