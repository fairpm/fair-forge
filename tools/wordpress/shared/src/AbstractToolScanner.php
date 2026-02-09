<?php

declare(strict_types=1);

namespace FairForge\Shared;

use RuntimeException;

/**
 * Base class for all FairForge tool scanners.
 *
 * Provides:
 *  - ZipHandler lifecycle (construction, SSL config)
 *  - Unified {@see scan()} dispatcher that routes a {@see ScanTarget} to
 *    the correct method (URL → download + extract, ZIP → extract, directory → direct)
 *  - Default implementations for {@see scanFromUrl()} and
 *    {@see scanFromZipFile()} that extract to a temp dir and delegate to
 *    {@see scanDirectory()}.
 *
 * Subclasses typically only need to implement:
 *  - {@see getToolName()}
 *  - {@see scanDirectory()}
 *
 * If the default download/extract strategy is sufficient, scanFromUrl() and
 * scanFromZipFile() can be left as-is.
 */
abstract class AbstractToolScanner implements ToolScannerInterface
{
    protected ZipHandler $zipHandler;

    /**
     * @param ZipHandler|null $zipHandler Custom handler, or null for default
     */
    public function __construct(?ZipHandler $zipHandler = null)
    {
        $this->zipHandler = $zipHandler ?? new ZipHandler();
    }

    // ------------------------------------------------------------------
    // ToolScannerInterface — common configuration
    // ------------------------------------------------------------------

    public function getZipHandler(): ZipHandler
    {
        return $this->zipHandler;
    }

    public function getSslVerify(): bool
    {
        return $this->zipHandler->getSslVerify();
    }

    public function setSslVerify(bool $verify): static
    {
        $this->zipHandler->setSslVerify($verify);

        return $this;
    }

    // ------------------------------------------------------------------
    // Unified dispatch
    // ------------------------------------------------------------------

    /**
     * Route a {@see ScanTarget} to the correct scan method.
     *
     * @throws RuntimeException If the scan fails
     */
    public function scan(ScanTarget $target): ToolResultInterface
    {
        return match ($target->type) {
            ScanTargetType::Url => $this->scanFromUrl($target->value),
            ScanTargetType::ZipFile => $this->scanFromZipFile($target->value),
            ScanTargetType::Directory => $this->scanDirectory($target->value),
        };
    }

    // ------------------------------------------------------------------
    // Default URL / ZIP strategies (extract → delegate to scanDirectory)
    // ------------------------------------------------------------------

    /**
     * Download a remote ZIP, extract it, scan the extracted directory,
     * then clean up.
     */
    public function scanFromUrl(string $url): ToolResultInterface
    {
        $tempDir = $this->zipHandler->downloadAndExtract($url);

        try {
            return $this->scanDirectory($tempDir);
        } finally {
            $this->zipHandler->removeDirectory($tempDir);
        }
    }

    /**
     * Extract a local ZIP, scan the extracted directory, then clean up.
     *
     * @throws RuntimeException If the ZIP file does not exist
     */
    public function scanFromZipFile(string $zipPath): ToolResultInterface
    {
        if (!file_exists($zipPath)) {
            throw new RuntimeException("ZIP file not found: {$zipPath}");
        }

        $tempDir = $this->zipHandler->extract($zipPath);

        try {
            return $this->scanDirectory($tempDir);
        } finally {
            $this->zipHandler->removeDirectory($tempDir);
        }
    }

    // ------------------------------------------------------------------
    // Abstract — must be implemented by each tool
    // ------------------------------------------------------------------

    /**
     * Machine-readable tool slug.
     */
    abstract public function getToolName(): string;

    /**
     * Perform the actual scan on an extracted / local directory.
     *
     * This is the core method; URL and ZIP input is normalised to a
     * directory before this is called.
     */
    abstract public function scanDirectory(string $directory): ToolResultInterface;
}
