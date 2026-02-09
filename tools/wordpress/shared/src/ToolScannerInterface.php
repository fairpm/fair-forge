<?php

declare(strict_types=1);

namespace FairForge\Shared;

/**
 * Defines the standard scanner contract for all FairForge tools.
 *
 * Every scanner MUST implement this interface so that:
 *  - Input handling (URL / ZIP / directory) is consistent across tools
 *  - Consumers can program against one contract instead of per-tool APIs
 *  - New tools automatically inherit the same dispatch logic from
 *    {@see AbstractToolScanner}
 */
interface ToolScannerInterface
{
    /**
     * Machine-readable scanner / tool identifier (slug).
     */
    public function getToolName(): string;

    /**
     * Unified entry point — dispatches to the correct method based on
     * the target type.
     */
    public function scan(ScanTarget $target): ToolResultInterface;

    /**
     * Scan from a remote URL (downloads + extracts the ZIP first).
     *
     * @param string $url Remote URL pointing to a ZIP file
     */
    public function scanFromUrl(string $url): ToolResultInterface;

    /**
     * Scan from a local ZIP file.
     *
     * @param string $zipPath Filesystem path to the ZIP
     */
    public function scanFromZipFile(string $zipPath): ToolResultInterface;

    /**
     * Scan a local directory.
     *
     * @param string $directory Filesystem path to the directory
     */
    public function scanDirectory(string $directory): ToolResultInterface;

    // ------------------------------------------------------------------
    // Common configuration
    // ------------------------------------------------------------------

    /**
     * Get the underlying ZIP handler.
     */
    public function getZipHandler(): ZipHandler;

    /**
     * Whether SSL certificate verification is enabled.
     */
    public function getSslVerify(): bool;

    /**
     * Enable or disable SSL certificate verification.
     *
     * @return static For method chaining
     */
    public function setSslVerify(bool $verify): static;
}
