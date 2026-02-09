<?php

declare(strict_types=1);

namespace FairForge\Shared;

use InvalidArgumentException;

/**
 * Value object representing the input target for any FairForge scanner.
 *
 * A target can be:
 *  - A remote URL pointing to a ZIP file
 *  - A path to a local ZIP file
 *  - A path to a local directory
 *
 * Use {@see ScanTarget::detect()} to auto-detect the type from a raw string,
 * or construct explicitly with the named constructors {@see fromUrl()},
 * {@see fromZipFile()}, {@see fromDirectory()}.
 */
class ScanTarget
{
    /**
     * @param ScanTargetType $type  What kind of target this is
     * @param string         $value The raw value (URL or filesystem path)
     */
    public function __construct(
        public readonly ScanTargetType $type,
        public readonly string $value,
    ) {
    }

    // ------------------------------------------------------------------
    // Named constructors
    // ------------------------------------------------------------------

    /**
     * Create a URL target.
     *
     * @throws InvalidArgumentException If the URL is not valid
     */
    public static function fromUrl(string $url): self
    {
        if (!filter_var($url, FILTER_VALIDATE_URL)) {
            throw new InvalidArgumentException("Invalid URL: {$url}");
        }

        return new self(ScanTargetType::Url, $url);
    }

    /**
     * Create a ZIP-file target.
     *
     * @throws InvalidArgumentException If the file does not exist or is not a ZIP
     */
    public static function fromZipFile(string $path): self
    {
        if (!is_file($path)) {
            throw new InvalidArgumentException("ZIP file not found: {$path}");
        }

        return new self(ScanTargetType::ZipFile, $path);
    }

    /**
     * Create a directory target.
     *
     * @throws InvalidArgumentException If the directory does not exist
     */
    public static function fromDirectory(string $path): self
    {
        if (!is_dir($path)) {
            throw new InvalidArgumentException("Directory not found: {$path}");
        }

        return new self(ScanTargetType::Directory, $path);
    }

    // ------------------------------------------------------------------
    // Auto-detection
    // ------------------------------------------------------------------

    /**
     * Auto-detect the target type from a raw string.
     *
     * Detection order:
     *  1. If it looks like a URL → {@see ScanTargetType::Url}
     *  2. If it's an existing file with a .zip extension → {@see ScanTargetType::ZipFile}
     *  3. If it's an existing directory → {@see ScanTargetType::Directory}
     *  4. Otherwise → throws
     *
     * @throws InvalidArgumentException When the target cannot be resolved
     */
    public static function detect(string $raw): self
    {
        if (filter_var($raw, FILTER_VALIDATE_URL)) {
            return new self(ScanTargetType::Url, $raw);
        }

        if (is_file($raw) && strtolower(pathinfo($raw, PATHINFO_EXTENSION)) === 'zip') {
            return new self(ScanTargetType::ZipFile, $raw);
        }

        if (is_dir($raw)) {
            return new self(ScanTargetType::Directory, $raw);
        }

        throw new InvalidArgumentException(
            "'{$raw}' is not a valid URL, ZIP file, or directory."
        );
    }

    // ------------------------------------------------------------------
    // Convenience query helpers
    // ------------------------------------------------------------------

    public function isUrl(): bool
    {
        return $this->type === ScanTargetType::Url;
    }

    public function isZipFile(): bool
    {
        return $this->type === ScanTargetType::ZipFile;
    }

    public function isDirectory(): bool
    {
        return $this->type === ScanTargetType::Directory;
    }
}
