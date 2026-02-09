<?php

declare(strict_types=1);

namespace FairForge\Shared;

/**
 * Base class for all FairForge tool results.
 *
 * Provides the standard JSON envelope and common serialisation helpers.
 * Subclasses only need to implement the abstract template methods;
 * the envelope assembly, JSON encoding, and file persistence are handled here.
 *
 * Envelope keys produced by {@see toArray()}:
 *
 *  - schema_version – semver of the shared envelope schema
 *  - tool           – machine-readable tool slug
 *  - success        – whether the scan completed without fatal errors
 *  - summary        – quick overview (tool-specific)
 *  - data           – detailed results (tool-specific)
 *  - issues         – flat list of issues / warnings
 *  - metadata       – contextual info; `scanned_at` is always prepended
 */
abstract class AbstractToolResult implements ToolResultInterface
{
    /**
     * Current version of the shared envelope schema.
     *
     * Bump this when the envelope structure itself changes.
     */
    public const SCHEMA_VERSION = '1.0.0';

    // ------------------------------------------------------------------
    // Template methods – override in each tool's result class
    // ------------------------------------------------------------------

    /**
     * Machine-readable tool slug, e.g. "phpcs", "security-header", "php-min-max".
     */
    abstract public function getToolName(): string;

    /**
     * Whether the scan completed without fatal errors.
     */
    abstract public function isSuccess(): bool;

    /**
     * Quick overview suitable for dashboards / CI summaries.
     *
     * @return array<string, mixed>
     */
    abstract public function getSummary(): array;

    /**
     * Detailed, tool-specific body of the report.
     *
     * @return array<string, mixed>
     */
    abstract public function getData(): array;

    /**
     * Flat list of issues, warnings, or recommendations.
     *
     * @return array<int, mixed>
     */
    abstract public function getIssues(): array;

    /**
     * Tool-specific metadata (e.g. scanned_directory, standard, etc.).
     *
     * `scanned_at` is injected automatically by {@see toArray()} —
     * implementations do NOT need to include it.
     *
     * @return array<string, mixed>
     */
    abstract public function getMetadata(): array;

    // ------------------------------------------------------------------
    // Envelope assembly & serialisation (final – not meant to be overridden)
    // ------------------------------------------------------------------

    /**
     * Assemble the standard envelope array.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'schema_version' => self::SCHEMA_VERSION,
            'tool' => $this->getToolName(),
            'success' => $this->isSuccess(),
            'summary' => $this->getSummary(),
            'data' => $this->getData(),
            'issues' => $this->getIssues(),
            'metadata' => array_merge(
                ['scanned_at' => date('c')],
                $this->getMetadata(),
            ),
        ];
    }

    /**
     * {@inheritDoc}
     */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }

    /**
     * {@inheritDoc}
     */
    public function toJson(int $flags = JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES): string
    {
        return json_encode($this, $flags) ?: '{}';
    }

    /**
     * {@inheritDoc}
     */
    public function saveToFile(string $filePath, int $flags = JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES): bool
    {
        $json = $this->toJson($flags);

        return file_put_contents($filePath, $json) !== false;
    }
}
