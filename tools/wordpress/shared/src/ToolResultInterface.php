<?php

declare(strict_types=1);

namespace FairForge\Shared;

use JsonSerializable;

/**
 * Defines the standard output schema for all FairForge static-check tools.
 *
 * Every tool result MUST implement this interface so that the JSON envelope
 * is consistent across tools and can be consumed by automated pipelines.
 *
 * Standard envelope (produced by toArray()):
 *
 *     {
 *         "schema_version": "1.0.0",
 *         "tool":           "<tool-slug>",
 *         "success":        true|false,
 *         "summary":        { … tool-specific quick overview … },
 *         "data":           { … tool-specific detailed results … },
 *         "issues":         [ … list of issues/warnings found … ],
 *         "metadata":       { "scanned_at": "ISO-8601", … }
 *     }
 */
interface ToolResultInterface extends JsonSerializable
{
    /**
     * Machine-readable tool identifier (slug), e.g. "phpcs", "security-header".
     */
    public function getToolName(): string;

    /**
     * Whether the scan itself completed without fatal errors.
     */
    public function isSuccess(): bool;

    /**
     * Quick overview suitable for dashboards / CI summaries.
     *
     * @return array<string, mixed>
     */
    public function getSummary(): array;

    /**
     * Detailed, tool-specific results (the "body" of the report).
     *
     * @return array<string, mixed>
     */
    public function getData(): array;

    /**
     * Flat list of issues, warnings, or recommendations found by the tool.
     *
     * @return array<int, mixed>
     */
    public function getIssues(): array;

    /**
     * Tool-specific metadata (scanned_directory, standard used, etc.).
     *
     * The base envelope will automatically prepend a `scanned_at` timestamp.
     *
     * @return array<string, mixed>
     */
    public function getMetadata(): array;

    /**
     * Full result as a standard envelope array.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array;

    /**
     * Full result as a JSON string.
     */
    public function toJson(int $flags = JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES): string;

    /**
     * Persist the result to a JSON file.
     *
     * @return bool True on success
     */
    public function saveToFile(string $filePath, int $flags = JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES): bool;
}
