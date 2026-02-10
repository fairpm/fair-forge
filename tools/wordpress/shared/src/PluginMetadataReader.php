<?php

declare(strict_types=1);

namespace FairForge\Shared;

use FAIR\DID\Parsers\PluginHeaderParser;
use FAIR\DID\Parsers\ReadmeParser;

/**
 * Reads WordPress plugin metadata using the fairpm/did-manager parsers.
 *
 * Wraps {@see PluginHeaderParser} and {@see ReadmeParser} to provide:
 * - Standard header parsing (Author, Author URI, Plugin URI, Security, etc.)
 * - Extended header parsing for fields not yet in the upstream parser (Support)
 * - readme.txt parsing (contributors, donate link, sections, etc.)
 * - Main-file discovery
 *
 * This is the single entry-point that all FairForge scanner modules should use
 * instead of hand-rolling regex against plugin headers.
 */
class PluginMetadataReader
{
    /**
     * Maximum bytes to read from a file when extracting extended headers.
     */
    private const MAX_HEADER_SIZE = 8192;

    /**
     * Extended fields not yet recognised by the upstream PluginHeaderParser.
     */
    private const EXTENDED_FIELDS = [
        'Support',
    ];

    private PluginHeaderParser $headerParser;
    private ReadmeParser $readmeParser;

    public function __construct(
        ?PluginHeaderParser $headerParser = null,
        ?ReadmeParser $readmeParser = null,
    ) {
        $this->headerParser = $headerParser ?? new PluginHeaderParser();
        $this->readmeParser = $readmeParser ?? new ReadmeParser();
    }

    /**
     * Parse plugin headers from a directory.
     *
     * Returns the normalised header array from PluginHeaderParser enriched
     * with any extended fields (e.g. `support`).
     *
     * @param string $path Plugin directory path.
     * @return array<string, mixed> Parsed headers (snake_case keys).
     */
    public function parse(string $path): array
    {
        $mainFile = $this->headerParser->find_main_file($path);
        if ($mainFile === null) {
            return $this->headerParser->parse($path);
        }

        return $this->parseFile($mainFile);
    }

    /**
     * Parse plugin headers from a specific file.
     *
     * Handles files with multiple comment blocks (e.g. Akismet has a
     * @package docblock before the actual plugin header) by locating the
     * correct block before delegating to the upstream parser.
     *
     * @param string $filePath Path to the main PHP file.
     * @return array<string, mixed> Parsed headers (snake_case keys).
     */
    public function parseFile(string $filePath): array
    {
        $content = file_get_contents($filePath, false, null, 0, self::MAX_HEADER_SIZE);
        if ($content === false) {
            return [];
        }

        // First, try the upstream parser directly.
        $headers = $this->headerParser->parse_content($content);

        // If the upstream parser missed the Plugin Name (e.g. a preceding
        // docblock was matched instead), locate the correct comment block
        // and re-parse only that block.
        if (empty($headers['plugin_name'])) {
            $correctBlock = $this->findPluginHeaderBlock($content);
            if ($correctBlock !== null) {
                $headers = $this->headerParser->parse_content($correctBlock);
            }
        }

        $extended = $this->parseExtendedFields($filePath);

        return array_merge($headers, $extended);
    }

    /**
     * Find the main plugin file in a directory.
     *
     * @param string $path Plugin directory (or file) path.
     * @return string|null Absolute path to the main plugin file, or null.
     */
    public function findMainFile(string $path): ?string
    {
        return $this->headerParser->find_main_file($path);
    }

    /**
     * Whether the given path contains a valid plugin.
     *
     * @param string $path Directory or file path.
     */
    public function isValidPlugin(string $path): bool
    {
        return $this->headerParser->is_valid_plugin($path);
    }

    /**
     * Get the underlying PluginHeaderParser instance.
     */
    public function getHeaderParser(): PluginHeaderParser
    {
        return $this->headerParser;
    }

    /**
     * Get the underlying ReadmeParser instance.
     */
    public function getReadmeParser(): ReadmeParser
    {
        return $this->readmeParser;
    }

    /**
     * Parse readme.txt from a plugin directory.
     *
     * Returns the standard ReadmeParser output augmented with any custom
     * (non-standard) sections found in the readme.txt file.  The upstream
     * WordPress.org parser only recognises standard sections (description,
     * installation, faq, changelog, screenshots, upgrade_notice,
     * other_notes).  Any additional `== Section ==` blocks are extracted
     * via regex and merged into the sections array.
     *
     * @param string $path Plugin directory path.
     * @return array<string, mixed> Parsed readme data (name, header, short_description, sections).
     */
    public function parseReadme(string $path): array
    {
        $data = $this->readmeParser->parse($path);

        $readmePath = $this->readmeParser->find_readme($path);
        if ($readmePath !== null) {
            $customSections = $this->extractCustomSections(
                $readmePath,
                $data['sections'] ?? [],
            );
            if (!empty($customSections)) {
                $data['sections'] = array_merge($data['sections'] ?? [], $customSections);
            }
        }

        return $data;
    }

    /**
     * Parse a specific readme file.
     *
     * Like {@see parseReadme()}, the result includes any non-standard
     * sections extracted from the raw file content.
     *
     * @param string $filePath Path to readme.txt.
     * @return array<string, mixed> Parsed readme data.
     */
    public function parseReadmeFile(string $filePath): array
    {
        $data = $this->readmeParser->parse_file($filePath);

        $customSections = $this->extractCustomSections(
            $filePath,
            $data['sections'] ?? [],
        );
        if (!empty($customSections)) {
            $data['sections'] = array_merge($data['sections'] ?? [], $customSections);
        }

        return $data;
    }

    /**
     * Find the readme.txt file in a directory.
     *
     * @param string $path Plugin directory path.
     * @return string|null Absolute path to the readme file, or null.
     */
    public function findReadme(string $path): ?string
    {
        return $this->readmeParser->find_readme($path);
    }

    // ------------------------------------------------------------------
    // Custom readme-section extraction
    // ------------------------------------------------------------------

    /**
     * Extract non-standard sections from a readme.txt file.
     *
     * The upstream WordPress.org parser only recognises a fixed set of
     * sections (description, installation, faq, changelog, screenshots,
     * upgrade_notice, other_notes).  This method reads the raw file and
     * extracts any `== Section Name ==` blocks that are NOT already
     * present in the parsed output.
     *
     * @param string               $filePath         Absolute path to the readme file.
     * @param array<string, string> $existingSections Sections already parsed by the upstream parser.
     * @return array<string, string> Custom sections (snake_case keys => content).
     */
    private function extractCustomSections(string $filePath, array $existingSections): array
    {
        $content = file_get_contents($filePath);
        if ($content === false) {
            return [];
        }

        // Find all == Section Name == headers (exactly two = signs, not the
        // === Plugin Title === line which uses three) and their byte-offsets.
        if (!preg_match_all('/^==(?!=)\s*(.+?)\s*==(?!=)/m', $content, $matches, PREG_OFFSET_CAPTURE)) {
            return [];
        }

        $customSections = [];
        $count = count($matches[0]);

        for ($i = 0; $i < $count; $i++) {
            $sectionName = trim($matches[1][$i][0]);
            $key = strtolower(str_replace(' ', '_', $sectionName));

            // Skip sections already handled by the upstream parser.
            if (isset($existingSections[$key])) {
                continue;
            }

            // Content starts right after the == header == line.
            $headerEnd = $matches[0][$i][1] + strlen($matches[0][$i][0]);

            // Content ends at the next == header == or end-of-file.
            $contentEnd = ($i + 1 < $count)
                ? $matches[0][$i + 1][1]
                : strlen($content);

            $sectionContent = trim(substr($content, $headerEnd, $contentEnd - $headerEnd));

            if ($sectionContent !== '') {
                $customSections[$key] = $sectionContent;
            }
        }

        return $customSections;
    }

    // ------------------------------------------------------------------
    // Extended-field extraction
    // ------------------------------------------------------------------

    /**
     * Extract extended header fields that the upstream parser does not
     * yet recognise from the plugin-header comment block.
     *
     * @param string $filePath Path to the main plugin file.
     * @return array<string, string> Extended headers (snake_case keys).
     */
    private function parseExtendedFields(string $filePath): array
    {
        if (!file_exists($filePath) || !is_readable($filePath)) {
            return [];
        }

        $content = file_get_contents($filePath, false, null, 0, self::MAX_HEADER_SIZE);
        if ($content === false) {
            return [];
        }

        // Locate the plugin-header comment block (the one containing "Plugin Name:").
        $commentBlock = $this->findPluginHeaderBlock($content);
        if ($commentBlock === null) {
            return [];
        }

        $extended = [];

        foreach (self::EXTENDED_FIELDS as $field) {
            $pattern = '/^\s*\*?\s*' . preg_quote($field, '/') . ':\s*(.+?)\s*$/mi';
            if (preg_match($pattern, $commentBlock, $m)) {
                $key = strtolower(str_replace(' ', '_', $field));
                $extended[$key] = trim($m[1]);
            }
        }

        return $extended;
    }

    /**
     * Find the comment block that contains "Plugin Name:".
     *
     * Handles files with multiple comment blocks (e.g. Akismet has a docblock
     * before the actual plugin header).
     */
    private function findPluginHeaderBlock(string $content): ?string
    {
        if (!preg_match_all('/\/\*\*?.*?\*\//s', $content, $allBlocks)) {
            return null;
        }

        foreach ($allBlocks[0] as $block) {
            if (preg_match('/^\s*\*?\s*Plugin Name:/mi', $block)) {
                return $block;
            }
        }

        return null;
    }
}
