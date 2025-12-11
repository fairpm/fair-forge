<?php

declare(strict_types=1);

namespace FairForge\Tools\WordPress\PluginStaticChecks\Tests;

use FairForge\Tools\WordPress\PluginStaticChecks\ScanResult;
use PHPUnit\Framework\TestCase;

/**
 * Tests for the ScanResult class.
 *
 * These tests verify the immutable result object that holds PHPCS scan data,
 * including summary calculations, JSON serialization, and file output.
 */
class ScanResultTest extends TestCase
{
    /**
     * Test that the success property correctly reflects the scan status.
     */
    public function testSuccessProperty(): void
    {
        $result = $this->createScanResult(success: true);
        $this->assertTrue($result->success);

        $result = $this->createScanResult(success: false);
        $this->assertFalse($result->success);
    }

    /**
     * Test that the errorCount property is set correctly.
     */
    public function testErrorCountProperty(): void
    {
        $result = $this->createScanResult(errorCount: 5);
        $this->assertEquals(5, $result->errorCount);
    }

    /**
     * Test that the warningCount property is set correctly.
     */
    public function testWarningCountProperty(): void
    {
        $result = $this->createScanResult(warningCount: 10);
        $this->assertEquals(10, $result->warningCount);
    }

    /**
     * Test that hasErrors returns true when errors exist.
     */
    public function testHasErrorsReturnsTrueWhenErrorsExist(): void
    {
        $result = $this->createScanResult(errorCount: 1);
        $this->assertTrue($result->hasErrors());
    }

    /**
     * Test that hasErrors returns false when no errors exist.
     */
    public function testHasErrorsReturnsFalseWhenNoErrors(): void
    {
        $result = $this->createScanResult(errorCount: 0);
        $this->assertFalse($result->hasErrors());
    }

    /**
     * Test that hasWarnings returns true when warnings exist.
     */
    public function testHasWarningsReturnsTrueWhenWarningsExist(): void
    {
        $result = $this->createScanResult(warningCount: 1);
        $this->assertTrue($result->hasWarnings());
    }

    /**
     * Test that hasWarnings returns false when no warnings exist.
     */
    public function testHasWarningsReturnsFalseWhenNoWarnings(): void
    {
        $result = $this->createScanResult(warningCount: 0);
        $this->assertFalse($result->hasWarnings());
    }

    /**
     * Test that hasIssues returns true when errors exist (but no warnings).
     */
    public function testHasIssuesReturnsTrueWhenErrorsExist(): void
    {
        $result = $this->createScanResult(errorCount: 1, warningCount: 0);
        $this->assertTrue($result->hasIssues());
    }

    /**
     * Test that hasIssues returns true when warnings exist (but no errors).
     */
    public function testHasIssuesReturnsTrueWhenWarningsExist(): void
    {
        $result = $this->createScanResult(errorCount: 0, warningCount: 1);
        $this->assertTrue($result->hasIssues());
    }

    /**
     * Test that hasIssues returns false when no issues (errors or warnings) exist.
     */
    public function testHasIssuesReturnsFalseWhenNoIssues(): void
    {
        $result = $this->createScanResult(errorCount: 0, warningCount: 0);
        $this->assertFalse($result->hasIssues());
    }

    /**
     * Test that getFileCount returns the correct number of files with issues.
     */
    public function testGetFileCountReturnsCorrectCount(): void
    {
        $files = [
            'file1.php' => ['errors' => 1, 'warnings' => 0, 'messages' => []],
            'file2.php' => ['errors' => 0, 'warnings' => 1, 'messages' => []],
        ];
        $result = $this->createScanResult(files: $files);
        $this->assertEquals(2, $result->getFileCount());
    }

    /**
     * Test that getFileCount returns zero when no files have issues.
     */
    public function testGetFileCountReturnsZeroForEmptyFiles(): void
    {
        $result = $this->createScanResult(files: []);
        $this->assertEquals(0, $result->getFileCount());
    }

    /**
     * Test that getSummary returns an array with all expected keys.
     */
    public function testGetSummaryContainsExpectedKeys(): void
    {
        $result = $this->createScanResult(
            errorCount: 5,
            warningCount: 10,
            standard: 'WordPress-Core'
        );
        $summary = $result->getSummary();

        $this->assertArrayHasKey('success', $summary);
        $this->assertArrayHasKey('errors', $summary);
        $this->assertArrayHasKey('warnings', $summary);
        $this->assertArrayHasKey('fixable', $summary);
        $this->assertArrayHasKey('files_scanned', $summary);
        $this->assertArrayHasKey('standard', $summary);

        $this->assertTrue($summary['success']);
        $this->assertEquals(5, $summary['errors']);
        $this->assertEquals(10, $summary['warnings']);
        $this->assertEquals('WordPress-Core', $summary['standard']);
    }

    /**
     * Test that getAllErrors filters messages to only return ERROR type messages.
     */
    public function testGetAllErrorsFiltersCorrectly(): void
    {
        $files = [
            'file1.php' => [
                'errors' => 1,
                'warnings' => 1,
                'messages' => [
                    [
                        'type' => 'ERROR',
                        'message' => 'Error 1',
                        'line' => 10,
                        'column' => 1,
                        'source' => 'Test',
                        'severity' => 5,
                        'fixable' => false,
                    ],
                    [
                        'type' => 'WARNING',
                        'message' => 'Warning 1',
                        'line' => 20,
                        'column' => 1,
                        'source' => 'Test',
                        'severity' => 5,
                        'fixable' => false,
                    ],
                ],
            ],
        ];
        $result = $this->createScanResult(files: $files, errorCount: 1, warningCount: 1);

        $errors = $result->getAllErrors();
        $this->assertCount(1, $errors);
        $this->assertEquals('Error 1', $errors[0]['message']);
        $this->assertEquals('file1.php', $errors[0]['file']);
    }

    /**
     * Test that getAllWarnings filters messages to only return WARNING type messages.
     */
    public function testGetAllWarningsFiltersCorrectly(): void
    {
        $files = [
            'file1.php' => [
                'errors' => 1,
                'warnings' => 1,
                'messages' => [
                    [
                        'type' => 'ERROR',
                        'message' => 'Error 1',
                        'line' => 10,
                        'column' => 1,
                        'source' => 'Test',
                        'severity' => 5,
                        'fixable' => false,
                    ],
                    [
                        'type' => 'WARNING',
                        'message' => 'Warning 1',
                        'line' => 20,
                        'column' => 1,
                        'source' => 'Test',
                        'severity' => 5,
                        'fixable' => false,
                    ],
                ],
            ],
        ];
        $result = $this->createScanResult(files: $files, errorCount: 1, warningCount: 1);

        $warnings = $result->getAllWarnings();
        $this->assertCount(1, $warnings);
        $this->assertEquals('Warning 1', $warnings[0]['message']);
    }

    /**
     * Test that toArray returns an array with the expected structure.
     */
    public function testToArrayContainsExpectedStructure(): void
    {
        $result = $this->createScanResult(
            success: true,
            errorCount: 1,
            warningCount: 2
        );

        $array = $result->toArray();

        $this->assertArrayHasKey('success', $array);
        $this->assertArrayHasKey('summary', $array);
        $this->assertArrayHasKey('totals', $array);
        $this->assertArrayHasKey('files', $array);
        $this->assertArrayHasKey('metadata', $array);
    }

    /**
     * Test that toArray includes parse_error key when a parse error is present.
     */
    public function testToArrayIncludesParseErrorWhenPresent(): void
    {
        $result = $this->createScanResult(parseError: 'JSON parse error');

        $array = $result->toArray();

        $this->assertArrayHasKey('parse_error', $array);
        $this->assertEquals('JSON parse error', $array['parse_error']);
    }

    /**
     * Test that toArray includes raw_output key when raw output is present.
     */
    public function testToArrayIncludesRawOutputWhenPresent(): void
    {
        $result = $this->createScanResult(rawOutput: 'Raw PHPCS output');

        $array = $result->toArray();

        $this->assertArrayHasKey('raw_output', $array);
        $this->assertEquals('Raw PHPCS output', $array['raw_output']);
    }

    /**
     * Test that toJson returns valid JSON that can be decoded.
     */
    public function testToJsonReturnsValidJson(): void
    {
        $result = $this->createScanResult(errorCount: 5);

        $json = $result->toJson();

        $decoded = json_decode($json, true);
        $this->assertNotNull($decoded);
        $this->assertEquals(JSON_ERROR_NONE, json_last_error());
    }

    /**
     * Test that jsonSerialize enables json_encode to work directly on ScanResult.
     */
    public function testJsonSerializeReturnsArrayForJsonEncode(): void
    {
        $result = $this->createScanResult(errorCount: 5);

        $json = json_encode($result);

        $this->assertIsString($json);
        $decoded = json_decode($json, true);
        $this->assertEquals(5, $decoded['summary']['errors']);
    }

    /**
     * Test that saveToFile creates a JSON file with the scan results.
     */
    public function testSaveToFileCreatesFile(): void
    {
        $result = $this->createScanResult(errorCount: 3);
        $tempFile = sys_get_temp_dir() . '/scan_result_test_' . uniqid() . '.json';

        try {
            $success = $result->saveToFile($tempFile);

            $this->assertTrue($success);
            $this->assertFileExists($tempFile);

            $content = file_get_contents($tempFile);
            $decoded = json_decode($content, true);
            $this->assertEquals(3, $decoded['summary']['errors']);
        } finally {
            if (file_exists($tempFile)) {
                unlink($tempFile);
            }
        }
    }

    /**
     * Test that metadata includes the standard and PHPCS exit code.
     */
    public function testMetadataContainsStandardAndExitCode(): void
    {
        $result = $this->createScanResult(
            standard: 'WordPress-Extra',
            phpcsExitCode: 1
        );

        $array = $result->toArray();

        $this->assertEquals('WordPress-Extra', $array['metadata']['standard']);
        $this->assertEquals(1, $array['metadata']['phpcs_exit_code']);
    }

    /**
     * Test that metadata includes a scanned_at timestamp in ISO 8601 format.
     */
    public function testMetadataContainsScannedAtTimestamp(): void
    {
        $result = $this->createScanResult();

        $array = $result->toArray();

        $this->assertArrayHasKey('scanned_at', $array['metadata']);
        $this->assertMatchesRegularExpression('/^\d{4}-\d{2}-\d{2}T/', $array['metadata']['scanned_at']);
    }

    /**
     * Create a ScanResult instance with the specified parameters.
     *
     * @param bool $success Whether the scan completed successfully
     * @param int $errorCount Total number of errors
     * @param int $warningCount Total number of warnings
     * @param array<string, array> $files Files with issues
     * @param array|null $totals Summary totals (auto-generated if null)
     * @param string $scannedDirectory The directory that was scanned
     * @param string $standard The PHPCS standard used
     * @param int $phpcsExitCode The PHPCS exit code
     * @param string|null $rawOutput Raw output if parsing failed
     * @param string|null $parseError Parse error message if any
     *
     * @return ScanResult The created instance
     */
    private function createScanResult(
        bool $success = true,
        int $errorCount = 0,
        int $warningCount = 0,
        array $files = [],
        ?array $totals = null,
        string $scannedDirectory = '/test/dir',
        string $standard = 'WordPress',
        int $phpcsExitCode = 0,
        ?string $rawOutput = null,
        ?string $parseError = null
    ): ScanResult {
        return new ScanResult(
            success: $success,
            errorCount: $errorCount,
            warningCount: $warningCount,
            files: $files,
            totals: $totals ?? ['errors' => $errorCount, 'warnings' => $warningCount, 'fixable' => 0],
            scannedDirectory: $scannedDirectory,
            standard: $standard,
            phpcsExitCode: $phpcsExitCode,
            rawOutput: $rawOutput,
            parseError: $parseError
        );
    }
}
