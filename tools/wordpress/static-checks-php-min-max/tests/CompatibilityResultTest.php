<?php

declare(strict_types=1);

namespace FairForge\Tools\PhpMinMax\Tests;

use FairForge\Shared\AbstractToolResult;
use FairForge\Shared\ToolResultInterface;
use FairForge\Tools\PhpMinMax\CompatibilityResult;
use PHPUnit\Framework\TestCase;

/**
 * Tests for the CompatibilityResult class.
 */
class CompatibilityResultTest extends TestCase
{
    /**
     * Test that CompatibilityResult implements ToolResultInterface.
     */
    public function testImplementsToolResultInterface(): void
    {
        $result = $this->createResult();
        $this->assertInstanceOf(ToolResultInterface::class, $result);
    }

    /**
     * Test getToolName returns correct slug.
     */
    public function testGetToolName(): void
    {
        $result = $this->createResult();
        $this->assertEquals('php-min-max', $result->getToolName());
    }

    /**
     * Test isSuccess returns correct value.
     */
    public function testIsSuccess(): void
    {
        $result = $this->createResult(success: true);
        $this->assertTrue($result->isSuccess());

        $result = $this->createResult(success: false);
        $this->assertFalse($result->isSuccess());
    }

    /**
     * Test that the success property correctly reflects the scan status.
     */
    public function testSuccessProperty(): void
    {
        $result = $this->createResult(success: true);
        $this->assertTrue($result->success);

        $result = $this->createResult(success: false);
        $this->assertFalse($result->success);
    }

    /**
     * Test that minVersion property is set correctly.
     */
    public function testMinVersionProperty(): void
    {
        $result = $this->createResult(minVersion: '7.4');
        $this->assertEquals('7.4', $result->minVersion);
    }

    /**
     * Test that maxVersion property is set correctly.
     */
    public function testMaxVersionProperty(): void
    {
        $result = $this->createResult(maxVersion: '8.4');
        $this->assertEquals('8.4', $result->maxVersion);
    }

    /**
     * Test hasPassingVersions returns true when versions passed.
     */
    public function testHasPassingVersionsReturnsTrue(): void
    {
        $result = $this->createResult(passedVersions: ['7.4', '8.0', '8.1']);
        $this->assertTrue($result->hasPassingVersions());
    }

    /**
     * Test hasPassingVersions returns false when no versions passed.
     */
    public function testHasPassingVersionsReturnsFalse(): void
    {
        $result = $this->createResult(passedVersions: []);
        $this->assertFalse($result->hasPassingVersions());
    }

    /**
     * Test hasIssues returns true when issues exist.
     */
    public function testHasIssuesReturnsTrue(): void
    {
        $issues = [
            [
                'file' => 'test.php',
                'line' => 10,
                'type' => 'ERROR',
                'message' => 'Test error',
                'source' => 'PHPCompatibility.Test',
                'affectedVersions' => ['5.6'],
            ],
        ];
        $result = $this->createResult(issues: $issues);
        $this->assertTrue($result->hasIssues());
    }

    /**
     * Test hasIssues returns false when no issues exist.
     */
    public function testHasIssuesReturnsFalse(): void
    {
        $result = $this->createResult(issues: []);
        $this->assertFalse($result->hasIssues());
    }

    /**
     * Test getErrorCount returns correct count.
     */
    public function testGetErrorCount(): void
    {
        $issues = [
            ['file' => 'a.php', 'line' => 1, 'type' => 'ERROR', 'message' => 'e1', 'source' => 's1', 'affectedVersions' => []],
            ['file' => 'b.php', 'line' => 2, 'type' => 'WARNING', 'message' => 'w1', 'source' => 's2', 'affectedVersions' => []],
            ['file' => 'c.php', 'line' => 3, 'type' => 'ERROR', 'message' => 'e2', 'source' => 's3', 'affectedVersions' => []],
        ];
        $result = $this->createResult(issues: $issues);
        $this->assertEquals(2, $result->getErrorCount());
    }

    /**
     * Test getWarningCount returns correct count.
     */
    public function testGetWarningCount(): void
    {
        $issues = [
            ['file' => 'a.php', 'line' => 1, 'type' => 'ERROR', 'message' => 'e1', 'source' => 's1', 'affectedVersions' => []],
            ['file' => 'b.php', 'line' => 2, 'type' => 'WARNING', 'message' => 'w1', 'source' => 's2', 'affectedVersions' => []],
            ['file' => 'c.php', 'line' => 3, 'type' => 'WARNING', 'message' => 'w2', 'source' => 's3', 'affectedVersions' => []],
        ];
        $result = $this->createResult(issues: $issues);
        $this->assertEquals(2, $result->getWarningCount());
    }

    /**
     * Test isVersionCompatible returns correct value.
     */
    public function testIsVersionCompatible(): void
    {
        $result = $this->createResult(passedVersions: ['7.4', '8.0', '8.1']);

        $this->assertTrue($result->isVersionCompatible('7.4'));
        $this->assertTrue($result->isVersionCompatible('8.0'));
        $this->assertFalse($result->isVersionCompatible('5.6'));
    }

    /**
     * Test getVersionRange returns correct range string.
     */
    public function testGetVersionRange(): void
    {
        $result = $this->createResult(minVersion: '7.4', maxVersion: '8.4');
        $this->assertEquals('>=7.4 <=8.4', $result->getVersionRange());
    }

    /**
     * Test getVersionRange returns single version when min equals max.
     */
    public function testGetVersionRangeSingleVersion(): void
    {
        $result = $this->createResult(minVersion: '8.0', maxVersion: '8.0');
        $this->assertEquals('=8.0', $result->getVersionRange());
    }

    /**
     * Test getVersionRange returns null when no versions.
     */
    public function testGetVersionRangeReturnsNull(): void
    {
        $result = $this->createResult(minVersion: null, maxVersion: null);
        $this->assertNull($result->getVersionRange());
    }

    /**
     * Test getComposerConstraint returns correct constraint.
     */
    public function testGetComposerConstraint(): void
    {
        $result = $this->createResult(minVersion: '7.4', maxVersion: '8.4');
        $constraint = $result->getComposerConstraint();
        $this->assertStringContainsString('^7.4', $constraint);
        $this->assertStringContainsString('^8.0', $constraint);
    }

    /**
     * Test getComposerConstraint for same major version.
     */
    public function testGetComposerConstraintSameMajor(): void
    {
        $result = $this->createResult(minVersion: '8.0', maxVersion: '8.4');
        $this->assertEquals('>=8.0', $result->getComposerConstraint());
    }

    /**
     * Test getSummary contains expected keys.
     */
    public function testGetSummaryContainsExpectedKeys(): void
    {
        $result = $this->createResult();
        $summary = $result->getSummary();

        $this->assertArrayHasKey('success', $summary);
        $this->assertArrayHasKey('min_version', $summary);
        $this->assertArrayHasKey('max_version', $summary);
        $this->assertArrayHasKey('version_range', $summary);
        $this->assertArrayHasKey('composer_constraint', $summary);
        $this->assertArrayHasKey('passed_count', $summary);
        $this->assertArrayHasKey('failed_count', $summary);
        $this->assertArrayHasKey('issue_count', $summary);
    }

    /**
     * Test toArray returns the standard shared-envelope structure.
     */
    public function testToArrayReturnsCorrectStructure(): void
    {
        $result = $this->createResult();
        $array = $result->toArray();

        // Standard envelope keys
        $this->assertArrayHasKey('schema_version', $array);
        $this->assertArrayHasKey('tool', $array);
        $this->assertArrayHasKey('success', $array);
        $this->assertArrayHasKey('summary', $array);
        $this->assertArrayHasKey('data', $array);
        $this->assertArrayHasKey('issues', $array);
        $this->assertArrayHasKey('metadata', $array);

        $this->assertEquals(AbstractToolResult::SCHEMA_VERSION, $array['schema_version']);
        $this->assertEquals('php-min-max', $array['tool']);

        // Tool-specific data lives inside 'data'
        $this->assertArrayHasKey('compatibility', $array['data']);
        $this->assertArrayHasKey('versions', $array['data']);
    }

    /**
     * Test jsonSerialize returns same as toArray.
     */
    public function testJsonSerialize(): void
    {
        $result = $this->createResult();
        $this->assertEquals($result->toArray(), $result->jsonSerialize());
    }

    /**
     * Test toJson returns valid JSON.
     */
    public function testToJsonReturnsValidJson(): void
    {
        $result = $this->createResult();
        $json = $result->toJson();

        $decoded = json_decode($json, true);
        $this->assertNotNull($decoded);
        $this->assertEquals(JSON_ERROR_NONE, json_last_error());
    }

    /**
     * Test saveToFile writes correct content.
     */
    public function testSaveToFile(): void
    {
        $result = $this->createResult();
        $tempFile = sys_get_temp_dir() . '/compatibility_result_test_' . uniqid() . '.json';

        try {
            $saved = $result->saveToFile($tempFile);
            $this->assertTrue($saved);
            $this->assertFileExists($tempFile);

            $content = file_get_contents($tempFile);
            $decoded = json_decode($content, true);
            $this->assertEquals($result->toArray(), $decoded);
        } finally {
            @unlink($tempFile);
        }
    }

    /**
     * Test getErrorsByFile returns grouped errors.
     */
    public function testGetErrorsByFile(): void
    {
        $issues = [
            ['file' => 'a.php', 'line' => 1, 'type' => 'ERROR', 'message' => 'e1', 'source' => 's1', 'affectedVersions' => ['5.6']],
            ['file' => 'a.php', 'line' => 5, 'type' => 'ERROR', 'message' => 'e2', 'source' => 's2', 'affectedVersions' => ['5.6']],
            ['file' => 'b.php', 'line' => 2, 'type' => 'WARNING', 'message' => 'w1', 'source' => 's3', 'affectedVersions' => []],
            ['file' => 'b.php', 'line' => 3, 'type' => 'ERROR', 'message' => 'e3', 'source' => 's4', 'affectedVersions' => ['7.0']],
        ];
        $result = $this->createResult(issues: $issues);
        $byFile = $result->getErrorsByFile();

        $this->assertCount(2, $byFile);
        $this->assertArrayHasKey('a.php', $byFile);
        $this->assertArrayHasKey('b.php', $byFile);
        $this->assertCount(2, $byFile['a.php']);
        $this->assertCount(1, $byFile['b.php']);
    }

    /**
     * Helper to create a CompatibilityResult with default values.
     */
    private function createResult(
        bool $success = true,
        ?string $minVersion = '7.4',
        ?string $maxVersion = '8.4',
        array $passedVersions = ['7.4', '8.0', '8.1', '8.2', '8.3', '8.4'],
        array $failedVersions = [],
        array $warningVersions = [],
        array $issues = [],
        string $scannedDirectory = '/tmp/test',
    ): CompatibilityResult {
        return new CompatibilityResult(
            success: $success,
            minVersion: $minVersion,
            maxVersion: $maxVersion,
            passedVersions: $passedVersions,
            failedVersions: $failedVersions,
            warningVersions: $warningVersions,
            issues: $issues,
            scannedDirectory: $scannedDirectory,
        );
    }
}
