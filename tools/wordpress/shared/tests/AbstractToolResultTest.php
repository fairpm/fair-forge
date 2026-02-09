<?php

declare(strict_types=1);

namespace FairForge\Shared\Tests;

use FairForge\Shared\AbstractToolResult;
use FairForge\Shared\ToolResultInterface;
use PHPUnit\Framework\TestCase;

/**
 * Concrete stub used only for testing the abstract base class.
 */
class ConcreteToolResult extends AbstractToolResult
{
    public function __construct(
        private readonly bool $success = true,
        private readonly array $summary = [],
        private readonly array $data = [],
        private readonly array $issues = [],
        private readonly array $metadata = [],
        private readonly string $toolName = 'test-tool',
    ) {
    }

    public function getToolName(): string
    {
        return $this->toolName;
    }

    public function isSuccess(): bool
    {
        return $this->success;
    }

    public function getSummary(): array
    {
        return $this->summary;
    }

    public function getData(): array
    {
        return $this->data;
    }

    public function getIssues(): array
    {
        return $this->issues;
    }

    public function getMetadata(): array
    {
        return $this->metadata;
    }
}

/**
 * Tests for AbstractToolResult and ToolResultInterface.
 */
class AbstractToolResultTest extends TestCase
{
    /**
     * Test that ConcreteToolResult implements ToolResultInterface.
     */
    public function testImplementsInterface(): void
    {
        $result = new ConcreteToolResult();
        $this->assertInstanceOf(ToolResultInterface::class, $result);
    }

    /**
     * Test that toArray produces the standard envelope keys.
     */
    public function testToArrayHasStandardEnvelopeKeys(): void
    {
        $result = new ConcreteToolResult();
        $array = $result->toArray();

        $this->assertArrayHasKey('schema_version', $array);
        $this->assertArrayHasKey('tool', $array);
        $this->assertArrayHasKey('success', $array);
        $this->assertArrayHasKey('summary', $array);
        $this->assertArrayHasKey('data', $array);
        $this->assertArrayHasKey('issues', $array);
        $this->assertArrayHasKey('metadata', $array);
    }

    /**
     * Test that schema_version is set correctly.
     */
    public function testSchemaVersion(): void
    {
        $result = new ConcreteToolResult();
        $array = $result->toArray();

        $this->assertEquals(AbstractToolResult::SCHEMA_VERSION, $array['schema_version']);
        $this->assertEquals('1.0.0', $array['schema_version']);
    }

    /**
     * Test that tool name is reflected in the envelope.
     */
    public function testToolName(): void
    {
        $result = new ConcreteToolResult(toolName: 'my-scanner');
        $array = $result->toArray();

        $this->assertEquals('my-scanner', $array['tool']);
    }

    /**
     * Test that success flag is forwarded.
     */
    public function testSuccessTrue(): void
    {
        $result = new ConcreteToolResult(success: true);
        $this->assertTrue($result->toArray()['success']);
    }

    /**
     * Test that success false is forwarded.
     */
    public function testSuccessFalse(): void
    {
        $result = new ConcreteToolResult(success: false);
        $this->assertFalse($result->toArray()['success']);
    }

    /**
     * Test that summary data is passed through.
     */
    public function testSummaryPassthrough(): void
    {
        $summary = ['errors' => 5, 'warnings' => 3];
        $result = new ConcreteToolResult(summary: $summary);

        $this->assertEquals($summary, $result->toArray()['summary']);
    }

    /**
     * Test that data section is passed through.
     */
    public function testDataPassthrough(): void
    {
        $data = ['files' => ['a.php' => ['errors' => 1]]];
        $result = new ConcreteToolResult(data: $data);

        $this->assertEquals($data, $result->toArray()['data']);
    }

    /**
     * Test that issues are passed through.
     */
    public function testIssuesPassthrough(): void
    {
        $issues = ['Missing header', 'Inconsistent contact'];
        $result = new ConcreteToolResult(issues: $issues);

        $this->assertEquals($issues, $result->toArray()['issues']);
    }

    /**
     * Test that metadata includes scanned_at timestamp.
     */
    public function testMetadataIncludesScannedAt(): void
    {
        $result = new ConcreteToolResult(metadata: ['custom_key' => 'value']);
        $meta = $result->toArray()['metadata'];

        $this->assertArrayHasKey('scanned_at', $meta);
        $this->assertMatchesRegularExpression('/^\d{4}-\d{2}-\d{2}T/', $meta['scanned_at']);
    }

    /**
     * Test that tool-specific metadata is merged in.
     */
    public function testMetadataMergesToolSpecificKeys(): void
    {
        $result = new ConcreteToolResult(metadata: [
            'scanned_directory' => '/tmp/test',
            'standard' => 'WordPress',
        ]);
        $meta = $result->toArray()['metadata'];

        $this->assertEquals('/tmp/test', $meta['scanned_directory']);
        $this->assertEquals('WordPress', $meta['standard']);
    }

    /**
     * Test that toJson returns valid JSON.
     */
    public function testToJsonReturnsValidJson(): void
    {
        $result = new ConcreteToolResult(summary: ['errors' => 2]);
        $json = $result->toJson();

        $decoded = json_decode($json, true);
        $this->assertNotNull($decoded);
        $this->assertEquals(JSON_ERROR_NONE, json_last_error());
        $this->assertEquals('test-tool', $decoded['tool']);
    }

    /**
     * Test that jsonSerialize returns the same as toArray.
     */
    public function testJsonSerializeMatchesToArray(): void
    {
        $result = new ConcreteToolResult();
        $this->assertEquals($result->toArray(), $result->jsonSerialize());
    }

    /**
     * Test that json_encode works directly on the result object.
     */
    public function testJsonEncodeDirectly(): void
    {
        $result = new ConcreteToolResult(success: true, toolName: 'direct-test');
        $json = json_encode($result);

        $this->assertIsString($json);
        $decoded = json_decode($json, true);
        $this->assertEquals('direct-test', $decoded['tool']);
        $this->assertTrue($decoded['success']);
    }

    /**
     * Test that saveToFile persists correct JSON.
     */
    public function testSaveToFile(): void
    {
        $result = new ConcreteToolResult(
            success: true,
            summary: ['count' => 42],
            toolName: 'file-test',
        );
        $tempFile = sys_get_temp_dir() . '/abstract_result_test_' . uniqid() . '.json';

        try {
            $saved = $result->saveToFile($tempFile);
            $this->assertTrue($saved);
            $this->assertFileExists($tempFile);

            $content = file_get_contents($tempFile);
            $decoded = json_decode($content, true);

            $this->assertEquals('1.0.0', $decoded['schema_version']);
            $this->assertEquals('file-test', $decoded['tool']);
            $this->assertTrue($decoded['success']);
            $this->assertEquals(42, $decoded['summary']['count']);
        } finally {
            if (file_exists($tempFile)) {
                unlink($tempFile);
            }
        }
    }

    /**
     * Test that the envelope has exactly the expected top-level keys (no extras).
     */
    public function testEnvelopeHasExactKeys(): void
    {
        $result = new ConcreteToolResult();
        $keys = array_keys($result->toArray());

        $expected = ['schema_version', 'tool', 'success', 'summary', 'data', 'issues', 'metadata'];
        $this->assertEquals($expected, $keys);
    }

    /**
     * Test SCHEMA_VERSION constant is accessible.
     */
    public function testSchemaVersionConstant(): void
    {
        $this->assertIsString(AbstractToolResult::SCHEMA_VERSION);
        $this->assertMatchesRegularExpression('/^\d+\.\d+\.\d+$/', AbstractToolResult::SCHEMA_VERSION);
    }
}
