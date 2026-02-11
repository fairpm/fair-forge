<?php

declare(strict_types=1);

namespace FairForge\Tools\ContactInfo\Tests;

use FairForge\Shared\AbstractToolResult;
use FairForge\Shared\ToolResultInterface;
use FairForge\Tools\ContactInfo\ContactInfoResult;
use PHPUnit\Framework\TestCase;

/**
 * Tests for the ContactInfoResult class (publisher contact only).
 */
class ContactInfoResultTest extends TestCase
{
    /**
     * Test basic construction with all parameters.
     */
    public function testConstruction(): void
    {
        $result = new ContactInfoResult(
            success: true,
            publisherName: 'John Doe',
            publisherUri: 'mailto:john@johndoe.com',
            projectUri: 'https://example.com/my-plugin',
            headerFile: 'my-plugin.php',
            issues: [],
            scannedDirectory: '/tmp/test',
            packageType: 'plugin',
        );

        $this->assertTrue($result->success);
        $this->assertEquals('John Doe', $result->publisherName);
        $this->assertEquals('mailto:john@johndoe.com', $result->publisherUri);
        $this->assertEquals('https://example.com/my-plugin', $result->projectUri);
        $this->assertEquals('my-plugin.php', $result->headerFile);
        $this->assertEmpty($result->issues);
        $this->assertEquals('/tmp/test', $result->scannedDirectory);
        $this->assertEquals('plugin', $result->packageType);
    }

    /**
     * Test hasPublisherInfo returns true when publisher name exists.
     */
    public function testHasPublisherInfoWithName(): void
    {
        $result = $this->createResult(publisherName: 'John Doe');
        $this->assertTrue($result->hasPublisherInfo());
    }

    /**
     * Test hasPublisherInfo returns true when publisher URI exists.
     */
    public function testHasPublisherInfoWithUri(): void
    {
        $result = $this->createResult(publisherUri: 'https://example.com');
        $this->assertTrue($result->hasPublisherInfo());
    }

    /**
     * Test hasPublisherInfo returns false when no publisher info.
     */
    public function testHasPublisherInfoWhenMissing(): void
    {
        $result = $this->createResult();
        $this->assertFalse($result->hasPublisherInfo());
    }

    /**
     * Test hasProjectUri returns true when project URI exists.
     */
    public function testHasProjectUriWhenPresent(): void
    {
        $result = $this->createResult(projectUri: 'https://example.com/plugin');
        $this->assertTrue($result->hasProjectUri());
    }

    /**
     * Test hasProjectUri returns false when missing.
     */
    public function testHasProjectUriWhenMissing(): void
    {
        $result = $this->createResult();
        $this->assertFalse($result->hasProjectUri());
    }

    /**
     * Test hasIssues returns true when issues exist.
     */
    public function testHasIssuesWhenPresent(): void
    {
        $result = $this->createResult(issues: ['Missing Author header']);
        $this->assertTrue($result->hasIssues());
    }

    /**
     * Test hasIssues returns false when no issues.
     */
    public function testHasIssuesWhenEmpty(): void
    {
        $result = $this->createResult();
        $this->assertFalse($result->hasIssues());
    }

    /**
     * Test passes returns true when all conditions met.
     */
    public function testPassesWhenAllConditionsMet(): void
    {
        $result = $this->createResult(
            success: true,
            publisherName: 'John Doe',
            publisherUri: 'mailto:john@example.com',
        );
        $this->assertTrue($result->passes());
    }

    /**
     * Test passes returns false when no publisher info.
     */
    public function testPassesFailsWithoutPublisherInfo(): void
    {
        $result = $this->createResult(
            success: true,
        );
        $this->assertFalse($result->passes());
    }

    /**
     * Test passes returns false when scan failed.
     */
    public function testPassesFailsWhenScanFailed(): void
    {
        $result = $this->createResult(
            success: false,
            publisherName: 'John Doe',
            publisherUri: 'mailto:john@example.com',
        );
        $this->assertFalse($result->passes());
    }

    /**
     * Test passes returns false when no email address is present.
     */
    public function testPassesFailsWithoutEmail(): void
    {
        $result = $this->createResult(
            success: true,
            publisherName: 'John Doe',
            publisherUri: 'https://example.com',
        );
        $this->assertFalse($result->passes());
    }

    /**
     * Test hasEmail returns true when publisher URI has email.
     */
    public function testHasEmailWithPublisherUri(): void
    {
        $result = $this->createResult(publisherUri: 'mailto:dev@example.com');
        $this->assertTrue($result->hasEmail());
    }

    /**
     * Test hasEmail returns false when only URLs present.
     */
    public function testHasEmailReturnsFalseWithOnlyUrls(): void
    {
        $result = $this->createResult(
            publisherUri: 'https://example.com',
        );
        $this->assertFalse($result->hasEmail());
    }

    /**
     * Test hasEmail returns false when no contacts at all.
     */
    public function testHasEmailReturnsFalseWhenEmpty(): void
    {
        $result = $this->createResult();
        $this->assertFalse($result->hasEmail());
    }

    /**
     * Test getSummary returns expected structure.
     */
    public function testGetSummary(): void
    {
        $result = $this->createResult(
            success: true,
            publisherName: 'John Doe',
            publisherUri: 'mailto:john@johndoe.com',
            projectUri: 'https://example.com/plugin',
            issues: ['Warning: something'],
            packageType: 'plugin',
        );

        $summary = $result->getSummary();

        $this->assertTrue($summary['success']);
        $this->assertTrue($summary['passes']);
        $this->assertTrue($summary['has_publisher_name']);
        $this->assertTrue($summary['has_publisher_uri']);
        $this->assertTrue($summary['has_project_uri']);
        $this->assertTrue($summary['has_email']);
        $this->assertEquals(1, $summary['issue_count']);
        $this->assertEquals('John Doe', $summary['publisher_name']);
        $this->assertEquals('mailto:john@johndoe.com', $summary['publisher_uri']);
        $this->assertEquals('plugin', $summary['package_type']);
    }

    /**
     * Test that ContactInfoResult implements ToolResultInterface.
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
        $this->assertEquals('contact-info', $result->getToolName());
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
     * Test toArray returns the standard shared-envelope structure.
     */
    public function testToArray(): void
    {
        $result = $this->createResult(
            publisherName: 'John Doe',
            publisherUri: 'mailto:john@johndoe.com',
            projectUri: 'https://example.com/plugin',
            headerFile: 'plugin.php',
        );

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
        $this->assertEquals('contact-info', $array['tool']);

        // Tool-specific data lives inside 'data'
        $this->assertEquals('John Doe', $array['data']['publisher']['name']);
        $this->assertEquals('mailto:john@johndoe.com', $array['data']['publisher']['uri']);
        $this->assertEquals('plugin.php', $array['data']['publisher']['file']);
        $this->assertEquals('https://example.com/plugin', $array['data']['project']['uri']);
    }

    /**
     * Test toJson returns valid JSON with shared envelope.
     */
    public function testToJson(): void
    {
        $result = $this->createResult(
            publisherName: 'Test Author',
            publisherUri: 'mailto:test@example.com',
        );
        $json = $result->toJson();

        $decoded = json_decode($json, true);
        $this->assertNotNull($decoded);
        $this->assertEquals('contact-info', $decoded['tool']);
        $this->assertEquals('Test Author', $decoded['data']['publisher']['name']);
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
     * Test saveToFile saves JSON with shared envelope.
     */
    public function testSaveToFile(): void
    {
        $result = $this->createResult(
            publisherName: 'Test Author',
            publisherUri: 'mailto:test@example.com',
        );
        $tempFile = sys_get_temp_dir() . '/contact-info-result-test-' . uniqid() . '.json';

        try {
            $saved = $result->saveToFile($tempFile);
            $this->assertTrue($saved);
            $this->assertFileExists($tempFile);

            $content = file_get_contents($tempFile);
            $decoded = json_decode($content, true);
            $this->assertEquals('contact-info', $decoded['tool']);
            $this->assertEquals('Test Author', $decoded['data']['publisher']['name']);
        } finally {
            if (file_exists($tempFile)) {
                unlink($tempFile);
            }
        }
    }

    /**
     * Helper to create a ContactInfoResult with defaults.
     */
    private function createResult(
        bool $success = true,
        ?string $publisherName = null,
        ?string $publisherUri = null,
        ?string $projectUri = null,
        ?string $headerFile = null,
        array $issues = [],
        ?string $packageType = null,
    ): ContactInfoResult {
        return new ContactInfoResult(
            success: $success,
            publisherName: $publisherName,
            publisherUri: $publisherUri,
            projectUri: $projectUri,
            headerFile: $headerFile,
            issues: $issues,
            scannedDirectory: '/tmp/test',
            packageType: $packageType,
        );
    }
}
