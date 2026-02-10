<?php

declare(strict_types=1);

namespace FairForge\Tools\ContactInfo\Tests;

use FairForge\Shared\AbstractToolResult;
use FairForge\Shared\ToolResultInterface;
use FairForge\Tools\ContactInfo\ContactInfoResult;
use PHPUnit\Framework\TestCase;

/**
 * Tests for the ContactInfoResult class.
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
            publisherUri: 'https://johndoe.com',
            projectUri: 'https://example.com/my-plugin',
            supportHeaderContact: 'support@example.com',
            headerFile: 'my-plugin.php',
            hasSupportMd: true,
            supportMdContact: 'support@example.com',
            isConsistent: true,
            issues: [],
            scannedDirectory: '/tmp/test',
            packageType: 'plugin',
        );

        $this->assertTrue($result->success);
        $this->assertEquals('John Doe', $result->publisherName);
        $this->assertEquals('https://johndoe.com', $result->publisherUri);
        $this->assertEquals('https://example.com/my-plugin', $result->projectUri);
        $this->assertEquals('support@example.com', $result->supportHeaderContact);
        $this->assertEquals('my-plugin.php', $result->headerFile);
        $this->assertTrue($result->hasSupportMd);
        $this->assertEquals('support@example.com', $result->supportMdContact);
        $this->assertTrue($result->isConsistent);
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
     * Test hasSupportHeader returns true when support header contact exists.
     */
    public function testHasSupportHeaderWhenPresent(): void
    {
        $result = $this->createResult(supportHeaderContact: 'support@example.com');
        $this->assertTrue($result->hasSupportHeader());
    }

    /**
     * Test hasSupportHeader returns false when no support header.
     */
    public function testHasSupportHeaderWhenMissing(): void
    {
        $result = $this->createResult();
        $this->assertFalse($result->hasSupportHeader());
    }

    /**
     * Test hasSupportFile returns true when SUPPORT.md exists.
     */
    public function testHasSupportFileWithMd(): void
    {
        $result = $this->createResult(hasSupportMd: true);
        $this->assertTrue($result->hasSupportFile());
    }

    /**
     * Test hasSupportFile returns false when no files.
     */
    public function testHasSupportFileWhenMissing(): void
    {
        $result = $this->createResult();
        $this->assertFalse($result->hasSupportFile());
    }

    /**
     * Test hasSupportInfo returns true with header.
     */
    public function testHasSupportInfoWithHeader(): void
    {
        $result = $this->createResult(supportHeaderContact: 'support@example.com');
        $this->assertTrue($result->hasSupportInfo());
    }

    /**
     * Test hasSupportInfo returns true with file.
     */
    public function testHasSupportInfoWithFile(): void
    {
        $result = $this->createResult(hasSupportMd: true);
        $this->assertTrue($result->hasSupportInfo());
    }

    /**
     * Test hasSupportInfo returns false with nothing.
     */
    public function testHasSupportInfoWhenMissing(): void
    {
        $result = $this->createResult();
        $this->assertFalse($result->hasSupportInfo());
    }

    /**
     * Test hasContactInfo returns true with publisher info.
     */
    public function testHasContactInfoWithPublisher(): void
    {
        $result = $this->createResult(publisherName: 'John Doe');
        $this->assertTrue($result->hasContactInfo());
    }

    /**
     * Test hasContactInfo returns true with support info.
     */
    public function testHasContactInfoWithSupport(): void
    {
        $result = $this->createResult(supportHeaderContact: 'support@example.com');
        $this->assertTrue($result->hasContactInfo());
    }

    /**
     * Test hasContactInfo returns false with nothing.
     */
    public function testHasContactInfoWhenMissing(): void
    {
        $result = $this->createResult();
        $this->assertFalse($result->hasContactInfo());
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
     * Test getPrimarySupportContact returns header contact first.
     */
    public function testGetPrimarySupportContactPrefersHeader(): void
    {
        $result = $this->createResult(
            supportHeaderContact: 'header@example.com',
            hasSupportMd: true,
            supportMdContact: 'md@example.com',
        );
        $this->assertEquals('header@example.com', $result->getPrimarySupportContact());
    }

    /**
     * Test getPrimarySupportContact falls back to SUPPORT.md.
     */
    public function testGetPrimarySupportContactFallsBackToMd(): void
    {
        $result = $this->createResult(
            hasSupportMd: true,
            supportMdContact: 'md@example.com',
        );
        $this->assertEquals('md@example.com', $result->getPrimarySupportContact());
    }

    /**
     * Test getPrimarySupportContact returns null when nothing found.
     */
    public function testGetPrimarySupportContactReturnsNullWhenMissing(): void
    {
        $result = $this->createResult();
        $this->assertNull($result->getPrimarySupportContact());
    }

    /**
     * Test passes returns true when all conditions met.
     */
    public function testPassesWhenAllConditionsMet(): void
    {
        $result = $this->createResult(
            success: true,
            publisherName: 'John Doe',
            supportHeaderContact: 'support@example.com',
            isConsistent: true,
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
            isConsistent: true,
        );
        $this->assertFalse($result->passes());
    }

    /**
     * Test passes returns false when not consistent.
     */
    public function testPassesFailsWhenInconsistent(): void
    {
        $result = $this->createResult(
            success: true,
            publisherName: 'John Doe',
            supportHeaderContact: 'support@example.com',
            isConsistent: false,
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
            supportHeaderContact: 'support@example.com',
            isConsistent: true,
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
            supportHeaderContact: 'https://example.com/support',
            isConsistent: true,
        );
        $this->assertFalse($result->passes());
    }

    /**
     * Test hasEmail returns true when support header has email.
     */
    public function testHasEmailWithSupportHeader(): void
    {
        $result = $this->createResult(supportHeaderContact: 'support@example.com');
        $this->assertTrue($result->hasEmail());
    }

    /**
     * Test hasEmail returns true when SUPPORT.md has email.
     */
    public function testHasEmailWithSupportMd(): void
    {
        $result = $this->createResult(hasSupportMd: true, supportMdContact: 'help@example.com');
        $this->assertTrue($result->hasEmail());
    }

    /**
     * Test hasEmail returns true when publisher URI is a mailto.
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
            supportHeaderContact: 'https://example.com/support',
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
            publisherUri: 'https://johndoe.com',
            supportHeaderContact: 'support@example.com',
            hasSupportMd: true,
            supportMdContact: 'support@example.com',
            isConsistent: true,
            issues: ['Warning: something'],
            packageType: 'plugin',
        );

        $summary = $result->getSummary();

        $this->assertTrue($summary['success']);
        $this->assertTrue($summary['passes']);
        $this->assertTrue($summary['has_publisher_name']);
        $this->assertTrue($summary['has_publisher_uri']);
        $this->assertTrue($summary['has_support_header']);
        $this->assertTrue($summary['has_support_md']);
        $this->assertTrue($summary['is_consistent']);
        $this->assertEquals(1, $summary['issue_count']);
        $this->assertEquals('John Doe', $summary['publisher_name']);
        $this->assertEquals('https://johndoe.com', $summary['publisher_uri']);
        $this->assertEquals('support@example.com', $summary['primary_support_contact']);
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
            publisherUri: 'https://johndoe.com',
            projectUri: 'https://example.com/plugin',
            supportHeaderContact: 'support@example.com',
            headerFile: 'plugin.php',
            hasSupportMd: true,
            supportMdContact: 'support@example.com',
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
        $this->assertEquals('https://johndoe.com', $array['data']['publisher']['uri']);
        $this->assertEquals('plugin.php', $array['data']['publisher']['file']);
        $this->assertEquals('https://example.com/plugin', $array['data']['project']['uri']);
        $this->assertTrue($array['data']['support']['header']['found']);
        $this->assertEquals('support@example.com', $array['data']['support']['header']['contact']);
        $this->assertTrue($array['data']['support']['support_md']['exists']);
    }

    /**
     * Test toJson returns valid JSON with shared envelope.
     */
    public function testToJson(): void
    {
        $result = $this->createResult(
            publisherName: 'Test Author',
            supportHeaderContact: 'test@example.com',
        );
        $json = $result->toJson();

        $decoded = json_decode($json, true);
        $this->assertNotNull($decoded);
        $this->assertEquals('contact-info', $decoded['tool']);
        $this->assertEquals('Test Author', $decoded['data']['publisher']['name']);
        $this->assertEquals('test@example.com', $decoded['data']['support']['header']['contact']);
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
            supportHeaderContact: 'test@example.com',
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
            $this->assertEquals('test@example.com', $decoded['data']['support']['header']['contact']);
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
        ?string $supportHeaderContact = null,
        ?string $headerFile = null,
        bool $hasSupportMd = false,
        ?string $supportMdContact = null,
        bool $isConsistent = true,
        array $issues = [],
        ?string $packageType = null,
    ): ContactInfoResult {
        return new ContactInfoResult(
            success: $success,
            publisherName: $publisherName,
            publisherUri: $publisherUri,
            projectUri: $projectUri,
            supportHeaderContact: $supportHeaderContact,
            headerFile: $headerFile,
            hasSupportMd: $hasSupportMd,
            supportMdContact: $supportMdContact,
            isConsistent: $isConsistent,
            issues: $issues,
            scannedDirectory: '/tmp/test',
            packageType: $packageType,
        );
    }
}
