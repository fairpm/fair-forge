<?php

declare(strict_types=1);

namespace FairForge\Tools\SupportInfo\Tests;

use FairForge\Shared\AbstractToolResult;
use FairForge\Shared\ToolResultInterface;
use FairForge\Tools\SupportInfo\SupportInfoResult;
use PHPUnit\Framework\TestCase;

/**
 * Tests for the SupportInfoResult class.
 */
class SupportInfoResultTest extends TestCase
{
    /**
     * Test basic construction with all parameters.
     */
    public function testConstruction(): void
    {
        $result = new SupportInfoResult(
            success: true,
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
     * Test hasIssues returns true when issues exist.
     */
    public function testHasIssuesWhenPresent(): void
    {
        $result = $this->createResult(issues: ['Missing Support header']);
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
     * Test hasEmail returns false when only URLs present.
     */
    public function testHasEmailReturnsFalseWithOnlyUrls(): void
    {
        $result = $this->createResult(
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
     * Test getPrimarySupportInfo returns header contact first.
     */
    public function testGetPrimarySupportInfoPrefersHeader(): void
    {
        $result = $this->createResult(
            supportHeaderContact: 'header@example.com',
            hasSupportMd: true,
            supportMdContact: 'md@example.com',
        );
        $this->assertEquals('header@example.com', $result->getPrimarySupportInfo());
    }

    /**
     * Test getPrimarySupportInfo falls back to SUPPORT.md.
     */
    public function testGetPrimarySupportInfoFallsBackToMd(): void
    {
        $result = $this->createResult(
            hasSupportMd: true,
            supportMdContact: 'md@example.com',
        );
        $this->assertEquals('md@example.com', $result->getPrimarySupportInfo());
    }

    /**
     * Test getPrimarySupportInfo returns null when nothing found.
     */
    public function testGetPrimarySupportInfoReturnsNullWhenMissing(): void
    {
        $result = $this->createResult();
        $this->assertNull($result->getPrimarySupportInfo());
    }

    /**
     * Test passes returns true when all conditions met (header + email + consistent).
     */
    public function testPassesWhenAllConditionsMet(): void
    {
        $result = $this->createResult(
            success: true,
            supportHeaderContact: 'support@example.com',
            isConsistent: true,
        );
        $this->assertTrue($result->passes());
    }

    /**
     * Test passes returns false when no support header.
     */
    public function testPassesFailsWithoutSupportHeader(): void
    {
        $result = $this->createResult(
            success: true,
            hasSupportMd: true,
            supportMdContact: 'support@example.com',
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
            supportHeaderContact: 'https://example.com/support',
            isConsistent: true,
        );
        $this->assertFalse($result->passes());
    }

    /**
     * Test getSummary returns expected structure.
     */
    public function testGetSummary(): void
    {
        $result = $this->createResult(
            success: true,
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
        $this->assertTrue($summary['has_support_header']);
        $this->assertTrue($summary['has_support_md']);
        $this->assertTrue($summary['has_email']);
        $this->assertTrue($summary['is_consistent']);
        $this->assertEquals(1, $summary['issue_count']);
        $this->assertEquals('support@example.com', $summary['primary_support_contact']);
        $this->assertEquals('plugin', $summary['package_type']);
    }

    /**
     * Test that SupportInfoResult implements ToolResultInterface.
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
        $this->assertEquals('support-info', $result->getToolName());
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
        $this->assertEquals('support-info', $array['tool']);

        // Tool-specific data lives inside 'data'
        $this->assertTrue($array['data']['support']['header']['found']);
        $this->assertEquals('support@example.com', $array['data']['support']['header']['contact']);
        $this->assertEquals('plugin.php', $array['data']['support']['header']['file']);
        $this->assertTrue($array['data']['support']['support_md']['exists']);
        $this->assertEquals('support@example.com', $array['data']['support']['support_md']['contact']);
        $this->assertTrue($array['data']['consistency']['is_consistent']);
        $this->assertEquals('support@example.com', $array['data']['consistency']['primary_support_contact']);
    }

    /**
     * Test toJson returns valid JSON with shared envelope.
     */
    public function testToJson(): void
    {
        $result = $this->createResult(
            supportHeaderContact: 'test@example.com',
        );
        $json = $result->toJson();

        $decoded = json_decode($json, true);
        $this->assertNotNull($decoded);
        $this->assertEquals('support-info', $decoded['tool']);
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
            supportHeaderContact: 'test@example.com',
        );
        $tempFile = sys_get_temp_dir() . '/support-info-result-test-' . uniqid() . '.json';

        try {
            $saved = $result->saveToFile($tempFile);
            $this->assertTrue($saved);
            $this->assertFileExists($tempFile);

            $content = file_get_contents($tempFile);
            $decoded = json_decode($content, true);
            $this->assertEquals('support-info', $decoded['tool']);
            $this->assertEquals('test@example.com', $decoded['data']['support']['header']['contact']);
        } finally {
            if (file_exists($tempFile)) {
                unlink($tempFile);
            }
        }
    }

    /**
     * Helper to create a SupportInfoResult with defaults.
     */
    private function createResult(
        bool $success = true,
        ?string $supportHeaderContact = null,
        ?string $headerFile = null,
        bool $hasSupportMd = false,
        ?string $supportMdContact = null,
        bool $isConsistent = true,
        array $issues = [],
        ?string $packageType = null,
    ): SupportInfoResult {
        return new SupportInfoResult(
            success: $success,
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
