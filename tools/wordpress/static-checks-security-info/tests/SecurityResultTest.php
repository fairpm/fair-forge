<?php

declare(strict_types=1);

namespace FairForge\Tools\SecurityInfo\Tests;

use FairForge\Shared\AbstractToolResult;
use FairForge\Shared\ToolResultInterface;
use FairForge\Tools\SecurityInfo\SecurityResult;
use PHPUnit\Framework\TestCase;

/**
 * Tests for the SecurityResult class.
 */
class SecurityResultTest extends TestCase
{
    /**
     * Test basic construction with all parameters.
     */
    public function testConstruction(): void
    {
        $result = new SecurityResult(
            success: true,
            headerContact: 'security@example.com',
            headerFile: 'my-plugin.php',
            hasSecurityMd: true,
            securityMdContact: 'security@example.com',
            hasSecurityTxt: false,
            securityTxtContact: null,
            isConsistent: true,
            issues: [],
            scannedDirectory: '/tmp/test',
            packageType: 'plugin',
        );

        $this->assertTrue($result->success);
        $this->assertEquals('security@example.com', $result->headerContact);
        $this->assertEquals('my-plugin.php', $result->headerFile);
        $this->assertTrue($result->hasSecurityMd);
        $this->assertEquals('security@example.com', $result->securityMdContact);
        $this->assertFalse($result->hasSecurityTxt);
        $this->assertNull($result->securityTxtContact);
        $this->assertTrue($result->isConsistent);
        $this->assertEmpty($result->issues);
        $this->assertEquals('/tmp/test', $result->scannedDirectory);
        $this->assertEquals('plugin', $result->packageType);
    }

    /**
     * Test hasSecurityHeader returns true when header contact exists.
     */
    public function testHasSecurityHeaderWhenPresent(): void
    {
        $result = $this->createResult(headerContact: 'security@example.com');
        $this->assertTrue($result->hasSecurityHeader());
    }

    /**
     * Test hasSecurityHeader returns false when no header.
     */
    public function testHasSecurityHeaderWhenMissing(): void
    {
        $result = $this->createResult();
        $this->assertFalse($result->hasSecurityHeader());
    }

    /**
     * Test hasSecurityFile returns true when security.md exists.
     */
    public function testHasSecurityFileWithMd(): void
    {
        $result = $this->createResult(hasSecurityMd: true);
        $this->assertTrue($result->hasSecurityFile());
    }

    /**
     * Test hasSecurityFile returns true when security.txt exists.
     */
    public function testHasSecurityFileWithTxt(): void
    {
        $result = $this->createResult(hasSecurityTxt: true);
        $this->assertTrue($result->hasSecurityFile());
    }

    /**
     * Test hasSecurityFile returns false when no files.
     */
    public function testHasSecurityFileWhenMissing(): void
    {
        $result = $this->createResult();
        $this->assertFalse($result->hasSecurityFile());
    }

    /**
     * Test hasSecurityInfo returns true with header.
     */
    public function testHasSecurityInfoWithHeader(): void
    {
        $result = $this->createResult(headerContact: 'security@example.com');
        $this->assertTrue($result->hasSecurityInfo());
    }

    /**
     * Test hasSecurityInfo returns true with file.
     */
    public function testHasSecurityInfoWithFile(): void
    {
        $result = $this->createResult(hasSecurityMd: true);
        $this->assertTrue($result->hasSecurityInfo());
    }

    /**
     * Test hasSecurityInfo returns false with nothing.
     */
    public function testHasSecurityInfoWhenMissing(): void
    {
        $result = $this->createResult();
        $this->assertFalse($result->hasSecurityInfo());
    }

    /**
     * Test hasIssues returns true when issues exist.
     */
    public function testHasIssuesWhenPresent(): void
    {
        $result = $this->createResult(issues: ['Missing security header']);
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
     * Test getPrimaryContact returns header contact first.
     */
    public function testGetPrimaryContactPrefersHeader(): void
    {
        $result = $this->createResult(
            headerContact: 'header@example.com',
            hasSecurityMd: true,
            securityMdContact: 'md@example.com',
        );
        $this->assertEquals('header@example.com', $result->getPrimaryContact());
    }

    /**
     * Test getPrimaryContact falls back to security.md.
     */
    public function testGetPrimaryContactFallsBackToMd(): void
    {
        $result = $this->createResult(
            hasSecurityMd: true,
            securityMdContact: 'md@example.com',
        );
        $this->assertEquals('md@example.com', $result->getPrimaryContact());
    }

    /**
     * Test getPrimaryContact falls back to security.txt.
     */
    public function testGetPrimaryContactFallsBackToTxt(): void
    {
        $result = $this->createResult(
            hasSecurityTxt: true,
            securityTxtContact: 'txt@example.com',
        );
        $this->assertEquals('txt@example.com', $result->getPrimaryContact());
    }

    /**
     * Test getPrimaryContact returns null when nothing found.
     */
    public function testGetPrimaryContactReturnsNullWhenMissing(): void
    {
        $result = $this->createResult();
        $this->assertNull($result->getPrimaryContact());
    }

    /**
     * Test passes returns true when all conditions met.
     */
    public function testPassesWhenAllConditionsMet(): void
    {
        $result = $this->createResult(
            success: true,
            headerContact: 'security@example.com',
            isConsistent: true,
        );
        $this->assertTrue($result->passes());
    }

    /**
     * Test passes returns false when no header.
     */
    public function testPassesFailsWithoutHeader(): void
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
            headerContact: 'security@example.com',
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
            headerContact: 'security@example.com',
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
            headerContact: 'security@example.com',
            hasSecurityMd: true,
            securityMdContact: 'security@example.com',
            isConsistent: true,
            issues: ['Warning: something'],
            packageType: 'plugin',
        );

        $summary = $result->getSummary();

        $this->assertTrue($summary['success']);
        $this->assertTrue($summary['passes']);
        $this->assertTrue($summary['has_header']);
        $this->assertTrue($summary['has_security_md']);
        $this->assertFalse($summary['has_security_txt']);
        $this->assertTrue($summary['is_consistent']);
        $this->assertEquals(1, $summary['issue_count']);
        $this->assertEquals('security@example.com', $summary['primary_contact']);
        $this->assertEquals('plugin', $summary['package_type']);
    }

    /**
     * Test that SecurityResult implements ToolResultInterface.
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
        $this->assertEquals('security-info', $result->getToolName());
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
            headerContact: 'security@example.com',
            headerFile: 'plugin.php',
            hasSecurityMd: true,
            securityMdContact: 'security@example.com',
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
        $this->assertEquals('security-info', $array['tool']);

        // Tool-specific data lives inside 'data'
        $this->assertEquals('security@example.com', $array['data']['header']['contact']);
        $this->assertEquals('plugin.php', $array['data']['header']['file']);
        $this->assertTrue($array['data']['files']['security_md']['exists']);
    }

    /**
     * Test toJson returns valid JSON with shared envelope.
     */
    public function testToJson(): void
    {
        $result = $this->createResult(headerContact: 'test@example.com');
        $json = $result->toJson();

        $decoded = json_decode($json, true);
        $this->assertNotNull($decoded);
        $this->assertEquals('security-info', $decoded['tool']);
        $this->assertEquals('test@example.com', $decoded['data']['header']['contact']);
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
        $result = $this->createResult(headerContact: 'test@example.com');
        $tempFile = sys_get_temp_dir() . '/security-result-test-' . uniqid() . '.json';

        try {
            $saved = $result->saveToFile($tempFile);
            $this->assertTrue($saved);
            $this->assertFileExists($tempFile);

            $content = file_get_contents($tempFile);
            $decoded = json_decode($content, true);
            $this->assertEquals('security-info', $decoded['tool']);
            $this->assertEquals('test@example.com', $decoded['data']['header']['contact']);
        } finally {
            if (file_exists($tempFile)) {
                unlink($tempFile);
            }
        }
    }

    /**
     * Helper to create a SecurityResult with defaults.
     */
    private function createResult(
        bool $success = true,
        ?string $headerContact = null,
        ?string $headerFile = null,
        bool $hasSecurityMd = false,
        ?string $securityMdContact = null,
        bool $hasSecurityTxt = false,
        ?string $securityTxtContact = null,
        bool $isConsistent = true,
        array $issues = [],
        ?string $packageType = null,
    ): SecurityResult {
        return new SecurityResult(
            success: $success,
            headerContact: $headerContact,
            headerFile: $headerFile,
            hasSecurityMd: $hasSecurityMd,
            securityMdContact: $securityMdContact,
            hasSecurityTxt: $hasSecurityTxt,
            securityTxtContact: $securityTxtContact,
            isConsistent: $isConsistent,
            issues: $issues,
            scannedDirectory: '/tmp/test',
            packageType: $packageType,
        );
    }
}
