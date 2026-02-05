<?php

declare(strict_types=1);

namespace FairForge\Tools\SecurityHeader\Tests;

use FairForge\Shared\ZipHandler;
use FairForge\Tools\SecurityHeader\SecurityResult;
use FairForge\Tools\SecurityHeader\SecurityScanner;
use PHPUnit\Framework\TestCase;

/**
 * Tests for the SecurityScanner class.
 */
class SecurityScannerTest extends TestCase
{
    private SecurityScanner $scanner;
    private string $testDir;

    protected function setUp(): void
    {
        $this->scanner = new SecurityScanner();
        $this->testDir = sys_get_temp_dir() . '/security-scanner-test-' . uniqid();
        mkdir($this->testDir, 0777, true);
    }

    protected function tearDown(): void
    {
        $this->removeDirectory($this->testDir);
    }

    /**
     * Test that SSL verification is enabled by default.
     */
    public function testDefaultSslVerifyIsTrue(): void
    {
        $this->assertTrue($this->scanner->getSslVerify());
    }

    /**
     * Test that SSL verification can be toggled.
     */
    public function testSetSslVerify(): void
    {
        $this->scanner->setSslVerify(false);
        $this->assertFalse($this->scanner->getSslVerify());

        $this->scanner->setSslVerify(true);
        $this->assertTrue($this->scanner->getSslVerify());
    }

    /**
     * Test that setSslVerify returns self for method chaining.
     */
    public function testSetSslVerifyReturnsSelf(): void
    {
        $result = $this->scanner->setSslVerify(false);
        $this->assertSame($this->scanner, $result);
    }

    /**
     * Test that getZipHandler returns a ZipHandler instance.
     */
    public function testGetZipHandlerReturnsInstance(): void
    {
        $this->assertInstanceOf(ZipHandler::class, $this->scanner->getZipHandler());
    }

    /**
     * Test scanning a directory that doesn't exist.
     */
    public function testScanNonExistentDirectory(): void
    {
        $result = $this->scanner->scanDirectory('/nonexistent/path');

        $this->assertFalse($result->success);
        $this->assertNotEmpty($result->issues);
        $this->assertNotNull($result->parseError);
    }

    /**
     * Test scanning a plugin with security header.
     */
    public function testScanPluginWithSecurityHeader(): void
    {
        $pluginDir = $this->testDir . '/my-plugin';
        mkdir($pluginDir);

        file_put_contents($pluginDir . '/my-plugin.php', <<<'PHP'
<?php
/**
 * Plugin Name: My Plugin
 * Description: A test plugin
 * Version: 1.0.0
 * Security: security@example.com
 */
PHP);

        $result = $this->scanner->scanDirectory($pluginDir);

        $this->assertTrue($result->success);
        $this->assertEquals('security@example.com', $result->headerContact);
        $this->assertEquals('my-plugin.php', $result->headerFile);
        $this->assertEquals('plugin', $result->packageType);
    }

    /**
     * Test scanning a plugin with security URL header.
     */
    public function testScanPluginWithSecurityUrlHeader(): void
    {
        $pluginDir = $this->testDir . '/my-plugin';
        mkdir($pluginDir);

        file_put_contents($pluginDir . '/my-plugin.php', <<<'PHP'
<?php
/**
 * Plugin Name: My Plugin
 * Security: https://example.com/security
 */
PHP);

        $result = $this->scanner->scanDirectory($pluginDir);

        $this->assertTrue($result->success);
        $this->assertEquals('https://example.com/security', $result->headerContact);
    }

    /**
     * Test scanning a plugin without security header.
     */
    public function testScanPluginWithoutSecurityHeader(): void
    {
        $pluginDir = $this->testDir . '/my-plugin';
        mkdir($pluginDir);

        file_put_contents($pluginDir . '/my-plugin.php', <<<'PHP'
<?php
/**
 * Plugin Name: My Plugin
 * Description: A test plugin
 */
PHP);

        $result = $this->scanner->scanDirectory($pluginDir);

        $this->assertTrue($result->success);
        $this->assertNull($result->headerContact);
        $this->assertFalse($result->passes());
        $this->assertTrue($result->hasIssues());
    }

    /**
     * Test scanning a theme with security header.
     */
    public function testScanThemeWithSecurityHeader(): void
    {
        $themeDir = $this->testDir . '/my-theme';
        mkdir($themeDir);

        file_put_contents($themeDir . '/style.css', <<<'CSS'
/*
Theme Name: My Theme
Description: A test theme
Security: security@example.com
*/
CSS);

        $result = $this->scanner->scanDirectory($themeDir);

        $this->assertTrue($result->success);
        $this->assertEquals('security@example.com', $result->headerContact);
        $this->assertEquals('theme', $result->packageType);
    }

    /**
     * Test scanning with security.md file.
     */
    public function testScanWithSecurityMd(): void
    {
        $pluginDir = $this->testDir . '/my-plugin';
        mkdir($pluginDir);

        file_put_contents($pluginDir . '/my-plugin.php', <<<'PHP'
<?php
/**
 * Plugin Name: My Plugin
 * Security: security@example.com
 */
PHP);

        file_put_contents($pluginDir . '/SECURITY.md', <<<'MD'
# Security Policy

To report a vulnerability, please contact security@example.com.
MD);

        $result = $this->scanner->scanDirectory($pluginDir);

        $this->assertTrue($result->success);
        $this->assertTrue($result->hasSecurityMd);
        $this->assertEquals('security@example.com', $result->securityMdContact);
        $this->assertTrue($result->isConsistent);
    }

    /**
     * Test scanning with security.txt file.
     */
    public function testScanWithSecurityTxt(): void
    {
        $pluginDir = $this->testDir . '/my-plugin';
        mkdir($pluginDir);

        file_put_contents($pluginDir . '/my-plugin.php', <<<'PHP'
<?php
/**
 * Plugin Name: My Plugin
 * Security: security@example.com
 */
PHP);

        file_put_contents($pluginDir . '/security.txt', <<<'TXT'
Contact: security@example.com
Expires: 2030-01-01T00:00:00.000Z
TXT);

        $result = $this->scanner->scanDirectory($pluginDir);

        $this->assertTrue($result->success);
        $this->assertTrue($result->hasSecurityTxt);
        $this->assertEquals('security@example.com', $result->securityTxtContact);
        $this->assertTrue($result->isConsistent);
    }

    /**
     * Test scanning with inconsistent security contacts.
     */
    public function testScanWithInconsistentContacts(): void
    {
        $pluginDir = $this->testDir . '/my-plugin';
        mkdir($pluginDir);

        file_put_contents($pluginDir . '/my-plugin.php', <<<'PHP'
<?php
/**
 * Plugin Name: My Plugin
 * Security: security@example.com
 */
PHP);

        file_put_contents($pluginDir . '/SECURITY.md', <<<'MD'
# Security

Contact: other@example.com
MD);

        $result = $this->scanner->scanDirectory($pluginDir);

        $this->assertTrue($result->success);
        $this->assertFalse($result->isConsistent);
        $this->assertFalse($result->passes());
        $this->assertTrue($result->hasIssues());
    }

    /**
     * Test scanning directory with nested plugin directory (ZIP extract).
     */
    public function testScanNestedDirectory(): void
    {
        $extractDir = $this->testDir . '/extract';
        mkdir($extractDir);
        $pluginDir = $extractDir . '/my-plugin';
        mkdir($pluginDir);

        file_put_contents($pluginDir . '/my-plugin.php', <<<'PHP'
<?php
/**
 * Plugin Name: My Plugin
 * Security: security@example.com
 */
PHP);

        $result = $this->scanner->scanDirectory($extractDir);

        $this->assertTrue($result->success);
        $this->assertEquals('security@example.com', $result->headerContact);
    }

    /**
     * Test scanning returns correct result instance.
     */
    public function testScanReturnsSecurityResult(): void
    {
        $pluginDir = $this->testDir . '/my-plugin';
        mkdir($pluginDir);

        file_put_contents($pluginDir . '/my-plugin.php', <<<'PHP'
<?php
/**
 * Plugin Name: My Plugin
 */
PHP);

        $result = $this->scanner->scanDirectory($pluginDir);

        $this->assertInstanceOf(SecurityResult::class, $result);
    }

    /**
     * Test security.md with URL contact.
     */
    public function testSecurityMdWithUrlContact(): void
    {
        $pluginDir = $this->testDir . '/my-plugin';
        mkdir($pluginDir);

        file_put_contents($pluginDir . '/my-plugin.php', <<<'PHP'
<?php
/**
 * Plugin Name: My Plugin
 * Security: https://example.com/security-report
 */
PHP);

        file_put_contents($pluginDir . '/SECURITY.md', <<<'MD'
# Security

Report vulnerabilities at https://example.com/security-report
MD);

        $result = $this->scanner->scanDirectory($pluginDir);

        $this->assertTrue($result->success);
        $this->assertTrue($result->hasSecurityMd);
        $this->assertStringContainsString('example.com', $result->securityMdContact ?? '');
    }

    /**
     * Test no main file found generates issue.
     */
    public function testNoMainFileFoundGeneratesIssue(): void
    {
        $dir = $this->testDir . '/empty';
        mkdir($dir);
        file_put_contents($dir . '/readme.txt', 'Test');

        $result = $this->scanner->scanDirectory($dir);

        $this->assertTrue($result->success);
        $this->assertNull($result->packageType);
        $this->assertTrue($result->hasIssues());
    }

    /**
     * Test contact normalization handles mailto prefix.
     */
    public function testContactNormalizationWithMailto(): void
    {
        $pluginDir = $this->testDir . '/my-plugin';
        mkdir($pluginDir);

        file_put_contents($pluginDir . '/my-plugin.php', <<<'PHP'
<?php
/**
 * Plugin Name: My Plugin
 * Security: security@example.com
 */
PHP);

        file_put_contents($pluginDir . '/security.txt', <<<'TXT'
Contact: mailto:security@example.com
TXT);

        $result = $this->scanner->scanDirectory($pluginDir);

        $this->assertTrue($result->success);
        $this->assertTrue($result->isConsistent);
    }

    /**
     * Test multiple plugin files picks correct one.
     */
    public function testMultiplePluginFilesPicksCorrectOne(): void
    {
        $pluginDir = $this->testDir . '/my-plugin';
        mkdir($pluginDir);

        // Main plugin file (matches dir name)
        file_put_contents($pluginDir . '/my-plugin.php', <<<'PHP'
<?php
/**
 * Plugin Name: My Plugin
 * Security: main@example.com
 */
PHP);

        // Another plugin file
        file_put_contents($pluginDir . '/other.php', <<<'PHP'
<?php
/**
 * Plugin Name: Other
 * Security: other@example.com
 */
PHP);

        $result = $this->scanner->scanDirectory($pluginDir);

        $this->assertEquals('main@example.com', $result->headerContact);
        $this->assertEquals('my-plugin.php', $result->headerFile);
    }

    /**
     * Remove directory recursively.
     */
    private function removeDirectory(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }

        $items = array_diff(scandir($dir) ?: [], ['.', '..']);
        foreach ($items as $item) {
            $path = $dir . '/' . $item;
            if (is_dir($path)) {
                $this->removeDirectory($path);
            } else {
                unlink($path);
            }
        }
        rmdir($dir);
    }
}
