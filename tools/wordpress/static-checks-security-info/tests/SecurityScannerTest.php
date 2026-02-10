<?php

declare(strict_types=1);

namespace FairForge\Tools\SecurityInfo\Tests;

use FairForge\Shared\ScanTarget;
use FairForge\Shared\ToolScannerInterface;
use FairForge\Shared\ZipHandler;
use FairForge\Tools\SecurityInfo\SecurityResult;
use FairForge\Tools\SecurityInfo\SecurityScanner;
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
     * Test that SecurityScanner implements ToolScannerInterface.
     */
    public function testImplementsToolScannerInterface(): void
    {
        $this->assertInstanceOf(ToolScannerInterface::class, $this->scanner);
    }

    /**
     * Test getToolName returns correct slug.
     */
    public function testGetToolName(): void
    {
        $this->assertEquals('security-info', $this->scanner->getToolName());
    }

    /**
     * Test scan() dispatches directory target correctly.
     */
    public function testScanWithDirectoryTarget(): void
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

        $target = ScanTarget::fromDirectory($pluginDir);
        $result = $this->scanner->scan($target);

        $this->assertInstanceOf(SecurityResult::class, $result);
        $this->assertTrue($result->success);
        $this->assertEquals('security@example.com', $result->headerContact);
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
     * Test scanning a non-plugin directory returns no main file.
     */
    public function testScanNonPluginDirectoryReturnsNoMainFile(): void
    {
        $emptyDir = $this->testDir . '/not-a-plugin';
        mkdir($emptyDir);

        file_put_contents($emptyDir . '/readme.txt', 'Not a plugin');

        $result = $this->scanner->scanDirectory($emptyDir);

        $this->assertTrue($result->success);
        $this->assertNull($result->headerContact);
        $this->assertNull($result->packageType);
        $this->assertContains('Could not identify the main plugin file', $result->issues);
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
     * Test plugin with docblock before the real plugin header (like Akismet).
     */
    public function testPluginWithDocblockBeforeHeader(): void
    {
        $pluginDir = $this->testDir . '/my-plugin';
        mkdir($pluginDir);

        file_put_contents($pluginDir . '/my-plugin.php', <<<'PHP'
<?php
/**
 * @package MyPlugin
 */
/*
Plugin Name: My Plugin
Security: security@example.com
*/
PHP);

        $result = $this->scanner->scanDirectory($pluginDir);

        $this->assertTrue($result->success);
        $this->assertEquals('security@example.com', $result->headerContact);
    }

    // -------------------------------------------------------
    // readme.txt integration tests
    // -------------------------------------------------------

    /**
     * Test that readme.txt security section with email is extracted.
     */
    public function testReadmeSecuritySectionWithEmail(): void
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

        file_put_contents($pluginDir . '/readme.txt', <<<'TXT'
=== My Plugin ===
Contributors: johndoe
Tags: test
Requires at least: 5.0
Tested up to: 6.4
Stable tag: 1.0
License: GPLv2

A test plugin.

== Description ==
Full description here.

== Security ==
To report a vulnerability, email security@example.com responsibly.
TXT);

        $result = $this->scanner->scanDirectory($pluginDir);

        $this->assertTrue($result->hasReadmeSecuritySection());
        $this->assertEquals('security@example.com', $result->readmeSecurityContact);
    }

    /**
     * Test that hasSecurityInfo is true when only readme.txt has security section.
     */
    public function testHasSecurityInfoFromReadmeOnly(): void
    {
        $pluginDir = $this->testDir . '/my-plugin';
        mkdir($pluginDir);

        file_put_contents($pluginDir . '/my-plugin.php', <<<'PHP'
<?php
/**
 * Plugin Name: My Plugin
 */
PHP);

        file_put_contents($pluginDir . '/readme.txt', <<<'TXT'
=== My Plugin ===
Contributors: johndoe
Tags: test
Requires at least: 5.0
Tested up to: 6.4
Stable tag: 1.0
License: GPLv2

A test plugin.

== Description ==
Full description here.

== Security ==
Report issues to security@example.com
TXT);

        $result = $this->scanner->scanDirectory($pluginDir);

        $this->assertTrue($result->hasSecurityInfo());
        $this->assertTrue($result->hasReadmeSecuritySection());
    }

    /**
     * Test readme.txt security contact included in consistency check.
     */
    public function testReadmeSecurityConsistencyWithHeader(): void
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

        file_put_contents($pluginDir . '/readme.txt', <<<'TXT'
=== My Plugin ===
Contributors: johndoe
Tags: test
Requires at least: 5.0
Tested up to: 6.4
Stable tag: 1.0
License: GPLv2

A test plugin.

== Description ==
Full description here.

== Security ==
Contact security@example.com to report vulnerabilities.
TXT);

        $result = $this->scanner->scanDirectory($pluginDir);

        $this->assertTrue($result->isConsistent);
    }

    /**
     * Test readme.txt security contact inconsistency with header.
     */
    public function testReadmeSecurityInconsistencyWithHeader(): void
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

        file_put_contents($pluginDir . '/readme.txt', <<<'TXT'
=== My Plugin ===
Contributors: johndoe
Tags: test
Requires at least: 5.0
Tested up to: 6.4
Stable tag: 1.0
License: GPLv2

A test plugin.

== Description ==
Full description here.

== Security ==
Contact different@other.com to report vulnerabilities.
TXT);

        $result = $this->scanner->scanDirectory($pluginDir);

        $this->assertFalse($result->isConsistent);
    }

    /**
     * Test no readme.txt security section results in null contact.
     */
    public function testNoReadmeSecuritySection(): void
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

        file_put_contents($pluginDir . '/readme.txt', <<<'TXT'
=== My Plugin ===
Contributors: johndoe
Tags: test
Requires at least: 5.0
Tested up to: 6.4
Stable tag: 1.0
License: GPLv2

A test plugin.

== Description ==
Full description here.
TXT);

        $result = $this->scanner->scanDirectory($pluginDir);

        $this->assertFalse($result->hasReadmeSecuritySection());
        $this->assertNull($result->readmeSecurityContact);
    }

    /**
     * Test readme security contact in getData output.
     */
    public function testReadmeSecurityFieldsInGetData(): void
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

        file_put_contents($pluginDir . '/readme.txt', <<<'TXT'
=== My Plugin ===
Contributors: johndoe
Tags: test
Requires at least: 5.0
Tested up to: 6.4
Stable tag: 1.0
License: GPLv2

A test plugin.

== Description ==
Full description here.

== Security ==
Report to security@example.com
TXT);

        $result = $this->scanner->scanDirectory($pluginDir);
        $data = $result->getData();

        $this->assertArrayHasKey('readme_txt', $data['files']);
        $this->assertTrue($data['files']['readme_txt']['has_security_section']);
        $this->assertEquals('security@example.com', $data['files']['readme_txt']['contact']);
    }

    /**
     * Test getPrimaryContact falls through to readme contact.
     */
    public function testGetPrimaryContactFallsToReadme(): void
    {
        $pluginDir = $this->testDir . '/my-plugin';
        mkdir($pluginDir);

        file_put_contents($pluginDir . '/my-plugin.php', <<<'PHP'
<?php
/**
 * Plugin Name: My Plugin
 */
PHP);

        file_put_contents($pluginDir . '/readme.txt', <<<'TXT'
=== My Plugin ===
Contributors: johndoe
Tags: test
Requires at least: 5.0
Tested up to: 6.4
Stable tag: 1.0
License: GPLv2

A test plugin.

== Description ==
Full description here.

== Security ==
Report to readme-security@example.com
TXT);

        $result = $this->scanner->scanDirectory($pluginDir);

        $this->assertEquals('readme-security@example.com', $result->getPrimaryContact());
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
