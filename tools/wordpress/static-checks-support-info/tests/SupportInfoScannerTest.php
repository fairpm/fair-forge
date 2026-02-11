<?php

declare(strict_types=1);

namespace FairForge\Tools\SupportInfo\Tests;

use FairForge\Shared\ScanTarget;
use FairForge\Shared\ToolScannerInterface;
use FairForge\Shared\ZipHandler;
use FairForge\Tools\SupportInfo\SupportInfoResult;
use FairForge\Tools\SupportInfo\SupportInfoScanner;
use PHPUnit\Framework\TestCase;

/**
 * Tests for the SupportInfoScanner class.
 */
class SupportInfoScannerTest extends TestCase
{
    private SupportInfoScanner $scanner;
    private string $testDir;

    protected function setUp(): void
    {
        $this->scanner = new SupportInfoScanner();
        $this->testDir = sys_get_temp_dir() . '/support-info-scanner-test-' . uniqid();
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
     * Test that SupportInfoScanner implements ToolScannerInterface.
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
        $this->assertEquals('support-info', $this->scanner->getToolName());
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
 * Author: John Doe
 * Support: support@example.com
 */
PHP);

        $target = ScanTarget::fromDirectory($pluginDir);
        $result = $this->scanner->scan($target);

        $this->assertInstanceOf(SupportInfoResult::class, $result);
        $this->assertTrue($result->success);
        $this->assertEquals('support@example.com', $result->supportHeaderContact);
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
     * Test scanning a plugin with Support email header.
     */
    public function testScanPluginWithSupportEmailHeader(): void
    {
        $pluginDir = $this->testDir . '/my-plugin';
        mkdir($pluginDir);

        file_put_contents($pluginDir . '/my-plugin.php', <<<'PHP'
<?php
/**
 * Plugin Name: My Plugin
 * Description: A test plugin
 * Version: 1.0.0
 * Author: John Doe
 * Support: support@example.com
 */
PHP);

        $result = $this->scanner->scanDirectory($pluginDir);

        $this->assertTrue($result->success);
        $this->assertEquals('support@example.com', $result->supportHeaderContact);
        $this->assertEquals('my-plugin.php', $result->headerFile);
        $this->assertEquals('plugin', $result->packageType);
        $this->assertTrue($result->hasSupportHeader());
        $this->assertTrue($result->hasEmail());
        $this->assertTrue($result->passes());
    }

    /**
     * Test scanning a plugin with Support URL header.
     */
    public function testScanPluginWithSupportUrlHeader(): void
    {
        $pluginDir = $this->testDir . '/my-plugin';
        mkdir($pluginDir);

        file_put_contents($pluginDir . '/my-plugin.php', <<<'PHP'
<?php
/**
 * Plugin Name: My Plugin
 * Author: John Doe
 * Support: https://example.com/support
 */
PHP);

        $result = $this->scanner->scanDirectory($pluginDir);

        $this->assertTrue($result->success);
        $this->assertEquals('https://example.com/support', $result->supportHeaderContact);
        $this->assertTrue($result->hasSupportHeader());
        $this->assertFalse($result->hasEmail());
        $this->assertFalse($result->passes());
    }

    /**
     * Test scanning a plugin without Support header.
     */
    public function testScanPluginWithoutSupportHeader(): void
    {
        $pluginDir = $this->testDir . '/my-plugin';
        mkdir($pluginDir);

        file_put_contents($pluginDir . '/my-plugin.php', <<<'PHP'
<?php
/**
 * Plugin Name: My Plugin
 * Description: A test plugin
 * Author: John Doe
 */
PHP);

        $result = $this->scanner->scanDirectory($pluginDir);

        $this->assertTrue($result->success);
        $this->assertNull($result->supportHeaderContact);
        $this->assertFalse($result->hasSupportHeader());
        $this->assertFalse($result->passes());
        $this->assertTrue($result->hasIssues());
    }

    /**
     * Test scanning a theme with Support header.
     */
    public function testScanNonPluginDirectoryReturnsNoMainFile(): void
    {
        $emptyDir = $this->testDir . '/not-a-plugin';
        mkdir($emptyDir);

        file_put_contents($emptyDir . '/readme.txt', 'Not a plugin');

        $result = $this->scanner->scanDirectory($emptyDir);

        $this->assertTrue($result->success);
        $this->assertNull($result->supportHeaderContact);
        $this->assertNull($result->packageType);
        $this->assertFalse($result->passes());
    }

    /**
     * Test scanning with SUPPORT.md file only.
     */
    public function testScanWithSupportMdOnly(): void
    {
        $pluginDir = $this->testDir . '/my-plugin';
        mkdir($pluginDir);

        file_put_contents($pluginDir . '/my-plugin.php', <<<'PHP'
<?php
/**
 * Plugin Name: My Plugin
 * Author: John Doe
 */
PHP);

        file_put_contents($pluginDir . '/SUPPORT.md', <<<'MD'
# Support

For help with this plugin, please contact support@example.com.
MD);

        $result = $this->scanner->scanDirectory($pluginDir);

        $this->assertTrue($result->success);
        $this->assertNull($result->supportHeaderContact);
        $this->assertTrue($result->hasSupportMd);
        $this->assertEquals('support@example.com', $result->supportMdContact);
        $this->assertTrue($result->hasSupportFile());
        $this->assertTrue($result->hasSupportInfo());
        // Does not pass because no support header
        $this->assertFalse($result->passes());
    }

    /**
     * Test scanning with both Support header and SUPPORT.md (consistent).
     */
    public function testScanWithConsistentSupportSources(): void
    {
        $pluginDir = $this->testDir . '/my-plugin';
        mkdir($pluginDir);

        file_put_contents($pluginDir . '/my-plugin.php', <<<'PHP'
<?php
/**
 * Plugin Name: My Plugin
 * Author: John Doe
 * Support: support@example.com
 */
PHP);

        file_put_contents($pluginDir . '/SUPPORT.md', <<<'MD'
# Support

For help with this plugin, please contact support@example.com.
MD);

        $result = $this->scanner->scanDirectory($pluginDir);

        $this->assertTrue($result->success);
        $this->assertEquals('support@example.com', $result->supportHeaderContact);
        $this->assertTrue($result->hasSupportMd);
        $this->assertEquals('support@example.com', $result->supportMdContact);
        $this->assertTrue($result->isConsistent);
        $this->assertTrue($result->passes());
    }

    /**
     * Test scanning with inconsistent support contacts.
     */
    public function testScanWithInconsistentSupportInfos(): void
    {
        $pluginDir = $this->testDir . '/my-plugin';
        mkdir($pluginDir);

        file_put_contents($pluginDir . '/my-plugin.php', <<<'PHP'
<?php
/**
 * Plugin Name: My Plugin
 * Author: John Doe
 * Support: support@example.com
 */
PHP);

        file_put_contents($pluginDir . '/SUPPORT.md', <<<'MD'
# Support

Contact: other@example.com
MD);

        $result = $this->scanner->scanDirectory($pluginDir);

        $this->assertTrue($result->success);
        $this->assertFalse($result->isConsistent);
        $this->assertFalse($result->passes());
        $this->assertTrue($result->hasIssues());
    }

    /**
     * Test SUPPORT.md with URL contact.
     */
    public function testSupportMdWithUrlContact(): void
    {
        $pluginDir = $this->testDir . '/my-plugin';
        mkdir($pluginDir);

        file_put_contents($pluginDir . '/my-plugin.php', <<<'PHP'
<?php
/**
 * Plugin Name: My Plugin
 * Author: John Doe
 * Support: https://example.com/support-forum
 */
PHP);

        file_put_contents($pluginDir . '/SUPPORT.md', <<<'MD'
# Support

Get help at https://example.com/support-forum
MD);

        $result = $this->scanner->scanDirectory($pluginDir);

        $this->assertTrue($result->success);
        $this->assertTrue($result->hasSupportMd);
        $this->assertStringContainsString('example.com', $result->supportMdContact ?? '');
        $this->assertTrue($result->isConsistent);
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
 * Author: John Doe
 * Support: support@example.com
 */
PHP);

        file_put_contents($pluginDir . '/SUPPORT.md', <<<'MD'
# Support

Contact: mailto:support@example.com
MD);

        $result = $this->scanner->scanDirectory($pluginDir);

        $this->assertTrue($result->success);
        $this->assertTrue($result->isConsistent);
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
 * Author: John Doe
 * Support: support@example.com
 */
PHP);

        $result = $this->scanner->scanDirectory($extractDir);

        $this->assertTrue($result->success);
        $this->assertEquals('support@example.com', $result->supportHeaderContact);
    }

    /**
     * Test scanning returns correct result instance.
     */
    public function testScanReturnsSupportInfoResult(): void
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

        $this->assertInstanceOf(SupportInfoResult::class, $result);
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
 * Support: main-support@example.com
 */
PHP);

        // Another plugin file
        file_put_contents($pluginDir . '/other.php', <<<'PHP'
<?php
/**
 * Plugin Name: Other
 * Support: other-support@example.com
 */
PHP);

        $result = $this->scanner->scanDirectory($pluginDir);

        $this->assertEquals('main-support@example.com', $result->supportHeaderContact);
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
Plugin URI: https://example.com/my-plugin
Author: Jane Doe
Support: support@janedoe.com
*/
PHP);

        $result = $this->scanner->scanDirectory($pluginDir);

        $this->assertTrue($result->success);
        $this->assertEquals('support@janedoe.com', $result->supportHeaderContact);
    }

    /**
     * Test SUPPORT.md exists but has no extractable contact.
     */
    public function testSupportMdExistsButNoContact(): void
    {
        $pluginDir = $this->testDir . '/my-plugin';
        mkdir($pluginDir);

        file_put_contents($pluginDir . '/my-plugin.php', <<<'PHP'
<?php
/**
 * Plugin Name: My Plugin
 * Support: support@example.com
 */
PHP);

        file_put_contents($pluginDir . '/SUPPORT.md', <<<'MD'
# Support

Please use the forums for help.
MD);

        $result = $this->scanner->scanDirectory($pluginDir);

        $this->assertTrue($result->success);
        $this->assertTrue($result->hasSupportMd);
        $this->assertNull($result->supportMdContact);
        $this->assertTrue($result->hasIssues());
    }

    /**
     * Test no support info at all.
     */
    public function testNoSupportInfoAtAll(): void
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

        $this->assertFalse($result->hasSupportHeader());
        $this->assertFalse($result->hasSupportFile());
        $this->assertFalse($result->hasSupportInfo());
        $this->assertFalse($result->passes());
    }

    /**
     * Test SUPPORT.md with case-insensitive filename lookup (support.md).
     */
    public function testSupportMdCaseInsensitive(): void
    {
        $pluginDir = $this->testDir . '/my-plugin';
        mkdir($pluginDir);

        file_put_contents($pluginDir . '/my-plugin.php', <<<'PHP'
<?php
/**
 * Plugin Name: My Plugin
 * Support: support@example.com
 */
PHP);

        file_put_contents($pluginDir . '/support.md', <<<'MD'
# Support

Contact: support@example.com
MD);

        $result = $this->scanner->scanDirectory($pluginDir);

        $this->assertTrue($result->hasSupportMd);
    }

    /**
     * Test email detection in Support header with email.
     */
    public function testEmailDetectionInSupportHeader(): void
    {
        $pluginDir = $this->testDir . '/my-plugin';
        mkdir($pluginDir);

        file_put_contents($pluginDir . '/my-plugin.php', <<<'PHP'
<?php
/**
 * Plugin Name: My Plugin
 * Support: help@mycompany.org
 */
PHP);

        $result = $this->scanner->scanDirectory($pluginDir);

        $this->assertTrue($result->hasEmail());
    }

    /**
     * Test email detection in SUPPORT.md contact.
     */
    public function testEmailDetectionInSupportMd(): void
    {
        $pluginDir = $this->testDir . '/my-plugin';
        mkdir($pluginDir);

        file_put_contents($pluginDir . '/my-plugin.php', <<<'PHP'
<?php
/**
 * Plugin Name: My Plugin
 */
PHP);

        file_put_contents($pluginDir . '/SUPPORT.md', <<<'MD'
# Support

Email us at team@plugin-support.co.uk for help.
MD);

        $result = $this->scanner->scanDirectory($pluginDir);

        $this->assertTrue($result->hasEmail());
    }

    /**
     * Test no email when only URLs present.
     */
    public function testNoEmailWithOnlyUrls(): void
    {
        $pluginDir = $this->testDir . '/my-plugin';
        mkdir($pluginDir);

        file_put_contents($pluginDir . '/my-plugin.php', <<<'PHP'
<?php
/**
 * Plugin Name: My Plugin
 * Support: https://example.com/support
 */
PHP);

        $result = $this->scanner->scanDirectory($pluginDir);

        $this->assertFalse($result->hasEmail());
    }

    // -------------------------------------------------------
    // readme.txt integration tests
    // -------------------------------------------------------

    /**
     * Test that readme.txt support section with email is extracted.
     */
    public function testReadmeSupportSectionWithEmail(): void
    {
        $pluginDir = $this->testDir . '/my-plugin';
        mkdir($pluginDir);

        file_put_contents($pluginDir . '/my-plugin.php', <<<'PHP'
<?php
/**
 * Plugin Name: My Plugin
 * Support: support@example.com
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

== Support ==
For support requests, email support@example.com or visit our forums.
TXT);

        $result = $this->scanner->scanDirectory($pluginDir);

        $this->assertTrue($result->hasReadmeSupportSection());
        $this->assertEquals('support@example.com', $result->readmeSupportContact);
    }

    /**
     * Test that readme.txt support section with URL is extracted.
     */
    public function testReadmeSupportSectionWithUrl(): void
    {
        $pluginDir = $this->testDir . '/my-plugin';
        mkdir($pluginDir);

        file_put_contents($pluginDir . '/my-plugin.php', <<<'PHP'
<?php
/**
 * Plugin Name: My Plugin
 * Support: https://example.com/support
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

== Support ==
Visit https://example.com/support for help.
TXT);

        $result = $this->scanner->scanDirectory($pluginDir);

        $this->assertTrue($result->hasReadmeSupportSection());
        $this->assertEquals('https://example.com/support', $result->readmeSupportContact);
    }

    /**
     * Test that hasSupportInfo is true when only readme.txt has support section.
     */
    public function testHasSupportInfoFromReadmeOnly(): void
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

== Support ==
For support email help@example.com
TXT);

        $result = $this->scanner->scanDirectory($pluginDir);

        $this->assertTrue($result->hasSupportInfo());
        $this->assertTrue($result->hasReadmeSupportSection());
        $this->assertEquals('help@example.com', $result->readmeSupportContact);
    }

    /**
     * Test readme.txt support contact included in consistency check.
     */
    public function testReadmeSupportConsistencyWithHeader(): void
    {
        $pluginDir = $this->testDir . '/my-plugin';
        mkdir($pluginDir);

        file_put_contents($pluginDir . '/my-plugin.php', <<<'PHP'
<?php
/**
 * Plugin Name: My Plugin
 * Support: support@example.com
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

== Support ==
Contact support@example.com for help.
TXT);

        $result = $this->scanner->scanDirectory($pluginDir);

        $this->assertTrue($result->isConsistent);
    }

    /**
     * Test readme.txt support contact inconsistency with header.
     */
    public function testReadmeSupportInconsistencyWithHeader(): void
    {
        $pluginDir = $this->testDir . '/my-plugin';
        mkdir($pluginDir);

        file_put_contents($pluginDir . '/my-plugin.php', <<<'PHP'
<?php
/**
 * Plugin Name: My Plugin
 * Support: support@example.com
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

== Support ==
Contact different@other.com for help.
TXT);

        $result = $this->scanner->scanDirectory($pluginDir);

        $this->assertFalse($result->isConsistent);
    }

    /**
     * Test no readme.txt support section results in null contact.
     */
    public function testNoReadmeSupportSection(): void
    {
        $pluginDir = $this->testDir . '/my-plugin';
        mkdir($pluginDir);

        file_put_contents($pluginDir . '/my-plugin.php', <<<'PHP'
<?php
/**
 * Plugin Name: My Plugin
 * Support: support@example.com
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

        $this->assertFalse($result->hasReadmeSupportSection());
        $this->assertNull($result->readmeSupportContact);
    }

    /**
     * Test readme support contact in getData output.
     */
    public function testReadmeSupportFieldsInGetData(): void
    {
        $pluginDir = $this->testDir . '/my-plugin';
        mkdir($pluginDir);

        file_put_contents($pluginDir . '/my-plugin.php', <<<'PHP'
<?php
/**
 * Plugin Name: My Plugin
 * Support: support@example.com
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

== Support ==
Email support@example.com for help.
TXT);

        $result = $this->scanner->scanDirectory($pluginDir);
        $data = $result->getData();

        $this->assertArrayHasKey('readme_txt', $data['support']);
        $this->assertTrue($data['support']['readme_txt']['has_support_section']);
        $this->assertEquals('support@example.com', $data['support']['readme_txt']['contact']);
    }

    /**
     * Test getPrimarySupportInfo falls through to readme contact.
     */
    public function testGetPrimarySupportInfoFallsToReadme(): void
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

== Support ==
Contact readme-support@example.com for help.
TXT);

        $result = $this->scanner->scanDirectory($pluginDir);

        $this->assertEquals('readme-support@example.com', $result->getPrimarySupportInfo());
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
