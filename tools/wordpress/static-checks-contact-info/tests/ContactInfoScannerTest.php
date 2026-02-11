<?php

declare(strict_types=1);

namespace FairForge\Tools\ContactInfo\Tests;

use FairForge\Shared\ScanTarget;
use FairForge\Shared\ToolScannerInterface;
use FairForge\Shared\ZipHandler;
use FairForge\Tools\ContactInfo\ContactInfoResult;
use FairForge\Tools\ContactInfo\ContactInfoScanner;
use PHPUnit\Framework\TestCase;

/**
 * Tests for the ContactInfoScanner class (publisher contact only).
 */
class ContactInfoScannerTest extends TestCase
{
    private ContactInfoScanner $scanner;
    private string $testDir;

    protected function setUp(): void
    {
        $this->scanner = new ContactInfoScanner();
        $this->testDir = sys_get_temp_dir() . '/contact-info-scanner-test-' . uniqid();
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
     * Test that ContactInfoScanner implements ToolScannerInterface.
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
        $this->assertEquals('contact-info', $this->scanner->getToolName());
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
 * Author URI: mailto:john@example.com
 */
PHP);

        $target = ScanTarget::fromDirectory($pluginDir);
        $result = $this->scanner->scan($target);

        $this->assertInstanceOf(ContactInfoResult::class, $result);
        $this->assertTrue($result->success);
        $this->assertEquals('John Doe', $result->publisherName);
        $this->assertEquals('mailto:john@example.com', $result->publisherUri);
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
     * Test scanning a plugin with all publisher headers.
     */
    public function testScanPluginWithAllHeaders(): void
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
 * Author URI: mailto:john@johndoe.com
 * Plugin URI: https://example.com/my-plugin
 */
PHP);

        $result = $this->scanner->scanDirectory($pluginDir);

        $this->assertTrue($result->success);
        $this->assertEquals('John Doe', $result->publisherName);
        $this->assertEquals('mailto:john@johndoe.com', $result->publisherUri);
        $this->assertEquals('https://example.com/my-plugin', $result->projectUri);
        $this->assertEquals('my-plugin.php', $result->headerFile);
        $this->assertEquals('plugin', $result->packageType);
    }

    /**
     * Test scanning a plugin without any publisher headers.
     */
    public function testScanPluginWithoutPublisherHeaders(): void
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
        $this->assertNull($result->publisherName);
        $this->assertNull($result->publisherUri);
        $this->assertFalse($result->passes());
        $this->assertTrue($result->hasIssues());
    }

    /**
     * Test scanning a plugin with just Author (publisher name only, no email).
     */
    public function testScanPluginWithAuthorOnlyNoEmail(): void
    {
        $pluginDir = $this->testDir . '/my-plugin';
        mkdir($pluginDir);

        file_put_contents($pluginDir . '/my-plugin.php', <<<'PHP'
<?php
/**
 * Plugin Name: My Plugin
 * Author: Jane Doe
 */
PHP);

        $result = $this->scanner->scanDirectory($pluginDir);

        $this->assertTrue($result->success);
        $this->assertEquals('Jane Doe', $result->publisherName);
        $this->assertNull($result->publisherUri);
        $this->assertTrue($result->hasPublisherInfo());
        $this->assertFalse($result->hasEmail());
        $this->assertFalse($result->passes());
    }

    /**
     * Test scanning a plugin with Author and email passes.
     */
    public function testScanPluginWithAuthorAndEmailPasses(): void
    {
        $pluginDir = $this->testDir . '/my-plugin';
        mkdir($pluginDir);

        file_put_contents($pluginDir . '/my-plugin.php', <<<'PHP'
<?php
/**
 * Plugin Name: My Plugin
 * Author: Jane Doe
 * Author URI: mailto:jane@example.com
 */
PHP);

        $result = $this->scanner->scanDirectory($pluginDir);

        $this->assertTrue($result->success);
        $this->assertEquals('Jane Doe', $result->publisherName);
        $this->assertTrue($result->hasEmail());
        $this->assertTrue($result->passes());
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
 * Author URI: mailto:john@example.com
 */
PHP);

        $result = $this->scanner->scanDirectory($extractDir);

        $this->assertTrue($result->success);
        $this->assertEquals('John Doe', $result->publisherName);
        $this->assertEquals('mailto:john@example.com', $result->publisherUri);
    }

    /**
     * Test scanning returns correct result instance.
     */
    public function testScanReturnsContactInfoResult(): void
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

        $this->assertInstanceOf(ContactInfoResult::class, $result);
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
 * Author: Main Author
 * Author URI: mailto:main@example.com
 */
PHP);

        // Another plugin file
        file_put_contents($pluginDir . '/other.php', <<<'PHP'
<?php
/**
 * Plugin Name: Other
 * Author: Other Author
 * Author URI: mailto:other@example.com
 */
PHP);

        $result = $this->scanner->scanDirectory($pluginDir);

        $this->assertEquals('Main Author', $result->publisherName);
        $this->assertEquals('mailto:main@example.com', $result->publisherUri);
        $this->assertEquals('my-plugin.php', $result->headerFile);
    }

    /**
     * Test scanning plugin with Plugin URI.
     */
    public function testScanPluginWithPluginUri(): void
    {
        $pluginDir = $this->testDir . '/my-plugin';
        mkdir($pluginDir);

        file_put_contents($pluginDir . '/my-plugin.php', <<<'PHP'
<?php
/**
 * Plugin Name: My Plugin
 * Plugin URI: https://example.com/my-plugin
 * Author: John Doe
 */
PHP);

        $result = $this->scanner->scanDirectory($pluginDir);

        $this->assertEquals('https://example.com/my-plugin', $result->projectUri);
    }


    /**
     * Test publisher info with Author URI only (no email, does not pass).
     */
    public function testPublisherInfoWithUriOnlyNoEmail(): void
    {
        $pluginDir = $this->testDir . '/my-plugin';
        mkdir($pluginDir);

        file_put_contents($pluginDir . '/my-plugin.php', <<<'PHP'
<?php
/**
 * Plugin Name: My Plugin
 * Author URI: https://example.com
 */
PHP);

        $result = $this->scanner->scanDirectory($pluginDir);

        $this->assertTrue($result->success);
        $this->assertNull($result->publisherName);
        $this->assertEquals('https://example.com', $result->publisherUri);
        $this->assertTrue($result->hasPublisherInfo());
        $this->assertFalse($result->hasEmail());
        $this->assertFalse($result->passes());
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
Author URI: mailto:jane@janedoe.com
*/
PHP);

        $result = $this->scanner->scanDirectory($pluginDir);

        $this->assertTrue($result->success);
        $this->assertEquals('Jane Doe', $result->publisherName);
        $this->assertEquals('mailto:jane@janedoe.com', $result->publisherUri);
        $this->assertEquals('https://example.com/my-plugin', $result->projectUri);
    }

    /**
     * Test has no publisher info when nothing is present.
     */
    public function testHasNoPublisherInfo(): void
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

        $this->assertFalse($result->hasPublisherInfo());
    }


    // -------------------------------------------------------
    // readme.txt integration tests
    // -------------------------------------------------------

    /**
     * Test that readme.txt contributors are extracted.
     */
    public function testReadmeContributorsExtracted(): void
    {
        $pluginDir = $this->testDir . '/my-plugin';
        mkdir($pluginDir);

        file_put_contents($pluginDir . '/my-plugin.php', <<<'PHP'
<?php
/**
 * Plugin Name: My Plugin
 * Author: John Doe
 * Author URI: mailto:john@example.com
 */
PHP);

        file_put_contents($pluginDir . '/readme.txt', <<<'TXT'
=== My Plugin ===
Contributors: johndoe, janedoe
Donate link: https://example.com/donate
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

        $this->assertTrue($result->hasReadmeContributors());
        $this->assertContains('johndoe', $result->readmeContributors);
        $this->assertContains('janedoe', $result->readmeContributors);
    }

    /**
     * Test that readme.txt donate link is extracted.
     */
    public function testReadmeDonateLinExtracted(): void
    {
        $pluginDir = $this->testDir . '/my-plugin';
        mkdir($pluginDir);

        file_put_contents($pluginDir . '/my-plugin.php', <<<'PHP'
<?php
/**
 * Plugin Name: My Plugin
 * Author: John Doe
 * Author URI: mailto:john@example.com
 */
PHP);

        file_put_contents($pluginDir . '/readme.txt', <<<'TXT'
=== My Plugin ===
Contributors: johndoe
Donate link: https://example.com/donate
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

        $this->assertTrue($result->hasReadmeDonateLink());
        $this->assertEquals('https://example.com/donate', $result->readmeDonateLink);
    }

    /**
     * Test that donate link with email address satisfies the email check.
     */
    public function testReadmeDonateLinWithEmailCountsAsEmail(): void
    {
        $pluginDir = $this->testDir . '/my-plugin';
        mkdir($pluginDir);

        file_put_contents($pluginDir . '/my-plugin.php', <<<'PHP'
<?php
/**
 * Plugin Name: My Plugin
 * Author: John Doe
 * Author URI: https://example.com
 */
PHP);

        file_put_contents($pluginDir . '/readme.txt', <<<'TXT'
=== My Plugin ===
Contributors: johndoe
Donate link: mailto:donate@example.com
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

        $this->assertTrue($result->hasEmail());
    }

    /**
     * Test that missing readme.txt contributors generates an issue.
     */
    public function testNoReadmeContributorsGeneratesIssue(): void
    {
        $pluginDir = $this->testDir . '/my-plugin';
        mkdir($pluginDir);

        file_put_contents($pluginDir . '/my-plugin.php', <<<'PHP'
<?php
/**
 * Plugin Name: My Plugin
 * Author: John Doe
 * Author URI: mailto:john@example.com
 */
PHP);

        // No readme.txt at all
        $result = $this->scanner->scanDirectory($pluginDir);

        $this->assertFalse($result->hasReadmeContributors());
        $this->assertContains('No contributors listed in readme.txt', $result->issues);
    }

    /**
     * Test that having readme.txt contributors avoids that issue.
     */
    public function testReadmeContributorsPresentNoIssue(): void
    {
        $pluginDir = $this->testDir . '/my-plugin';
        mkdir($pluginDir);

        file_put_contents($pluginDir . '/my-plugin.php', <<<'PHP'
<?php
/**
 * Plugin Name: My Plugin
 * Author: John Doe
 * Author URI: mailto:john@example.com
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

        $this->assertTrue($result->hasReadmeContributors());
        $this->assertNotContains('No contributors listed in readme.txt', $result->issues);
    }

    /**
     * Test that readme fields appear in getData output.
     */
    public function testReadmeFieldsInGetData(): void
    {
        $pluginDir = $this->testDir . '/my-plugin';
        mkdir($pluginDir);

        file_put_contents($pluginDir . '/my-plugin.php', <<<'PHP'
<?php
/**
 * Plugin Name: My Plugin
 * Author: John Doe
 * Author URI: mailto:john@example.com
 */
PHP);

        file_put_contents($pluginDir . '/readme.txt', <<<'TXT'
=== My Plugin ===
Contributors: johndoe, janedoe
Donate link: https://example.com/donate
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
        $data = $result->getData();

        $this->assertArrayHasKey('readme', $data);
        $this->assertArrayHasKey('contributors', $data['readme']);
        $this->assertArrayHasKey('donate_link', $data['readme']);
        $this->assertContains('johndoe', $data['readme']['contributors']);
        $this->assertEquals('https://example.com/donate', $data['readme']['donate_link']);
    }

    /**
     * Test that readme fields appear in getSummary output.
     */
    public function testReadmeFieldsInGetSummary(): void
    {
        $pluginDir = $this->testDir . '/my-plugin';
        mkdir($pluginDir);

        file_put_contents($pluginDir . '/my-plugin.php', <<<'PHP'
<?php
/**
 * Plugin Name: My Plugin
 * Author: John Doe
 * Author URI: mailto:john@example.com
 */
PHP);

        file_put_contents($pluginDir . '/readme.txt', <<<'TXT'
=== My Plugin ===
Contributors: johndoe
Donate link: https://example.com/donate
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
        $summary = $result->getSummary();

        $this->assertArrayHasKey('has_readme_contributors', $summary);
        $this->assertArrayHasKey('has_readme_donate_link', $summary);
        $this->assertTrue($summary['has_readme_contributors']);
        $this->assertTrue($summary['has_readme_donate_link']);
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
