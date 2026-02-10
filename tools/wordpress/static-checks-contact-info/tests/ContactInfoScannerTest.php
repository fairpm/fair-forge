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
 * Tests for the ContactInfoScanner class.
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
 * Author URI: https://example.com
 * Support: support@example.com
 */
PHP);

        $target = ScanTarget::fromDirectory($pluginDir);
        $result = $this->scanner->scan($target);

        $this->assertInstanceOf(ContactInfoResult::class, $result);
        $this->assertTrue($result->success);
        $this->assertEquals('John Doe', $result->publisherName);
        $this->assertEquals('https://example.com', $result->publisherUri);
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
     * Test scanning a plugin with all contact headers.
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
 * Author URI: https://johndoe.com
 * Plugin URI: https://example.com/my-plugin
 * Support: support@example.com
 */
PHP);

        $result = $this->scanner->scanDirectory($pluginDir);

        $this->assertTrue($result->success);
        $this->assertEquals('John Doe', $result->publisherName);
        $this->assertEquals('https://johndoe.com', $result->publisherUri);
        $this->assertEquals('https://example.com/my-plugin', $result->projectUri);
        $this->assertEquals('support@example.com', $result->supportHeaderContact);
        $this->assertEquals('my-plugin.php', $result->headerFile);
        $this->assertEquals('plugin', $result->packageType);
    }

    /**
     * Test scanning a plugin with support URL header.
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
    }

    /**
     * Test scanning a plugin without any contact headers.
     */
    public function testScanPluginWithoutContactHeaders(): void
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
        $this->assertNull($result->supportHeaderContact);
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
 * Support: jane@example.com
 */
PHP);

        $result = $this->scanner->scanDirectory($pluginDir);

        $this->assertTrue($result->success);
        $this->assertEquals('Jane Doe', $result->publisherName);
        $this->assertTrue($result->hasEmail());
        $this->assertTrue($result->passes());
    }

    /**
     * Test scanning a theme with contact headers.
     */
    public function testScanThemeWithContactHeaders(): void
    {
        $themeDir = $this->testDir . '/my-theme';
        mkdir($themeDir);

        file_put_contents($themeDir . '/style.css', <<<'CSS'
/*
Theme Name: My Theme
Description: A test theme
Author: Theme Author
Author URI: https://themeauthor.com
Theme URI: https://example.com/my-theme
Support: support@themeauthor.com
*/
CSS);

        $result = $this->scanner->scanDirectory($themeDir);

        $this->assertTrue($result->success);
        $this->assertEquals('Theme Author', $result->publisherName);
        $this->assertEquals('https://themeauthor.com', $result->publisherUri);
        $this->assertEquals('https://example.com/my-theme', $result->projectUri);
        $this->assertEquals('support@themeauthor.com', $result->supportHeaderContact);
        $this->assertEquals('theme', $result->packageType);
    }

    /**
     * Test scanning with SUPPORT.md file.
     */
    public function testScanWithSupportMd(): void
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
        $this->assertTrue($result->hasSupportMd);
        $this->assertEquals('support@example.com', $result->supportMdContact);
        $this->assertTrue($result->isConsistent);
    }

    /**
     * Test scanning with inconsistent support contacts.
     */
    public function testScanWithInconsistentSupportContacts(): void
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
 * Author URI: https://example.com
 */
PHP);

        $result = $this->scanner->scanDirectory($extractDir);

        $this->assertTrue($result->success);
        $this->assertEquals('John Doe', $result->publisherName);
        $this->assertEquals('https://example.com', $result->publisherUri);
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
 * Author URI: https://main.example.com
 */
PHP);

        // Another plugin file
        file_put_contents($pluginDir . '/other.php', <<<'PHP'
<?php
/**
 * Plugin Name: Other
 * Author: Other Author
 * Author URI: https://other.example.com
 */
PHP);

        $result = $this->scanner->scanDirectory($pluginDir);

        $this->assertEquals('Main Author', $result->publisherName);
        $this->assertEquals('https://main.example.com', $result->publisherUri);
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
     * Test scanning theme with Theme URI.
     */
    public function testScanThemeWithThemeUri(): void
    {
        $themeDir = $this->testDir . '/my-theme';
        mkdir($themeDir);

        file_put_contents($themeDir . '/style.css', <<<'CSS'
/*
Theme Name: My Theme
Theme URI: https://example.com/my-theme
Author: Theme Dev
*/
CSS);

        $result = $this->scanner->scanDirectory($themeDir);

        $this->assertEquals('https://example.com/my-theme', $result->projectUri);
        $this->assertEquals('Theme Dev', $result->publisherName);
        $this->assertEquals('theme', $result->packageType);
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
Author URI: https://janedoe.com
Support: support@janedoe.com
*/
PHP);

        $result = $this->scanner->scanDirectory($pluginDir);

        $this->assertTrue($result->success);
        $this->assertEquals('Jane Doe', $result->publisherName);
        $this->assertEquals('https://janedoe.com', $result->publisherUri);
        $this->assertEquals('https://example.com/my-plugin', $result->projectUri);
        $this->assertEquals('support@janedoe.com', $result->supportHeaderContact);
    }

    /**
     * Test has no contact info when nothing is present.
     */
    public function testHasNoContactInfo(): void
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
        $this->assertFalse($result->hasSupportInfo());
        $this->assertFalse($result->hasContactInfo());
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
