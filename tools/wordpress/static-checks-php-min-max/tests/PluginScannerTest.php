<?php

declare(strict_types=1);

namespace FairForge\Tools\WordPress\PluginStaticChecks\Tests;

use FairForge\Tools\WordPress\PluginStaticChecks\PluginScanner;
use FairForge\Tools\WordPress\PluginStaticChecks\ScanResult;
use FairForge\Tools\WordPress\PluginStaticChecks\ZipHandler;
use PHPUnit\Framework\TestCase;
use RuntimeException;

/**
 * Tests for the PluginScanner class.
 *
 * These tests verify the WordPress plugin scanner functionality including
 * configuration, ZIP handling integration, and directory scanning.
 */
class PluginScannerTest extends TestCase
{
    private PluginScanner $scanner;

    /**
     * Set up test fixtures.
     *
     * Creates a new PluginScanner instance for each test.
     */
    protected function setUp(): void
    {
        $this->scanner = new PluginScanner();
    }

    /**
     * Test that the default PHPCS standard is 'WordPress'.
     */
    public function testDefaultStandardIsWordPress(): void
    {
        $this->assertEquals('WordPress', $this->scanner->getStandard());
    }

    /**
     * Test that a custom PHPCS standard can be set.
     */
    public function testSetStandard(): void
    {
        $this->scanner->setStandard('WordPress-Core');
        $this->assertEquals('WordPress-Core', $this->scanner->getStandard());
    }

    /**
     * Test that setStandard returns self for method chaining.
     */
    public function testSetStandardReturnsSelf(): void
    {
        $result = $this->scanner->setStandard('WordPress');
        $this->assertSame($this->scanner, $result);
    }

    /**
     * Test that the default extensions list contains only 'php'.
     */
    public function testDefaultExtensionsIsPhp(): void
    {
        $extensions = $this->scanner->getExtensions();
        $this->assertEquals(['php'], $extensions);
    }

    /**
     * Test that custom file extensions can be set.
     */
    public function testSetExtensions(): void
    {
        $this->scanner->setExtensions(['php', 'inc', 'module']);
        $extensions = $this->scanner->getExtensions();
        $this->assertEquals(['php', 'inc', 'module'], $extensions);
    }

    /**
     * Test that setExtensions returns self for method chaining.
     */
    public function testSetExtensionsReturnsSelf(): void
    {
        $result = $this->scanner->setExtensions(['php']);
        $this->assertSame($this->scanner, $result);
    }

    /**
     * Test that warnings are included by default.
     */
    public function testDefaultIncludeWarningsIsTrue(): void
    {
        $this->assertTrue($this->scanner->getIncludeWarnings());
    }

    /**
     * Test that warning inclusion can be toggled on and off.
     */
    public function testSetIncludeWarnings(): void
    {
        $this->scanner->setIncludeWarnings(false);
        $this->assertFalse($this->scanner->getIncludeWarnings());

        $this->scanner->setIncludeWarnings(true);
        $this->assertTrue($this->scanner->getIncludeWarnings());
    }

    /**
     * Test that setIncludeWarnings returns self for method chaining.
     */
    public function testSetIncludeWarningsReturnsSelf(): void
    {
        $result = $this->scanner->setIncludeWarnings(false);
        $this->assertSame($this->scanner, $result);
    }

    /**
     * Test that the default severity level is 1 (minimum).
     */
    public function testDefaultSeverityIsOne(): void
    {
        $this->assertEquals(1, $this->scanner->getSeverity());
    }

    /**
     * Test that a custom severity level can be set.
     */
    public function testSetSeverity(): void
    {
        $this->scanner->setSeverity(5);
        $this->assertEquals(5, $this->scanner->getSeverity());
    }

    /**
     * Test that severity values below 1 are clamped to 1.
     */
    public function testSetSeverityClampsToMinimum(): void
    {
        $this->scanner->setSeverity(0);
        $this->assertEquals(1, $this->scanner->getSeverity());

        $this->scanner->setSeverity(-5);
        $this->assertEquals(1, $this->scanner->getSeverity());
    }

    /**
     * Test that severity values above 10 are clamped to 10.
     */
    public function testSetSeverityClampsToMaximum(): void
    {
        $this->scanner->setSeverity(15);
        $this->assertEquals(10, $this->scanner->getSeverity());
    }

    /**
     * Test that setSeverity returns self for method chaining.
     */
    public function testSetSeverityReturnsSelf(): void
    {
        $result = $this->scanner->setSeverity(5);
        $this->assertSame($this->scanner, $result);
    }

    /**
     * Test that setAdditionalArgs returns self for method chaining.
     */
    public function testSetAdditionalArgsReturnsSelf(): void
    {
        $result = $this->scanner->setAdditionalArgs(['--tab-width=4']);
        $this->assertSame($this->scanner, $result);
    }

    /**
     * Test that getZipHandler returns a ZipHandler instance.
     */
    public function testGetZipHandlerReturnsZipHandler(): void
    {
        $handler = $this->scanner->getZipHandler();
        $this->assertInstanceOf(ZipHandler::class, $handler);
    }

    /**
     * Test that a custom ZipHandler can be injected via constructor.
     */
    public function testConstructorAcceptsCustomZipHandler(): void
    {
        $customHandler = new ZipHandler();
        $customHandler->setSslVerify(false);

        $scanner = new PluginScanner($customHandler);

        $this->assertSame($customHandler, $scanner->getZipHandler());
        $this->assertFalse($scanner->getSslVerify());
    }

    /**
     * Test that setSslVerify delegates to the ZipHandler.
     */
    public function testSetSslVerifyDelegatesToZipHandler(): void
    {
        $this->scanner->setSslVerify(false);
        $this->assertFalse($this->scanner->getZipHandler()->getSslVerify());

        $this->scanner->setSslVerify(true);
        $this->assertTrue($this->scanner->getZipHandler()->getSslVerify());
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
     * Test that scanDirectory throws RuntimeException for non-existent directories.
     */
    public function testScanDirectoryThrowsForNonExistentDirectory(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Directory not found');

        $this->scanner->scanDirectory('/nonexistent/directory');
    }

    /**
     * Test that scanFromZipFile throws RuntimeException for non-existent ZIP files.
     */
    public function testScanFromZipFileThrowsForNonExistentFile(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('ZIP file not found');

        $this->scanner->scanFromZipFile('/nonexistent/file.zip');
    }

    /**
     * Test that scanDirectory returns a ScanResult for valid directories.
     */
    public function testScanDirectoryReturnsScanResult(): void
    {
        // Create a temporary directory with a PHP file
        $tempDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'scanner_test_' . uniqid();
        mkdir($tempDir, 0o755, true);
        file_put_contents($tempDir . '/test.php', '<?php echo "Hello";');

        try {
            $result = $this->scanner->scanDirectory($tempDir);

            $this->assertInstanceOf(ScanResult::class, $result);
            $this->assertTrue($result->success);
        } finally {
            // Clean up
            @unlink($tempDir . '/test.php');
            @rmdir($tempDir);
        }
    }

    /**
     * Test that scanning PHP code with violations produces issues in the result.
     */
    public function testScanDirectoryWithValidPhpFileProducesResults(): void
    {
        // Create a temporary directory with a PHP file that has issues
        $tempDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'scanner_test_' . uniqid();
        mkdir($tempDir, 0o755, true);

        // Write PHP code that violates WordPress standards
        $phpCode = <<<'PHP'
            <?php
            function test_func($a,$b){
            echo $a;
            }
            PHP;
        file_put_contents($tempDir . '/test.php', $phpCode);

        try {
            $result = $this->scanner->scanDirectory($tempDir);

            $this->assertInstanceOf(ScanResult::class, $result);
            $this->assertTrue($result->success);
            // The code should have some issues
            $this->assertTrue($result->hasIssues());
        } finally {
            // Clean up
            @unlink($tempDir . '/test.php');
            @rmdir($tempDir);
        }
    }
}
