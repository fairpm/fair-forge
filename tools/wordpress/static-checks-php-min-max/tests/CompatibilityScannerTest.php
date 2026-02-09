<?php

declare(strict_types=1);

namespace FairForge\Tools\PhpMinMax\Tests;

use FairForge\Shared\ScanTarget;
use FairForge\Shared\ToolScannerInterface;
use FairForge\Shared\ZipHandler;
use FairForge\Tools\PhpMinMax\CompatibilityResult;
use FairForge\Tools\PhpMinMax\CompatibilityScanner;
use PHPUnit\Framework\TestCase;
use RuntimeException;

/**
 * Tests for the CompatibilityScanner class.
 */
class CompatibilityScannerTest extends TestCase
{
    private CompatibilityScanner $scanner;

    protected function setUp(): void
    {
        $this->scanner = new CompatibilityScanner();
    }

    /**
     * Test that PHP_VERSIONS constant contains expected versions.
     */
    public function testPhpVersionsConstant(): void
    {
        $versions = CompatibilityScanner::PHP_VERSIONS;

        $this->assertContains('5.2', $versions);
        $this->assertContains('7.4', $versions);
        $this->assertContains('8.0', $versions);
        $this->assertContains('8.4', $versions);
    }

    /**
     * Test that CompatibilityScanner implements ToolScannerInterface.
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
        $this->assertEquals('php-min-max', $this->scanner->getToolName());
    }

    /**
     * Test scan() dispatches directory target and returns CompatibilityResult.
     */
    public function testScanWithDirectoryTarget(): void
    {
        $tempDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'scanner_scan_test_' . uniqid();
        mkdir($tempDir, 0o755, true);
        file_put_contents($tempDir . '/test.php', '<?php echo "Hello";');

        try {
            $target = ScanTarget::fromDirectory($tempDir);
            $result = $this->scanner->scan($target);

            $this->assertInstanceOf(CompatibilityResult::class, $result);
            $this->assertTrue($result->success);
        } finally {
            @unlink($tempDir . '/test.php');
            @rmdir($tempDir);
        }
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
     * Test that a custom ZipHandler can be injected via constructor.
     */
    public function testCustomZipHandlerCanBeInjected(): void
    {
        $customHandler = new ZipHandler();
        $customHandler->setUserAgent('CustomAgent/1.0');

        $scanner = new CompatibilityScanner($customHandler);
        $this->assertSame($customHandler, $scanner->getZipHandler());
    }

    /**
     * Test that scanFromZipFile throws exception for non-existent file.
     */
    public function testScanFromZipFileThrowsForMissingFile(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('ZIP file not found');
        $this->scanner->scanFromZipFile('/nonexistent/file.zip');
    }

    /**
     * Test that scanDirectory throws exception for non-existent directory.
     */
    public function testScanDirectoryThrowsForMissingDirectory(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Directory not found');
        $this->scanner->scanDirectory('/nonexistent/directory');
    }

    /**
     * Test that scanDirectory returns a CompatibilityResult.
     */
    public function testScanDirectoryReturnsCompatibilityResult(): void
    {
        // Create a temp directory with a simple PHP file
        $tempDir = sys_get_temp_dir() . '/php_min_max_test_' . uniqid();
        mkdir($tempDir, 0755, true);
        file_put_contents($tempDir . '/test.php', '<?php echo "Hello";');

        try {
            $result = $this->scanner->scanDirectory($tempDir);
            $this->assertInstanceOf(CompatibilityResult::class, $result);
            $this->assertTrue($result->success);
        } finally {
            @unlink($tempDir . '/test.php');
            @rmdir($tempDir);
        }
    }
}
