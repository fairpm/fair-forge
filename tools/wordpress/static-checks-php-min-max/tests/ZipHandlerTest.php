<?php

declare(strict_types=1);

namespace FairForge\Tools\WordPress\PluginStaticChecks\Tests;

use FairForge\Tools\WordPress\PluginStaticChecks\ZipHandler;
use PHPUnit\Framework\TestCase;
use RuntimeException;

/**
 * Tests for the ZipHandler class.
 *
 * These tests verify ZIP file download, extraction, validation,
 * and directory management operations.
 */
class ZipHandlerTest extends TestCase
{
    private ZipHandler $handler;

    private string $tempDir;

    /**
     * Set up test fixtures.
     *
     * Creates a new ZipHandler instance and a temporary directory for each test.
     */
    protected function setUp(): void
    {
        $this->handler = new ZipHandler();
        $this->tempDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'zip_handler_test_' . uniqid();
        mkdir($this->tempDir, 0o755, true);
    }

    /**
     * Tear down test fixtures.
     *
     * Removes the temporary directory after each test.
     */
    protected function tearDown(): void
    {
        if (is_dir($this->tempDir)) {
            $this->handler->removeDirectory($this->tempDir);
        }
    }

    /**
     * Test that SSL verification is enabled by default.
     */
    public function testDefaultSslVerifyIsTrue(): void
    {
        $this->assertTrue($this->handler->getSslVerify());
    }

    /**
     * Test that SSL verification can be toggled on and off.
     */
    public function testSetSslVerify(): void
    {
        $this->handler->setSslVerify(false);
        $this->assertFalse($this->handler->getSslVerify());

        $this->handler->setSslVerify(true);
        $this->assertTrue($this->handler->getSslVerify());
    }

    /**
     * Test that setSslVerify returns self for method chaining.
     */
    public function testSetSslVerifyReturnsSelf(): void
    {
        $result = $this->handler->setSslVerify(false);
        $this->assertSame($this->handler, $result);
    }

    /**
     * Test that the default user agent contains the FairForge identifier.
     */
    public function testDefaultUserAgent(): void
    {
        $this->assertStringContainsString('FairForge', $this->handler->getUserAgent());
    }

    /**
     * Test that a custom user agent can be set.
     */
    public function testSetUserAgent(): void
    {
        $this->handler->setUserAgent('TestAgent/1.0');
        $this->assertEquals('TestAgent/1.0', $this->handler->getUserAgent());
    }

    /**
     * Test that setUserAgent returns self for method chaining.
     */
    public function testSetUserAgentReturnsSelf(): void
    {
        $result = $this->handler->setUserAgent('Test');
        $this->assertSame($this->handler, $result);
    }

    /**
     * Test that the default connection timeout is 30 seconds.
     */
    public function testDefaultConnectTimeout(): void
    {
        $this->assertEquals(30, $this->handler->getConnectTimeout());
    }

    /**
     * Test that a custom connection timeout can be set.
     */
    public function testSetConnectTimeout(): void
    {
        $this->handler->setConnectTimeout(60);
        $this->assertEquals(60, $this->handler->getConnectTimeout());
    }

    /**
     * Test that the default transfer timeout is 120 seconds.
     */
    public function testDefaultTimeout(): void
    {
        $this->assertEquals(120, $this->handler->getTimeout());
    }

    /**
     * Test that a custom transfer timeout can be set.
     */
    public function testSetTimeout(): void
    {
        $this->handler->setTimeout(300);
        $this->assertEquals(300, $this->handler->getTimeout());
    }

    /**
     * Test that isValidZip returns false for non-existent files.
     */
    public function testIsValidZipReturnsFalseForNonExistentFile(): void
    {
        $this->assertFalse($this->handler->isValidZip('/nonexistent/file.zip'));
    }

    /**
     * Test that isValidZip returns false for files that are not ZIP archives.
     */
    public function testIsValidZipReturnsFalseForNonZipFile(): void
    {
        $textFile = $this->tempDir . '/test.txt';
        file_put_contents($textFile, 'This is not a ZIP file');

        $this->assertFalse($this->handler->isValidZip($textFile));
    }

    /**
     * Test that createTempDirectory creates a directory with the specified prefix.
     */
    public function testCreateTempDirectory(): void
    {
        $dir = $this->handler->createTempDirectory('test_prefix_');

        $this->assertDirectoryExists($dir);
        $this->assertStringContainsString('test_prefix_', $dir);

        // Clean up
        $this->handler->removeDirectory($dir);
    }

    /**
     * Test that removeDirectory recursively removes all files and subdirectories.
     */
    public function testRemoveDirectoryRemovesFilesAndDirectories(): void
    {
        // Create nested structure
        $subDir = $this->tempDir . '/subdir';
        mkdir($subDir, 0o755, true);
        file_put_contents($this->tempDir . '/file1.txt', 'content1');
        file_put_contents($subDir . '/file2.txt', 'content2');

        $this->handler->removeDirectory($this->tempDir);

        $this->assertDirectoryDoesNotExist($this->tempDir);
    }

    /**
     * Test that removeDirectory does not throw for non-existent directories.
     */
    public function testRemoveDirectoryHandlesNonExistentDirectory(): void
    {
        // Should not throw
        $this->handler->removeDirectory('/nonexistent/directory');
        $this->assertTrue(true);
    }

    /**
     * Test that extract throws RuntimeException for non-existent ZIP files.
     */
    public function testExtractThrowsExceptionForNonExistentZip(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('ZIP file not found');

        $this->handler->extract('/nonexistent/file.zip');
    }

    /**
     * Test that listContents throws RuntimeException for non-existent ZIP files.
     */
    public function testListContentsThrowsExceptionForNonExistentZip(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('ZIP file not found');

        $this->handler->listContents('/nonexistent/file.zip');
    }

    /**
     * Test that download throws RuntimeException for invalid/unreachable URLs.
     */
    public function testDownloadThrowsExceptionForInvalidUrl(): void
    {
        $this->handler->setSslVerify(false);

        $this->expectException(RuntimeException::class);

        $this->handler->download('http://invalid.invalid.invalid/file.zip');
    }
}
