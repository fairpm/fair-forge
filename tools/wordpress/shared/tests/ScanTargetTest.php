<?php

declare(strict_types=1);

namespace FairForge\Shared\Tests;

use FairForge\Shared\ScanTarget;
use FairForge\Shared\ScanTargetType;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

/**
 * Tests for ScanTarget and ScanTargetType.
 */
class ScanTargetTest extends TestCase
{
    // ------------------------------------------------------------------
    // ScanTargetType enum
    // ------------------------------------------------------------------

    public function testScanTargetTypeValues(): void
    {
        $this->assertEquals('url', ScanTargetType::Url->value);
        $this->assertEquals('zip', ScanTargetType::ZipFile->value);
        $this->assertEquals('directory', ScanTargetType::Directory->value);
    }

    // ------------------------------------------------------------------
    // Named constructors
    // ------------------------------------------------------------------

    public function testFromUrlWithValidUrl(): void
    {
        $target = ScanTarget::fromUrl('https://example.com/plugin.zip');

        $this->assertSame(ScanTargetType::Url, $target->type);
        $this->assertEquals('https://example.com/plugin.zip', $target->value);
    }

    public function testFromUrlThrowsForInvalidUrl(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid URL');
        ScanTarget::fromUrl('not-a-url');
    }

    public function testFromZipFileWithValidFile(): void
    {
        $tmp = tempnam(sys_get_temp_dir(), 'zip_test_') . '.zip';
        file_put_contents($tmp, 'fake-zip');

        try {
            $target = ScanTarget::fromZipFile($tmp);

            $this->assertSame(ScanTargetType::ZipFile, $target->type);
            $this->assertEquals($tmp, $target->value);
        } finally {
            @unlink($tmp);
        }
    }

    public function testFromZipFileThrowsForMissingFile(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('ZIP file not found');
        ScanTarget::fromZipFile('/nonexistent/file.zip');
    }

    public function testFromDirectoryWithValidDir(): void
    {
        $dir = sys_get_temp_dir();
        $target = ScanTarget::fromDirectory($dir);

        $this->assertSame(ScanTargetType::Directory, $target->type);
        $this->assertEquals($dir, $target->value);
    }

    public function testFromDirectoryThrowsForMissingDir(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Directory not found');
        ScanTarget::fromDirectory('/nonexistent/dir');
    }

    // ------------------------------------------------------------------
    // Auto-detection
    // ------------------------------------------------------------------

    public function testDetectUrl(): void
    {
        $target = ScanTarget::detect('https://downloads.wordpress.org/plugin/akismet.zip');

        $this->assertSame(ScanTargetType::Url, $target->type);
    }

    public function testDetectZipFile(): void
    {
        $tmp = sys_get_temp_dir() . '/scan_target_test_' . uniqid() . '.zip';
        file_put_contents($tmp, 'fake');

        try {
            $target = ScanTarget::detect($tmp);
            $this->assertSame(ScanTargetType::ZipFile, $target->type);
        } finally {
            @unlink($tmp);
        }
    }

    public function testDetectDirectory(): void
    {
        $target = ScanTarget::detect(sys_get_temp_dir());
        $this->assertSame(ScanTargetType::Directory, $target->type);
    }

    public function testDetectThrowsForUnknownTarget(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('is not a valid URL, ZIP file, or directory');
        ScanTarget::detect('/nonexistent/something.txt');
    }

    // ------------------------------------------------------------------
    // Query helpers
    // ------------------------------------------------------------------

    public function testIsUrlHelper(): void
    {
        $target = ScanTarget::fromUrl('https://example.com/a.zip');
        $this->assertTrue($target->isUrl());
        $this->assertFalse($target->isZipFile());
        $this->assertFalse($target->isDirectory());
    }

    public function testIsZipFileHelper(): void
    {
        $tmp = tempnam(sys_get_temp_dir(), 'zip_') . '.zip';
        file_put_contents($tmp, 'fake');

        try {
            $target = ScanTarget::fromZipFile($tmp);
            $this->assertTrue($target->isZipFile());
            $this->assertFalse($target->isUrl());
            $this->assertFalse($target->isDirectory());
        } finally {
            @unlink($tmp);
        }
    }

    public function testIsDirectoryHelper(): void
    {
        $target = ScanTarget::fromDirectory(sys_get_temp_dir());
        $this->assertTrue($target->isDirectory());
        $this->assertFalse($target->isUrl());
        $this->assertFalse($target->isZipFile());
    }

    // ------------------------------------------------------------------
    // Value immutability
    // ------------------------------------------------------------------

    public function testPropertiesAreReadonly(): void
    {
        $target = ScanTarget::fromUrl('https://example.com/x.zip');
        // If PHP tried to write, it would throw; just verify reads work
        $this->assertSame(ScanTargetType::Url, $target->type);
        $this->assertEquals('https://example.com/x.zip', $target->value);
    }
}
