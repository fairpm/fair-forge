<?php

declare(strict_types=1);

namespace FairForge\Shared\Tests;

use FairForge\Shared\AbstractToolScanner;
use FairForge\Shared\ScanTarget;
use FairForge\Shared\ScanTargetType;
use FairForge\Shared\ToolResultInterface;
use FairForge\Shared\ToolScannerInterface;
use FairForge\Shared\ZipHandler;
use PHPUnit\Framework\TestCase;
use RuntimeException;

/**
 * Minimal concrete scanner stub used for testing the abstract base.
 */
class StubScanner extends AbstractToolScanner
{
    /** @var string|null The directory passed to scanDirectory */
    public ?string $lastScannedDir = null;

    public function getToolName(): string
    {
        return 'stub-scanner';
    }

    public function scanDirectory(string $directory): ToolResultInterface
    {
        $this->lastScannedDir = $directory;

        // Return a minimal ConcreteToolResult (declared in the same tests/ dir)
        return new ConcreteToolResult(
            success: true,
            summary: ['scanned' => $directory],
            toolName: 'stub-scanner',
        );
    }
}

/**
 * Tests for AbstractToolScanner and ToolScannerInterface.
 */
class AbstractToolScannerTest extends TestCase
{
    /**
     * Test that a concrete scanner implements ToolScannerInterface.
     */
    public function testImplementsInterface(): void
    {
        $scanner = new StubScanner();
        $this->assertInstanceOf(ToolScannerInterface::class, $scanner);
    }

    /**
     * Test getToolName returns the slug.
     */
    public function testGetToolName(): void
    {
        $scanner = new StubScanner();
        $this->assertEquals('stub-scanner', $scanner->getToolName());
    }

    // ------------------------------------------------------------------
    // ZipHandler / SSL
    // ------------------------------------------------------------------

    public function testDefaultZipHandlerIsCreated(): void
    {
        $scanner = new StubScanner();
        $this->assertInstanceOf(ZipHandler::class, $scanner->getZipHandler());
    }

    public function testCustomZipHandlerIsUsed(): void
    {
        $custom = new ZipHandler();
        $custom->setSslVerify(false);

        $scanner = new StubScanner($custom);
        $this->assertSame($custom, $scanner->getZipHandler());
        $this->assertFalse($scanner->getSslVerify());
    }

    public function testGetSslVerifyDefaultTrue(): void
    {
        $scanner = new StubScanner();
        $this->assertTrue($scanner->getSslVerify());
    }

    public function testSetSslVerifyToggles(): void
    {
        $scanner = new StubScanner();
        $scanner->setSslVerify(false);
        $this->assertFalse($scanner->getSslVerify());

        $scanner->setSslVerify(true);
        $this->assertTrue($scanner->getSslVerify());
    }

    public function testSetSslVerifyReturnsSelf(): void
    {
        $scanner = new StubScanner();
        $result = $scanner->setSslVerify(false);
        $this->assertSame($scanner, $result);
    }

    // ------------------------------------------------------------------
    // scan() dispatch
    // ------------------------------------------------------------------

    public function testScanDispatchesToDirectory(): void
    {
        $dir = sys_get_temp_dir();
        $target = new ScanTarget(ScanTargetType::Directory, $dir);

        $scanner = new StubScanner();
        $result = $scanner->scan($target);

        $this->assertInstanceOf(ToolResultInterface::class, $result);
        $this->assertEquals($dir, $scanner->lastScannedDir);
    }

    // ------------------------------------------------------------------
    // scanDirectory — basic
    // ------------------------------------------------------------------

    public function testScanDirectoryReturnsResult(): void
    {
        $scanner = new StubScanner();
        $result = $scanner->scanDirectory(sys_get_temp_dir());

        $this->assertInstanceOf(ToolResultInterface::class, $result);
        $this->assertTrue($result->isSuccess());
    }

    // ------------------------------------------------------------------
    // scanFromZipFile — error handling
    // ------------------------------------------------------------------

    public function testScanFromZipFileThrowsForMissing(): void
    {
        $scanner = new StubScanner();
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('ZIP file not found');
        $scanner->scanFromZipFile('/nonexistent/file.zip');
    }

    // ------------------------------------------------------------------
    // ScanTarget integration with scan()
    // ------------------------------------------------------------------

    public function testScanTargetDetectThenScanDirectory(): void
    {
        $target = ScanTarget::detect(sys_get_temp_dir());
        $scanner = new StubScanner();
        $result = $scanner->scan($target);

        $this->assertInstanceOf(ToolResultInterface::class, $result);
        $this->assertEquals(sys_get_temp_dir(), $scanner->lastScannedDir);
    }
}
