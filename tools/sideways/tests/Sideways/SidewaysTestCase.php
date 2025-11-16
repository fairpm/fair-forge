<?php
declare(strict_types=1);

namespace Tests\AspireBuild\Tools\Sideways;

use AspireBuild\Tools\Sideways\Sideways;
use PHPUnit\Framework\TestCase;

class SidewaysTestCase extends TestCase {

    protected Sideways $parser;

    protected function setUp(): void
    {
        parent::setUp();
        $this->parser = $this->newParser();
    }

    protected function newParser(): Sideways
    {
        return new Sideways();
    }

    protected function assertRender(string $markdown, string $expectedHtml): void
    {
        static::assertSame($expectedHtml, $this->parser->renderToHtml($markdown));
    }
}
