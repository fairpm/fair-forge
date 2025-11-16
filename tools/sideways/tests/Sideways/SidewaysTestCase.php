<?php
declare(strict_types=1);

namespace Tests\AspireBuild\Tools\Sideways;

use AspireBuild\Tools\Sideways\Parsedown;
use AspireBuild\Tools\Sideways\Sideways;
use PHPUnit\Framework\TestCase;

class SidewaysTestCase extends TestCase
{
    protected Sideways|Parsedown $parser;

    protected function setUp(): void
    {
        parent::setUp();
        $this->parser = $this->newParser();
    }

    /** override this method to use Parsedown or pass additional args to their constructors */
    protected function newParser(): Sideways|Parsedown
    {
        return new Sideways();
    }

    protected function render(string $markdown): string
    {
        return $this->parser instanceof Sideways
            ? $this->parser->renderToHtml($markdown)
            : $this->parser->text($markdown);
    }
}
