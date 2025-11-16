<?php

namespace Sideways;

use Tests\AspireBuild\Tools\Sideways\SidewaysTestCase;
use PHPUnit\Framework\ExpectationFailedException;

// Remember to only make one assertion per test method, since they will throw on the first failure
class ExpectedFailuresTest extends SidewaysTestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->expectException(ExpectationFailedException::class);
    }

    public function test_ghfm_h1(): void
    {
        $this->assertRender('= Header =', '<h1>Header</h1>');
    }

    public function test_ghfm_h2(): void
    {
        $this->assertRender('== Header ==', '<h2>Header</h2>');
    }
}
