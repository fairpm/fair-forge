<?php

namespace Sideways;

use AspireBuild\Tools\Sideways\Sideways;
use DirectoryIterator;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\AspireBuild\Tools\Sideways\SidewaysTestCase;
use Tests\AspireBuild\Tools\Sideways\TrustDelegatedExtension;
use Tests\AspireBuild\Tools\Sideways\UnsafeExtension;

class BasicMarkdownTest extends SidewaysTestCase
{
    public function test_headers(): void
    {
        $this->assertRender('# Header', '<h1>Header</h1>');
        $this->assertRender('## Header', '<h2>Header</h2>');
        $this->assertRender('### Header', '<h3>Header</h3>');
        $this->assertRender('#### Header', '<h4>Header</h4>');
        $this->assertRender('##### Header', '<h5>Header</h5>');
        $this->assertRender('###### Header', '<h6>Header</h6>');

        $this->assertRender('# Header #', '<h1>Header</h1>');
        $this->assertRender('# Header   ##', '<h1>Header</h1>');
        $this->assertRender('## Header    ###########', '<h2>Header</h2>'); // eats any number of hashes on the right

        $this->assertRender('####### Header', '<p>####### Header</p>'); // 7 or more will not parse
    }

    public function test_emphasis(): void
    {
        $this->assertRender('some *em text* here', '<p>some <em>em text</em> here</p>');
        $this->assertRender('some _em text_ here', '<p>some <em>em text</em> here</p>');
    }
}
