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

        $this->assertRender("Header\n======", '<h1>Header</h1>');
        $this->assertRender("Header\n------", '<h2>Header</h2>');

        $this->assertRender("Header\n======\n======", "<h1>Header</h1>\n<p>======</p>");
        $this->assertRender("Header\n------\n------", "<h2>Header</h2>\n<hr />");

        // Any number of = or - on the line after will work
        $this->assertRender("Header\n=", '<h1>Header</h1>');
        $this->assertRender("Header\n-", '<h2>Header</h2>');
        $this->assertRender("Header\n=====", '<h1>Header</h1>');
        $this->assertRender("Header\n-----", '<h2>Header</h2>');
        $this->assertRender("Header\n==========", '<h1>Header</h1>');
        $this->assertRender("Header\n----------", '<h2>Header</h2>');

        $this->assertRender("Header\n ======", "<h1>Header</h1>");
        $this->assertRender("Header\n   ======", "<h1>Header</h1>"); // up to 3 leading whitespaces
    }

    public function test_emphasis(): void
    {
        $this->assertRender('some *em text* here', '<p>some <em>em text</em> here</p>');
        $this->assertRender('some _em text_ here', '<p>some <em>em text</em> here</p>');
    }

    public function test_links(): void
    {
        $this->assertRender('[link text](http://example.com)', '<p><a href="http://example.com">link text</a></p>');
    }

    public function test_lists(): void
    {
        $this->assertRender('* item 1', "<ul>\n<li>item 1</li>\n</ul>");
        $this->assertRender('1. item 1', "<ol>\n<li>item 1</li>\n</ol>");
    }

    public function test_fenced_code(): void
    {
        $this->assertRender("```\nfoobar\n```", '<pre><code>foobar</code></pre>');
        $this->assertRender("```php\nfoobar\n```", '<pre><code class="language-php">foobar</code></pre>');
        $this->assertRender("```narf\nfoobar\n```", '<pre><code class="language-narf">foobar</code></pre>');
    }
}
