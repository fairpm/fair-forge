<?php

namespace Sideways;

use Tests\AspireBuild\Tools\Sideways\SidewaysTestCase;

class MalformedMarkdownTest extends SidewaysTestCase
{
    public function test_broken_underline_headers_are_text(): void
    {
        $this->assertRender("Header\n=== ===", "<p>Header\n=== ===</p>"); // broken lines will not parse
        $this->assertRender("Header\n-=-=-=", "<p>Header\n-=-=-=</p>");   // mixed lines will not parse
    }

    public function test_h1_indent_underline_is_text(): void
    {
        // all leading space is consumed
        $this->assertRender("Header\n    ======", "<p>Header\n======</p>");
        $this->assertRender("Header\n        ======", "<p>Header\n======</p>");
    }

    public function test_h2_indent_underline_is_hr(): void
    {
        // all leading space is consumed
        $this->assertRender("Header\n    ------", "<p>Header</p>\n<hr />");
        $this->assertRender("Header\n        ------", "<p>Header</p>\n<hr />");
    }
}
