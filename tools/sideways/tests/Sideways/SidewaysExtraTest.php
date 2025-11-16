<?php

namespace Tests\AspireBuild\Tools\Sideways;

use AspireBuild\Tools\Sideways\Sideways;
use DirectoryIterator;
use PHPUnit\Framework\Attributes\DataProvider;

class SidewaysExtraTest extends SidewaysTestCase
{
    #[DataProvider('data')]
    public function test_data_dir($test, $dir): void
    {
        $markdown = file_get_contents("$dir/$test.md");

        $expectedMarkup = file_get_contents("$dir/$test.html");

        $expectedMarkup = str_replace("\r\n", "\n", $expectedMarkup);
        $expectedMarkup = str_replace("\r", "\n", $expectedMarkup);

        $safeMode = str_starts_with($test, 'xss');
        $strictMode = str_starts_with($test, 'strict');

        $sideways = new Sideways(safeMode: $safeMode, strictMode: $strictMode, extra: true);

        $actualMarkup = $sideways->renderToHtml($markdown);

        $this->assertEquals($expectedMarkup, $actualMarkup);
    }

    public function testRawHtml(): void
    {
        $markdown = "```php\nfoobar\n```";
        $expectedMarkup = '<pre><code class="language-php"><p>foobar</p></code></pre>';
        $expectedSafeMarkup = '<pre><code class="language-php">&lt;p&gt;foobar&lt;/p&gt;</code></pre>';

        $unsafeExtension = new UnsafeExtension(safeMode: false);
        $actualMarkup = $unsafeExtension->renderToHtml($markdown);

        $this->assertEquals($expectedMarkup, $actualMarkup);

        $unsafeExtension = new UnsafeExtension(safeMode: true);
        $actualSafeMarkup = $unsafeExtension->renderToHtml($markdown);

        $this->assertEquals($expectedSafeMarkup, $actualSafeMarkup);
    }

    public function testTrustDelegatedRawHtml(): void
    {
        $markdown = "```php\nfoobar\n```";
        $expectedMarkup = '<pre><code class="language-php"><p>foobar</p></code></pre>';
        $expectedSafeMarkup = $expectedMarkup;

        $unsafeExtension = new TrustDelegatedExtension(safeMode: false);
        $actualMarkup = $unsafeExtension->renderToHtml($markdown);

        $this->assertEquals($expectedMarkup, $actualMarkup);

        $unsafeExtension = new TrustDelegatedExtension(safeMode: true);
        $actualSafeMarkup = $unsafeExtension->renderToHtml($markdown);

        $this->assertEquals($expectedSafeMarkup, $actualSafeMarkup);
    }

    public static function data(): array
    {
        $data = [];

        $dir = __DIR__ . '/data/extra';
        $Folder = new DirectoryIterator($dir);

        foreach ($Folder as $File) {
            /** @var $File DirectoryIterator */

            if (!$File->isFile()) {
                continue;
            }

            $filename = $File->getFilename();

            $extension = pathinfo($filename, PATHINFO_EXTENSION);

            if ($extension !== 'md') {
                continue;
            }

            $basename = $File->getBasename('.md');

            if (file_exists("$dir/$basename.html")) {
                $data [] = [$basename, $dir];
            }
        }

        return $data;
    }

    public function test_no_markup(): void
    {
        /** @noinspection HtmlDeprecatedAttribute */
        $markdownWithHtml = <<<MARKDOWN_WITH_MARKUP
            <div>_content_</div>

            sparse:

            <div>
            <div class="inner">
            _content_
            </div>
            </div>

            paragraph

            <style type="text/css">
                p {
                    color: red;
                }
            </style>

            comment

            <!-- html comment -->
            MARKDOWN_WITH_MARKUP;

        $expectedHtml = <<<EXPECTED_HTML
            <p>&lt;div&gt;<em>content</em>&lt;/div&gt;</p>
            <p>sparse:</p>
            <p>&lt;div&gt;
            &lt;div class="inner"&gt;
            <em>content</em>
            &lt;/div&gt;
            &lt;/div&gt;</p>
            <p>paragraph</p>
            <p>&lt;style type="text/css"&gt;
            p {
            color: red;
            }
            &lt;/style&gt;</p>
            <p>comment</p>
            <p>&lt;!-- html comment --&gt;</p>
            EXPECTED_HTML;

        $sidewaysWithNoMarkup = new Sideways(markupEscaped: true, extra: true);

        $this->assertEquals($expectedHtml, $sidewaysWithNoMarkup->renderToHtml($markdownWithHtml));
    }
}
