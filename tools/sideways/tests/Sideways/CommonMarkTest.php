<?php

namespace Tests\AspireBuild\Tools\Sideways;

use AspireBuild\Tools\Sideways\Parsedown;
use AspireBuild\Tools\Sideways\Sideways;
use AspireBuild\Util\Json;
use Override;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;

/**
 * Test Sideways against the CommonMark spec
 *
 * NOTE: FAILURES ARE EXPECTED!  This test is normally disabled by phpunit.xml
 *
 * Parsedown 1.8: 345 tests failed, 310 passed
 * Sideways main: 345 tests failed, 310 passed
 *
 * @link http://commonmark.org/ CommonMark
 */
#[Group('commonmark')]
#[Group('default-disabled')] // uncomment to enable
class CommonMarkTest extends SidewaysTestCase
{

    #[Override]
    protected function newParser(): Sideways|Parsedown
    {
        return new Sideways(urlsLinked: false);
        // return new Parsedown()->setUrlsLinked(false);
    }

    #[DataProvider('commonmark_tests')]
    public function test_commonmark_spec($markdown, $html, $example, $start_line, $end_line, $section): void
    {
        // HACK: remove trailing newline from markdown and html because the original spec parser did so
        //       it still doesn't treat newlines at all properly according to CommonMark, but it gets closer.
        if (str_ends_with($markdown, "\n") and str_ends_with($html, "\n")) {
            $markdown = substr($markdown, 0, -1);
            $html = substr($html, 0, -1);
        }

        expect($this->render($markdown))->toBe($html);
    }

    public static function commonmark_tests(): array
    {
        return Json::toAssoc(file_get_contents(__DIR__ . '/data/commonmark-spec-tests.json'));
        //   {
        //     "markdown": "\tfoo\tbaz\t\tbim\n",
        //     "html": "<pre><code>foo\tbaz\t\tbim\n</code></pre>\n",
        //     "example": 1,
        //     "start_line": 355,
        //     "end_line": 360,
        //     "section": "Tabs"
        //   },
    }

    //region disabled lax tests (for reference)

    // #[DataProvider('commonmark_tests')]
    // public function test_commonmark_spec_lax($markdown, $html, $example, $start_line, $end_line, $section): void
    // {
    //     // HACK: remove trailing newline from markdown and html because the original spec parser did so
    //     //       it still doesn't treat newlines at all properly according to CommonMark, but it gets closer.
    //     if (str_ends_with($markdown, "\n") and str_ends_with($html, "\n")) {
    //         $markdown = substr($markdown, 0, -1);
    //         $html = substr($html, 0, -1);
    //     }
    //
    //     $rendered = $this->render($markdown);
    //     $rendered = $this->normalize_html($rendered);
    //     // $rendered === $html or dd(compact('markdown', 'html', 'example', 'start_line', 'end_line', 'section', 'rendered'));
    //     expect($rendered)->toBe($html);
    // }

    // private function normalize_html(string $html): string
    // {
    //     // invisible whitespaces at the beginning and end of block elements
    //     // however, whitespaces at the beginning of <pre> elements do matter
    //
    //     $tag = $this->textLevelElementRegex();
    //     return \Safe\preg_replace(
    //         [
    //             "/(<(?!(?:$tag|\\bpre\\b))\\w+\\b[^>]*>(?:<{$tag}[^>]*>)*)\\s+/s",
    //             "/\\s+((?:<\\/$tag>)*<\\/(?!$tag)\\w+\\b>)/s",
    //         ],
    //         '$1',
    //         $html,
    //     );
    //
    //     // return preg_replace(
    //     //     [
    //     //         '/(<(?!(?:'
    //     //         . $this->textLevelElementRegex
    //     //         . '|\bpre\b))\w+\b[^>]*>(?:<'
    //     //         . $this->textLevelElementRegex
    //     //         . '[^>]*>)*)\s+/s',
    //     //         '/\s+((?:<\/'
    //     //         . $this->textLevelElementRegex
    //     //         . '>)*<\/(?!'
    //     //         . $this->textLevelElementRegex
    //     //         . ')\w+\b>)/s',
    //     //     ],
    //     //     '$1',
    //     //     $html,
    //     // );
    // }
    //
    // private function textLevelElementRegex(): string
    // {
    //     static $regex = null;
    //     return $regex ??= $this->_textLevelElementRegex();
    // }
    //
    // private function _textLevelElementRegex(): string
    // {
    //     $elements = $this->parser->getTextLevelElements();
    //     $elements = array_map(fn($e) => preg_quote($e, '/'), $elements);
    //     return '\b(?:' . implode('|', $elements) . ')\b';
    // }

    //endregion
}
