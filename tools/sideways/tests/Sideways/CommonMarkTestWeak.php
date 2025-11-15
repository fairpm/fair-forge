<?php

namespace Tests\AspireBuild\Tools\Sideways;

use PHPUnit\Framework\Attributes\DataProvider;

require_once(__DIR__ . '/CommonMarkTestStrict.php');

/**
 * Test Sideways against the CommonMark spec, but less aggressive
 *
 * The resulting HTML markup is cleaned up before comparison, so examples
 * which would normally fail due to actually invisible differences (e.g.
 * superfluous whitespaces), don't fail. However, cleanup relies on block
 * element detection. The detection doesn't work correctly when a element's
 * `display` CSS property is manipulated. According to that this test is only
 * a interim solution on Sideways's way to full CommonMark compatibility.
 *
 * @link http://commonmark.org/ CommonMark
 */
class CommonMarkTestWeak extends CommonMarkTestStrict
{
    protected string $textLevelElementRegex;

    protected function setUp(): void
    {
        parent::setUp();

        $textLevelElements = $this->sideways->getTextLevelElements();
        array_walk($textLevelElements, function (&$element) {
            $element = preg_quote($element, '/');
        });
        $this->textLevelElementRegex = '\b(?:' . implode('|', $textLevelElements) . ')\b';
    }

    #[DataProvider('data')]
    public function testExample($id, $section, $markdown, $expectedHtml): void
    {
        $expectedHtml = $this->cleanupHtml($expectedHtml);

        $actualHtml = $this->sideways->text($markdown);
        $actualHtml = $this->cleanupHtml($actualHtml);

        $this->assertEquals($expectedHtml, $actualHtml);
    }

    protected function cleanupHtml($markup): string
    {
        // invisible whitespaces at the beginning and end of block elements
        // however, whitespaces at the beginning of <pre> elements do matter
        return preg_replace(
            [
                '/(<(?!(?:'
                . $this->textLevelElementRegex
                . '|\bpre\b))\w+\b[^>]*>(?:<'
                . $this->textLevelElementRegex
                . '[^>]*>)*)\s+/s',
                '/\s+((?:<\/' . $this->textLevelElementRegex . '>)*<\/(?!' . $this->textLevelElementRegex . ')\w+\b>)/s',
            ],
            '$1',
            $markup,
        );
    }
}
