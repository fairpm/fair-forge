<?php

namespace Tests\AspireBuild\Tools\Sideways;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RuntimeException;

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
class CommonMarkWeakTest extends TestCase
{
    protected string $textLevelElementRegex;
    protected TestSideways $sideways;

    const string SPEC_URL = 'https://raw.githubusercontent.com/jgm/CommonMark/master/spec.txt';

    protected function setUp(): void
    {
        parent::setUp();

        $this->sideways = new TestSideways(urlsLinked: false);

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

    public static function data(): array
    {
        $spec = file_get_contents(self::SPEC_URL);
        if ($spec === false) {
            throw new RuntimeException('Unable to load CommonMark spec from ' . self::SPEC_URL);
        }

        $spec = str_replace("\r\n", "\n", $spec);
        $spec = strstr($spec, '<!-- END TESTS -->', true);

        $matches = [];
        preg_match_all('/^`{32} example\n((?s).*?)\n\.\n(?:|((?s).*?)\n)`{32}$|^#{1,6} *(.*?)$/m', $spec, $matches,
            PREG_SET_ORDER);

        $data = [];
        $currentId = 0;
        $currentSection = '';
        foreach ($matches as $match) {
            if (isset($match[3])) {
                $currentSection = $match[3];
            } else {
                $currentId++;
                $markdown = str_replace('→', "\t", $match[1]);
                $expectedHtml = isset($match[2]) ? str_replace('→', "\t", $match[2]) : '';

                $data[$currentId] = [
                    'id'           => $currentId,
                    'section'      => $currentSection,
                    'markdown'     => $markdown,
                    'expectedHtml' => $expectedHtml,
                ];
            }
        }

        return $data;
    }
}
