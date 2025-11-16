<?php

namespace Tests\AspireBuild\Tools\Sideways;

use AspireBuild\Tools\Sideways\Sideways;
use AspireBuild\Util\Regex;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;

/**
 * Test Sideways against the CommonMark spec
 *
 * @link http://commonmark.org/ CommonMark
 */
#[Group('commonmark')]
class CommonMarkStrictTest extends SidewaysTestCase
{
    protected Sideways $sideways;

    protected function setUp(): void
    {
        $this->sideways = new Sideways(urlsLinked: false);
    }

    /** @noinspection PhpUnusedParameterInspection */
    #[DataProvider('data')]
    public function testExample($id, $section, $markdown, $expectedHtml): void
    {
        $actualHtml = $this->sideways->renderToHtml($markdown);
        $this->assertEquals($expectedHtml, $actualHtml);
    }

    public static function data(): array
    {
        $spec = file_get_contents(__DIR__ . '/commonmark-spec.txt');
        $spec = str_replace("\r\n", "\n", $spec);
        $spec = strstr($spec, '<!-- END TESTS -->', true);

        $test_regex = '/^`{32} example\n((?s).*?)\n\.\n(?:|((?s).*?)\n)`{32}$|^#{1,6} *(.*?)$/m';
        $matches = Regex::allMatches($test_regex, $spec);

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
