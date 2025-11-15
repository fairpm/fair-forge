<?php

namespace Tests\AspireBuild\Tools\Sideways;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Test Sideways against the CommonMark spec
 *
 * @link http://commonmark.org/ CommonMark
 */
class CommonMarkTestStrict extends TestCase
{
    const string SPEC_URL = 'https://raw.githubusercontent.com/jgm/CommonMark/master/spec.txt';

    protected TestSideways $sideways;

    protected function setUp(): void
    {
        $this->sideways = new TestSideways(urlsLinked: false);
    }

    /** @noinspection PhpUnusedParameterInspection */
    #[DataProvider('data')]
    public function testExample($id, $section, $markdown, $expectedHtml): void
    {
        $actualHtml = $this->sideways->text($markdown);
        $this->assertEquals($expectedHtml, $actualHtml);
    }

    public static function data(): array
    {
        $spec = file_get_contents(self::SPEC_URL);
        if ($spec === false) {
            self::fail('Unable to load CommonMark spec from ' . self::SPEC_URL);
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
