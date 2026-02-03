<?php
declare(strict_types=1);


use FAIR\Forge\Tools\WpPlugin\HeaderParser;
use FAIR\Forge\Tools\WpPlugin\PartialPluginInformation;
use FAIR\Forge\Tools\WpPlugin\ReadmeParser;
use PHPUnit\Framework\TestCase;

class PartialPluginInformationTest extends TestCase
{
    public function test_parse_hello_dolly(): void
    {
        $hello_dolly_php = <<<'END'
            <?php
            /**
             * @package Hello_Dolly
             * @version 1.7.2
             */
            /*
            Plugin Name: Hello Dolly
            Plugin URI: http://wordpress.org/plugins/hello-dolly/
            Description: This is not just a plugin, it symbolizes the hope and enthusiasm of an entire generation summed up in two words sung most famously by Louis Armstrong: Hello, Dolly. When activated you will randomly see a lyric from <cite>Hello, Dolly</cite> in the upper right of your admin screen on every page.
            Author: Matt Mullenweg
            Version: 1.7.2
            Author URI: http://ma.tt/
            */

            function hello_dolly_get_lyric() {
                    /** These are the lyrics to Hello Dolly */
                    $lyrics = "Hello, Dolly
            Well, hello, Dolly
            ...etc...
            END;

        $hello_dolly_readme = <<<'END'
            === Hello Dolly ===
            Contributors: matt, wordpressdotorg
            Stable tag: 1.7.2
            Tested up to: 6.9
            Requires at least: 4.6

            This is not just a plugin, it symbolizes the hope and enthusiasm of an entire generation summed up in two words sung most famously by Louis Armstrong.

            == Description ==

            This is not just a plugin, it symbolizes the hope and enthusiasm of an entire generation summed up in two words sung most famously by Louis Armstrong: Hello, Dolly. When activated you will randomly see a lyric from <cite>Hello, Dolly</cite> in the upper right of your admin screen on every page.

            Thanks to Sanjib Ahmad for the artwork.
            END;

        $headers = (new HeaderParser())->parsePluginHeaders($hello_dolly_php);
        $readme = (new ReadmeParser())->parse($hello_dolly_readme);

        $info = PartialPluginInformation::fromHeadersAndReadme('hello-dolly', $headers, $readme);
        $arr = $info->jsonSerialize();

        expect($arr)->toBe([
            'name'              => 'Hello Dolly',
            'slug'              => 'hello-dolly',
            'version'           => '1.7.2',
            'author'            => 'Matt Mullenweg',
            'author_profile'    => 'http://ma.tt/',
            'description'       => '<p>This is not just a plugin, it symbolizes the hope and enthusiasm of an entire generation summed up in two words sung most famously by Louis Armstrong: Hello, Dolly. When activated you will randomly see a lyric from <cite>Hello, Dolly</cite> in the upper right of your admin screen on every page.</p>
<p>Thanks to Sanjib Ahmad for the artwork.</p>
',
            'short_description' => 'This is not just a plugin, it symbolizes the hope and enthusiasm of an entire generation summed up in two words sung most famously by Louis Armstrong.',
            'sections'          => [
                'description' => '<p>This is not just a plugin, it symbolizes the hope and enthusiasm of an entire generation summed up in two words sung most famously by Louis Armstrong: Hello, Dolly. When activated you will randomly see a lyric from <cite>Hello, Dolly</cite> in the upper right of your admin screen on every page.</p>
<p>Thanks to Sanjib Ahmad for the artwork.</p>
',
            ],
            'plugin_uri'        => 'http://wordpress.org/plugins/hello-dolly/',
            'stable_tag'        => '1.7.2',
        ]);
    }
}
