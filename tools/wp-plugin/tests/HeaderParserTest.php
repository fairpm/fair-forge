<?php
declare(strict_types=1);

namespace Tests\FAIR\Forge\Tools\WpPlugin;

use FAIR\Forge\Tools\WpPlugin\HeaderParser;
use PHPUnit\Framework\TestCase;

class HeaderParserTest extends TestCase
{
    public function test_parse_hello_dolly(): void
    {
        $hello_dolly = <<<'END'
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

        $parser = new HeaderParser();
        $headers = $parser->parsePluginHeaders($hello_dolly);
        $arr = $headers->jsonSerialize();
        expect($arr)->toBe([
            'name'             => 'Hello Dolly',
            'plugin_uri'       => 'http://wordpress.org/plugins/hello-dolly/',
            'description'      => 'This is not just a plugin, it symbolizes the hope and enthusiasm of an entire generation summed up in two words sung most famously by Louis Armstrong: Hello, Dolly. When activated you will randomly see a lyric from <cite>Hello, Dolly</cite> in the upper right of your admin screen on every page.',
            'version'          => '1.7.2',
            'requires_wp'      => '',
            'requires_php'     => '',
            'author'           => 'Matt Mullenweg',
            'author_uri'       => 'http://ma.tt/',
            'license'          => '',
            'license_uri'      => '',
            'text_domain'      => '',
            'domain_path'      => '',
            'network'          => '',
            'update_uri'       => '',
            'requires_plugins' => '',
            'tested_up_to'     => '',
        ]);
    }

    public function test_parse_description_comment_end(): void
    {
        $starry = <<<'END'
            /*
             @ Plugin Name: A Plugin
             @ Description: This is the *bestest* plugin ever.     */
            END;

        $parser = new HeaderParser();
        $headers = $parser->parsePluginHeaders($starry);
        expect($headers->description)->toBe('This is the *bestest* plugin ever.');
    }
}
