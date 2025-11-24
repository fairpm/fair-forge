<?php
declare(strict_types=1);

namespace Tests\FAIR\Forge\Tools\WpPlugin;

use FAIR\Forge\Tools\WpPlugin\ReadmeParser;
use PHPUnit\Framework\TestCase;

class ReadmeParserTest extends TestCase
{
    public function test_parse_hello_dolly(): void
    {
        $hello_dolly = <<<'END'
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

        $parser = new ReadmeParser();
        $readme = $parser->parse($hello_dolly);

        $arr = $readme->jsonSerialize();
        $sections = $arr['sections'];

        $this->assertEquals([
            'name'              => 'Hello Dolly',
            'short_description' => 'This is not just a plugin, it symbolizes the hope and enthusiasm of an entire generation summed up in two words sung most famously by Louis Armstrong.',
            'tested_up_to'      => '6.9',
            'requires_php'      => '',
            'requires_wp'       => '4.6',
            'contributors'      => ['matt', 'wordpressdotorg'],
            'stable_tag'        => '1.7.2',
            'sections'          => $sections,
            'tags'              => [],
            'donate_link'       => '',
            'license'           => '',
            'license_uri'       => '',
            '_warnings'         => [],
        ], $arr);

        $expected_description = <<<"END"
            <p>This is not just a plugin, it symbolizes the hope and enthusiasm of an entire generation summed up in two words sung most famously by Louis Armstrong: Hello, Dolly. When activated you will randomly see a lyric from <cite>Hello, Dolly</cite> in the upper right of your admin screen on every page.</p>
            <p>Thanks to Sanjib Ahmad for the artwork.</p>\n
            END;

        $this->assertEquals(['description' => $expected_description], $sections);
    }

    public function test_parse_yolo_seo(): void
    {
        // Tests the range of our parser while remaining relatively compliant with the established readme format.
        $yolo_seo_readme = <<<'END'
            === YOLO SEO – Move Fast & Break Your Site Ranking ===
            Contributors: nobody you know, just you
            Tags: SEO, YOLO & YAGNI!, meta something, schema
            Tested up to: 9.6
            Requires at least: 2.7
            Requires PHP: 6.6
            Stable tag: .9
            License: GPLv8 or earlier
            License URI: https://www.example.org

            YOLO SEO is the least powerful WordPress SEO plugin 〰 no kidding!

            == Description ==

            ### YOLO SEO - The Worst WordPress Plugin & Toolkit ###

            It would probably be a good idea to put more description here

            Our users consistently rate [YOLOSEO](https://yoloseo.example.org/?utm_source=unit_tests&utm_medium=link 'Something from Nothing SEO') as the most useless WordPress plugin ever to have been created.

            > <strong>YOLO-SEO Pro</strong><br />
            > If you [pay us more for some reason](https://yoloseo.example.io/?utm_source=unit_tests&utm_medium=link&utm_campaign=liteplugin 'Something from Nothing SEO Pro') then you get a bonus of nothing!

            [youtube https://youtu.be/dQw4w9WgXcQ?si=cCtl1K4wsYVfkpGv]

            ### What Makes YOLO-SEO Better than Other SEO Plugins ###

            Nothing whatsoever.  We can't even get the name of the plugin consistent.

            * **Inscrutable Setup Wizard**
            Our setup wizard consists of editing a php file with no documentation whatsoever.  No hints here either, bub!

            ### Advanced Features ###

            * **Total Control**
            Since YOLO-SEO doesn't actually function, you have to fix everything yourself, so you get to
            learn how the system functions from the ground up!

            == Changelog ==

            **New in Version 496.381.7.16 **

            * 🐐: Added support for .goat images.

            **New in Version 496.381.7.15 **

            * changed the architecture of the entire plugin
            (5,376 files changed with 8,255 additions and 97,022 deletions).

            **New in Version 496.381.7.14 **

            * fix typo

            == Frequently Asked Questions ==

            Please [go here first](https://dev-null-as-a-service.com) for help.

            = Who should use YOLO:SEO? =

            Not anyone sane.  But you're still reading, aren't you?

            = Will YOLO_SEO slow down my website? =

            It'll probably bring it to a crawl.

            = Why are these subheadings in h1 and the main headings in h2? =

            You know why.

            == Screenshots ==

            1. Numbered list items ([foo](http://bar.baz))
            2. Turn into screenshot links

            == Upgrade Notice ==

            = 3.1.2 =

            This update did stuff and I don't remember what.  YOLO.
            END;

        $parser = new ReadmeParser();
        $readme = $parser->parse($yolo_seo_readme);

        $arr = $readme->jsonSerialize();
        $sections = $arr['sections'];

        $this->assertEquals([
            'name'              => 'YOLO SEO – Move Fast &amp; Break Your Site Ranking',
            'short_description' => 'YOLO SEO is the least powerful WordPress SEO plugin 〰 no kidding!',
            'tested_up_to'      => '9.6',
            'requires_php'      => '6.6',
            'requires_wp'       => '2.7',
            'contributors'      => ['nobody you know', 'just you'],
            'stable_tag'        => '0.9',
            'sections'          => $sections,
            'tags'              => ['SEO', 'YOLO & YAGNI!', 'meta something', 'schema'],
            'donate_link'       => '',
            'license'           => 'GPLv8 or earlier',
            'license_uri'       => 'https://www.example.org',
            '_warnings'         => [],
        ], $arr);

        $expected_description = <<<'END'
            <h3>YOLO SEO - The Worst WordPress Plugin &amp; Toolkit</h3>
            <p>It would probably be a good idea to put more description here</p>
            <p>Our users consistently rate <a href="https://yoloseo.example.org/?utm_source=unit_tests&amp;utm_medium=link" title="Something from Nothing SEO">YOLOSEO</a> as the most useless WordPress plugin ever to have been created.</p>
            <blockquote>
            <p>&lt;strong&gt;YOLO-SEO Pro&lt;/strong&gt;&lt;br /&gt;
            If you <a href="https://yoloseo.example.io/?utm_source=unit_tests&amp;utm_medium=link&amp;utm_campaign=liteplugin" title="Something from Nothing SEO Pro">pay us more for some reason</a> then you get a bonus of nothing!</p>
            </blockquote>
            <p>[youtube <a href="https://youtu.be/dQw4w9WgXcQ?si=cCtl1K4wsYVfkpGv">https://youtu.be/dQw4w9WgXcQ?si=cCtl1K4wsYVfkpGv</a>]</p>
            <h3>What Makes YOLO-SEO Better than Other SEO Plugins</h3>
            <p>Nothing whatsoever.  We can't even get the name of the plugin consistent.</p>
            <ul>
            <li><strong>Inscrutable Setup Wizard</strong>
            Our setup wizard consists of editing a php file with no documentation whatsoever.  No hints here either, bub!</li>
            </ul>
            <h3>Advanced Features</h3>
            <ul>
            <li><strong>Total Control</strong>
            Since YOLO-SEO doesn't actually function, you have to fix everything yourself, so you get to
            learn how the system functions from the ground up!
            &lt;h3&gt;Frequently Asked Questions&lt;/h3&gt;
            Please <a href="https://yoloseo.example.dev/docs">sod right off</a> if you think we'll help with anything.</li>
            </ul>
            <p>= Who should use YOLO:SEO? =</p>
            <p>Not anyone sane.  But you're still reading, aren't you?</p>
            <p>= Will YOLO_SEO slow down my website? =</p>
            <p>It'll probably bring it to a crawl.&lt;h3&gt;Random Section That Doesn't Belong Anywhere&lt;/h3&gt;</p>
            <blockquote>
            <p>Here's a quoted line
            And another right below it.</p>
            </blockquote>
            <pre><code>                                               Here's a way-indented line</code></pre>
            <p>And another regular line.</p>
            END;

        $expected_faq = <<<'END'
            first faq is where is the faq?
            END;

        $wrong_expected_screenshots = <<<'END'
            <ol>
            <li>Numbered list items (<a href="http://bar.baz">foo</a>)</li>
            <li>Turn into screenshot links</li>
            </ol>
            END;

        $expected_screenshots = $wrong_expected_screenshots;

        $expected_changelog = <<<'END'
            <p><strong>New in Version 496.381.7.16 </strong></p>
            <ul>
            <li>🐐: Added support for .goat images.</li>
            </ul>
            <p><strong>New in Version 496.381.7.15 </strong></p>
            <ul>
            <li>changed the architecture of the entire plugin
            (5,376 files changed with 8,255 additions and 97,022 deletions).</li>
            </ul>
            <p><strong>New in Version 496.381.7.14 </strong></p>
            <ul>
            <li>fix typo</li>
            </ul>
            END;

        $expected_upgrade_notice = <<<'END'
            <p>= 3.1.2 =</p>
            <p>This update did stuff and I don't remember what.  YOLO.</p>
            END;

        $this->assertEquals([
            'description'    => $expected_description,
            // 'faq'         => $expected_faq,
            'screenshots'    => $expected_screenshots,
            'changelog'      => $expected_changelog,
            'upgrade_notice' => $expected_upgrade_notice,
        ], $sections);
    }

    public function test_parse_hello_cthulhu(): void
    {
        // This should eventually test every corner case, probably including zalgo text with invalid UTF-8 sequences.

        $hello_cthulhu = <<<'END'
            === Hello C'thulhu ===
            Contributors: chaz, chazworks
            Stable tag: 6.6.6
            Tested up to: 7.9
            Requires PHP: 8.8
            Tags: cthulhu, f'tagn, rlyeh, eldritch, old ones
            Requires at least: 6.6
            Donate Link: https://www.gofundyourself.com/c/hello-cthulhu
            License: GPL 3.0 or later
            License URI: https://gnu.org
            Ia! Ia! Cthulhu Ftagn!
            == Description ==

            This is not just a plugin, it symbolizes the mounting horror and insanity of an entire generation.

            [youtube https://youtu.be/ut82TDjciSg]

            When activated you will notice nothing, but gradually care about nothing, until your soul is an empty vessel
            into which the visions of his grand dread majesty will materialize and take form through your husk of a body
            as you do his bidding in the hopes that you shall be among those to watch the flames which consume the universe
            to base ash so that you may be be last to be burned in unholy eldritch fire.

            <script lang="eldritch">Ph'nglui mglw'nafh Cthulhu R'lyeh wgah'nagl fhtagn</script>

            Oh, and it also shows lyrics from Louis Armstrong's famous song <title>Hello Dolly</title> on your admin dashboard.

            ## Upgrade Notice

            Your husk will be discarded when it is no longer of use.  You are not to concern yourself with it.

            ## Frequently Asked Questions

            This is some stuff on top of the FAQ section.

            = What happens if I deactivate the plugin? =

            If the plugin's tendrils have fully wrapped themselves around your soul, your own body will wither and die.

            = Is this a FAQ? =

            No.

            **And stop asking questions.**

            Puny creature.

            ## Other Notes

            other notes here... (parsed or not, no idea)

            ## Screenshots

            Screenshots go here but only things in list tags make it into the property

            * anything in a markdown list will do
            * it can have arbitrary markup <a href="http://zalgo.org" onmouseover="alert('HE COMES')">and links</a>
            * ![the horror that awaits you](https://comicskingdom.com/_next/image?url=https%3A%2F%2Fwp.comicskingdom.com%2Fcomicskingdom-redesign-uploads-production%2F1995%2F12%2FFC-Sunday-8-19-Print-copy-scaled.jpg&w=3840&q=75)

            == Random Section That Doesn't Belong Anywhere ==

            > Here's a quoted line
            > And another right below it.

                                                               Here's a way-indented line

            And another regular line.

            ## Changelog

            This looks like free-form markdown

            * But nonetheless it usually has bullet points.
            * So let's have more bullet points
            * like this one
            END;

        $parser = new ReadmeParser();
        $readme = $parser->parse($hello_cthulhu);

        // dd($readme->sections['faq']);

        $arr = (array)$readme;
        $sections = $arr['sections']; // tested separately

        $this->assertEquals([
            'name'              => 'Hello C&#039;thulhu',
            'short_description' => 'Ia! Ia! Cthulhu Ftagn!',
            'tags'              => ['cthulhu', "f'tagn", 'rlyeh', 'eldritch', 'old ones'],
            'tested_up_to'      => '7.9',
            'requires_php'      => '8.8',
            'requires_wp'       => '6.6',
            'contributors'      => ['chaz', 'chazworks'],
            'stable_tag'        => '6.6.6',
            'donate_link'       => 'https://www.gofundyourself.com/c/hello-cthulhu',
            'license'           => 'GPL 3.0 or later',
            'license_uri'       => 'https://gnu.org',
            'sections'          => $sections,
            '_warnings'         => [],
        ], (array)$readme);

        $expected_description = <<<"END"
            <p>This is not just a plugin, it symbolizes the mounting horror and insanity of an entire generation.</p>
            <p>[youtube <a href="https://youtu.be/ut82TDjciSg">https://youtu.be/ut82TDjciSg</a>]</p>
            <p>When activated you will notice nothing, but gradually care about nothing, until your soul is an empty vessel
            into which the visions of his grand dread majesty will materialize and take form through your husk of a body
            as you do his bidding in the hopes that you shall be among those to watch the flames which consume the universe
            to base ash so that you may be be last to be burned in unholy eldritch fire.</p>
            &lt;script lang="eldritch"&gt;Ph'nglui mglw'nafh Cthulhu R'lyeh wgah'nagl fhtagn&lt;/script&gt;
            <p>Oh, and it also shows lyrics from Louis Armstrong's famous song &lt;title&gt;Hello Dolly&lt;/title&gt; on your admin dashboard.
            other notes here... (parsed or not, no idea)</p><h3>Random Section That Doesn't Belong Anywhere</h3>
            <blockquote>
            <p>Here's a quoted line
            And another right below it.</p>
            </blockquote>
            <pre><code>                                               Here's a way-indented line
            </code></pre>
            <p>And another regular line.</p>
            END;

        $expected_faq = <<<'END'
            <p>This is some stuff on top of the FAQ section.</p>
            <h3>What happens if I deactivate the plugin?</h3>
            <p>If the plugin's tendrils have fully wrapped themselves around your soul, your own body will wither and die.</p>
            <h3>Is this a FAQ?</h3>
            <p>No.</p>
            <p><strong>And stop asking questions.</strong></p>
            <p>Puny creature.</p>
            END;

        $expected_screenshots = <<<'END'
            <p>Screenshots go here but only things in list tags make it into the property</p>
            <ul>
            <li>anything in a markdown list will do</li>
            <li>it can have arbitrary markup <a href="http://zalgo.org">and links</a></li>
            <li><img src="https://comicskingdom.com/_next/image?url=https%3A%2F%2Fwp.comicskingdom.com%2Fcomicskingdom-redesign-uploads-production%2F1995%2F12%2FFC-Sunday-8-19-Print-copy-scaled.jpg&amp;w=3840&amp;q=75" alt="the horror that awaits you" /></li>
            </ul>
            END;

        $expected_changelog = <<<'END'
            <p>This looks like free-form markdown</p>
            <ul>
            <li>But nonetheless it usually has bullet points.</li>
            <li>So let's have more bullet points</li>
            <li>like this one</li>
            </ul>

            END;

        $expected_upgrade_notice = <<<'END'
            <p>Your husk will be discarded when it is no longer of use.  You are not to concern yourself with it.</p>

            END;

        // failures are easier to pick out with separate assertions
        expect($sections['description'])->toEqual($expected_description);
        expect($sections['faq'])->toEqual($expected_faq);
        expect($sections['screenshots'])->toEqual($expected_screenshots);
        expect($sections['changelog'])->toEqual($expected_changelog);
        expect($sections['upgrade_notice'])->toEqual($expected_upgrade_notice);
        expect($sections)->arrayToHaveCount(5);
    }
}
