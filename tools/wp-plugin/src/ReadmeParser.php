<?php

namespace FAIR\Forge\Tools\WpPlugin;

use Ds\Deque;
use FAIR\Forge\Util\Regex;
use HTMLPurifier;
use HTMLPurifier_Config;
use League\CommonMark\Environment\Environment;
use League\CommonMark\Extension\Autolink\AutolinkExtension;
use League\CommonMark\Extension\CommonMark\CommonMarkCoreExtension;
use League\CommonMark\Extension\DisallowedRawHtml\DisallowedRawHtmlExtension;
use League\CommonMark\Extension\Strikethrough\StrikethroughExtension;
use League\CommonMark\Extension\Table\TableExtension;
use League\CommonMark\MarkdownConverter;
use Normalizer;
use RuntimeException;

// Note: The metadata returned by this class still requires further processing downstream, specifically to
//       look up authors, generate screenshot links, check licenses, and substutute shortcodes like [youtube].

class ReadmeParser
{
    public array $warnings = [];

    public const array expected_sections = [
        'description',
        'installation',
        'faq',
        'screenshots',
        'changelog',
        'upgrade_notice',
        'other_notes',
    ];

    public const array alias_sections = [
        'frequently_asked_questions' => 'faq',
        'change_log'                 => 'changelog',
        'screenshot'                 => 'screenshots',
    ];

    public const array valid_headers = [
        'tested'            => 'tested_up_to',
        'tested up to'      => 'tested_up_to',
        'requires'          => 'requires_wp',
        'requires at least' => 'requires_wp',
        'requires php'      => 'requires_php',
        'tags'              => 'tags',
        'contributors'      => 'contributors',
        'donate link'       => 'donate_link',
        'stable tag'        => 'stable_tag',
        'license'           => 'license',
        'license uri'       => 'license_uri',
    ];

    private Deque $input;

    public function parse(string $str): ParsedReadme
    {
        $str = $this->ensure_utf8($str);

        $this->input = new Deque(array_map(fn($line) => rtrim($line, "\r\n"), preg_split('!\R!u', $str)));

        $defaults = [
            'name'              => '',
            'short_description' => '',
            'tags'              => [],
            'requires_wp'       => '',
            'tested_up_to'      => '',
            'requires_php'      => '',
            'contributors'      => [],
            'stable_tag'        => '',
            'donate_link'       => '',
            'license'           => '',
            'license_uri'       => '',
            'sections'          => [],
        ];

        $plugin_name = $this->parse_plugin_name();
        $raw_headers = $this->parse_headers();
        $short_description = $this->parse_short_description();
        $sections = $this->parse_sections();

        $fields = [
            'name'              => $plugin_name,
            'short_description' => $short_description,
            'sections'          => $sections,
            ...$this->extract_fields_from_headers($raw_headers),
        ];

        $fields = $this->fixup_fields($fields);
        $fields = [...$defaults, ...$fields, '_warnings' => $this->warnings];

        return new ParsedReadme(
            name             : $fields['name'],
            short_description: $fields['short_description'],
            tags             : $fields['tags'],
            requires_wp      : $fields['requires_wp'],
            tested_up_to     : $fields['tested_up_to'],
            requires_php     : $fields['requires_php'],
            contributors     : $fields['contributors'],
            stable_tag       : $fields['stable_tag'],
            donate_link      : $fields['donate_link'],
            license          : $fields['license'],
            license_uri      : $fields['license_uri'],
            sections         : $fields['sections'],
            _warnings        : $fields['_warnings'],
        );
    }

    private function ensure_utf8(string $str): string
    {
        if (str_starts_with($str[0], "\xFF\xFE")) {
            // UTF-16 BOM detected, convert to UTF8.  This is our only attempt at encoding detection.
            $str = \Safe\mb_convert_encoding($str, 'UTF-8', 'UTF-16');
        }

        if (str_starts_with($str, "\xEF\xBB\xBF")) {
            // UTF-8 BOM detected, strip it.
            $str = substr($str, 3);
        }

        mb_substitute_character(0xFFFD); // � - Replacement Character
        $str = mb_scrub($str, 'UTF-8');  // uses global state from mb_substitute_character()

        return normalizer_normalize($str, Normalizer::FORM_C);
    }

    private function parse_first_nonblank_line(): ?string
    {
        while (!$this->input->isEmpty()) {
            $line = $this->input->shift();
            if (trim($line) !== '') {
                return $line;
            }
        }
        return null;
    }

    private function eat_header_underlines(): void
    {
        while (!$this->input->isEmpty() && trim($this->input[0], '=-') === '') {
            $this->input->shift();
        }
    }

    private function parse_plugin_name(): string
    {
        $line = $this->parse_first_nonblank_line();

        $name = htmlspecialchars(strip_tags(trim($line, "#= \t\0\x0B")));

        $parsed = $this->read_header($line);

        if ($parsed && !isset(self::valid_headers[$parsed[0]])) {
            $this->input->unshift($line);
            $this->warnings['invalid_plugin_name_header'] = true;
            return '';
        }

        $this->eat_header_underlines();
        return $name;
    }

    private function parse_headers(): array
    {
        $line = $this->parse_first_nonblank_line();
        $last_line_was_blank = false;
        $headers = [];
        do {
            $value = null;
            $header = $this->read_header($line);

            // If it doesn't look like a header value, maybe break to the next section.
            if (!$header) {
                if (empty($line)) {
                    // Some plugins have line-breaks within the headers...
                    $last_line_was_blank = true;
                    continue;
                }

                // We've hit a line that is not blank, but also doesn't look like a header, assume the Short Description and end Header parsing.
                break;
            }

            [$key, $value] = $header;

            if (isset(self::valid_headers[$key])) {
                $headers[self::valid_headers[$key]] = $value;
            } elseif ($last_line_was_blank) {
                // If we skipped over a blank line, and then ended up with an unexpected header, assume we parsed too far and ended up in the Short Description.
                // This final line will be added back into the stack after the loop for further parsing.
                break;
            }

            $last_line_was_blank = false;
        } while (($line = $this->input->shift()) !== null);

        $this->input->unshift($line);

        return $headers;
    }

    private function read_comma_separated(string $input): array
    {
        return array_values(array_filter(array_map(trim(...), explode(',', $input))));
    }

    private function extract_fields_from_headers(array $headers): array
    {
        return [
            'tags'         => $this->read_comma_separated($headers['tags'] ?? ''),
            'requires_wp'  => $this->read_version($headers['requires_wp'] ?? ''),
            'tested_up_to' => $this->read_version($headers['tested_up_to'] ?? ''),
            'requires_php' => $this->read_version($headers['requires_php'] ?? ''),
            'contributors' => $this->read_comma_separated($headers['contributors'] ?? ''),
            'stable_tag'   => $this->read_stable_tag($headers['stable_tag'] ?? ''),
            'donate_link'  => $headers['donate_link'] ?? '',
            'license'      => $headers['license'] ?? '',
            'license_uri'  => $headers['license_uri'] ?? '',
        ];
    }

    private function fixup_fields(array $fields): array
    {
        $sections = $fields['sections'];

        if (empty($sections['description'])) {
            $sections['description'] = $fields['short_description'];
        }

        if (!empty($sections['other_notes'])) {
            $sections['description'] .= "\n" . $sections['other_notes'];
            unset($sections['other_notes']);
        }

        if (!empty($sections['faq'])) {
            $sections['faq'] = $this->fixup_faq_markdown($sections['faq']);
        }

        foreach ($sections as $section => $content) {
            $newcontent = mb_substr($content, 0, 1024 * 64); // 64K limit for every section.

            if ($content !== $newcontent) {
                $this->warnings["trimmed_section_$section"] = true;
            }

            $sections[$section] = $this->render_markdown($newcontent);
        }

        $short_description = $fields['short_description'];

        // Default short description to first line of description.
        if (!$short_description && !empty($sections['description'])) {
            $short_description = array_filter(explode("\n", $sections['description']))[0];
            $this->warnings['no_short_description_present'] = true;
        }

        $trimmed = mb_substr($short_description, 0, 150);

        if ($short_description !== $trimmed) {
            if (empty($this->warnings['no_short_description_present'])) {
                $this->warnings['trimmed_short_description'] = true;
            }
            $short_description = $trimmed;
        }

        $fields['short_description'] = $short_description;
        $fields['sections'] = $sections;
        return $fields;
    }

    private function fixup_faq_markdown(string $markdown): string
    {
        // the algorithm in legacy is to look for the first heading, treating '== Foo ==' as a heading
        // as well as '** Foo **', then assume the rest of the headings are consistent with that style.
        // the faqs array then becomes an array of [heading => content] pairs where content is whatever follows
        // the heading up til the next heading or the end of the section.  Headings are not strictly parsed to the
        // markdown standard: any line beginning with '#' or '=' is a heading, as is any bold line ('**' on both ends)

        // Although markdown supports dd/dt, it's oriented toward single lines, and we want arbitrary content,
        // so we'll take the expedient of just normalizing the custom-formatted headers to h3 markdown instead (###),
        // then using the DOM parser on the rendered html to collect the <h3> elements and their following siblings.

        $match = Regex::matches('/^(?:[=#]+.*|\*\*.*\*\*\$)$/m', $markdown);

        if (!$match) {
            // no headers, so just return the markdown as-is.
            return $markdown;
        }

        $header = $match[0];
        if (str_starts_with($header, '=')) {
            // Using the '== Foo ==' style of header, which we convert to ###.
            $markdown = Regex::replace('/^=+(.*?)=+$/m', '### $1', $markdown);
        } elseif (str_starts_with($header, '#')) {
            // replace all headers with ### regardless of their current level
            $markdown = Regex::replace('/^#+(.*?)#*$/m', '### $1', $markdown);
        } elseif (str_starts_with($header, '**')) {
            // replace all bolded lines with ###
            $markdown = Regex::replace('/^\*{2,6}(.*?)\*{2,6}/m', '### $1', $markdown);
        } else {
            // shouldn't happen
            throw new RuntimeException("Unexpected header style: $header");
        }

        return $markdown;
    }

    private function fixup_faq_html(string $html): string
    {
        // with a parsed 'faq' array, we did something like this
        //         $sections['faq'] .= "\n<dl>\n";
        //         foreach ($faq as $question => $answer) {
        //             $question_slug = rawurlencode(strtolower(trim($question)));
        //             $sections['faq'] .= "<dt id='$question_slug'><h3>$question</h3></dt>\n<dd>$answer</dd>\n";
        //         }
        //         $sections['faq'] .= "\n</dl>\n";
    }

    private function parse_short_description(): string
    {
        $short_description = '';

        while (!$this->input->isEmpty()) {
            $line = $this->input->shift();
            $trimmed = trim($line);
            if (empty($trimmed)) {
                continue;
            }

            if (Regex::matches('/^(?:==|##)/', $trimmed)) {
                $this->input->unshift($line);
                break;
            }

            $short_description .= $line . ' ';
        }
        return trim($short_description);
    }

    private function parse_sections(): array
    {
        $sections = array_fill_keys(self::expected_sections, '');
        $current = '';
        $section_name = '';
        while (!$this->input->isEmpty()) {
            $line = $this->input->shift();
            $trimmed = trim($line);
            if (empty($trimmed)) {
                $current .= "\n";
                continue;
            }

            // Stop only after a ## Markdown header, not a ###.

            // the original insanity:
            // if (
            //     ('=' === $trimmed[0] && isset($trimmed[1]) && '=' === $trimmed[1])
            //     || ('#' === $trimmed[0] && isset($trimmed[1]) && '#' === $trimmed[1] && isset($trimmed[2]) && '#' !== $trimmed[2])
            // ) {
            // if (Regex::matches('/^==|##(?:[^#]|$)/', $trimmed)) { // nope, not the same result
            if (str_starts_with($trimmed, '==')
                || (str_starts_with($trimmed, '##')
                    && !str_starts_with($trimmed, '###'))) {
                if (!empty($section_name)) {
                    $sections[$section_name] .= trim($current);
                }

                $current = '';
                $section_title = trim($line, "#= \t");
                $section_key = strtolower(Regex::replace('/\W+/', '_', $section_title));
                $section_name = self::alias_sections[$section_key] ?? $section_key;

                // move any unknown sections into other_notes
                if (!in_array($section_name, self::expected_sections, true)) {
                    $current .= "<h3>$section_title</h3>";
                    $section_name = 'other_notes';
                }
                continue;
            }

            $current .= $line . "\n";
        }

        if (!empty($section_name)) {
            $sections[$section_name] .= trim($current);
        }

        return array_filter($sections);
    }

    private function read_header(string $line): ?array
    {
        if (!str_contains($line, ':') || str_starts_with($line, '#') || str_starts_with($line, '=')) {
            return null;
        }

        [$key, $value] = explode(':', $line, 2);
        $key = strtolower(trim($key, " \t*-\r\n"));
        $value = trim($value, " \t*-\r\n");

        return [$key, $value];
    }

    private function read_stable_tag(string $tag): string
    {
        $tag = trim($tag);
        $tag = trim($tag, '"\''); // "trunk"
        $tag = Regex::replace('!^/?tags/!i', '', $tag); // "tags/1.2.3"
        $tag = Regex::replace('![^a-z0-9_.-]!i', '', $tag);

        str_starts_with($tag, '.') and $tag = "0$tag";

        return $tag;
    }

    private function read_version(string $str): string
    {
        return Regex::extract('(\d+(\.\d+){1,2})', $str) ?? '';
    }

    private function render_markdown(string $text): string
    {
        $text = $this->get_markdown_converter()->convert($text)->getContent();
        return $this->get_html_purifier()->purify($text);
    }

    private function get_markdown_converter(): MarkdownConverter
    {
        static $converter;
        return $converter ??= $this->_get_markdown_converter();
    }

    private function _get_markdown_converter(): MarkdownConverter
    {
        $config = [];
        $environment = new Environment($config);
        $environment->addExtension(new CommonMarkCoreExtension());
        // $environment->addExtension(new GithubFlavoredMarkdownExtension());

        $environment->addExtension(new AutolinkExtension());
        $environment->addExtension(new DisallowedRawHtmlExtension());
        // $environment->addExtension(new SmartPunctExtension());
        $environment->addExtension(new StrikethroughExtension());
        $environment->addExtension(new TableExtension());

        return new MarkdownConverter($environment);
    }

    private function get_html_purifier(): HtmlPurifier
    {
        static $purifier;
        return $purifier ??= $this->_get_html_purifier();
    }

    private function _get_html_purifier(): HtmlPurifier
    {
        $config = HTMLPurifier_Config::createDefault();
        // we don't really need this yet
        // $config->set('Cache.SerializerPath', Filesystem::mktempdir(prefix: 'htmlpurifier_'));
        $config->set('Cache.SerializerPath', null);
        return new HTMLPurifier($config);
    }

    /* disabled code below

    // we can strip stop-words like this later, it doesn't belong here.
    public const array ignore_tags = ['plugin', 'wordpress'];

    // Not used: We'll parse the DOM of the rendered markdown instead
    private function parse_section(array|string $lines): array
    {
        $key = $value = '';
        $return = [];

        if (!is_array($lines)) {
            $lines = explode("\n", $lines);
        }
        $trimmed_lines = array_map('trim', $lines);


         // The heading style being matched in the block. Can be 'heading' or 'bold'.
         // Standard Markdown headings (## .. and == ... ==) are used, but if none are present.
         // full line bolding will be used as a heading style.

        $heading_style = 'bold'; // 'heading' or 'bold'
        foreach ($trimmed_lines as $trimmed) {
            if ($trimmed && ($trimmed[0] === '#' || $trimmed[0] === '=')) {
                $heading_style = 'heading';
                break;
            }
        }

        $line_count = count($lines);
        for ($i = 0; $i < $line_count; $i++) {
            $line = &$lines[$i];
            $trimmed = &$trimmed_lines[$i];
            if (!$trimmed) {
                $value .= "\n";
                continue;
            }

            $is_heading = false;
            if ('heading' === $heading_style && ($trimmed[0] === '#' || $trimmed[0] === '=')) {
                $is_heading = true;
            } elseif ('bold' === $heading_style && (str_starts_with($trimmed, '**') && str_ends_with($trimmed, '**'))) {
                $is_heading = true;
            }

            if ($is_heading) {
                if ($value) {
                    $return[$key] = trim($value);
                }

                $value = '';
                // Trim off the first character of the line, as we know that's the heading style we're expecting to remove.
                $key = trim($line, $trimmed[0] . " \t");
                continue;
            }

            $value .= $line . "\n";
        }

        if ($key || $value) {
            $return[$key] = trim($value);
        }

        return $return;
    }

    // Validate the license specified.
    // if (!$fields['license']) {
    //     $this->warnings['license_missing'] = true;
    // } else {
    //     $license_error = $this->validate_license($fields['license']);
    //     if (true !== $license_error) {
    //         $this->warnings[$license_error] = $fields['license'];
    //     }
    // }

    // Fixup license containing a url
    // if (!empty($fields['license'])
    //     && empty($headers['license_uri'])
    //     && ($url = Regex::extract('!https?://\S+!i', $headers['license']))) {
    //     // Handle the many cases of "License: GPLv2 - http://..."
    //     $fields['license_uri'] = trim($url, " -*\t\n\r(");
    //     $fields['license'] = trim(str_replace($url, '', $headers['license']), " -*\t\n\r(");
    // }

    private function validate_license(string $license): bool|string
    {
        // https://www.gnu.org/licenses/license-list.en.html for possible compatible licenses.
        $probably_compatible = [
            'GPL',
            'General Public License',
            // 'GNU 2', 'GNU Public', 'GNU Version 2' explicitely not included, as it's not a specific license.
            'MIT',
            'ISC',
            'Expat',
            'Apache 2',
            'Apache License 2',
            'X11',
            'Modified BSD',
            'New BSD',
            '3 Clause BSD',
            'BSD 3',
            'FreeBSD',
            'Simplified BSD',
            '2 Clause BSD',
            'BSD 2',
            'MPL',
            'Mozilla Public License',
            strrev('LPFTW'),
            strrev('kcuf eht tahw od'), // To avoid some code scanners..
            'Public Domain',
            'CC0',
            'Unlicense',
            'CC BY', // Note: BY-NC & BY-ND are a no-no. See below.
            'zlib',
        ];

        $probably_incompatible = [
            '4 Clause BSD',
            'BSD 4 Clause',
            'Apache 1',
            'CC BY-NC',
            'CC-NC',
            'NonCommercial',
            'CC BY-ND',
            'NoDerivative',
            'EUPL',
            'OSL',
            'Personal use',
            'without permission',
            'without prior auth',
            'you may not',
            'Proprietery',
            'proprietary',
        ];

        $sanitize_license = static function (string $license): string {
            $license = strtolower($license);

            // Localised or verbose licences.
            $license = str_replace('licence', 'license', $license);
            $license = str_replace('clauses', 'clause', $license); // BSD
            $license = str_replace('creative commons', 'cc', $license);

            // If it looks like a full GPL statement, trim it back, for this function.
            if (str_contains($license, 'gnu general public license version 2, june 1991 copyright (c) 1989')) {
                $license = 'gplv2';
            }

            // Replace 'Version 9' & v9 with '9' for simplicity.
            $license = preg_replace('/(version |v)([0-9])/i', '$2', $license);

            // Remove unexpected characters
            $license = preg_replace('/(\s*[^a-z0-9. ]+\s*)/i', '', $license);

            // Remove all spaces
            return preg_replace('/\s+/', '', $license);
        };

        $probably_compatible = array_map($sanitize_license, $probably_compatible);
        $probably_incompatible = array_map($sanitize_license, $probably_incompatible);
        $license = $sanitize_license($license);

        // First check to see if it's most probably an incompatible license.
        if (array_any($probably_incompatible, fn($match) => str_contains($license, $match))) {
            return 'invalid_license';
        }

        if (array_any($probably_compatible, fn($match) => str_contains($license, $match))) {
            return true;
        }

        return 'unknown_license';
    }

    // we are definitely not making database lookups in a parser

    private function sanitize_contributors(array $users): array
    {
        foreach ($users as $i => $name) {
            // Trim any leading `@` off the name, in the event that someone uses `@joe-bloggs`.
            $name = ltrim($name, '@');

            // Contributors should be listed by their WordPress.org Login name (Example: 'Joe Bloggs')
            $user = get_user_by('login', $name);

            // Or failing that, by their user_nicename field (Example: 'joe-bloggs')
            if (!$user) {
                $user = get_user_by('slug', $name);
            }

            // In the event that something invalid is used, we'll ignore it (Example: 'Joe Bloggs (Australian Translation)')
            if (!$user) {
                $this->warnings['contributor_ignored'] ??= [];
                $this->warnings['contributor_ignored'][] = $name;
                unset($users[$i]);
                continue;
            }

            // Overwrite whatever the author has specified with the sanitized nicename.
            $users[$i] = $user->user_nicename;
        }
        return $users;
    }

    // we can limit tags in post-processing
    private function read_tags_header(string $input): array
    {
        $tags = explode(',', $input);
        $tags = array_map(trim(...), $tags);
        $tags = array_filter($tags);

        if (count($tags) > 5) {
            $this->warnings['too_many_tags'] = array_slice($tags, 5);
            $tags = array_slice($tags, 0, 5);
        }

        return $tags;
    }

        // In fixup_sections(): FAQ parsing will happen in post-processing, over the DOM of the parsed markdown
        //
        // if (!empty($faq)) {
        //     // If the FAQ contained data we couldn't parse, we'll treat it as freeform and display it before any questions which are found.
        //     if (isset($faq[''])) {
        //         $sections['faq'] .= $faq[''];
        //         unset($faq['']);
        //     }
        //
        //     if ($faq) {
        //         $sections['faq'] .= "\n<dl>\n";
        //         foreach ($faq as $question => $answer) {
        //             $question_slug = rawurlencode(strtolower(trim($question)));
        //             $sections['faq'] .= "<dt id='$question_slug'><h3>$question</h3></dt>\n<dd>$answer</dd>\n";
        //         }
        //         $sections['faq'] .= "\n</dl>\n";
        //     }
        // }
    */


}
