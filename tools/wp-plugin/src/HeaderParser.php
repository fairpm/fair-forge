<?php

declare(strict_types=1);

namespace FAIR\Forge\Tools\WpPlugin;

use FAIR\Forge\Util\Regex;

class HeaderParser
{
    /** @var array<string, string> */
    const array PLUGIN_HEADERS = [
        'name'             => 'Plugin Name',        // required
        'description'      => 'Description',        // required
        'version'          => 'Version',            // required
        'author'           => 'Author',             // required
        'license'          => 'License',            // required
        'requires_wp'      => 'Requires at least',  // strongly recommended
        'requires_php'     => 'Requires PHP',       // strongly recommended
        'plugin_uri'       => 'Plugin URI',
        'author_uri'       => 'Author URI',
        'license_uri'      => 'License URI',
        'text_domain'      => 'Text Domain',
        'domain_path'      => 'Domain Path',
        'network'          => 'Network', // if present, only value accepted is true
        'update_uri'       => 'Update URI',
        'requires_plugins' => 'Requires Plugins',
        'tested_up_to'     => 'Tested up to', // from Import::add_extra_plugin_headers
        // freaks and misfits
        // '_sitewide   => 'Site Wide Only',  // deprecated since 3.0, use Network instead
        // 'Title'      => 'Plugin Name',     // set by parser, not a header
        // 'AuthorName' => 'Author',          // set by parser, not a header
    ];

    /** @var array<string, string> */
    const array THEME_HEADERS = [
        // required fields
        'name'         => 'Theme Name',
        'author'       => 'Author',
        'description'  => 'Description',
        'version'      => 'Version',
        'requires_wp'  => 'Requires at least',
        'requires_php' => 'Requires PHP',
        'text_domain'  => 'Text Domain',
        // required fields documented on wp.org but not in WP_Theme::$file_headers.
        'tested_up_to' => 'Tested up to',
        'license'      => 'License',
        'license_uri'  => 'License URI',
        // optional fields
        'theme_uri'    => 'Theme URI',
        'author_uri'   => 'Author URI',
        'tags'         => 'Tags',
        'template'     => 'Template', // required in a child theme (all other fields except name become optional)
        'domain_path'  => 'Domain Path', // default: /languages
        // not documented on .org, presumably generated somewhere else
        'status'       => 'Status',
        'update_uri'   => 'Update URI',
    ];

    public function parsePluginHeaders(string $content): ParsedPluginHeaders
    {
        // https://developer.wordpress.org/plugins/plugin-basics/header-requirements/
        return new ParsedPluginHeaders(...$this->readHeaders($content, self::PLUGIN_HEADERS));
    }

    public function parseThemeHeaders(string $content): ParsedThemeHeaders
    {
        // https://developer.wordpress.org/themes/basics/main-stylesheet-style-css/#explanations
        return new ParsedThemeHeaders(...$this->readHeaders($content, self::THEME_HEADERS));
    }

    /**
     * @param array<string, string> $headers
     * @return array<string, string>
     */
    public function readHeaders(string $content, array $headers): array
    {
        $parsed = [];
        foreach ($headers as $field => $key) {
            $pattern = '/^(?:[ \t]*<\?php)?[ \t\/*#@]*' . $key . ':(.*)$/mi';
            $matches = Regex::matches($pattern, $content);
            if (!$matches) {
                continue;
            }
            $val = $matches[1];
            $val = Regex::replace('/\s*(?:\*\/|\?>).*/', '', $val);
            $val = mb_trim($val);
            $parsed[$field] = $val;
        }
        return $parsed;
    }
}
