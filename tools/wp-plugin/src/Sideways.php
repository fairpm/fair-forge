<?php

/** @noinspection PhpSameParameterValueInspection */
/** @noinspection PhpUnused */
/** @noinspection PhpUnusedPrivateMethodInspection */
/** @noinspection RegExpSimplifiable */

// Sideways Markdown Parser [WORKING TITLE]
//
// Based on Parsedown by Emanuil Rusev (https://erusev.com/) with extensive modifications.
// https://github.com/erusev/parsedown
//
// Original code licensed under the MIT License below:
//
// The MIT License (MIT)
//
// Copyright (c) 2013-2018 Emanuil Rusev, erusev.com
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

namespace AspireBuild\Tools\WpPlugin;

final class Sideways
{
    public function __construct(
        public readonly string $source,
        public readonly bool $breaksEnabled = false,
        public readonly bool $markupEscaped = false,
        public readonly bool $urlsLinked = true,
        public readonly bool $safeMode = false,
    ) {}

    public function toHtml(): string
    {
        $this->DefinitionData = [];
        $text = str_replace(["\r\n", "\r"], "\n", $this->source);
        $text = trim($text, "\n");
        $lines = explode("\n", $text);
        $markup = $this->lines($lines);
        return trim($markup, "\n");
    }

    //region Private API

    private array $DefinitionData = [];

    /** @var list<string> */
    private const array specialCharacters = [
        '\\',
        '`',
        '*',
        '_',
        '{',
        '}',
        '[',
        ']',
        '(',
        ')',
        '>',
        '#',
        '+',
        '-',
        '.',
        '!',
        '|',
    ];

    /** @var array<string, string> */
    private const array StrongRegex = [
        '*' => '/^[*]{2}((?:\\\\\*|[^*]|[*][^*]*[*])+?)[*]{2}(?![*])/s',
        '_' => '/^__((?:\\\\_|[^_]|_[^_]*_)+?)__(?!_)/us',
    ];

    /** @var array<string, string> */
    private const array EmRegex = [
        '*' => '/^[*]((?:\\\\\*|[^*]|[*][*][^*]+?[*][*])+?)[*](?![*])/s',
        '_' => '/^_((?:\\\\_|[^_]|__[^_]*__)+?)_(?!_)\b/us',
    ];

    private const string regexHtmlAttribute = '[a-zA-Z_:][\w:.-]*(?:\s*=\s*(?:[^"\'=<>`\s]+|"[^"]*"|\'[^\']*\'))?';

    /** @var list<string> */
    private const array voidElements = [
        'area',
        'base',
        'br',
        'col',
        'command',
        'embed',
        'hr',
        'img',
        'input',
        'link',
        'meta',
        'param',
        'source',
    ];

    /** @var list<string> */
    private const array textLevelElements = [
        'a',
        'br',
        'bdo',
        'abbr',
        'blink',
        'nextid',
        'acronym',
        'basefont',
        'b',
        'em',
        'big',
        'cite',
        'small',
        'spacer',
        'listing',
        'i',
        'rp',
        'del',
        'code',
        'strike',
        'marquee',
        'q',
        'rt',
        'ins',
        'font',
        'strong',
        's',
        'tt',
        'kbd',
        'mark',
        'u',
        'xm',
        'sub',
        'nobr',
        'sup',
        'ruby',
        'var',
        'span',
        'wbr',
        'time',
    ];

    /** @var list<string> */
    private const array safeLinksWhitelist = [
        'http://',
        'https://',
        'ftp://',
        'ftps://',
        'mailto:',
        'data:image/png;base64,',
        'data:image/gif;base64,',
        'data:image/jpeg;base64,',
        'irc:',
        'ircs:',
        'git:',
        'ssh:',
        'news:',
        'steam:',
    ];

    /** @var array<string, list<string>> */
    private const array BlockTypes = [
        '#' => ['Header'],
        '*' => ['Rule', 'List'],
        '+' => ['List'],
        '-' => ['SetextHeader', 'Table', 'Rule', 'List'],
        '0' => ['List'],
        '1' => ['List'],
        '2' => ['List'],
        '3' => ['List'],
        '4' => ['List'],
        '5' => ['List'],
        '6' => ['List'],
        '7' => ['List'],
        '8' => ['List'],
        '9' => ['List'],
        ':' => ['Table'],
        '<' => ['Comment', 'Markup'],
        '=' => ['SetextHeader'],
        '>' => ['Quote'],
        '[' => ['Reference'],
        '_' => ['Rule'],
        '`' => ['FencedCode'],
        '|' => ['Table'],
        '~' => ['FencedCode'],
    ];

    /** @var list<string> */
    private const array unmarkedBlockTypes = ['Code'];

    private function lines(array $lines): string
    {
        $CurrentBlock = null;

        foreach ($lines as $line) {
            if (rtrim($line) === '') {
                if (isset($CurrentBlock)) {
                    $CurrentBlock['interrupted'] = true;
                }

                continue;
            }

            if (str_contains($line, "\t")) {
                $parts = explode("\t", $line);

                $line = $parts[0];

                unset($parts[0]);

                foreach ($parts as $part) {
                    $shortage = 4 - mb_strlen($line, 'utf-8') % 4;

                    $line .= str_repeat(' ', $shortage);
                    $line .= $part;
                }
            }

            $indent = 0;

            while (isset($line[$indent]) and $line[$indent] === ' ') {
                $indent++;
            }

            $text = $indent > 0 ? substr($line, $indent) : $line;

            $Line = ['body' => $line, 'indent' => $indent, 'text' => $text];

            if (isset($CurrentBlock['continuable'])) {
                $Block = $this->{'block' . $CurrentBlock['type'] . 'Continue'}($Line, $CurrentBlock);

                if (isset($Block)) {
                    $CurrentBlock = $Block;

                    continue;
                }

                if ($this->isBlockCompletable($CurrentBlock['type'])) {
                    $CurrentBlock = $this->{'block' . $CurrentBlock['type'] . 'Complete'}($CurrentBlock);
                }
            }

            $marker = $text[0];

            $blockTypes = self::unmarkedBlockTypes;

            if (isset(self::BlockTypes[$marker])) {
                foreach (self::BlockTypes[$marker] as $blockType) {
                    $blockTypes [] = $blockType;
                }
            }

            foreach ($blockTypes as $blockType) {
                $Block = $this->{'block' . $blockType}($Line, $CurrentBlock);

                if (isset($Block)) {
                    $Block['type'] = $blockType;

                    if (!isset($Block['identified'])) {
                        $Blocks [] = $CurrentBlock;

                        $Block['identified'] = true;
                    }

                    if ($this->isBlockContinuable($blockType)) {
                        $Block['continuable'] = true;
                    }

                    $CurrentBlock = $Block;

                    continue 2;
                }
            }

            if (isset($CurrentBlock) and !isset($CurrentBlock['type']) and !isset($CurrentBlock['interrupted'])) {
                $CurrentBlock['element']['text'] .= "\n" . $text;
            } else {
                $Blocks [] = $CurrentBlock;

                $CurrentBlock = $this->paragraph($Line);

                $CurrentBlock['identified'] = true;
            }
        }

        if (isset($CurrentBlock['continuable']) and $this->isBlockCompletable($CurrentBlock['type'])) {
            $CurrentBlock = $this->{'block' . $CurrentBlock['type'] . 'Complete'}($CurrentBlock);
        }

        $Blocks [] = $CurrentBlock;

        unset($Blocks[0]);

        $markup = '';

        foreach ($Blocks as $Block) {
            if (isset($Block['hidden'])) {
                continue;
            }

            $markup .= "\n";
            $markup .= $Block['markup'] ?? $this->element($Block['element']);
        }

        $markup .= "\n";

        return $markup;
    }

    private function isBlockContinuable(string $Type): bool
    {
        return method_exists($this, 'block' . $Type . 'Continue');
    }

    private function isBlockCompletable(string $Type): bool
    {
        return method_exists($this, 'block' . $Type . 'Complete');
    }

    private function blockCode(array $Line, ?array $Block = null): ?array
    {
        if (isset($Block) and !isset($Block['type']) and !isset($Block['interrupted'])) {
            return null;
        }

        if ($Line['indent'] >= 4) {
            $text = substr($Line['body'], 4);

            return [
                'element' => [
                    'name'    => 'pre',
                    'handler' => 'element',
                    'text'    => [
                        'name' => 'code',
                        'text' => $text,
                    ],
                ],
            ];
        }
        return null;
    }

    private function blockCodeContinue(array $Line, array $Block): ?array
    {
        if ($Line['indent'] >= 4) {
            if (isset($Block['interrupted'])) {
                $Block['element']['text']['text'] .= "\n";

                unset($Block['interrupted']);
            }

            $Block['element']['text']['text'] .= "\n";

            $text = substr($Line['body'], 4);

            $Block['element']['text']['text'] .= $text;

            return $Block;
        }
        return null;
    }

    private function blockCodeComplete(array $Block): array
    {
        $text = $Block['element']['text']['text'];

        $Block['element']['text']['text'] = $text;

        return $Block;
    }

    private function blockComment(array $Line): ?array
    {
        if ($this->markupEscaped or $this->safeMode) {
            return null;
        }

        if (isset($Line['text'][3]) and $Line['text'][3] === '-' and $Line['text'][2] === '-' and $Line['text'][1]
            === '!') {
            $Block = [
                'markup' => $Line['body'],
            ];

            if (str_ends_with($Line['text'], '-->')) {
                $Block['closed'] = true;
            }

            return $Block;
        }
        return null;
    }

    private function blockCommentContinue(array $Line, array $Block): ?array
    {
        if (isset($Block['closed'])) {
            return null;
        }

        $Block['markup'] .= "\n" . $Line['body'];

        if (str_ends_with($Line['text'], '-->')) {
            $Block['closed'] = true;
        }

        return $Block;
    }

    private function blockFencedCode(array $Line): ?array
    {
        if (preg_match('/^[' . $Line['text'][0] . ']{3,}[ ]*([^`]+)?[ ]*$/', $Line['text'], $matches)) {
            $Element = [
                'name' => 'code',
                'text' => '',
            ];

            if (isset($matches[1])) {
                /**
                 * https://www.w3.org/TR/2011/WD-html5-20110525/elements.html#classes
                 * Every HTML element may have a class attribute specified.
                 * The attribute, if specified, must have a value that is a set
                 * of space-separated tokens representing the various classes
                 * that the element belongs to.
                 * [...]
                 * The space characters, for the purposes of this specification,
                 * are U+0020 SPACE, U+0009 CHARACTER TABULATION (tab),
                 * U+000A LINE FEED (LF), U+000C FORM FEED (FF), and
                 * U+000D CARRIAGE RETURN (CR).
                 */
                $language = substr($matches[1], 0, strcspn($matches[1], " \t\n\f\r"));

                $class = 'language-' . $language;

                $Element['attributes'] = [
                    'class' => $class,
                ];
            }

            return [
                'char'    => $Line['text'][0],
                'element' => [
                    'name'    => 'pre',
                    'handler' => 'element',
                    'text'    => $Element,
                ],
            ];
        }
        return null;
    }

    private function blockFencedCodeContinue(array $Line, array $Block): ?array
    {
        if (isset($Block['complete'])) {
            return null;
        }

        if (isset($Block['interrupted'])) {
            $Block['element']['text']['text'] .= "\n";

            unset($Block['interrupted']);
        }

        if (preg_match('/^' . $Block['char'] . '{3,}[ ]*$/', $Line['text'])) {
            $Block['element']['text']['text'] = substr($Block['element']['text']['text'], 1);

            $Block['complete'] = true;

            return $Block;
        }

        $Block['element']['text']['text'] .= "\n" . $Line['body'];

        return $Block;
    }

    private function blockFencedCodeComplete(array $Block): array
    {
        $text = $Block['element']['text']['text'];

        $Block['element']['text']['text'] = $text;

        return $Block;
    }

    private function blockHeader(array $Line): ?array
    {
        if (isset($Line['text'][1])) {
            $level = 1;

            while (isset($Line['text'][$level]) and $Line['text'][$level] === '#') {
                $level++;
            }

            if ($level > 6) {
                return null;
            }

            $text = trim($Line['text'], '# ');

            return [
                'element' => [
                    'name'    => 'h' . min(6, $level),
                    'text'    => $text,
                    'handler' => 'line',
                ],
            ];
        }
        return null;
    }

    private function blockList(array $Line): ?array
    {
        [$name, $pattern] = $Line['text'][0] <= '-' ? ['ul', '[*+-]'] : ['ol', '[0-9]+[.]'];

        if (preg_match('/^(' . $pattern . '[ ]+)(.*)/', $Line['text'], $matches)) {
            $Block = [
                'indent'  => $Line['indent'],
                'pattern' => $pattern,
                'element' => [
                    'name'    => $name,
                    'handler' => 'elements',
                ],
            ];

            if ($name === 'ol') {
                $listStart = strstr($matches[0], '.', true);

                if ($listStart !== '1') {
                    $Block['element']['attributes'] = ['start' => $listStart];
                }
            }

            $Block['li'] = [
                'name'    => 'li',
                'handler' => 'li',
                'text'    => [
                    $matches[2],
                ],
            ];

            $Block['element']['text'] [] = &$Block['li'];

            return $Block;
        }
        return null;
    }

    private function blockListContinue(array $Line, array $Block): ?array
    {
        if ($Block['indent'] === $Line['indent'] and preg_match('/^' . $Block['pattern'] . '(?:[ ]+(.*)|$)/',
                $Line['text'], $matches)) {
            if (isset($Block['interrupted'])) {
                $Block['li']['text'] [] = '';

                $Block['loose'] = true;

                unset($Block['interrupted']);
            }

            unset($Block['li']);

            $text = $matches[1] ?? '';

            $Block['li'] = [
                'name'    => 'li',
                'handler' => 'li',
                'text'    => [
                    $text,
                ],
            ];

            $Block['element']['text'] [] = &$Block['li'];

            return $Block;
        }

        if ($Line['text'][0] === '[' and $this->blockReference($Line)) {
            return $Block;
        }

        if (!isset($Block['interrupted'])) {
            $text = preg_replace('/^[ ]{0,4}/', '', $Line['body']);

            $Block['li']['text'] [] = $text;

            return $Block;
        }

        if ($Line['indent'] > 0) {
            $Block['li']['text'] [] = '';

            $text = preg_replace('/^[ ]{0,4}/', '', $Line['body']);

            $Block['li']['text'] [] = $text;

            unset($Block['interrupted']);

            return $Block;
        }
        return null;
    }

    private function blockListComplete(array $Block): array
    {
        if (isset($Block['loose'])) {
            foreach ($Block['element']['text'] as &$li) {
                if (end($li['text']) !== '') {
                    $li['text'] [] = '';
                }
            }
        }

        return $Block;
    }

    private function blockQuote(array $Line): ?array
    {
        if (preg_match('/^>[ ]?(.*)/', $Line['text'], $matches)) {
            return [
                'element' => [
                    'name'    => 'blockquote',
                    'handler' => 'lines',
                    'text'    => (array)$matches[1],
                ],
            ];
        }
        return null;
    }

    private function blockQuoteContinue(array $Line, array $Block): ?array
    {
        if ($Line['text'][0] === '>' and preg_match('/^>[ ]?(.*)/', $Line['text'], $matches)) {
            if (isset($Block['interrupted'])) {
                $Block['element']['text'] [] = '';

                unset($Block['interrupted']);
            }

            $Block['element']['text'] [] = $matches[1];

            return $Block;
        }

        if (!isset($Block['interrupted'])) {
            $Block['element']['text'] [] = $Line['text'];

            return $Block;
        }
        return null;
    }

    private function blockRule(array $Line): ?array
    {
        if (preg_match('/^([' . $Line['text'][0] . '])([ ]*\1){2,}[ ]*$/', $Line['text'])) {
            return [
                'element' => [
                    'name' => 'hr',
                ],
            ];
        }
        return null;
    }

    private function blockSetextHeader(array $Line, ?array $Block = null): ?array
    {
        if (!isset($Block) or isset($Block['type']) or isset($Block['interrupted'])) {
            return null;
        }

        if (rtrim($Line['text'], $Line['text'][0]) === '') {
            $Block['element']['name'] = $Line['text'][0] === '=' ? 'h1' : 'h2';

            return $Block;
        }
        return null;
    }

    private function blockMarkup(array $Line): ?array
    {
        if ($this->markupEscaped or $this->safeMode) {
            return null;
        }

        if (preg_match('/^<(\w[\w-]*)(?:[ ]*' . self::regexHtmlAttribute . ')*[ ]*(\/)?>/', $Line['text'], $matches)) {
            $element = strtolower($matches[1]);

            if (in_array($element, self::textLevelElements, true)) {
                return null;
            }

            $Block = [
                'name'   => $matches[1],
                'depth'  => 0,
                'markup' => $Line['text'],
            ];

            $length = strlen($matches[0]);

            $remainder = substr($Line['text'], $length);

            if (trim($remainder) === '') {
                if (isset($matches[2]) or in_array($matches[1], self::voidElements, true)) {
                    $Block['closed'] = true;

                    $Block['void'] = true;
                }
            } else {
                if (isset($matches[2]) or in_array($matches[1], self::voidElements, true)) {
                    return null;
                }

                if (preg_match('/<\/' . $matches[1] . '>[ ]*$/i', $remainder)) {
                    $Block['closed'] = true;
                }
            }

            return $Block;
        }
        return null;
    }

    private function blockMarkupContinue(array $Line, array $Block): ?array
    {
        if (isset($Block['closed'])) {
            return null;
        }

        if (preg_match('/^<' . $Block['name'] . '(?:[ ]*' . self::regexHtmlAttribute . ')*[ ]*>/i',
            $Line['text'])) // open
        {
            $Block['depth']++;
        }

        if (preg_match('/(.*?)<\/' . $Block['name'] . '>[ ]*$/i', $Line['text'])) // close
        {
            if ($Block['depth'] > 0) {
                $Block['depth']--;
            } else {
                $Block['closed'] = true;
            }
        }

        if (isset($Block['interrupted'])) {
            $Block['markup'] .= "\n";

            unset($Block['interrupted']);
        }

        $Block['markup'] .= "\n" . $Line['body'];

        return $Block;
    }

    private function blockReference(array $Line): ?array
    {
        if (preg_match('/^\[(.+?)\]:[ ]*<?(\S+?)>?(?:[ ]+["\'(](.+)["\')])?[ ]*$/', $Line['text'], $matches)) {
            $id = strtolower($matches[1]);

            $Data = [
                'url'   => $matches[2],
                'title' => null,
            ];

            if (isset($matches[3])) {
                $Data['title'] = $matches[3];
            }

            $this->DefinitionData['Reference'][$id] = $Data;

            return [
                'hidden' => true,
            ];
        }
        return null;
    }

    private function blockTable(array $Line, ?array $Block = null): ?array
    {
        if (!isset($Block) or isset($Block['type']) or isset($Block['interrupted'])) {
            return null;
        }

        if (str_contains($Block['element']['text'], '|') and rtrim($Line['text'], ' -:|') === '') {
            $alignments = [];

            $divider = $Line['text'];

            $divider = trim($divider);
            $divider = trim($divider, '|');

            $dividerCells = explode('|', $divider);

            foreach ($dividerCells as $dividerCell) {
                $dividerCell = trim($dividerCell);

                if ($dividerCell === '') {
                    continue;
                }

                $alignment = null;

                if ($dividerCell[0] === ':') {
                    $alignment = 'left';
                }

                if (str_ends_with($dividerCell, ':')) {
                    $alignment = $alignment === 'left' ? 'center' : 'right';
                }

                $alignments [] = $alignment;
            }

            $HeaderElements = [];

            $header = $Block['element']['text'];

            $header = trim($header);
            $header = trim($header, '|');

            $headerCells = explode('|', $header);

            foreach ($headerCells as $index => $headerCell) {
                $headerCell = trim($headerCell);

                $HeaderElement = [
                    'name'    => 'th',
                    'text'    => $headerCell,
                    'handler' => 'line',
                ];

                if (isset($alignments[$index])) {
                    $alignment = $alignments[$index];

                    $HeaderElement['attributes'] = [
                        'style' => 'text-align: ' . $alignment . ';',
                    ];
                }

                $HeaderElements [] = $HeaderElement;
            }

            $Block = [
                'alignments' => $alignments,
                'identified' => true,
                'element'    => [
                    'name'    => 'table',
                    'handler' => 'elements',
                ],
            ];

            $Block['element']['text'] [] = [
                'name'    => 'thead',
                'handler' => 'elements',
            ];

            $Block['element']['text'] [] = [
                'name'    => 'tbody',
                'handler' => 'elements',
                'text'    => [],
            ];

            $Block['element']['text'][0]['text'] [] = [
                'name'    => 'tr',
                'handler' => 'elements',
                'text'    => $HeaderElements,
            ];

            return $Block;
        }
        return null;
    }

    private function blockTableContinue(array $Line, array $Block): ?array
    {
        if (isset($Block['interrupted'])) {
            return null;
        }

        if ($Line['text'][0] === '|' or strpos($Line['text'], '|')) {
            $Elements = [];

            $row = $Line['text'];

            $row = trim($row);
            $row = trim($row, '|');

            preg_match_all('/(?:(\\\\[|])|[^|`]|`[^`]+`|`)+/', $row, $matches);

            foreach ($matches[0] as $index => $cell) {
                $cell = trim($cell);

                $Element = [
                    'name'    => 'td',
                    'handler' => 'line',
                    'text'    => $cell,
                ];

                if (isset($Block['alignments'][$index])) {
                    $Element['attributes'] = [
                        'style' => 'text-align: ' . $Block['alignments'][$index] . ';',
                    ];
                }

                $Elements [] = $Element;
            }

            $Element = [
                'name'    => 'tr',
                'handler' => 'elements',
                'text'    => $Elements,
            ];

            $Block['element']['text'][1]['text'] [] = $Element;

            return $Block;
        }
        return null;
    }

    private function paragraph(array $Line): array
    {
        return [
            'element' => [
                'name'    => 'p',
                'text'    => $Line['text'],
                'handler' => 'line',
            ],
        ];
    }

    private const array InlineTypes = [
        '"'  => ['SpecialCharacter'],
        '!'  => ['Image'],
        '&'  => ['SpecialCharacter'],
        '*'  => ['Emphasis'],
        ':'  => ['Url'],
        '<'  => ['UrlTag', 'EmailTag', 'Markup', 'SpecialCharacter'],
        '>'  => ['SpecialCharacter'],
        '['  => ['Link'],
        '_'  => ['Emphasis'],
        '`'  => ['Code'],
        '~'  => ['Strikethrough'],
        '\\' => ['EscapeSequence'],
    ];

    private string $inlineMarkerList = '!"*_&[:<>`~\\';

    private function line(string $text, array $nonNestables = []): string
    {
        $markup = '';

        // $excerpt is based on the first occurrence of a marker

        while ($excerpt = strpbrk($text, $this->inlineMarkerList)) {
            $marker = $excerpt[0];

            $markerPosition = strpos($text, $marker);

            $Excerpt = ['text' => $excerpt, 'context' => $text];

            foreach (self::InlineTypes[$marker] as $inlineType) {
                // check to see if the current inline type is nestable in the current context

                if (!empty($nonNestables) and in_array($inlineType, $nonNestables, true)) {
                    continue;
                }

                $Inline = $this->{'inline' . $inlineType}($Excerpt);

                if (!isset($Inline)) {
                    continue;
                }

                // makes sure that the inline belongs to "our" marker

                if (isset($Inline['position']) and $Inline['position'] > $markerPosition) {
                    continue;
                }

                // sets a default inline position

                if (!isset($Inline['position'])) {
                    $Inline['position'] = $markerPosition;
                }

                // cause the new element to 'inherit' our non nestables

                foreach ($nonNestables as $non_nestable) {
                    $Inline['element']['nonNestables'][] = $non_nestable;
                }

                // the text that comes before the inline
                $unmarkedText = substr($text, 0, $Inline['position']);

                // compile the unmarked text
                $markup .= $this->unmarkedText($unmarkedText);

                // compile the inline
                $markup .= $Inline['markup'] ?? $this->element($Inline['element']);

                // remove the examined text
                $text = substr($text, $Inline['position'] + $Inline['extent']);

                continue 2;
            }

            // the marker does not belong to an inline

            $unmarkedText = substr($text, 0, $markerPosition + 1);

            $markup .= $this->unmarkedText($unmarkedText);

            $text = substr($text, $markerPosition + 1);
        }

        $markup .= $this->unmarkedText($text);

        return $markup;
    }

    private function inlineCode(array $Excerpt): ?array
    {
        $marker = $Excerpt['text'][0];

        if (preg_match('/^(' . $marker . '+)[ ]*(.+?)[ ]*(?<!' . $marker . ')\1(?!' . $marker . ')/s', $Excerpt['text'],
            $matches)) {
            $text = $matches[2];
            $text = preg_replace("/[ ]*\n/", ' ', $text);

            return [
                'extent'  => strlen($matches[0]),
                'element' => [
                    'name' => 'code',
                    'text' => $text,
                ],
            ];
        }
        return null;
    }

    private function inlineEmailTag(array $Excerpt): ?array
    {
        if (str_contains($Excerpt['text'], '>') and preg_match('/^<((mailto:)?\S+?@\S+?)>/i', $Excerpt['text'],
                $matches)) {
            $url = $matches[1];

            if (!isset($matches[2])) {
                $url = 'mailto:' . $url;
            }

            return [
                'extent'  => strlen($matches[0]),
                'element' => [
                    'name'       => 'a',
                    'text'       => $matches[1],
                    'attributes' => [
                        'href' => $url,
                    ],
                ],
            ];
        }
        return null;
    }

    private function inlineEmphasis(array $Excerpt): ?array
    {
        if (!isset($Excerpt['text'][1])) {
            return null;
        }

        $marker = $Excerpt['text'][0];

        if ($Excerpt['text'][1] === $marker and preg_match(self::StrongRegex[$marker], $Excerpt['text'], $matches)) {
            $emphasis = 'strong';
        } elseif (preg_match(self::EmRegex[$marker], $Excerpt['text'], $matches)) {
            $emphasis = 'em';
        } else {
            return null;
        }

        return [
            'extent'  => strlen($matches[0]),
            'element' => [
                'name'    => $emphasis,
                'handler' => 'line',
                'text'    => $matches[1],
            ],
        ];
    }

    private function inlineEscapeSequence(array $Excerpt): ?array
    {
        if (isset($Excerpt['text'][1]) and in_array($Excerpt['text'][1], self::specialCharacters, true)) {
            return [
                'markup' => $Excerpt['text'][1],
                'extent' => 2,
            ];
        }
        return null;
    }

    private function inlineImage(array $Excerpt): ?array
    {
        if (!isset($Excerpt['text'][1]) or $Excerpt['text'][1] !== '[') {
            return null;
        }

        $Excerpt['text'] = substr($Excerpt['text'], 1);

        $Link = $this->inlineLink($Excerpt);

        if ($Link === null) {
            return null;
        }

        $Inline = [
            'extent'  => $Link['extent'] + 1,
            'element' => [
                'name'       => 'img',
                'attributes' => [
                    'src' => $Link['element']['attributes']['href'],
                    'alt' => $Link['element']['text'],
                ],
            ],
        ];

        $Inline['element']['attributes'] += $Link['element']['attributes'];

        unset($Inline['element']['attributes']['href']);

        return $Inline;
    }

    private function inlineLink(array $Excerpt): ?array
    {
        $Element = [
            'name'         => 'a',
            'handler'      => 'line',
            'nonNestables' => ['Url', 'Link'],
            'text'         => null,
            'attributes'   => [
                'href'  => null,
                'title' => null,
            ],
        ];

        $extent = 0;

        $remainder = $Excerpt['text'];

        if (preg_match('/\[((?:[^][]++|(?R))*+)\]/', $remainder, $matches)) {
            $Element['text'] = $matches[1];

            $extent += strlen($matches[0]);

            $remainder = substr($remainder, $extent);
        } else {
            return null;
        }

        if (preg_match('/^[(]\s*+((?:[^ ()]++|[(][^ )]+[)])++)(?:[ ]+("[^"]*"|\'[^\']*\'))?\s*[)]/', $remainder,
            $matches)) {
            $Element['attributes']['href'] = $matches[1];

            if (isset($matches[2])) {
                $Element['attributes']['title'] = substr($matches[2], 1, -1);
            }

            $extent += strlen($matches[0]);
        } else {
            if (preg_match('/^\s*\[(.*?)\]/', $remainder, $matches)) {
                $definition = $matches[1] !== '' ? $matches[1] : $Element['text'];
                $definition = strtolower($definition);

                $extent += strlen($matches[0]);
            } else {
                $definition = strtolower($Element['text']);
            }

            if (!isset($this->DefinitionData['Reference'][$definition])) {
                return null;
            }

            $Definition = $this->DefinitionData['Reference'][$definition];

            $Element['attributes']['href'] = $Definition['url'];
            $Element['attributes']['title'] = $Definition['title'];
        }

        return [
            'extent'  => $extent,
            'element' => $Element,
        ];
    }

    private function inlineMarkup(array $Excerpt): ?array
    {
        if ($this->markupEscaped or $this->safeMode or !str_contains($Excerpt['text'], '>')) {
            return null;
        }

        if ($Excerpt['text'][1] === '/' and preg_match('/^<\/\w[\w-]*[ ]*>/', $Excerpt['text'], $matches)) {
            return [
                'markup' => $matches[0],
                'extent' => strlen($matches[0]),
            ];
        }

        if ($Excerpt['text'][1] === '!' and preg_match('/^<!---?[^>-](?:-?[^-])*-->/', $Excerpt['text'], $matches)) {
            return [
                'markup' => $matches[0],
                'extent' => strlen($matches[0]),
            ];
        }

        if ($Excerpt['text'][1] !== ' ' and preg_match('/^<\w[\w-]*(?:[ ]*'
                . self::regexHtmlAttribute
                . ')*[ ]*\/?>/s', $Excerpt['text'], $matches)) {
            return [
                'markup' => $matches[0],
                'extent' => strlen($matches[0]),
            ];
        }
        return null;
    }

    private function inlineSpecialCharacter(array $Excerpt): ?array
    {
        if ($Excerpt['text'][0] === '&' and !preg_match('/^&#?\w+;/', $Excerpt['text'])) {
            return [
                'markup' => '&amp;',
                'extent' => 1,
            ];
        }

        $SpecialCharacter = ['>' => 'gt', '<' => 'lt', '"' => 'quot'];

        if (isset($SpecialCharacter[$Excerpt['text'][0]])) {
            return [
                'markup' => '&' . $SpecialCharacter[$Excerpt['text'][0]] . ';',
                'extent' => 1,
            ];
        }
        return null;
    }

    private function inlineStrikethrough(array $Excerpt): ?array
    {
        if (!isset($Excerpt['text'][1])) {
            return null;
        }

        if ($Excerpt['text'][1] === '~' and preg_match('/^~~(?=\S)(.+?)(?<=\S)~~/', $Excerpt['text'], $matches)) {
            return [
                'extent'  => strlen($matches[0]),
                'element' => [
                    'name'    => 'del',
                    'text'    => $matches[1],
                    'handler' => 'line',
                ],
            ];
        }
        return null;
    }

    private function inlineUrl(array $Excerpt): ?array
    {
        if ($this->urlsLinked !== true or !isset($Excerpt['text'][2]) or $Excerpt['text'][2] !== '/') {
            return null;
        }

        if (preg_match('/\bhttps?:[\/]{2}[^\s<]+\b\/*/ui', $Excerpt['context'], $matches, PREG_OFFSET_CAPTURE)) {
            $url = $matches[0][0];

            return [
                'extent'   => strlen($matches[0][0]),
                'position' => $matches[0][1],
                'element'  => [
                    'name'       => 'a',
                    'text'       => $url,
                    'attributes' => [
                        'href' => $url,
                    ],
                ],
            ];
        }
        return null;
    }

    private function inlineUrlTag(array $Excerpt): ?array
    {
        if (str_contains($Excerpt['text'], '>') and preg_match('/^<(\w+:\/{2}[^ >]+)>/i', $Excerpt['text'],
                $matches)) {
            $url = $matches[1];

            return [
                'extent'  => strlen($matches[0]),
                'element' => [
                    'name'       => 'a',
                    'text'       => $url,
                    'attributes' => [
                        'href' => $url,
                    ],
                ],
            ];
        }
        return null;
    }

    private function unmarkedText(string $text): array|string|null
    {
        if ($this->breaksEnabled) {
            $text = preg_replace('/[ ]*\n/', "<br />\n", $text);
        } else {
            $text = preg_replace('/(?:[ ][ ]+|[ ]*\\\\)\n/', "<br />\n", $text);
            $text = str_replace(" \n", "\n", $text);
        }

        return $text;
    }

    private function element(array $Element): string
    {
        if ($this->safeMode) {
            $Element = $this->sanitiseElement($Element);
        }

        $markup = '<' . $Element['name'];

        if (isset($Element['attributes'])) {
            foreach ($Element['attributes'] as $name => $value) {
                if ($value === null) {
                    continue;
                }

                $markup .= ' ' . $name . '="' . self::escape($value) . '"';
            }
        }

        $permitRawHtml = false;

        if (isset($Element['text'])) {
            $text = $Element['text'];
        }
        // very strongly consider an alternative if you're writing an
        // extension
        elseif (isset($Element['rawHtml'])) {
            $text = $Element['rawHtml'];
            $allowRawHtmlInSafeMode = isset($Element['allowRawHtmlInSafeMode']) && $Element['allowRawHtmlInSafeMode'];
            $permitRawHtml = !$this->safeMode || $allowRawHtmlInSafeMode;
        }

        if (isset($text)) {
            $markup .= '>';

            if (!isset($Element['nonNestables'])) {
                $Element['nonNestables'] = [];
            }

            if (isset($Element['handler'])) {
                $markup .= $this->{$Element['handler']}($text, $Element['nonNestables']);
            } elseif (!$permitRawHtml) {
                $markup .= self::escape($text, true);
            } else {
                $markup .= $text;
            }

            $markup .= '</' . $Element['name'] . '>';
        } else {
            $markup .= ' />';
        }

        return $markup;
    }

    private function elements(array $Elements): string
    {
        $markup = '';

        foreach ($Elements as $Element) {
            $markup .= "\n" . $this->element($Element);
        }

        $markup .= "\n";

        return $markup;
    }

    private function li(array $lines): array|string
    {
        $markup = $this->lines($lines);

        $trimmedMarkup = trim($markup);

        if (!in_array('', $lines, true) and str_starts_with($trimmedMarkup, '<p>')) {
            $markup = $trimmedMarkup;
            $markup = substr($markup, 3);

            $position = strpos($markup, "</p>");

            $markup = substr_replace($markup, '', $position, 4);
        }

        return $markup;
    }

    private function sanitiseElement(array $Element): array
    {
        static $goodAttribute = '/^[a-zA-Z0-9][a-zA-Z0-9-_]*+$/';
        static $safeUrlNameToAtt = [
            'a'   => 'href',
            'img' => 'src',
        ];

        if (isset($safeUrlNameToAtt[$Element['name']])) {
            $Element = $this->filterUnsafeUrlInAttribute($Element, $safeUrlNameToAtt[$Element['name']]);
        }

        if (!empty($Element['attributes'])) {
            foreach ($Element['attributes'] as $att => $val) {
                // filter out badly parsed attribute
                if (!preg_match($goodAttribute, $att)) {
                    unset($Element['attributes'][$att]);
                } // dump onevent attribute
                elseif (self::striAtStart($att, 'on')) {
                    unset($Element['attributes'][$att]);
                }
            }
        }

        return $Element;
    }

    private function filterUnsafeUrlInAttribute(array $Element, string $attribute): array
    {
        if (array_any(self::safeLinksWhitelist,
            fn($scheme) => self::striAtStart($Element['attributes'][$attribute], $scheme))) {
            return $Element;
        }

        $Element['attributes'][$attribute] = str_replace(':', '%3A', $Element['attributes'][$attribute]);

        return $Element;
    }

    private static function escape(string $text, bool $allowQuotes = false): string
    {
        return htmlspecialchars($text, $allowQuotes ? ENT_NOQUOTES : ENT_QUOTES, 'UTF-8');
    }

    private static function striAtStart(string $string, string $needle): bool
    {
        $len = strlen($needle);

        if ($len > strlen($string)) {
            return false;
        }

        return stripos($string, strtolower($needle)) === 0;
    }

    //endregion
}
