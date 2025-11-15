<?php

//
// Sideways Markdown parser - a refactored fork of Parsedown
//
// Author: Chuck Adams (chaz@chaz.works)
//
// Based on Parsedown, by Emanuil Rusev (http://erusev.com), distributed under The MIT License:
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
//

namespace AspireBuild\Tools\Sideways;

use Closure;
use DOMDocument;
use DOMElement;
use InvalidArgumentException;

class Sideways
{

    public function __construct(
        protected readonly bool $breaksEnabled = false,
        protected readonly bool $markupEscaped = false,
        protected readonly bool $urlsLinked = true,
        protected readonly bool $safeMode = false,
        protected readonly bool $strictMode = false,
        protected readonly bool $extra = false,
    ) {

        if ($extra) {
            $this->BlockTypes[':'] [] = 'DefinitionList';
            $this->BlockTypes['*'] [] = 'Abbreviation';

            # identify footnote definitions before reference definitions
            array_unshift($this->BlockTypes['['], 'Footnote');

            # identify footnote markers before before links
            array_unshift($this->InlineTypes['['], 'FootnoteMarker');
        }
    }

    public function text($text): string
    {
        $Elements = $this->textElements($text);
        $markup = $this->elements($Elements);
        $markup = trim($markup, "\n");

        if ($this->extra) {
            $markup = preg_replace('/<\/dl>\s+<dl>\s+/', '', $markup);

            if (isset($this->DefinitionData['Footnote'])) {
                $Element = $this->buildFootnoteElement();

                $markup .= "\n" . $this->element($Element);
            }
        }

        return $markup;
    }

    protected function textElements($text): array
    {
        // make sure no definitions are set
        $this->DefinitionData = [];

        // standardize line breaks
        $text = str_replace(["\r\n", "\r"], "\n", $text);

        // remove surrounding line breaks
        $text = trim($text, "\n");

        // split text into lines
        $lines = explode("\n", $text);

        // iterate through lines to identify blocks
        return $this->linesElements($lines);
    }

    protected array $safeLinksWhitelist = [
        'http://',
        'https://',
        'ftp://',
        'ftps://',
        'mailto:',
        'tel:',
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

    protected array $BlockTypes = [
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


    protected array $unmarkedBlockTypes = [
        'Code',
    ];

    protected function lines(array $lines): string
    {
        return $this->elements($this->linesElements($lines));
    }

    protected function linesElements(array $lines): array
    {
        $Elements = [];
        $CurrentBlock = null;

        foreach ($lines as $line) {
            if (rtrim($line) === '') {
                if (isset($CurrentBlock)) {
                    $CurrentBlock['interrupted'] = (isset($CurrentBlock['interrupted'])
                        ? $CurrentBlock['interrupted'] + 1 : 1
                    );
                }

                continue;
            }

            while (($beforeTab = strstr($line, "\t", true)) !== false) {
                $shortage = 4 - mb_strlen($beforeTab, 'utf-8') % 4;

                $line = $beforeTab
                    . str_repeat(' ', $shortage)
                    . substr($line, strlen($beforeTab) + 1);
            }

            $indent = strspn($line, ' ');

            $text = $indent > 0 ? substr($line, $indent) : $line;


            $Line = ['body' => $line, 'indent' => $indent, 'text' => $text];


            if (isset($CurrentBlock['continuable'])) {
                $methodName = 'block' . $CurrentBlock['type'] . 'Continue';
                $Block = $this->$methodName($Line, $CurrentBlock);

                if (isset($Block)) {
                    $CurrentBlock = $Block;

                    continue;
                }

                if ($this->isBlockCompletable($CurrentBlock['type'])) {
                    $methodName = 'block' . $CurrentBlock['type'] . 'Complete';
                    $CurrentBlock = $this->$methodName($CurrentBlock);
                }
            }


            $marker = $text[0];


            $blockTypes = $this->unmarkedBlockTypes;

            if (isset($this->BlockTypes[$marker])) {
                foreach ($this->BlockTypes[$marker] as $blockType) {
                    $blockTypes [] = $blockType;
                }
            }

            foreach ($blockTypes as $blockType) {
                $Block = $this->_dispatch('block', $blockType)($Line, $CurrentBlock);

                if (isset($Block)) {
                    $Block['type'] = $blockType;

                    if (!isset($Block['identified'])) {
                        if (isset($CurrentBlock)) {
                            $Elements[] = $this->extractElement($CurrentBlock);
                        }

                        $Block['identified'] = true;
                    }

                    if ($this->isBlockContinuable($blockType)) {
                        $Block['continuable'] = true;
                    }

                    $CurrentBlock = $Block;

                    continue 2;
                }
            }


            if (isset($CurrentBlock) and $CurrentBlock['type'] === 'Paragraph') {
                $Block = $this->paragraphContinue($Line, $CurrentBlock);
            }

            if (isset($Block)) {
                $CurrentBlock = $Block;
            } else {
                if (isset($CurrentBlock)) {
                    $Elements[] = $this->extractElement($CurrentBlock);
                }

                $CurrentBlock = $this->paragraph($Line);

                $CurrentBlock['identified'] = true;
            }
        }


        if (isset($CurrentBlock['continuable']) and $this->isBlockCompletable($CurrentBlock['type'])) {
            $methodName = 'block' . $CurrentBlock['type'] . 'Complete';
            $CurrentBlock = $this->$methodName($CurrentBlock);
        }


        if (isset($CurrentBlock)) {
            $Elements[] = $this->extractElement($CurrentBlock);
        }


        return $Elements;
    }

    protected function extractElement(array $Component)
    {
        if (!isset($Component['element'])) {
            if (isset($Component['markup'])) {
                $Component['element'] = ['rawHtml' => $Component['markup']];
            } elseif (isset($Component['hidden'])) {
                $Component['element'] = [];
            }
        }

        return $Component['element'];
    }

    protected function isBlockContinuable($Type): bool
    {
        // return method_exists($this, 'block' . $Type . 'Continue');
        return $this->_dispatch('continue', $Type) !== null;
    }

    protected function isBlockCompletable($Type): bool
    {
        return method_exists($this, 'block' . $Type . 'Complete');
    }

    protected function blockCode($Line, $Block = null): ?array
    {
        if (isset($Block) and $Block['type'] === 'Paragraph' and !isset($Block['interrupted'])) {
            return null;
        }

        if ($Line['indent'] >= 4) {
            $text = substr($Line['body'], 4);

            return [
                'element' => [
                    'name'    => 'pre',
                    'element' => [
                        'name' => 'code',
                        'text' => $text,
                    ],
                ],
            ];
        }
        return null;
    }

    protected function blockCodeContinue($Line, $Block): ?array
    {
        if ($Line['indent'] >= 4) {
            if (isset($Block['interrupted'])) {
                $Block['element']['element']['text'] .= str_repeat("\n", $Block['interrupted']);

                unset($Block['interrupted']);
            }

            $Block['element']['element']['text'] .= "\n";

            $text = substr($Line['body'], 4);

            $Block['element']['element']['text'] .= $text;

            return $Block;
        }
        return null;
    }

    protected function blockCodeComplete($Block)
    {
        return $Block;
    }

    protected function blockComment($Line): ?array
    {
        if ($this->markupEscaped or $this->safeMode) {
            return null;
        }

        if (str_starts_with($Line['text'], '<!--')) {
            $Block = [
                'element' => [
                    'rawHtml'   => $Line['body'],
                    'autobreak' => true,
                ],
            ];

            if (str_contains($Line['text'], '-->')) {
                $Block['closed'] = true;
            }

            return $Block;
        }
        return null;
    }

    protected function blockCommentContinue($Line, array $Block): ?array
    {
        if (isset($Block['closed'])) {
            return null;
        }

        $Block['element']['rawHtml'] .= "\n" . $Line['body'];

        if (str_contains($Line['text'], '-->')) {
            $Block['closed'] = true;
        }

        return $Block;
    }

    protected function blockFencedCode($Line): ?array
    {
        $marker = $Line['text'][0];

        $openerLength = strspn($Line['text'], $marker);

        if ($openerLength < 3) {
            return null;
        }

        $infostring = trim(substr($Line['text'], $openerLength), "\t ");

        if (str_contains($infostring, '`')) {
            return null;
        }

        $Element = [
            'name' => 'code',
            'text' => '',
        ];

        if ($infostring !== '') {
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
            $language = substr($infostring, 0, strcspn($infostring, " \t\n\f\r"));

            $Element['attributes'] = ['class' => "language-$language"];
        }

        return [
            'char'         => $marker,
            'openerLength' => $openerLength,
            'element'      => [
                'name'    => 'pre',
                'element' => $Element,
            ],
        ];
    }

    protected function blockFencedCodeContinue($Line, $Block): ?array
    {
        if (isset($Block['complete'])) {
            return null;
        }

        if (isset($Block['interrupted'])) {
            $Block['element']['element']['text'] .= str_repeat("\n", $Block['interrupted']);

            unset($Block['interrupted']);
        }

        if (($len = strspn($Line['text'], $Block['char'])) >= $Block['openerLength']
            and rtrim(substr($Line['text'], $len), ' ') === ''
        ) {
            $Block['element']['element']['text'] = substr($Block['element']['element']['text'], 1);

            $Block['complete'] = true;

            return $Block;
        }

        $Block['element']['element']['text'] .= "\n" . $Line['body'];

        return $Block;
    }

    protected function blockFencedCodeComplete($Block)
    {
        return $Block;
    }

    protected function blockHeader($Line): ?array
    {
        $level = strspn($Line['text'], '#');

        if ($level > 6) {
            return null;
        }

        $text = trim($Line['text'], '#');

        if ($this->strictMode and isset($text[0]) and $text[0] !== ' ') {
            return null;
        }

        $text = trim($text, ' ');

        $Block = [
            'element' => [
                'name'    => 'h' . $level,
                'handler' => [
                    'function'    => $this->lineElements(...),
                    'argument'    => $text,
                    'destination' => 'elements',
                ],
            ],
        ];

        if ($this->extra
            && preg_match('/[ #]*{(' . $this->regexAttribute . '+)}[ ]*$/', $Block['element']['handler']['argument'],
                $matches, PREG_OFFSET_CAPTURE)) {
            $attributeString = $matches[1][0];

            $Block['element']['attributes'] = $this->parseAttributeData($attributeString);

            $Block['element']['handler']['argument'] = substr($Block['element']['handler']['argument'], 0,
                $matches[0][1]);
        }

        return $Block;

    }

    protected function blockList($Line, ?array $CurrentBlock = null): ?array
    {
        [$name, $pattern] = $Line['text'][0] <= '-' ? ['ul', '[*+-]'] : ['ol', '[0-9]{1,9}+[.\)]'];

        if (preg_match('/^(' . $pattern . '([ ]++|$))(.*+)/', $Line['text'], $matches)) {
            $contentIndent = strlen($matches[2]);

            if ($contentIndent >= 5) {
                --$contentIndent;
                $matches[1] = substr($matches[1], 0, -$contentIndent);
                $matches[3] = str_repeat(' ', $contentIndent) . $matches[3];
            } elseif ($contentIndent === 0) {
                $matches[1] .= ' ';
            }

            $markerWithoutWhitespace = strstr($matches[1], ' ', true);

            $Block = [
                'indent'  => $Line['indent'],
                'pattern' => $pattern,
                'data'    => [
                    'type'       => $name,
                    'marker'     => $matches[1],
                    'markerType' => ($name === 'ul' ? $markerWithoutWhitespace : substr($markerWithoutWhitespace, -1)),
                ],
                'element' => [
                    'name'     => $name,
                    'elements' => [],
                ],
            ];
            $Block['data']['markerTypeRegex'] = preg_quote($Block['data']['markerType'], '/');

            if ($name === 'ol') {
                $listStart = ltrim(strstr($matches[1], $Block['data']['markerType'], true), '0') ?: '0';

                if ($listStart !== '1') {
                    if (
                        isset($CurrentBlock)
                        and $CurrentBlock['type'] === 'Paragraph'
                        and !isset($CurrentBlock['interrupted'])
                    ) {
                        return null;
                    }

                    $Block['element']['attributes'] = ['start' => $listStart];
                }
            }

            $Block['li'] = [
                'name'    => 'li',
                'handler' => [
                    'function'    => $this->li(...),
                    'argument'    => !empty($matches[3]) ? [$matches[3]] : [],
                    'destination' => 'elements',
                ],
            ];

            $Block['element']['elements'] [] = &$Block['li'];

            return $Block;
        }
        return null;
    }

    protected function blockListContinue($Line, array $Block): ?array
    {
        if (isset($Block['interrupted']) and empty($Block['li']['handler']['argument'])) {
            return null;
        }

        $requiredIndent = ($Block['indent'] + strlen($Block['data']['marker']));

        if ($Line['indent'] < $requiredIndent
            and (
                (
                    $Block['data']['type'] === 'ol'
                    and preg_match('/^[0-9]++' . $Block['data']['markerTypeRegex'] . '(?:[ ]++(.*)|$)/', $Line['text'],
                        $matches)
                ) or (
                    $Block['data']['type'] === 'ul'
                    and preg_match('/^' . $Block['data']['markerTypeRegex'] . '(?:[ ]++(.*)|$)/', $Line['text'],
                        $matches)
                )
            )) {
            if (isset($Block['interrupted'])) {
                $Block['li']['handler']['argument'] [] = '';

                $Block['loose'] = true;

                unset($Block['interrupted']);
            }

            unset($Block['li']);

            $text = $matches[1] ?? '';

            $Block['indent'] = $Line['indent'];

            $Block['li'] = [
                'name'    => 'li',
                'handler' => [
                    'function'    => $this->li(...),
                    'argument'    => [$text],
                    'destination' => 'elements',
                ],
            ];

            $Block['element']['elements'] [] = &$Block['li'];

            return $Block;
        }

        if ($Line['indent'] < $requiredIndent and $this->blockList($Line)
        ) {
            return null;
        }

        if ($Line['text'][0] === '[' and $this->blockReference($Line)) {
            return $Block;
        }

        if ($Line['indent'] >= $requiredIndent) {
            if (isset($Block['interrupted'])) {
                $Block['li']['handler']['argument'] [] = '';

                $Block['loose'] = true;

                unset($Block['interrupted']);
            }

            $text = substr($Line['body'], $requiredIndent);

            $Block['li']['handler']['argument'] [] = $text;

            return $Block;
        }

        if (!isset($Block['interrupted'])) {
            $text = preg_replace('/^[ ]{0,' . $requiredIndent . '}+/', '', $Line['body']);

            $Block['li']['handler']['argument'] [] = $text;

            return $Block;
        }
        return null;
    }

    protected function blockListComplete(array $Block): array
    {
        if (isset($Block['loose'])) {
            foreach ($Block['element']['elements'] as &$li) {
                if (end($li['handler']['argument']) !== '') {
                    $li['handler']['argument'] [] = '';
                }
            }
        }

        return $Block;
    }

    protected function blockQuote($Line): ?array
    {
        if (preg_match('/^>[ ]?+(.*+)/', $Line['text'], $matches)) {
            return [
                'element' => [
                    'name'    => 'blockquote',
                    'handler' => [
                        'function'    => $this->linesElements(...),
                        'argument'    => (array)$matches[1],
                        'destination' => 'elements',
                    ],
                ],
            ];
        }
        return null;
    }

    protected function blockQuoteContinue($Line, array $Block): ?array
    {
        if (isset($Block['interrupted'])) {
            return null;
        }

        if ($Line['text'][0] === '>' and preg_match('/^>[ ]?+(.*+)/', $Line['text'], $matches)) {
            $Block['element']['handler']['argument'] [] = $matches[1];

            return $Block;
        }

        $Block['element']['handler']['argument'] [] = $Line['text'];
        return $Block;
    }

    protected function blockRule($Line): ?array
    {
        $marker = $Line['text'][0];

        if (substr_count($Line['text'], $marker) >= 3 and rtrim($Line['text'], " $marker") === '') {
            return [
                'element' => [
                    'name' => 'hr',
                ],
            ];
        }
        return null;
    }

    protected function blockSetextHeader($Line, ?array $Block = null): ?array
    {
        if (!isset($Block) or $Block['type'] !== 'Paragraph' or isset($Block['interrupted'])) {
            return null;
        }

        if ($Line['indent'] < 4 and rtrim(rtrim($Line['text'], ' '), $Line['text'][0]) === '') {
            $Block['element']['name'] = $Line['text'][0] === '=' ? 'h1' : 'h2';
        } else {
            return null;
        }

        if ($this->extra && $Block !== null
            && preg_match('/[ ]*{(' . $this->regexAttribute . '+)}[ ]*$/', $Block['element']['handler']['argument'],
                $matches, PREG_OFFSET_CAPTURE)) {
            $attributeString = $matches[1][0];

            $Block['element']['attributes'] = $this->parseAttributeData($attributeString);

            $Block['element']['handler']['argument'] = substr($Block['element']['handler']['argument'], 0,
                $matches[0][1]);
        }

        return $Block;
    }

    protected function blockMarkup($Line): ?array
    {
        if ($this->extra) {
            return $this->_blockMarkup_Extra($Line);
        }

        if ($this->markupEscaped or $this->safeMode) {
            return null;
        }

        if (preg_match('/^<[\/]?+(\w*)(?:[ ]*+' . $this->regexHtmlAttribute . ')*+[ ]*+(\/)?>/', $Line['text'],
            $matches)) {
            $element = strtolower($matches[1]);

            if (in_array($element, $this->textLevelElements, true)) {
                return null;
            }

            return [
                'name'    => $matches[1],
                'element' => [
                    'rawHtml'   => $Line['text'],
                    'autobreak' => true,
                ],
            ];
        }
        return null;
    }

    protected function _blockMarkup_Extra($Line): ?array
    {
        if ($this->markupEscaped or $this->safeMode) {
            return null;
        }

        if (preg_match('/^<(\w[\w-]*)(?:[ ]*' . $this->regexHtmlAttribute . ')*[ ]*(\/)?>/', $Line['text'], $matches)) {
            $element = strtolower($matches[1]);

            if (in_array($element, $this->textLevelElements, true)) {
                return null;
            }

            $Block = [
                'name'    => $matches[1],
                'depth'   => 0,
                'element' => [
                    'rawHtml'   => $Line['text'],
                    'autobreak' => true,
                ],
            ];

            $length = strlen($matches[0]);
            $remainder = substr($Line['text'], $length);

            if (trim($remainder) === '') {
                if (isset($matches[2]) or in_array($matches[1], $this->voidElements, true)) {
                    $Block['closed'] = true;
                    $Block['void'] = true;
                }
            } else {
                if (isset($matches[2]) or in_array($matches[1], $this->voidElements, true)) {
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


    protected function blockMarkupContinue($Line, array $Block): ?array
    {
        if ($this->extra) {
            return $this->_blockMarkupContinue_Extra($Line, $Block);
        }

        if (isset($Block['closed']) or isset($Block['interrupted'])) {
            return null;
        }

        $Block['element']['rawHtml'] .= "\n" . $Line['body'];

        return $Block;
    }

    protected function _blockMarkupContinue_Extra($Line, array $Block): ?array
    {
        if (isset($Block['closed'])) {
            return null;
        }

        if (preg_match('/^<' . $Block['name'] . '(?:[ ]*' . $this->regexHtmlAttribute . ')*[ ]*>/i',
            $Line['text'])) # open
        {
            $Block['depth']++;
        }

        if (preg_match('/(.*?)<\/' . $Block['name'] . '>[ ]*$/i', $Line['text']))
        {
            if ($Block['depth'] > 0) {
                $Block['depth']--;
            } else {
                $Block['closed'] = true;
            }
        }

        if (isset($Block['interrupted'])) {
            $Block['element']['rawHtml'] .= "\n";
            unset($Block['interrupted']);
        }

        $Block['element']['rawHtml'] .= "\n" . $Line['body'];

        return $Block;
    }

    protected function blockMarkupComplete($Block)
    {
        if (!$this->extra) {
            return $Block;
        }
        if (!isset($Block['void'])) {
            $Block['element']['rawHtml'] = $this->processTag($Block['element']['rawHtml']);
        }

        return $Block;
    }

    protected function blockReference($Line): ?array
    {
        if (str_contains($Line['text'], ']')
            and preg_match('/^\[(.+?)\]:[ ]*+<?(\S+?)>?(?:[ ]+["\'(](.+)["\')])?[ ]*+$/', $Line['text'], $matches)
        ) {
            $id = strtolower($matches[1]);

            $Data = [
                'url'   => $matches[2],
                'title' => $matches[3] ?? null,
            ];

            $this->DefinitionData['Reference'][$id] = $Data;

            return [
                'element' => [],
            ];
        }
        return null;
    }

    protected function blockTable($Line, ?array $Block = null): ?array
    {
        if (!isset($Block) or $Block['type'] !== 'Paragraph' or isset($Block['interrupted'])) {
            return null;
        }

        if (
            !str_contains($Block['element']['handler']['argument'], '|')
            and !str_contains($Line['text'], '|')
            and !str_contains($Line['text'], ':')
            or str_contains($Block['element']['handler']['argument'], "\n")
        ) {
            return null;
        }

        if (rtrim($Line['text'], ' -:|') !== '') {
            return null;
        }

        $alignments = [];

        $divider = $Line['text'];

        $divider = trim($divider);
        $divider = trim($divider, '|');

        $dividerCells = explode('|', $divider);

        foreach ($dividerCells as $dividerCell) {
            $dividerCell = trim($dividerCell);

            if ($dividerCell === '') {
                return null;
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

        $header = $Block['element']['handler']['argument'];

        $header = trim($header);
        $header = trim($header, '|');

        $headerCells = explode('|', $header);

        if (count($headerCells) !== count($alignments)) {
            return null;
        }

        foreach ($headerCells as $index => $headerCell) {
            $headerCell = trim($headerCell);

            $HeaderElement = [
                'name'    => 'th',
                'handler' => [
                    'function'    => $this->lineElements(...),
                    'argument'    => $headerCell,
                    'destination' => 'elements',
                ],
            ];

            if (isset($alignments[$index])) {
                $alignment = $alignments[$index];

                $HeaderElement['attributes'] = [
                    'style' => "text-align: $alignment;",
                ];
            }

            $HeaderElements [] = $HeaderElement;
        }


        $Block = [
            'alignments' => $alignments,
            'identified' => true,
            'element'    => [
                'name'     => 'table',
                'elements' => [],
            ],
        ];

        $Block['element']['elements'] [] = [
            'name' => 'thead',
        ];

        $Block['element']['elements'] [] = [
            'name'     => 'tbody',
            'elements' => [],
        ];

        $Block['element']['elements'][0]['elements'] [] = [
            'name'     => 'tr',
            'elements' => $HeaderElements,
        ];

        return $Block;
    }

    protected function blockTableContinue($Line, array $Block): ?array
    {
        if (isset($Block['interrupted'])) {
            return null;
        }

        if (count($Block['alignments']) === 1 or $Line['text'][0] === '|' or strpos($Line['text'], '|')) {
            $Elements = [];

            $row = $Line['text'];

            $row = trim($row);
            $row = trim($row, '|');

            preg_match_all('/(?:(\\\\[|])|[^|`]|`[^`]++`|`)++/', $row, $matches);

            $cells = array_slice($matches[0], 0, count($Block['alignments']));

            foreach ($cells as $index => $cell) {
                $cell = trim($cell);

                $Element = [
                    'name'    => 'td',
                    'handler' => [
                        'function'    => $this->lineElements(...),
                        'argument'    => $cell,
                        'destination' => 'elements',
                    ],
                ];

                if (isset($Block['alignments'][$index])) {
                    $Element['attributes'] = [
                        'style' => 'text-align: ' . $Block['alignments'][$index] . ';',
                    ];
                }

                $Elements [] = $Element;
            }

            $Element = [
                'name'     => 'tr',
                'elements' => $Elements,
            ];

            $Block['element']['elements'][1]['elements'] [] = $Element;

            return $Block;
        }
        return null;
    }

    protected function paragraph($Line): array
    {
        return [
            'type'    => 'Paragraph',
            'element' => [
                'name'    => 'p',
                'handler' => [
                    'function'    => $this->lineElements(...),
                    'argument'    => $Line['text'],
                    'destination' => 'elements',
                ],
            ],
        ];
    }

    protected function paragraphContinue($Line, array $Block): ?array
    {
        if (isset($Block['interrupted'])) {
            return null;
        }

        $Block['element']['handler']['argument'] .= "\n" . $Line['text'];

        return $Block;
    }

    protected array $InlineTypes = [
        '!'  => ['Image'],
        '&'  => ['SpecialCharacter'],
        '*'  => ['Emphasis'],
        ':'  => ['Url'],
        '<'  => ['UrlTag', 'EmailTag', 'Markup'],
        '['  => ['Link'],
        '_'  => ['Emphasis'],
        '`'  => ['Code'],
        '~'  => ['Strikethrough'],
        '\\' => ['EscapeSequence'],
    ];


    protected string $inlineMarkerList = '!*_&[:<`~\\';

    public function line($text, $nonNestables = []): string
    {
        return $this->elements($this->lineElements($text, $nonNestables));
    }

    protected function lineElements($text, $nonNestables = []): array
    {
        // standardize line breaks
        $text = str_replace(["\r\n", "\r"], "\n", $text);

        $Elements = [];

        $nonNestables = (empty($nonNestables)
            ? []
            : array_combine($nonNestables, $nonNestables)
        );

        // $excerpt is based on the first occurrence of a marker

        while ($excerpt = strpbrk($text, $this->inlineMarkerList)) {
            $marker = $excerpt[0];

            $markerPosition = strlen($text) - strlen($excerpt);

            $Excerpt = ['text' => $excerpt, 'context' => $text];

            foreach ($this->InlineTypes[$marker] as $inlineType) {
                // check to see if the current inline type is nestable in the current context

                if (isset($nonNestables[$inlineType])) {
                    continue;
                }

                $Inline = $this->_dispatch('inline', $inlineType)($Excerpt);

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


                $Inline['element']['nonNestables'] = isset($Inline['element']['nonNestables'])
                    ? array_merge($Inline['element']['nonNestables'], $nonNestables)
                    : $nonNestables;

                // the text that comes before the inline
                $unmarkedText = substr($text, 0, $Inline['position']);

                // compile the unmarked text
                $InlineText = $this->inlineText($unmarkedText);
                $Elements[] = $InlineText['element'];

                // compile the inline
                $Elements[] = $this->extractElement($Inline);

                // remove the examined text
                $text = substr($text, $Inline['position'] + $Inline['extent']);

                continue 2;
            }

            // the marker does not belong to an inline

            $unmarkedText = substr($text, 0, $markerPosition + 1);

            $InlineText = $this->inlineText($unmarkedText);
            $Elements[] = $InlineText['element'];

            $text = substr($text, $markerPosition + 1);
        }

        $InlineText = $this->inlineText($text);
        $Elements[] = $InlineText['element'];

        foreach ($Elements as &$Element) {
            if (!isset($Element['autobreak'])) {
                $Element['autobreak'] = false;
            }
        }

        return $Elements;
    }

    protected function inlineText($text): array
    {
        $Inline = [
            'extent'  => strlen($text),
            'element' => [],
        ];

        $Inline['element']['elements'] = self::pregReplaceElements(
            $this->breaksEnabled ? '/[ ]*+\n/' : '/(?:[ ]*+\\\\|[ ]{2,}+)\n/',
            [
                ['name' => 'br'],
                ['text' => "\n"],
            ],
            $text,
        );

        if ($this->extra && isset($this->DefinitionData['Abbreviation'])) {
            foreach ($this->DefinitionData['Abbreviation'] as $abbreviation => $meaning) {
                $this->currentAbreviation = $abbreviation;
                $this->currentMeaning = $meaning;

                $Inline['element'] = $this->elementApplyRecursiveDepthFirst(
                    $this->insertAbreviation(...),
                    $Inline['element'],
                );
            }
        }

        return $Inline;
    }

    protected function inlineCode($Excerpt): ?array
    {
        $marker = $Excerpt['text'][0];

        if (preg_match('/^([' . $marker . ']++)[ ]*+(.+?)[ ]*+(?<![' . $marker . '])\1(?!' . $marker . ')/s',
            $Excerpt['text'], $matches)) {
            $text = $matches[2];
            $text = preg_replace('/[ ]*+\n/', ' ', $text);

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

    protected function inlineEmailTag($Excerpt): ?array
    {
        $hostnameLabel = '[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?';

        $commonMarkEmail = '[a-zA-Z0-9.!#$%&\'*+\/=?^_`{|}~-]++@'
            . $hostnameLabel . '(?:\.' . $hostnameLabel . ')*';

        if (str_contains($Excerpt['text'], '>')
            and preg_match("/^<((mailto:)?$commonMarkEmail)>/i", $Excerpt['text'], $matches)
        ) {
            $url = $matches[1];

            if (!isset($matches[2])) {
                $url = "mailto:$url";
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

    protected function inlineEmphasis($Excerpt): ?array
    {
        if (!isset($Excerpt['text'][1])) {
            return null;
        }

        $marker = $Excerpt['text'][0];

        if ($Excerpt['text'][1] === $marker and preg_match($this->StrongRegex[$marker], $Excerpt['text'], $matches)) {
            $emphasis = 'strong';
        } elseif (preg_match($this->EmRegex[$marker], $Excerpt['text'], $matches)) {
            $emphasis = 'em';
        } else {
            return null;
        }

        return [
            'extent'  => strlen($matches[0]),
            'element' => [
                'name'    => $emphasis,
                'handler' => [
                    'function'    => $this->lineElements(...),
                    'argument'    => $matches[1],
                    'destination' => 'elements',
                ],
            ],
        ];
    }

    protected function inlineEscapeSequence($Excerpt): ?array
    {
        if (isset($Excerpt['text'][1]) and in_array($Excerpt['text'][1], $this->specialCharacters, true)) {
            return [
                'element' => ['rawHtml' => $Excerpt['text'][1]],
                'extent'  => 2,
            ];
        }
        return null;
    }

    protected function inlineImage($Excerpt): ?array
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
                    'alt' => $Link['element']['handler']['argument'],
                ],
                'autobreak'  => true,
            ],
        ];

        $Inline['element']['attributes'] += $Link['element']['attributes'];

        unset($Inline['element']['attributes']['href']);

        return $Inline;
    }

    protected function inlineLink($Excerpt): ?array
    {
        $Element = [
            'name'         => 'a',
            'handler'      => [
                'function'    => $this->lineElements(...),
                'argument'    => null,
                'destination' => 'elements',
            ],
            'nonNestables' => ['Url', 'Link'],
            'attributes'   => [
                'href'  => null,
                'title' => null,
            ],
        ];

        $extent = 0;

        $remainder = $Excerpt['text'];

        if (preg_match('/\[((?:[^][]++|(?R))*+)\]/', $remainder, $matches)) {
            $Element['handler']['argument'] = $matches[1];

            $extent += strlen($matches[0]);

            $remainder = substr($remainder, $extent);
        } else {
            return null;
        }

        if (preg_match('/^[(]\s*+((?:[^ ()]++|[(][^ )]+[)])++)(?:[ ]+("[^"]*+"|\'[^\']*+\'))?\s*+[)]/', $remainder,
            $matches)) {
            $Element['attributes']['href'] = $matches[1];

            if (isset($matches[2])) {
                $Element['attributes']['title'] = substr($matches[2], 1, -1);
            }

            $extent += strlen($matches[0]);
        } else {
            if (preg_match('/^\s*\[(.*?)\]/', $remainder, $matches)) {
                $definition = $matches[1] !== '' ? $matches[1] : $Element['handler']['argument'];
                $definition = strtolower($definition);

                $extent += strlen($matches[0]);
            } else {
                $definition = strtolower($Element['handler']['argument']);
            }

            if (!isset($this->DefinitionData['Reference'][$definition])) {
                return null;
            }

            $Definition = $this->DefinitionData['Reference'][$definition];

            $Element['attributes']['href'] = $Definition['url'];
            $Element['attributes']['title'] = $Definition['title'];
        }

        $Link = [
            'extent'  => $extent,
            'element' => $Element,
        ];

        if ($this->extra) {
            $remainder = substr($Excerpt['text'], $Link['extent']);

            if (preg_match('/^[ ]*{(' . $this->regexAttribute . '+)}/', $remainder, $matches)) {
                $Link['element']['attributes'] += $this->parseAttributeData($matches[1]);

                $Link['extent'] += strlen($matches[0]);
            }
        }

        return $Link;
    }

    protected function inlineMarkup($Excerpt): ?array
    {
        if ($this->markupEscaped or $this->safeMode or !str_contains($Excerpt['text'], '>')) {
            return null;
        }

        if ($Excerpt['text'][1] === '/' and preg_match('/^<\/\w[\w-]*+[ ]*+>/', $Excerpt['text'], $matches)) {
            return [
                'element' => ['rawHtml' => $matches[0]],
                'extent'  => strlen($matches[0]),
            ];
        }

        if ($Excerpt['text'][1] === '!' and preg_match('/^<!---?[^>-](?:-?+[^-])*-->/', $Excerpt['text'], $matches)) {
            return [
                'element' => ['rawHtml' => $matches[0]],
                'extent'  => strlen($matches[0]),
            ];
        }

        if ($Excerpt['text'][1] !== ' ' and preg_match('/^<\w[\w-]*+(?:[ ]*+'
                . $this->regexHtmlAttribute
                . ')*+[ ]*+\/?>/s', $Excerpt['text'], $matches)) {
            return [
                'element' => ['rawHtml' => $matches[0]],
                'extent'  => strlen($matches[0]),
            ];
        }
        return null;
    }

    protected function inlineSpecialCharacter($Excerpt): ?array
    {
        if (substr($Excerpt['text'], 1, 1) !== ' ' and str_contains($Excerpt['text'], ';')
            and preg_match('/^&(#?+[0-9a-zA-Z]++);/', $Excerpt['text'], $matches)
        ) {
            return [
                'element' => ['rawHtml' => '&' . $matches[1] . ';'],
                'extent'  => strlen($matches[0]),
            ];
        }

        return null;
    }

    protected function inlineStrikethrough($Excerpt): ?array
    {
        if (!isset($Excerpt['text'][1])) {
            return null;
        }

        if ($Excerpt['text'][1] === '~' and preg_match('/^~~(?=\S)(.+?)(?<=\S)~~/', $Excerpt['text'], $matches)) {
            return [
                'extent'  => strlen($matches[0]),
                'element' => [
                    'name'    => 'del',
                    'handler' => [
                        'function'    => $this->lineElements(...),
                        'argument'    => $matches[1],
                        'destination' => 'elements',
                    ],
                ],
            ];
        }
        return null;
    }

    protected function inlineUrl($Excerpt): ?array
    {
        if ($this->urlsLinked !== true or !isset($Excerpt['text'][2]) or $Excerpt['text'][2] !== '/') {
            return null;
        }

        if (str_contains($Excerpt['context'], 'http')
            and preg_match('/\bhttps?+:[\/]{2}[^\s<]+\b\/*+/ui', $Excerpt['context'], $matches, PREG_OFFSET_CAPTURE)
        ) {
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

    protected function inlineUrlTag($Excerpt): ?array
    {
        if (str_contains($Excerpt['text'], '>') and preg_match('/^<(\w++:\/{2}[^ >]++)>/i', $Excerpt['text'],
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


    /** @noinspection PhpUnused */
    protected function unmarkedText($text): string
    {
        $Inline = $this->inlineText($text);
        return $this->element($Inline['element']);
    }

    protected function handle(array $Element): array
    {
        if (isset($Element['handler'])) {
            if (!isset($Element['nonNestables'])) {
                $Element['nonNestables'] = [];
            }

            if (is_string($Element['handler'])) {
                $function = $Element['handler'];
                $argument = $Element['text'];
                unset($Element['text']);
                $destination = 'rawHtml';
            } else {
                $function = $Element['handler']['function'];
                $argument = $Element['handler']['argument'];
                $destination = $Element['handler']['destination'];
            }

            // $Element[$destination] = $this->{$function}($argument, $Element['nonNestables']);
            $Element[$destination] = $function($argument, $Element['nonNestables']);

            if ($destination === 'handler') {
                $Element = $this->handle($Element);
            }

            unset($Element['handler']);
        }

        return $Element;
    }

    /** @noinspection PhpUnused */
    protected function handleElementRecursive(array $Element)
    {
        return $this->elementApplyRecursive($this->handle(...), $Element);
    }

    /** @noinspection PhpUnused */
    protected function handleElementsRecursive(array $Elements): array
    {
        return $this->elementsApplyRecursive($this->handle(...), $Elements);
    }

    protected function elementApplyRecursive(Closure $closure, array $Element)
    {
        $Element = $closure($Element);

        if (isset($Element['elements'])) {
            $Element['elements'] = $this->elementsApplyRecursive($closure, $Element['elements']);
        } elseif (isset($Element['element'])) {
            $Element['element'] = $this->elementApplyRecursive($closure, $Element['element']);
        }

        return $Element;
    }

    protected function elementApplyRecursiveDepthFirst($closure, array $Element)
    {
        if (isset($Element['elements'])) {
            $Element['elements'] = $this->elementsApplyRecursiveDepthFirst($closure, $Element['elements']);
        } elseif (isset($Element['element'])) {
            $Element['element'] = $this->elementsApplyRecursiveDepthFirst($closure, $Element['element']);
        }

        return $closure($Element);
    }

    protected function elementsApplyRecursive($closure, array $Elements): array
    {
        foreach ($Elements as &$Element) {
            $Element = $this->elementApplyRecursive($closure, $Element);
        }

        return $Elements;
    }

    protected function elementsApplyRecursiveDepthFirst($closure, array $Elements): array
    {
        foreach ($Elements as &$Element) {
            $Element = $this->elementApplyRecursiveDepthFirst($closure, $Element);
        }

        return $Elements;
    }

    protected function element(array $Element): string
    {
        if ($this->safeMode) {
            $Element = $this->sanitiseElement($Element);
        }

        // identity map if element has no handler
        $Element = $this->handle($Element);

        $hasName = isset($Element['name']);

        $markup = '';

        if ($hasName) {
            $markup .= '<' . $Element['name'];

            if (isset($Element['attributes'])) {
                foreach ($Element['attributes'] as $name => $value) {
                    if ($value === null) {
                        continue;
                    }

                    $markup .= " $name=\"" . self::escape($value) . '"';
                }
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

        $hasContent = isset($text) || isset($Element['element']) || isset($Element['elements']);

        if ($hasContent) {
            $markup .= $hasName ? '>' : '';

            $text ??= '';

            if (isset($Element['elements'])) {
                $markup .= $this->elements($Element['elements']);
            } elseif (isset($Element['element'])) {
                $markup .= $this->element($Element['element']);
            } elseif (!$permitRawHtml) {
                $markup .= self::escape($text, true);
            } else {
                $markup .= $text;
            }

            $markup .= $hasName ? '</' . $Element['name'] . '>' : '';
        } elseif ($hasName) {
            $markup .= ' />';
        }

        return $markup;
    }

    protected function elements(array $Elements): string
    {
        $markup = '';

        $autoBreak = true;

        foreach ($Elements as $Element) {
            if (empty($Element)) {
                continue;
            }

            $autoBreakNext = ($Element['autobreak'] ?? isset($Element['name'])
            );
            // (autobreak === false) covers both sides of an element
            $autoBreak = !$autoBreak ? $autoBreak : $autoBreakNext;

            $markup .= ($autoBreak ? "\n" : '') . $this->element($Element);
            $autoBreak = $autoBreakNext;
        }

        $markup .= $autoBreak ? "\n" : '';

        return $markup;
    }

    protected function li($lines): array
    {
        $Elements = $this->linesElements($lines);

        if (!in_array('', $lines, true)
            and isset($Elements[0]) and isset($Elements[0]['name'])
            and $Elements[0]['name'] === 'p'
        ) {
            unset($Elements[0]['name']);
        }

        return $Elements;
    }

    /**
     * Replace occurrences $regexp with $Elements in $text. Return an array of
     * elements representing the replacement.
     */
    protected static function pregReplaceElements($regexp, $Elements, $text): array
    {
        $newElements = [];

        while (preg_match($regexp, $text, $matches, PREG_OFFSET_CAPTURE)) {
            $offset = $matches[0][1];
            $before = substr($text, 0, $offset);
            $after = substr($text, $offset + strlen($matches[0][0]));

            $newElements[] = ['text' => $before];

            foreach ($Elements as $Element) {
                $newElements[] = $Element;
            }

            $text = $after;
        }

        $newElements[] = ['text' => $text];

        return $newElements;
    }

    public function parse($text): string
    {
        return $this->text($text);
    }

    protected function sanitiseElement(array $Element): array
    {
        static $goodAttribute = '/^[a-zA-Z0-9][a-zA-Z0-9-_]*+$/';
        static $safeUrlNameToAtt = [
            'a'   => 'href',
            'img' => 'src',
        ];

        if (!isset($Element['name'])) {
            unset($Element['attributes']);
            return $Element;
        }

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

    protected function filterUnsafeUrlInAttribute(array $Element, $attribute): array
    {
        if (array_any($this->safeLinksWhitelist,
            fn($scheme) => self::striAtStart($Element['attributes'][$attribute], $scheme))) {
            return $Element;
        }

        $Element['attributes'][$attribute] = str_replace(':', '%3A', $Element['attributes'][$attribute]);

        return $Element;
    }

    protected static function escape($text, $allowQuotes = false): string
    {
        return htmlspecialchars($text, $allowQuotes ? ENT_NOQUOTES : ENT_QUOTES, 'UTF-8');
    }

    protected static function striAtStart($string, $needle): bool
    {
        $len = strlen($needle);

        if ($len > strlen($string)) {
            return false;
        }

        return stripos($string, strtolower($needle)) === 0;
    }

    public static function instance($name = 'default')
    {
        if (isset(self::$instances[$name])) {
            return self::$instances[$name];
        }

        $instance = new static();

        self::$instances[$name] = $instance;

        return $instance;
    }

    private static array $instances = [];

    protected array $DefinitionData = [];

    protected array $specialCharacters = [
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
        '~',
    ];

    protected array $StrongRegex = [
        '*' => '/^[*]{2}((?:\\\\\*|[^*]|[*][^*]*+[*])+?)[*]{2}(?![*])/s',
        '_' => '/^__((?:\\\\_|[^_]|_[^_]*+_)+?)__(?!_)/us',
    ];

    protected array $EmRegex = [
        '*' => '/^[*]((?:\\\\\*|[^*]|[*][*][^*]+?[*][*])+?)[*](?![*])/s',
        '_' => '/^_((?:\\\\_|[^_]|__[^_]*__)+?)_(?!_)\b/us',
    ];

    protected string $regexHtmlAttribute = '[a-zA-Z_:][\w:.-]*+(?:\s*+=\s*+(?:[^"\'=<>`\s]+|"[^"]*+"|\'[^\']*+\'))?+';

    protected array $voidElements = [
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

    protected array $textLevelElements = [
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


    // "Extra"

    protected function blockAbbreviation($Line): ?array
    {
        if (preg_match('/^\*\[(.+?)\]:[ ]*(.+?)[ ]*$/', $Line['text'], $matches)) {
            $this->DefinitionData['Abbreviation'][$matches[1]] = $matches[2];

            return ['hidden' => true];
        }
        return null;
    }

    protected function blockFootnote($Line): ?array
    {
        if (preg_match('/^\[\^(.+?)\]:[ ]?(.*)$/', $Line['text'], $matches)) {
            return [
                'label'  => $matches[1],
                'text'   => $matches[2],
                'hidden' => true,
            ];
        }
        return null;
    }

    protected function blockFootnoteContinue($Line, $Block): ?array
    {
        if ($Line['text'][0] === '[' and preg_match('/^\[\^(.+?)\]:/', $Line['text'])) {
            return null;
        }

        if (isset($Block['interrupted'])) {
            if ($Line['indent'] >= 4) {
                $Block['text'] .= "\n\n" . $Line['text'];

                return $Block;
            }
        } else {
            $Block['text'] .= "\n" . $Line['text'];

            return $Block;
        }
        return null;
    }

    protected function blockFootnoteComplete($Block)
    {
        $this->DefinitionData['Footnote'][$Block['label']] = [
            'text'   => $Block['text'],
            'count'  => null,
            'number' => null,
        ];

        return $Block;
    }

    protected function blockDefinitionList($Line, $Block): ?array
    {
        if (!isset($Block) or $Block['type'] !== 'Paragraph') {
            return null;
        }

        $Element = [
            'name'     => 'dl',
            'elements' => [],
        ];

        $terms = explode("\n", $Block['element']['handler']['argument']);

        foreach ($terms as $term) {
            $Element['elements'] [] = [
                'name'    => 'dt',
                'handler' => [
                    'function'    => $this->lineElements(...),
                    'argument'    => $term,
                    'destination' => 'elements',
                ],
            ];
        }

        $Block['element'] = $Element;

        return $this->addDdElement($Line, $Block);
    }

    protected function blockDefinitionListContinue($Line, array $Block): ?array
    {
        if ($Line['text'][0] === ':') {
            return $this->addDdElement($Line, $Block);
        }

        if (isset($Block['interrupted']) and $Line['indent'] === 0) {
            return null;
        }

        if (isset($Block['interrupted'])) {
            $Block['dd']['handler']['function'] = $this->textElements(...);
            $Block['dd']['handler']['argument'] .= "\n\n";

            $Block['dd']['handler']['destination'] = 'elements';

            unset($Block['interrupted']);
        }

        $text = substr($Line['body'], min($Line['indent'], 4));

        $Block['dd']['handler']['argument'] .= "\n" . $text;

        return $Block;
    }

    private int $footnoteCount = 0;

    protected function inlineFootnoteMarker($Excerpt): ?array
    {
        if (preg_match('/^\[\^(.+?)\]/', $Excerpt['text'], $matches)) {
            $name = $matches[1];

            if (!isset($this->DefinitionData['Footnote'][$name])) {
                return null;
            }

            $this->DefinitionData['Footnote'][$name]['count']++;

            if (!isset($this->DefinitionData['Footnote'][$name]['number'])) {
                $this->DefinitionData['Footnote'][$name]['number'] = ++$this->footnoteCount; # » &
            }

            $Element = [
                'name'       => 'sup',
                'attributes' => ['id' => 'fnref' . $this->DefinitionData['Footnote'][$name]['count'] . ':' . $name],
                'element'    => [
                    'name'       => 'a',
                    'attributes' => ['href' => '#fn:' . $name, 'class' => 'footnote-ref'],
                    'text'       => $this->DefinitionData['Footnote'][$name]['number'],
                ],
            ];

            return [
                'extent'  => strlen($matches[0]),
                'element' => $Element,
            ];
        }
        return null;
    }

    private string $currentAbreviation;
    private string $currentMeaning;

    protected function insertAbreviation(array $Element): array
    {
        if (isset($Element['text'])) {
            $Element['elements'] = self::pregReplaceElements(
                '/\b' . preg_quote($this->currentAbreviation, '/') . '\b/',
                [
                    [
                        'name'       => 'abbr',
                        'attributes' => [
                            'title' => $this->currentMeaning,
                        ],
                        'text'       => $this->currentAbreviation,
                    ],
                ],
                $Element['text'],
            );

            unset($Element['text']);
        }

        return $Element;
    }

    //region "Extra" Utility Methods (Apparently Unused)

    protected function addDdElement(array $Line, array $Block): array
    {
        $text = substr($Line['text'], 1);
        $text = trim($text);

        unset($Block['dd']);

        $Block['dd'] = [
            'name'    => 'dd',
            'handler' => [
                'function'    => $this->lineElements(...),
                'argument'    => $text,
                'destination' => 'elements',
            ],
        ];

        if (isset($Block['interrupted'])) {
            $Block['dd']['handler']['function'] = $this->textElements(...);;

            unset($Block['interrupted']);
        }

        $Block['element']['elements'] [] = &$Block['dd'];

        return $Block;
    }

    protected function buildFootnoteElement(): array
    {
        $Element = [
            'name'       => 'div',
            'attributes' => ['class' => 'footnotes'],
            'elements'   => [
                ['name' => 'hr'],
                [
                    'name'     => 'ol',
                    'elements' => [],
                ],
            ],
        ];

        uasort($this->DefinitionData['Footnote'], self::sortFootnotes(...));

        foreach ($this->DefinitionData['Footnote'] as $definitionId => $DefinitionData) {
            if (!isset($DefinitionData['number'])) {
                continue;
            }

            $text = $DefinitionData['text'];

            $textElements = $this->textElements($text);

            $numbers = range(1, $DefinitionData['count']);

            $backLinkElements = [];

            foreach ($numbers as $number) {
                $backLinkElements[] = ['text' => ' '];
                $backLinkElements[] = [
                    'name'                   => 'a',
                    'attributes'             => [
                        'href'  => "#fnref$number:$definitionId",
                        'rev'   => 'footnote',
                        'class' => 'footnote-backref',
                    ],
                    'rawHtml'                => '&#8617;',
                    'allowRawHtmlInSafeMode' => true,
                    'autobreak'              => false,
                ];
            }

            unset($backLinkElements[0]);

            $n = count($textElements) - 1;

            if ($textElements[$n]['name'] === 'p') {
                $backLinkElements = array_merge(
                    [
                        [
                            'rawHtml'                => '&#160;',
                            'allowRawHtmlInSafeMode' => true,
                        ],
                    ],
                    $backLinkElements,
                );

                unset($textElements[$n]['name']);

                $textElements[$n] = [
                    'name'     => 'p',
                    'elements' => array_merge(
                        [$textElements[$n]],
                        $backLinkElements,
                    ),
                ];
            } else {
                $textElements[] = [
                    'name'     => 'p',
                    'elements' => $backLinkElements,
                ];
            }

            $Element['elements'][1]['elements'] [] = [
                'name'       => 'li',
                'attributes' => ['id' => 'fn:' . $definitionId],
                'elements'   => array_merge(
                    $textElements,
                ),
            ];
        }

        return $Element;
    }

    protected function parseAttributeData($attributeString): array
    {
        $Data = [];

        $attributes = preg_split('/[ ]+/', $attributeString, -1, PREG_SPLIT_NO_EMPTY);

        foreach ($attributes as $attribute) {
            if ($attribute[0] === '#') {
                $Data['id'] = substr($attribute, 1);
            } else # "."
            {
                $classes [] = substr($attribute, 1);
            }
        }

        if (isset($classes)) {
            $Data['class'] = implode(' ', $classes);
        }

        return $Data;
    }

    protected function processTag($elementMarkup): array|false|string # recursive
    {
        # http://stackoverflow.com/q/1148928/200145
        libxml_use_internal_errors(true);

        $DOMDocument = new DOMDocument;

        # http://stackoverflow.com/q/11309194/200145
        // $elementMarkup = mb_convert_encoding($elementMarkup, 'HTML-ENTITIES', 'UTF-8'); // deprecated
        // $elementMarkup = htmlspecialchars($elementMarkup); // converts way more than the above did
        // For Sideways, we'll force the encoding beforehand.  It'll always be UTF-8 by the time we get here.

        # http://stackoverflow.com/q/4879946/200145
        $DOMDocument->loadHTML($elementMarkup);
        $DOMDocument->removeChild($DOMDocument->doctype);
        $DOMDocument->replaceChild($DOMDocument->firstChild->firstChild->firstChild, $DOMDocument->firstChild);

        $elementText = '';

        if ($DOMDocument->documentElement->getAttribute('markdown') === '1') {
            foreach ($DOMDocument->documentElement->childNodes as $Node) {
                $elementText .= $DOMDocument->saveHTML($Node);
            }

            $DOMDocument->documentElement->removeAttribute('markdown');

            $elementText = "\n" . $this->text($elementText) . "\n";
        } else {
            foreach ($DOMDocument->documentElement->childNodes as $Node) {
                $nodeMarkup = $DOMDocument->saveHTML($Node);

                if ($Node instanceof DOMElement and !in_array($Node->nodeName, $this->textLevelElements, true)) {
                    $elementText .= $this->processTag($nodeMarkup);
                } else {
                    $elementText .= $nodeMarkup;
                }
            }
        }

        # because we don't want for markup to get encoded
        $DOMDocument->documentElement->nodeValue = 'placeholder\x1A';

        $markup = $DOMDocument->saveHTML($DOMDocument->documentElement);
        return str_replace('placeholder\x1A', $elementText, $markup);
    }

    protected function sortFootnotes($A, $B) # callback
    {
        return $A['number'] - $B['number'];
    }

    protected string $regexAttribute = '(?:[#.][-\w]+[ ]*)';

    //endregion


    protected function _dispatch(string $name, string $type): ?Closure {
        /** @noinspection PhpExpressionAlwaysNullInspection (false positive) */
        return match ($name) {
            'block' => match ($type) {
                'Code' => $this->blockCode(...),
                'Comment' => $this->blockComment(...),
                'FencedCode' => $this->blockFencedCode(...),
                'Header' => $this->blockHeader(...),
                'List' => $this->blockList(...),
                'Quote' => $this->blockQuote(...),
                'Rule' => $this->blockRule(...),
                'SetextHeader' => $this->blockSetextHeader(...),
                'Markup' => $this->blockMarkup(...),
                'Reference' => $this->blockReference(...),
                'Table' => $this->blockTable(...),
                // Extra
                'Abbreviation' => $this->blockAbbreviation(...),
                'DefinitionList' => $this->blockDefinitionList(...),
                'Footnote' => $this->blockFootnote(...),

                default => null,
            },
            'continue' => match ($type) {
                'Code' => $this->blockCodeContinue(...),
                'Comment' => $this->blockCommentContinue(...),
                'FencedCode' => $this->blockFencedCodeContinue(...),
                'List' => $this->blockListContinue(...),
                'Quote' => $this->blockQuoteContinue(...),
                'Markup' => $this->blockMarkupContinue(...),
                'Table' => $this->blockTableContinue(...),
                // Extra
                'DefinitionList' => $this->blockDefinitionListContinue(...),
                'Footnote' => $this->blockFootnoteContinue(...),
                default => null,
            },
            'complete' => match ($type) {
                'Code' => $this->blockCodeComplete(...),
                'FencedCode' => $this->blockFencedCodeComplete(...),
                'List' => $this->blockListComplete(...),
                // Extra
                'Markup' => $this->blockMarkupComplete(...),
                'Footnote' => $this->blockFootnoteComplete(...),
            },
            'inline' => match ($type) {
                'Text' => $this->inlineText(...),
                'Code' => $this->inlineCode(...),
                'EmailTag' => $this->inlineEmailTag(...),
                'Emphasis' => $this->inlineEmphasis(...),
                'EscapeSequence' => $this->inlineEscapeSequence(...),
                'Image' => $this->inlineImage(...),
                'Link' => $this->inlineLink(...),
                'Markup' => $this->inlineMarkup(...),
                'SpecialCharacter' => $this->inlineSpecialCharacter(...),
                'Strikethrough' => $this->inlineStrikethrough(...),
                'Url' => $this->inlineUrl(...),
                'UrlTag' => $this->inlineUrlTag(...),
                //
                'FootnoteMarker' => $this->inlineFootnoteMarker(...),
                // default => throw new InvalidArgumentException("Unknown inline type: $type"),
                default => null,
            },
            default => throw new InvalidArgumentException("Invalid method type: $type"),
        };
    }
}
