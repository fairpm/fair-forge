<?php
declare(strict_types=1);

namespace FAIR\Forge\Tools\WpPlugin;

use JsonSerializable;

readonly class ParsedReadme implements JsonSerializable
{

    public function __construct(
        public string $name,
        public string $short_description,

        /** @var list<string> */
        public array $tags,
        public string $requires_wp,
        public string $tested_up_to,
        public string $requires_php,
        /** @var list<string> */
        public array $contributors,
        public string $stable_tag,
        public string $donate_link,
        public string $license,
        public string $license_uri,

        /** @var array<string, string> */
        public array $sections,

        /** @var list<string> */
        public array $_warnings,
    ) {}

    public function jsonSerialize(): array
    {
        return [
            'name'              => $this->name,
            'short_description' => $this->short_description,
            'sections'          => $this->sections,
            'tags'              => $this->tags,
            'requires_wp'       => $this->requires_wp,
            'tested_up_to'      => $this->tested_up_to,
            'requires_php'      => $this->requires_php,
            'contributors'      => $this->contributors,
            'stable_tag'        => $this->stable_tag,
            'donate_link'       => $this->donate_link,
            'license'           => $this->license,
            'license_uri'       => $this->license_uri,
            '_warnings'         => $this->_warnings,
        ];
    }
}
