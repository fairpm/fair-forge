<?php
declare(strict_types=1);

namespace FAIR\Forge\Tools\WpPlugin;

use JsonSerializable;

readonly class ParsedThemeHeaders implements JsonSerializable
{
    public function __construct(
        public string $name,
        public string $author = '',
        public string $description = '',
        public string $tags = '',
        public string $version = '',
        public string $requires_wp = '',
        public string $requires_php = '',
        public string $text_domain = '',
        public string $domain_path = '',
        public string $tested_up_to = '',
        public string $license = '',
        public string $license_uri = '',
        public string $theme_uri = '',
        public string $author_uri = '',
        public string $update_uri = '',
        public string $template = '',
        public string $status = '',
    ) {}

    public function jsonSerialize(): array
    {
        return [
            'name'         => $this->name,
            'author'       => $this->author,
            'description'  => $this->description,
            'tags'         => $this->tags,
            'version'      => $this->version,
            'requires_wp'  => $this->requires_wp,
            'requires_php' => $this->requires_php,
            'text_domain'  => $this->text_domain,
            'domain_path'  => $this->domain_path,
            'tested_up_to' => $this->tested_up_to,
            'license'      => $this->license,
            'license_uri'  => $this->license_uri,
            'theme_uri'    => $this->theme_uri,
            'author_uri'   => $this->author_uri,
            'update_uri'   => $this->update_uri,
            'template'     => $this->template,
            'status'       => $this->status,
        ];
    }
}
