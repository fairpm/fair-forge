<?php

declare(strict_types=1);

namespace FAIR\Forge\Tools\WpPlugin;

use JsonSerializable;

readonly class ParsedPluginHeaders implements JsonSerializable
{
    public function __construct(
        public string $name, // Name
        public string $plugin_uri = '', // PluginURI
        public string $description = '', // Description
        public string $version = '', // Version
        public string $requires_wp = '', // RequiresWP
        public string $requires_php = '', // RequiresPHP
        public string $author = '', // Author
        public string $author_uri = '', // AuthorURI
        public string $license = '', // License
        public string $license_uri = '', // LicenseURI
        public string $text_domain = '', // TextDomain
        public string $domain_path = '', // DomainPath
        public string $network = '', // Network
        public string $update_uri = '', // UpdateURI
        public string $requires_plugins = '', // RequiresPlugins
        public string $tested_up_to = '', // TestedUpTo
    ) {}

    public function jsonSerialize(): array
    {
        return [
            'name'             => $this->name,
            'plugin_uri'       => $this->plugin_uri,
            'description'      => $this->description,
            'version'          => $this->version,
            'requires_wp'      => $this->requires_wp,
            'requires_php'     => $this->requires_php,
            'author'           => $this->author,
            'author_uri'       => $this->author_uri,
            'license'          => $this->license,
            'license_uri'      => $this->license_uri,
            'text_domain'      => $this->text_domain,
            'domain_path'      => $this->domain_path,
            'network'          => $this->network,
            'update_uri'       => $this->update_uri,
            'requires_plugins' => $this->requires_plugins,
            'tested_up_to'     => $this->tested_up_to,
        ];
    }
}
