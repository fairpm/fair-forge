<?php
declare(strict_types=1);

namespace FAIR\Forge\Tools\WpPlugin;

// Represents as much of a plugins/info/1.2/?action=plugin_information response as we can statically determine,
// with null values standing in for fields that must be filled in later.  Does no validation or normalization.

readonly class PartialPluginInformation implements \JsonSerializable
{
    public function __construct(
        // name, slug, and version are all required.  Everything else defaults to null.
        public string $name,
        public string $slug,    // supplied externally, usually the directory name of the plugin
        public string $version,

        // All following groups of properties are in sorted order, regardless of how they're organized elsewhere.

        public ?string $author = null, // maybe should be required?
        public ?string $author_profile = null,
        public ?array $banners = null,
        public ?bool $business_model = null,
        public ?string $commercial_support_url = null,
        public ?array $contributors = null,
        public ?string $description = null,
        public ?string $donate_link = null,
        public ?string $download_link = null,
        public ?string $homepage = null,
        public ?array $icons = null,
        public ?string $preview_link = null,
        public ?string $repository_url = null,
        public ?string $requires = null,
        public ?string $requires_php = null,
        public ?array $requires_plugins = null,
        public ?array $screenshots = null,
        public ?string $short_description = null,
        public ?string $support_url = null,
        public ?array $sections = null,
        public ?array $tags = null,
        public ?string $tested = null,
        public ?array $versions = null,

        // Items only served by AspireCloud
        public ?string $domain_path = null,
        public ?string $license = null,
        public ?string $license_uri = null,
        public ?string $network = null,
        public ?string $plugin_uri = null,
        public ?string $stable_tag = null,
        public ?string $text_domain = null,
        public ?string $update_uri = null,

        // Items we have to scrape from upstream
        public ?int $active_installs = null,
        public ?string $added = null,
        public ?int $downloaded = null,
        public ?string $last_updated = null,
        public ?int $num_ratings = null,
        public ?int $rating = null,
        public ?array $ratings = null,
        public ?int $support_threads = null,
        public ?int $support_threads_resolved = null,

    ) {}

    public function jsonSerialize(): array
    {
        return array_filter(get_object_vars($this), static fn($v) => $v !== null);
    }

    public static function fromHeadersAndReadme(
        string $slug,
        ParsedPluginHeaders $headers,
        ParsedReadme $readme,
    ): self {
        // TODO: check the readme/headers precedence for each field
        return new self(
            name             : $headers->name ?? $readme->name,
            slug             : $slug,
            version          : $headers->version,
            author           : $headers->author,
            author_profile   : $headers->author_uri ?: null,
            description      : $readme->sections['description'] ?? $headers->description,
            donate_link      : $readme->donate_link ?: null,
            requires         : $headers->requires_wp ?? $readme->requires_wp ?: null,
            requires_php     : $headers->requires_php ?? $readme->requires_php ?: null,
            short_description: $readme->short_description ?? $headers->description ?: null,
            sections         : $readme->sections ?: null,
            tags             : $readme->tags ?: null,
            tested           : $headers->tested_up_to ?? $readme->tested_up_to ?: null,
            domain_path      : $headers->domain_path ?: null,
            license          : $headers->license ?? $readme->license ?: null,
            license_uri      : $headers->license_uri ?? $readme->license_uri ?: null,
            network          : $headers->network ?: null,
            plugin_uri       : $headers->plugin_uri ?: null,
            stable_tag       : $readme->stable_tag ?: null,
            text_domain      : $headers->text_domain ?: null,
            update_uri       : $headers->update_uri ?: null,
        );
        // requires_plugins : $headers->requires_plugins, // needs parsing
        // contributors     : $readme->contributors,      // needs db lookups
    }
}




