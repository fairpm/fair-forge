<?php
declare(strict_types=1);

namespace AspireBuild\Tools\Sideways;

readonly class Line {
    public function __construct(
        public string $text,
        public int $indent = 0,
        public ?string $body = null,
    ) {}
}
