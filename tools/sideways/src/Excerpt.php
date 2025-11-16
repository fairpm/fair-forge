<?php
declare(strict_types=1);

namespace AspireBuild\Tools\Sideways;

class Excerpt
{
    public function __construct(public string $text, public string $context) {}
}
