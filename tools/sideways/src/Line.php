<?php
declare(strict_types=1);

namespace AspireBuild\Tools\Sideways;

class Line
{
    public function __construct(public readonly string $body) {}

    public int $indent {
        get => strspn($this->body, ' ');
    }

    public string $text {
        get => ltrim($this->body);
    }

    public string $marker {
        get => $this->text[0] ?? '';
    }
}
