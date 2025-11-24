<?php
declare(strict_types=1);

namespace FAIR\Forge\Util;

class Regex
{
    public static function extract(string $pattern, string $subject): ?string
    {
        return self::matches($pattern, $subject)[0] ?? null;
    }

    /** @return list<string> */
    public static function matches(string $pattern, string $subject): array
    {
        \Safe\preg_match($pattern, $subject, $matches);
        return $matches ?? [];
    }

    /** @return list<list<string>> */
    public static function allMatches(string $pattern, string $subject): array
    {
        \Safe\preg_match_all($pattern, $subject, $matches, PREG_SET_ORDER);
        return $matches ?? [];
    }

    public static function replace(string $pattern, string $replacement, string $subject, int $limit = -1): string
    {
        return \Safe\preg_replace($pattern, $replacement, $subject, $limit);
    }
}
