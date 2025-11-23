<?php
declare(strict_types=1);

namespace FAIR\Forge\Util;

class Filesystem
{
    public static function mktempdir(?string $dir = null, string $prefix = '', int $permissions = 0o700): string
    {
        $dir ??= sys_get_temp_dir();
        $path = tempnam($dir, $prefix);
        \Safe\unlink($path);
        \Safe\mkdir($path, $permissions);
        return $path;
    }
}
