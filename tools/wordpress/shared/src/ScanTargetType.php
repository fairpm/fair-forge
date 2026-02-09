<?php

declare(strict_types=1);

namespace FairForge\Shared;

/**
 * Enum representing the type of scan target.
 */
enum ScanTargetType: string
{
    case Url = 'url';
    case ZipFile = 'zip';
    case Directory = 'directory';
}
