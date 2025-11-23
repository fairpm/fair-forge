#!/usr/bin/env php
<?php
declare(strict_types=1);

require_once $_ENV['FAIR_FORGE'] . '/vendor/autoload.php';

use FAIR\Forge\Tools\WpPlugin\HeaderParser;
use FAIR\Forge\Util\Json;

$parser = new HeaderParser();

$parsed = $parser->parsePluginHeaders(file_get_contents('php://stdin'));
echo Json::encode($parsed);

