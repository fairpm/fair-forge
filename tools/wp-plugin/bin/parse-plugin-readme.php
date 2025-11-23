#!/usr/bin/env php
<?php
declare(strict_types=1);

require_once $_ENV['FAIR_FORGE'] . '/vendor/autoload.php';

use FAIR\Forge\Tools\WpPlugin\ReadmeParser;
use FAIR\Forge\Util\Json;

$parser = new ReadmeParser();

$parsed = $parser->parse(file_get_contents('php://stdin'));
echo Json::encode($parsed);

