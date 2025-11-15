<?php

namespace Tests\AspireBuild\Tools\Sideways;

use AspireBuild\Tools\Sideways\Sideways;

class TestSideways extends Sideways
{
    public function getTextLevelElements(): array
    {
        return $this->textLevelElements;
    }
}
