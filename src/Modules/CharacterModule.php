<?php

namespace GameCrypto\Modules;

use InvalidArgumentException;

class CharacterModule extends AbstractSoapModule
{
    public function rename(string $characterName): string
    {
        return $this->executeSegments(['character', 'rename', $characterName]);
    }

    public function customize(string $characterName): string
    {
        return $this->executeSegments(['character', 'customize', $characterName]);
    }

    public function changeRace(string $characterName): string
    {
        return $this->executeSegments(['character', 'changerace', $characterName]);
    }

    public function changeFaction(string $characterName): string
    {
        return $this->executeSegments(['character', 'changefaction', $characterName]);
    }

    public function setLevel(string $characterName, int $level): string
    {
        if ($level < 1) {
            throw new InvalidArgumentException('Character level must be at least 1.');
        }

        return $this->executeSegments(['character', 'level', $characterName, $level]);
    }
}