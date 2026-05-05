<?php

namespace GameCrypto\Modules;

class ModerationModule extends AbstractSoapModule
{
    public function banAccount(string $accountName, string|int $duration, string $reason): string
    {
        return $this->executeSegments(['ban', 'account', $accountName, $duration, $reason]);
    }

    public function unbanAccount(string $accountName): string
    {
        return $this->executeSegments(['unban', 'account', $accountName]);
    }

    public function banCharacter(string $characterName, string|int $duration, string $reason): string
    {
        return $this->executeSegments(['ban', 'character', $characterName, $duration, $reason]);
    }

    public function unbanCharacter(string $characterName): string
    {
        return $this->executeSegments(['unban', 'character', $characterName]);
    }
}