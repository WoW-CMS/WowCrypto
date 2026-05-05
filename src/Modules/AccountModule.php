<?php

namespace GameCrypto\Modules;

class AccountModule extends AbstractSoapModule
{
    public function create(string $username, string $password, ?string $email = null): string
    {
        return $this->executeSegments(['acc', 'create', $username, $password, $email]);
    }

    public function createBnet(string $email, string $password): string
    {
        return $this->executeSegments(['bnet', 'create', $email, $password]);
    }
}