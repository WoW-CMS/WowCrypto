<?php

namespace GameCrypto;

use GameCrypto\Contracts\WoWEncryptorInterface;
use GameCrypto\Enums\EmulatorType;
use GameCrypto\Config\EmulatorConfig;
use GameCrypto\Factories\EncryptorFactory;

class WoWCrypto
{
    private WoWEncryptorInterface $encryptor;
    private EmulatorConfig $config;

    public function __construct(EmulatorType $emulatorType, ?EmulatorConfig $config = null)
    {
        $this->config = $config ?? $emulatorType->getDefaultConfig();
        $this->encryptor = EncryptorFactory::create($this->config->getEncryptionType());
    }

    public function encrypt(string $username, string $password): string
    {
        return $this->encryptor->encrypt($username, $password);
    }

    public function verify(string $username, string $password, string $hash): bool
    {
        return $this->encryptor->verify($username, $password, $hash);
    }
}