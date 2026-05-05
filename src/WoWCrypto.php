<?php

namespace GameCrypto;

use GameCrypto\Contracts\AccountPayloadFormatterInterface;
use GameCrypto\Contracts\WoWEncryptorInterface;
use GameCrypto\Config\EmulatorConfig;
use GameCrypto\Enums\EmulatorType;
use GameCrypto\Factories\AccountPayloadFormatterFactory;
use GameCrypto\Factories\EncryptorFactory;

class WoWCrypto
{
    private WoWEncryptorInterface $encryptor;
    private EmulatorConfig $config;
    private EmulatorType $emulatorType;
    private AccountPayloadFormatterInterface $accountPayloadFormatter;

    public function __construct(EmulatorType $emulatorType, ?EmulatorConfig $config = null)
    {
        $this->emulatorType = $emulatorType;
        $this->config = $config ?? $emulatorType->getDefaultConfig();
        $this->encryptor = EncryptorFactory::create($this->config->getEncryptionType());
        $this->accountPayloadFormatter = AccountPayloadFormatterFactory::create($emulatorType, $this->encryptor);
    }

    public function encrypt(string $username, string $password): array
    {
        return $this->encryptor->encrypt($username, $password);
    }

    public function verify(string $username, string $password, array|string $hash): bool
    {
        return $this->encryptor->verify($username, $password, $hash);
    }

    /**
        * Builds an emulator-specific payload so the host CMS can validate, insert, and link the account.
     *
     * @return array<string, mixed>
     */
    public function prepareAccountPayload(string $username, string $password, ?string $email = null): array
    {
        return $this->accountPayloadFormatter->formatPayload($username, $password, $email);
    }
}