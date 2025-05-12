<?php

namespace GameCrypto\Factories;

use GameCrypto\Enums\EmulatorType;
use GameCrypto\Contracts\WoWEncryptorInterface;
use GameCrypto\Encryptors\ShaPassHashEncryptor;
use GameCrypto\Encryptors\SRP6Encryptor;
use GameCrypto\Encryptors\BNetEncryptor;

class EncryptorFactory
{
    /**
     * Creates an encryptor instance based on the emulator type
     *
     * @param EmulatorType $emulatorType
     * @return WoWEncryptorInterface
     */
    public static function create(EmulatorType $emulatorType): WoWEncryptorInterface
    {
        return match($emulatorType) {
            EmulatorType::MANGOS => new ShaPassHashEncryptor(),
            EmulatorType::TRINITY_CORE => new SRP6Encryptor(true),
            EmulatorType::AZEROTH_CORE => new SRP6Encryptor(true),
            EmulatorType::CMANGOS => new ShaPassHashEncryptor(),
            EmulatorType::SKYFIRE => new BNetEncryptor(),
        };
    }
}