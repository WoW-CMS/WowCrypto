<?php

namespace GameCrypto\Factories;

use GameCrypto\AccountPayloads\MangosPayloadFormatter;
use GameCrypto\AccountPayloads\SkyfirePayloadFormatter;
use GameCrypto\AccountPayloads\TrinityPayloadFormatter;
use GameCrypto\Contracts\AccountPayloadFormatterInterface;
use GameCrypto\Contracts\WoWEncryptorInterface;
use GameCrypto\Enums\EmulatorType;

class AccountPayloadFormatterFactory
{
    public static function create(EmulatorType $emulatorType, WoWEncryptorInterface $encryptor): AccountPayloadFormatterInterface
    {
        return match ($emulatorType) {
            EmulatorType::MANGOS, EmulatorType::CMANGOS => new MangosPayloadFormatter($emulatorType, $encryptor),
            EmulatorType::TRINITY_CORE, EmulatorType::AZEROTH_CORE => new TrinityPayloadFormatter($emulatorType, $encryptor),
            EmulatorType::SKYFIRE => new SkyfirePayloadFormatter($emulatorType, $encryptor),
        };
    }
}