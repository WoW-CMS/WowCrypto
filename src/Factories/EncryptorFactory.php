<?php

namespace GameCrypto\Factories;

use GameCrypto\Contracts\WoWEncryptorInterface;
use GameCrypto\Enums\EncryptionType;
use GameCrypto\Encryptors\ShaPassHashEncryptor;
use GameCrypto\Encryptors\SRP6Encryptor;
use GameCrypto\Encryptors\BNetEncryptor;

class EncryptorFactory
{
    public static function create(EncryptionType $encryptionType): WoWEncryptorInterface
    {
        return match($encryptionType) {
            EncryptionType::SHA_PASS_HASH => new ShaPassHashEncryptor(),
            EncryptionType::SRP6_V1 => new SRP6Encryptor(false),
            EncryptionType::SRP6_V2 => new SRP6Encryptor(true),
            EncryptionType::BNET => new BNetEncryptor(),
        };
    }
}