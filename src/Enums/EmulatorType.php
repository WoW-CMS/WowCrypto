<?php

namespace GameCrypto\Enums;

use GameCrypto\Config\EmulatorConfig;
use GameCrypto\Config\MangosConfig;
use GameCrypto\Config\TrinityConfig;

enum EmulatorType: string
{
    case MANGOS = 'mangos';
    case TRINITY_CORE = 'trinity_core';
    case AZEROTH_CORE = 'azeroth_core';
    case CMANGOS = 'cmangos';
    case SKYFIRE = 'skyfire';

    public function getEncryptionType(): EncryptionType
    {
        return match($this) {
            self::MANGOS, self::CMANGOS => EncryptionType::SHA_PASS_HASH,
            self::TRINITY_CORE, self::AZEROTH_CORE => EncryptionType::SRP6_V2,
            self::SKYFIRE => EncryptionType::BNET,
        };
    }

    
    public function getDefaultConfig(): EmulatorConfig
    {
        return match($this) {
            self::MANGOS => new MangosConfig(),
            self::TRINITY_CORE => new TrinityConfig(),
        };
    }
}