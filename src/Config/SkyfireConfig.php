<?php

namespace GameCrypto\Config;

use GameCrypto\Enums\EncryptionType;

class SkyfireConfig extends EmulatorConfig
{
    public function __construct(EncryptionType $encryptionType = EncryptionType::BNET)
    {
        $this->encryptionType = $encryptionType;
    }

    public function getEncryptionType(): EncryptionType
    {
        return $this->encryptionType;
    }
}