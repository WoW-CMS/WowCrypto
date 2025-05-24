<?php

namespace GameCrypto\Config;

use GameCrypto\Enums\EncryptionType;

class MangosConfig extends EmulatorConfig
{
    public function __construct(EncryptionType $encryptionType = EncryptionType::SHA_PASS_HASH)
    {
        $this->encryptionType = $encryptionType;
    }

    public function getEncryptionType(): EncryptionType
    {
        return $this->encryptionType;
    }
}