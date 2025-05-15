<?php

namespace GameCrypto\Config;

use GameCrypto\Enums\EncryptionType;

abstract class EmulatorConfig
{
    protected EncryptionType $encryptionType;

    abstract public function getEncryptionType(): EncryptionType;
}