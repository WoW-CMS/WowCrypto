<?php

namespace GameCrypto\Modules;

class ServerModule extends AbstractSoapModule
{
    public function info(): string
    {
        return $this->executeSegments(['server', 'info']);
    }
}