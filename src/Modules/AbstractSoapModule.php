<?php

namespace GameCrypto\Modules;

use GameCrypto\SoapAccountCreator;
use GameCrypto\SoapCommand;

abstract class AbstractSoapModule
{
    public function __construct(protected readonly SoapAccountCreator $client)
    {
    }

    protected function execute(SoapCommand|string $command): string
    {
        return $this->client->execute($command);
    }

    /**
     * @param iterable<string|int|float|bool|\Stringable|null> $segments
     */
    protected function executeSegments(iterable $segments): string
    {
        return $this->client->executeSegments($segments);
    }
}