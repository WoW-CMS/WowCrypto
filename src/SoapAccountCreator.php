<?php

namespace GameCrypto;

use GameCrypto\Modules\AccountModule;
use GameCrypto\Modules\CharacterModule;
use GameCrypto\Modules\MailModule;
use GameCrypto\Modules\ModerationModule;
use GameCrypto\Modules\ServerModule;
use SoapParam;

class SoapAccountCreator
{
    private string $host;
    private int $port;
    private string $user;
    private string $pass;
    private string $urn;
    private bool $useSSL;
    private ?AccountModule $accountModule = null;
    private ?CharacterModule $characterModule = null;
    private ?MailModule $mailModule = null;
    private ?ModerationModule $moderationModule = null;
    private ?ServerModule $serverModule = null;

    public function __construct(string $host, int $port, string $user, string $pass, string $urn, bool $useSSL = false)
    {
        $this->host = $host;
        $this->port = $port;
        $this->user = $user;
        $this->pass = $pass;
        $this->urn  = $urn;
        $this->useSSL = $useSSL;
    }

    private function getSoapClient(): \SoapClient
    {
        return new \SoapClient(null, [
            'location' => ($this->useSSL ? 'https://' : 'http://') . $this->host . ':' . $this->port . '/',
            'uri' => 'urn:'. $this->urn,
            'style' => SOAP_RPC,
            'login' => $this->user,
            'password' => $this->pass,
            'keep_alive' => false
        ]);
    }

    public function account(): AccountModule
    {
        return $this->accountModule ??= new AccountModule($this);
    }

    public function character(): CharacterModule
    {
        return $this->characterModule ??= new CharacterModule($this);
    }

    public function mail(): MailModule
    {
        return $this->mailModule ??= new MailModule($this);
    }

    public function moderation(): ModerationModule
    {
        return $this->moderationModule ??= new ModerationModule($this);
    }

    public function server(): ServerModule
    {
        return $this->serverModule ??= new ServerModule($this);
    }

    public function customCommand(string $command): string
    {
        return $this->execute(SoapCommand::raw($command));
    }

    public function execute(SoapCommand|string $command): string
    {
        $commandString = $command instanceof SoapCommand
            ? $command->toCommandString()
            : SoapCommand::raw($command)->toCommandString();

        $client = $this->getSoapClient();

        return $client->executeCommand(new SoapParam($commandString, 'command'));
    }

    /**
     * @param iterable<string|int|float|bool|\Stringable|null> $segments
     */
    public function executeSegments(iterable $segments): string
    {
        return $this->execute(SoapCommand::fromSegments($segments));
    }
}