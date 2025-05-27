<?php

namespace GameCrypto;

use SoapParam;

class SoapAccountCreator
{
    private string $host;
    private int $port;
    private string $user;
    private string $pass;
    private bool $useSSL;

    public function __construct(string $host, int $port, string $user, string $pass, bool $useSSL = false)
    {
        $this->host = $host;
        $this->port = $port;
        $this->user = $user;
        $this->pass = $pass;
        $this->useSSL = $useSSL;
    }

    private function getSoapClient(): \SoapClient
    {
        return new \SoapClient(null, [
            'location' => ($this->useSSL ? 'https://' : 'http://') . $this->host . ':' . $this->port . '/',
            'uri' => 'urn:TC',
            'style' => SOAP_RPC,
            'login' => $this->user,
            'password' => $this->pass,
            'keep_alive' => false
        ]);
    }

    public function createAccount(string $username, string $password, ?string $email): string
    {
        $cmd = "acc create $username $password $email";

        $client = $this->getSoapClient();
        return $client->executeCommand(new SoapParam($cmd, 'command'));
    }

    public function createAccountBnet(string $email, string $password): string
    {
        $cmd = "bnet create $email $password";

        $client = $this->getSoapClient();
        return $client->executeCommand(new SoapParam($cmd, 'command'));
    }

    public function soapTest(): string
    {
        $client = $this->getSoapClient();
        return $client->executeCommand(new SoapParam('server info', 'command'));
    }

    public function customCommand(string $command): string
    {
        $client = $this->getSoapClient();
        return $client->executeCommand(new SoapParam($command, 'command'));
    }
}