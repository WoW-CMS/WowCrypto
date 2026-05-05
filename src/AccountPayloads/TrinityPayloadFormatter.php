<?php

namespace GameCrypto\AccountPayloads;

use GameCrypto\Contracts\AccountPayloadFormatterInterface;
use GameCrypto\Contracts\WoWEncryptorInterface;
use GameCrypto\Enums\EmulatorType;
use InvalidArgumentException;

class TrinityPayloadFormatter implements AccountPayloadFormatterInterface
{
    public function __construct(
        private readonly EmulatorType $emulatorType,
        private readonly WoWEncryptorInterface $encryptor
    ) {
    }

    public function formatPayload(string $username, string $password, ?string $email = null): array
    {
        $normalizedUsername = strtoupper($username);
        $normalizedEmail = $email !== null ? strtoupper($email) : null;

        $payload = $this->encryptor->encrypt($normalizedUsername, $password);
        $salt = $payload['salt'] ?? null;
        $verifier = $payload['verifier'] ?? null;

        if ($salt === null || $verifier === null) {
            throw new InvalidArgumentException('The configured encryptor did not produce the salt and verifier required for a Trinity-style payload.');
        }

        return [
            'emulator' => $this->emulatorType->value,
            'identity' => [
                'username' => $normalizedUsername,
                'email' => $normalizedEmail,
                'login_field' => 'username',
                'login_value' => $normalizedUsername,
            ],
            'cms' => [
                'account_table' => 'account',
                'account_primary_key' => 'id',
                'lookup' => [
                    'username' => $normalizedUsername,
                    'email' => $normalizedEmail,
                ],
                'insert' => [
                    'username' => $normalizedUsername,
                    'email' => $normalizedEmail,
                    'salt' => $salt,
                    'verifier' => $verifier,
                ],
            ],
            'credentials' => [
                'salt' => $salt,
                'verifier' => $verifier,
            ],
        ];
    }
}