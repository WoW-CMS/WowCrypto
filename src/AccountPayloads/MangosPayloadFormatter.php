<?php

namespace GameCrypto\AccountPayloads;

use GameCrypto\Contracts\AccountPayloadFormatterInterface;
use GameCrypto\Contracts\WoWEncryptorInterface;
use GameCrypto\Enums\EmulatorType;
use InvalidArgumentException;

class MangosPayloadFormatter implements AccountPayloadFormatterInterface
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
        $hash = $payload['hash'] ?? null;

        if ($hash === null) {
            throw new InvalidArgumentException('The configured encryptor did not produce the hash required for a MaNGOS-style payload.');
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
                    'sha_pass_hash' => $hash,
                ],
            ],
            'credentials' => [
                'sha_pass_hash' => $hash,
            ],
        ];
    }
}