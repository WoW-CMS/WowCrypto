<?php

namespace GameCrypto\AccountPayloads;

use GameCrypto\Contracts\AccountPayloadFormatterInterface;
use GameCrypto\Contracts\WoWEncryptorInterface;
use GameCrypto\Enums\EmulatorType;
use InvalidArgumentException;

class SkyfirePayloadFormatter implements AccountPayloadFormatterInterface
{
    public function __construct(
        private readonly EmulatorType $emulatorType,
        private readonly WoWEncryptorInterface $encryptor
    ) {
    }

    public function formatPayload(string $username, string $password, ?string $email = null): array
    {
        if ($email === null || $email === '') {
            throw new InvalidArgumentException('SkyFire payload generation requires an email because Battle.net style accounts use email as identity.');
        }

        $normalizedUsername = strtoupper($username);
        $normalizedEmail = strtoupper($email);

        $payload = $this->encryptor->encrypt($normalizedEmail, $password);
        $hash = $payload['hash'] ?? null;

        if ($hash === null) {
            throw new InvalidArgumentException('The configured encryptor did not produce the hash required for a SkyFire payload.');
        }

        return [
            'emulator' => $this->emulatorType->value,
            'identity' => [
                'username' => $normalizedUsername,
                'email' => $normalizedEmail,
                'login_field' => 'email',
                'login_value' => $normalizedEmail,
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
                ],
                'credential_mapping_status' => 'manual',
            ],
            'credentials' => [
                'bnet_hash' => $hash,
            ],
        ];
    }
}