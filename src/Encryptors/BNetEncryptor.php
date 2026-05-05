<?php

namespace GameCrypto\Encryptors;

use GameCrypto\Contracts\WoWEncryptorInterface;

/**
 * Class BNetEncryptor
 * 
 * Battle.net password encryption implementation.
 * Uses SHA256 with specific Battle.net modifications for password hashing.
 * 
 * @package GameCrypto\Encryptors
 */
class BNetEncryptor implements WoWEncryptorInterface
{
    /**
     * Encrypts a password using Battle.net's encryption method
     * The process involves:
     * 1. Double SHA256 hashing
     * 2. String manipulation (uppercase, reverse)
     * 3. Hex encoding
     *
     * @param string $username The Battle.net account username
     * @param string $password The account password
     * @return string The encrypted password hash
     */
    public function encrypt(string $username, string $password): array
    {
        $hash = strtoupper(bin2hex(strrev(hex2bin(strtoupper(hash('sha256', strtoupper(hash('sha256', strtoupper($username)) . ':' . strtoupper($password))))))));
        return ['hash' => $hash];
    }

    /**
     * Verifies if a password matches with its Battle.net hash
     *
     * @param string $username The Battle.net account username
     * @param string $password The account password to verify
     * @param array<string, string>|string $hash The hash payload to compare against
     * @return bool Returns true if the password matches, false otherwise
     */
    public function verify(string $username, string $password, array|string $hash): bool
    {
        $expectedHash = is_array($hash) ? ($hash['hash'] ?? null) : $hash;

        if ($expectedHash === null) {
            return false;
        }

        return $this->encrypt($username, $password)['hash'] === strtoupper($expectedHash);
    }
}