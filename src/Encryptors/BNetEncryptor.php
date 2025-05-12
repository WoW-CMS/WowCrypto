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
    public function encrypt(string $username, string $password): string
    {
        return strtoupper(bin2hex(strrev(hex2bin(strtoupper(hash('sha256', strtoupper(hash('sha256', strtoupper($username)) . ':' . strtoupper($password))))))));
    }

    /**
     * Verifies if a password matches with its Battle.net hash
     *
     * @param string $username The Battle.net account username
     * @param string $password The account password to verify
     * @param string $hash The hash to compare against
     * @return bool Returns true if the password matches, false otherwise
     */
    public function verify(string $username, string $password, string $hash): bool
    {
        return $this->encrypt($username, $password) === strtoupper($hash);
    }
}