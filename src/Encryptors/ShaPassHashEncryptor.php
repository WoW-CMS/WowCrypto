<?php

namespace GameCrypto\Encryptors;

use GameCrypto\Contracts\WoWEncryptorInterface;

/**
 * Class ShaPassHashEncryptor
 * 
 * Classic WoW password encryption implementation.
 * Uses SHA1 hashing for password encryption, commonly used in
 * vanilla, TBC, and WotLK servers.
 * 
 * @package GameCrypto\Encryptors
 */
class ShaPassHashEncryptor implements WoWEncryptorInterface
{
    /**
     * Encrypts a password using the SHA1 method
     *
     * @param string $username The account username
     * @param string $password The account password
     * @return string The encrypted password hash
     */
    public function encrypt(string $username, string $password): string
    {
        return strtoupper(sha1(strtoupper($username . ':' . $password)));
    }

    /**
     * Verifies if a password matches with its SHA1 hash
     *
     * @param string $username The account username
     * @param string $password The account password to verify
     * @param string $hash The hash to compare against
     * @return bool Returns true if the password matches, false otherwise
     */
    public function verify(string $username, string $password, string $hash): bool
    {
        return $this->encrypt($username, $password) === strtoupper($hash);
    }
}