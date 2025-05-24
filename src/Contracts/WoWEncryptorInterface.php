<?php

namespace GameCrypto\Contracts;

interface WoWEncryptorInterface
{
    /**
     * Encrypts the provided credentials.
     *
     * @param string $username
     * @param string $password
     * @return array<string, string> Returns an array with at least a 'hash' key, and optionally 'salt' and 'verifier'.
     */
    public function encrypt(string $username, string $password): array;

    /**
     * Verifica si una contraseña coincide con el hash
     *
     * @param string $username
     * @param string $password
     * @param string $hash
     * @return bool
     */
    public function verify(string $username, string $password, string $hash): bool;
}