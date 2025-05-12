<?php

namespace GameCrypto\Contracts;

interface WoWEncryptorInterface
{
    /**
     * Encripta una contraseña usando el método específico
     *
     * @param string $username
     * @param string $password
     * @return string
     */
    public function encrypt(string $username, string $password): string;

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