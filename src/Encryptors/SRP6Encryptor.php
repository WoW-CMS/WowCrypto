<?php

namespace GameCrypto\Encryptors;

use GameCrypto\Contracts\WoWEncryptorInterface;

/**
 * Class SRP6Encryptor
 * 
 * Implements the Secure Remote Password (SRP6) protocol for WoW authentication.
 * Supports both SRP6 version 1 and version 2, commonly used in modern WoW servers.
 * 
 * @package GameCrypto\Encryptors
 */
class SRP6Encryptor implements WoWEncryptorInterface
{
    /**
     * @var bool Flag to determine if using SRP6 version 2
     */
    private bool $isV2;

    /**
     * @var string The generator value used in the SRP6 protocol
     */
    private string $g = '7';

    /**
     * @var string The large safe prime number used in the SRP6 protocol
     */
    private string $N;

    /**
     * SRP6Encryptor constructor
     *
     * @param bool $isV2 Whether to use SRP6 version 2 (default: false)
     */
    public function __construct(bool $isV2 = false)
    {
        $this->isV2 = $isV2;
        $this->N = '894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7';
    }

    /**
     * Encrypts a password using the selected SRP6 version
     *
     * @param string $username The account username
     * @param string $password The account password
     * @return string The encrypted password hash
     */
    public function encrypt(string $username, string $password): array
    {
        if ($this->isV2) {
            $salt = random_bytes(32);
            $g    = gmp_init(7);
            $N    = gmp_init($this->N, 16);

            $h1 = sha1(strtoupper($username. ':'. $password), true);
            $h2 = sha1($salt.$h1, true);
            
            $h2 = gmp_import($h2, 1, GMP_LSW_FIRST);

            $verifier = gmp_powm($g, $h2, $N);
            $verifier = gmp_export($verifier, 1, GMP_LSW_FIRST);
            $verifier = str_pad($verifier, 32, chr(0), STR_PAD_RIGHT);

            return [
                'verifier' => $verifier,
               'salt'     => $salt,
            ];
        }

        $h1 = sha1(strtoupper($username . ':' . $password), true);
        return ['hash' => strtoupper(bin2hex($h1)), 'salt' => ''];
    }

    /**
     * Verifies if a password matches with its SRP6 hash
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

    /**
     * Calculates the SRP6 version 1 hash
     *
     * @param string $username The account username
     * @param string $password The account password
     * @return string The calculated hash
     */
    private function calculateV1Hash(string $username, string $password): string
    {
        $h1 = sha1(strtoupper($username . ':' . $password), true);
        return strtoupper(bin2hex($h1));
    }

    /**
     * Calculates the SRP6 version 2 hash following RFC 2945
     *
     * @param string $username The account username
     * @param string $password The account password
     * @return string The calculated hash
     */
    private function calculateV2Hash(string $username, string $password): array
    {
        // Cálculo del hash para SRP6 versión 2
        $salt = random_bytes(16);
        $saltHex = bin2hex($salt);
        
        // Calcular x (RFC 2945)
        $h1 = sha1(strtoupper($username . ':' . $password), true);
        $h2 = sha1($salt . $h1, true);
        $x = new \GMP(bin2hex($h2), 16);
        
        // Calcular v = g^x % N
        $g = new \GMP($this->g);
        $N = new \GMP($this->N, 16);
        $v = gmp_powm($g, $x, $N);
        
        // Convertir v a hexadecimal
        $vHex = gmp_strval($v, 16);
        $vHex = str_pad($vHex, 32, '0', STR_PAD_LEFT);
        
        return [
            'hash' => $vHex,
            'salt' => $saltHex
        ];
    }
}