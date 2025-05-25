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
     * @param bool $isV2 Whether to use SRP6 version 2 (default: true)
     */
    public function __construct(bool $isV2 = true)
    {
        $this->isV2 = $isV2;
        $this->N = '894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7'; // This is for v1SRP
    }

    /**
     * Encrypts a password using the selected SRP6 version
     *
     * @param string $username The account username
     * @param string $password The account password
     * @return string The encrypted password hash
     */
    public function encrypt(string $email, string $password): array
    {
        $salt = random_bytes(32);
        $g    = gmp_init(2);
        $N    = gmp_init(
            'AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B0331
            0DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4F
            F747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0
            D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9
            DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73',
            16
        );

        $password = strtoupper(hash('sha256', strtoupper($email), false)) . ":" . $password;
        $xBytes = hash_pbkdf2('sha512', $password, $salt, 15000, 64, true);
        $x = gmp_import($xBytes, 1, GMP_MSW_FIRST);
        
        if (ord($xBytes[0]) & 0x80)
        {
            $fix = gmp_init('100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 16);
            $x = gmp_sub($x, $fix);
        }

        $x = gmp_mod($x, gmp_sub($N, 1));
        
        // G^h2 mod N
        $verifier = gmp_powm($g, $x, $N);

        // convert back to a byte array (little-endian)
        $verifier = gmp_export($verifier, 1, GMP_LSW_FIRST);
        $verifier = str_pad($verifier, 256, chr(0), STR_PAD_RIGHT);

        return [
            'verifier' => $verifier,
            'salt'     => $salt,
        ];
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