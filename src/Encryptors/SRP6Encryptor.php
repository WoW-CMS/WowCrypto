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

        $verifier = self::calculateV2Hash($email, $password, $salt);

        return [$salt, $verifier];
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
     * Calculates the SRP6 hash for a given username, password, and salt
     * 
     * @param string $username The account username
     * @param string $password The account password
     * @param string $salt The salt value
     * @return string The calculated SRP6 hash
     */
    protected function calculateV2Hash(string $username, string $password, string $salt): string
    {
        // Algorithm for SRP6 version 2
        $g = gmp_init(2);
        $N = gmp_init('AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73', 16);
    
        $srpPassword = strtoupper(hash('sha256', strtoupper($username), false)) . ":" . $password;

        // calculate x
        $xBytes = hash_pbkdf2("sha512", $srpPassword, $salt, 15000, 64, true);
        $x = gmp_import($xBytes, 1, GMP_MSW_FIRST);
        if (ord($xBytes[0]) & 0x80)
        {
            $fix = gmp_init('100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 16);
            $x = gmp_sub($x, $fix);
        }
        $x = gmp_mod($x, gmp_sub($N, 1));

        // g^h2 mod N
        $verifier = gmp_powm($g, $x, $N);

        // convert back to a byte array (little-endian)
        $verifier = gmp_export($verifier, 1, GMP_LSW_FIRST);

        // pad to 256 bytes, remember that zeros go on the end in little-endian!
        $verifier = str_pad($verifier, 256, chr(0), STR_PAD_RIGHT);

        // done!
        return $verifier;
    }
}