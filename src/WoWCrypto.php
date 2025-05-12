<?php

namespace GameCrypto;

use GameCrypto\Contracts\WoWEncryptorInterface;
use GameCrypto\Enums\EmulatorType;
use GameCrypto\Factories\EncryptorFactory;

/**
 * Class WoWCrypto
 * 
 * Main class for handling World of Warcraft password encryption.
 * This class acts as a facade for different WoW encryption implementations.
 * 
 * @package GameCrypto
 */
class WoWCrypto
{
    /**
     * @var WoWEncryptorInterface The encryptor implementation
     */
    private WoWEncryptorInterface $encryptor;

    /**
     * @var EmulatorType The type of emulator being used
     */
    private EmulatorType $emulatorType;

    /**
     * WoWCrypto constructor
     *
     * @param EmulatorType $emulatorType The type of emulator to use
     */
    public function __construct(EmulatorType $emulatorType)
    {
        $this->emulatorType = $emulatorType;
        $this->encryptor = EncryptorFactory::create($emulatorType);
    }

    /**
     * Encrypts a password using the configured encryptor
     *
     * @param string $username The account username
     * @param string $password The account password
     * @return string The encrypted password hash
     */
    public function encrypt(string $username, string $password): string
    {
        return $this->encryptor->encrypt($username, $password);
    }

    /**
     * Verifies if a password matches with its hash
     *
     * @param string $username The account username
     * @param string $password The account password to verify
     * @param string $hash The hash to compare against
     * @return bool Returns true if the password matches, false otherwise
     */
    public function verify(string $username, string $password, string $hash): bool
    {
        return $this->encryptor->verify($username, $password, $hash);
    }
}