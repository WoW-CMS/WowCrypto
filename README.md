# WowCrypto 🎮

A specialized PHP library for World of Warcraft encryption protocols. WowCrypto implements the necessary cryptographic functions for authentication in different WoW emulators.

## ⚡ Features

- **Multiple Emulators Support**: Ready for the most popular emulators
  - MaNGOS (SHA_PASS_HASH)
  - TrinityCore (SRP6 V2)
  - AzerothCore (SRP6 V2)
  - CMaNGOS (SHA_PASS_HASH)
  - Skyfire (Battle.net)

- **Encryption Methods**:
  - SHA_PASS_HASH (Vanilla/TBC)
  - SRP6 V1 & V2 (WotLK+)
  - Battle.net (Modern WoW)

## 🚀 Installation

```bash
composer require wowcrypto/wowcrypto
```

## 📖 Basic Usage

```php
use GameCrypto\WoWCrypto;
use GameCrypto\Enums\EmulatorType;

// Create instance for TrinityCore
$crypto = new WoWCrypto(EmulatorType::TRINITY_CORE);

// Encrypt password
$hash = $crypto->encrypt('USERNAME', 'PASSWORD');

// Verify password
$isValid = $crypto->verify('USERNAME', 'PASSWORD', $hash);
```

## 🛠️ Advanced Configuration

```php
use GameCrypto\WoWCrypto;
use GameCrypto\Enums\EmulatorType;
use GameCrypto\Config\TrinityConfig;
use GameCrypto\Enums\EncryptionType;

// Use SRP6 V1 in TrinityCore
$config = new TrinityConfig(EncryptionType::SRP6_V1);
$crypto = new WoWCrypto(EmulatorType::TRINITY_CORE, $config);
```

## ## 🔒 Available Encryption Methods

- SHA_PASS_HASH (Vanilla/TBC)
- SRP6 V1 & V2 (WotLK+)
- Battle.net (Modern WoW)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👥 Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.
