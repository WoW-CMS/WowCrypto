# WowCrypto

WowCrypto is a PHP library for World of Warcraft authentication data and SOAP console commands.

It is designed for CMS or launcher integrations that need to:
- generate emulator-specific password data
- verify credentials against the expected emulator format
- prepare account payloads for insertion from the host application
- execute TrinityCore-style SOAP commands through a modular API

The library does not need to own account creation inside your CMS. Its main job is to generate the correct auth data and provide a clean command surface for console actions.

## Features

- Support for multiple emulator families.
- SHA_PASS_HASH support for MaNGOS-style auth.
- SRP6 support for TrinityCore and AzerothCore style auth.
- Battle.net style hash support for SkyFire-like flows.
- Emulator-specific account payload generation for host CMS integrations.
- Modular SOAP command API for account, mail, character, moderation, and server actions.
- Safe SOAP command building for arguments with spaces or quotes.

## Supported Emulators

- MaNGOS
- CMaNGOS
- TrinityCore
- AzerothCore
- SkyFire

## Supported Encryption Types

- `SHA_PASS_HASH`
- `SRP6_V1`
- `SRP6_V2`
- `BNET`

## Requirements

- PHP `>= 8.1`
- `ext-openssl`
- `ext-gmp`

## Installation

```bash
composer require wowcrypto/wowcrypto
```

## Quick Start

```php
use GameCrypto\Enums\EmulatorType;
use GameCrypto\WoWCrypto;

$crypto = new WoWCrypto(EmulatorType::TRINITY_CORE);

$payload = $crypto->encrypt('USERNAME', 'PASSWORD');
$isValid = $crypto->verify('USERNAME', 'PASSWORD', $payload);
```

## Core API

The main entry point is `GameCrypto\WoWCrypto`.

Available methods:
- `encrypt(string $username, string $password): array`
- `verify(string $username, string $password, array|string $hash): bool`
- `prepareAccountPayload(string $username, string $password, ?string $email = null): array`

## Encryption Examples

### MaNGOS / CMaNGOS

```php
use GameCrypto\Enums\EmulatorType;
use GameCrypto\WoWCrypto;

$crypto = new WoWCrypto(EmulatorType::MANGOS);

$payload = $crypto->encrypt('USERNAME', 'PASSWORD');

// Example result:
// ['hash' => '...']
```

### TrinityCore / AzerothCore

```php
use GameCrypto\Enums\EmulatorType;
use GameCrypto\WoWCrypto;

$crypto = new WoWCrypto(EmulatorType::TRINITY_CORE);

$payload = $crypto->encrypt('USERNAME', 'PASSWORD');

// Example result:
// ['salt' => '...', 'verifier' => '...']
```

### SkyFire / Battle.net Style

```php
use GameCrypto\Enums\EmulatorType;
use GameCrypto\WoWCrypto;

$crypto = new WoWCrypto(EmulatorType::SKYFIRE);

$payload = $crypto->encrypt('EMAIL@EXAMPLE.COM', 'PASSWORD');

// Example result:
// ['hash' => '...']
```

## Verification Example

```php
use GameCrypto\Enums\EmulatorType;
use GameCrypto\WoWCrypto;

$crypto = new WoWCrypto(EmulatorType::TRINITY_CORE);
$payload = $crypto->encrypt('USERNAME', 'PASSWORD');

$valid = $crypto->verify('USERNAME', 'PASSWORD', $payload);
```

## Advanced Encryption Configuration

If you need to force a specific encryption variant, pass an emulator config.

```php
use GameCrypto\Config\TrinityConfig;
use GameCrypto\Enums\EmulatorType;
use GameCrypto\Enums\EncryptionType;
use GameCrypto\WoWCrypto;

$config = new TrinityConfig(EncryptionType::SRP6_V1);
$crypto = new WoWCrypto(EmulatorType::TRINITY_CORE, $config);
```

## CMS Integration

This library is intended to work well when your CMS owns validation, insertion, and account linking.

Use `prepareAccountPayload(...)` when your application needs emulator-specific data for the auth database.

```php
use GameCrypto\Enums\EmulatorType;
use GameCrypto\WoWCrypto;

$crypto = new WoWCrypto(EmulatorType::TRINITY_CORE);

$payload = $crypto->prepareAccountPayload('USERNAME', 'PASSWORD', 'mail@example.com');
```

The payload is shaped for a CMS flow that typically:
- checks duplicates in the auth `account` table
- inserts emulator-specific credential columns
- reads the auth account primary key
- links that created game account to the local CMS user

### Payload Structure

`prepareAccountPayload(...)` returns an array with these top-level keys:
- `emulator`
- `identity`
- `cms`
- `credentials`

### `identity`

Contains normalized identity data used by the host application.

Example fields:
- `username`
- `email`
- `login_field`
- `login_value`

### `cms`

Contains host-application-oriented metadata.

Example fields:
- `account_table`
- `account_primary_key`
- `lookup`
- `insert`

### `credentials`

Contains the emulator-specific auth values.

Examples:
- MaNGOS: `sha_pass_hash`
- TrinityCore: `salt`, `verifier`
- SkyFire: `bnet_hash`

## Payload Examples

### MaNGOS Payload

```php
use GameCrypto\Enums\EmulatorType;
use GameCrypto\WoWCrypto;

$crypto = new WoWCrypto(EmulatorType::MANGOS);
$payload = $crypto->prepareAccountPayload('USERNAME', 'PASSWORD', 'mail@example.com');

// Relevant fields:
// $payload['cms']['lookup']['username']
// $payload['cms']['insert']['sha_pass_hash']
// $payload['credentials']['sha_pass_hash']
```

### TrinityCore Payload

```php
use GameCrypto\Enums\EmulatorType;
use GameCrypto\WoWCrypto;

$crypto = new WoWCrypto(EmulatorType::TRINITY_CORE);
$payload = $crypto->prepareAccountPayload('USERNAME', 'PASSWORD', 'mail@example.com');

// Relevant fields:
// $payload['cms']['insert']['salt']
// $payload['cms']['insert']['verifier']
// $payload['credentials']['salt']
// $payload['credentials']['verifier']
```

### SkyFire Payload

```php
use GameCrypto\Enums\EmulatorType;
use GameCrypto\WoWCrypto;

$crypto = new WoWCrypto(EmulatorType::SKYFIRE);
$payload = $crypto->prepareAccountPayload('USERNAME', 'PASSWORD', 'mail@example.com');

// Relevant fields:
// $payload['identity']['login_field'] === 'email'
// $payload['credentials']['bnet_hash']
```

## SOAP Support

`GameCrypto\SoapAccountCreator` is the transport entry point for SOAP console commands.

It exposes a modular surface instead of concentrating all commands in a single file.

Available modules:
- `account()`
- `mail()`
- `character()`
- `moderation()`
- `server()`

Low-level helpers still available on the transport:
- `customCommand(string $command): string`
- `execute(SoapCommand|string $command): string`
- `executeSegments(iterable $segments): string`

## Basic SOAP Usage

```php
use GameCrypto\SoapAccountCreator;

$soap = new SoapAccountCreator('127.0.0.1', 7878, 'soap_user', 'soap_pass', 'TC');

$result = $soap->server()->info();
```

## SOAP Module Examples

### Account Module

```php
$soap->account()->create('USERNAME', 'PASSWORD', 'mail@example.com');
$soap->account()->createBnet('mail@example.com', 'PASSWORD');
```

### Mail Module

```php
$soap->mail()->send('PLAYERNAME', 'Welcome', 'Your rewards are waiting.');

$soap->mail()->sendMoney(
    'PLAYERNAME',
    'Compensation',
    'Thanks for your patience.',
    500000
);

$soap->mail()->sendItems(
    'PLAYERNAME',
    'Starter Pack',
    'Enjoy your items.',
    [6948 => 1, 17031 => 5]
);

$soap->mail()->sendItemsAndMoney(
    'PLAYERNAME',
    'Bundle',
    'Items and gold included.',
    [6948 => 1, 17031 => 5],
    100000
);
```

### Character Module

```php
$soap->character()->rename('PLAYERNAME');
$soap->character()->customize('PLAYERNAME');
$soap->character()->changeRace('PLAYERNAME');
$soap->character()->changeFaction('PLAYERNAME');
$soap->character()->setLevel('PLAYERNAME', 80);
```

### Moderation Module

```php
$soap->moderation()->banAccount('ACCOUNTNAME', '7d', 'Chargeback investigation');
$soap->moderation()->unbanAccount('ACCOUNTNAME');
$soap->moderation()->banCharacter('PLAYERNAME', '1d', 'Abusive chat');
$soap->moderation()->unbanCharacter('PLAYERNAME');
```

### Server Module

```php
$soap->server()->info();
```

## Building Complex SOAP Commands

For commands that do not yet have a dedicated module helper, you can still build them safely with segments.

```php
$soap->executeSegments(['character', 'rename', 'Old Name']);
$soap->executeSegments(['send', 'mail', 'Player Name', 'Welcome title', 'Body with spaces']);
```

If you already have the raw command string, you can still send it directly.

```php
$soap->customCommand('server info');
```

## `SoapCommand`

`GameCrypto\SoapCommand` exists for lower-level command construction when you want full control over composition and escaping.

```php
use GameCrypto\SoapCommand;

$command = SoapCommand::fromSegments(['character', 'rename', 'Player With Spaces']);
$soap->execute($command);
```

## Project Structure

Important public areas of the library:
- `src/WoWCrypto.php`: encryption and payload facade
- `src/Config/`: emulator configuration objects
- `src/Encryptors/`: encryption implementations
- `src/Enums/`: emulator and encryption enums
- `src/AccountPayloads/`: CMS payload builders
- `src/SoapAccountCreator.php`: SOAP transport and module access
- `src/Modules/`: SOAP command modules
- `src/SoapCommand.php`: safe SOAP command builder

## Notes

- Username and email normalization may be emulator-specific. The payload builders already normalize values for the CMS-oriented account flow.
- SkyFire payloads currently expose Battle.net-oriented identity and hash data, but you should still verify the exact target auth schema in your host application.
- SOAP helpers are oriented to TrinityCore-style command usage.

## License

This project is licensed under the MIT License. See `LICENSE` for details.
