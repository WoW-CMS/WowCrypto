# Changelog

All notable changes to this project are documented in this file.

## 1.3.0 - 2026-05-05

### Added

- Added emulator-specific account payload generation for CMS-driven account creation flows.
- Added payload builders for MaNGOS-style, TrinityCore/AzerothCore-style, and SkyFire-style authentication data.
- Added a dedicated `prepareAccountPayload(...)` API on `GameCrypto\WoWCrypto`.
- Added `SkyfireConfig` and completed default config resolution for all currently supported emulator families.
- Added a modular SOAP command architecture under `src/Modules/`.
- Added SOAP modules for:
  - account commands
  - mail commands
  - character commands
  - moderation commands
  - server commands
- Added `GameCrypto\SoapCommand` to safely compose SOAP commands from segments.
- Added support for complex SOAP arguments with spaces and quotes without forcing consumers to manually concatenate raw strings.
- Added higher-level TrinityCore-oriented SOAP helpers for:
  - account creation
  - Battle.net account creation
  - in-game mail
  - mail with money
  - mail with items
  - mail with items and money
  - character rename
  - character customization
  - character race change
  - character faction change
  - character level changes
  - account ban and unban
  - character ban and unban
- Added documentation for the current public API, payload structure, and modular SOAP usage.

### Changed

- Reworked the library positioning so it better fits CMS integrations where the CMS owns validation, insertion, and account linking.
- Refocused the package on generating authentication data and integration payloads instead of owning direct database account creation.
- Reworked the README to document the current architecture and usage model in English.
- Refactored `SoapAccountCreator` into a lightweight SOAP transport and module entry point.
- Moved command-specific SOAP logic out of the main SOAP class and into dedicated module files for maintainability.
- Normalized encryption output shapes so emulator-specific auth payloads are returned consistently.
- Updated verification logic so array-based payloads can be validated correctly, including SRP6 payload verification.
- Completed emulator default config mapping for MaNGOS, CMaNGOS, TrinityCore, AzerothCore, and SkyFire.
- Improved the public encryption flow so `WoWCrypto` can produce both raw auth material and CMS-oriented payloads.

### Fixed

- Fixed inconsistent encryptor return formats across the supported encryption implementations.
- Fixed verification behavior for hash payloads that are returned as structured arrays instead of plain strings.
- Fixed SRP6 encryption output so it exposes named fields such as `salt` and `verifier` instead of positional arrays.
- Fixed emulator default config handling where some supported emulator enum values did not resolve to a default configuration.
- Fixed the overall SOAP command composition flow so commands with quoted or spaced arguments can be built more safely.

### Removed

- Removed the intermediate direct database account creator layer from the library surface.
- Removed the account-creation abstraction that assumed the library should insert into emulator auth databases directly.
- Removed command-heavy SOAP logic from the main `SoapAccountCreator` class in favor of module-based organization.

### Notes

- The library now assumes the host CMS or application is responsible for account validation, persistence, and linking.
- `prepareAccountPayload(...)` is intended to provide the emulator-specific values needed by that host application.
- The SOAP layer is now structured for growth, so future command groups can be added as separate modules instead of expanding a single large class.