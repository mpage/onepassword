Vault Locations
===============
Source:  https://guides.agilebits.com/1password-mac-kb/5/en/topic/data-locations

App Store:
~/Library/Containers/2BUA8C4S2C.com.agilebits.onepassword-osx-helper/Data/Library/Data/OnePassword.sqlite

Web Store:
~/Library/Application Support/1Password 4/Data/OnePassword.sqlite

OPData Format
=============

- 8  bytes - string "opdata01"
- 8  bytes - plaintext length; uint64_t, little endian
- 16 bytes - IV
- variable - ciphertext
- 32 bytes - MAC

Crypto
======

Source: https://support.1password.com/opvault-design/

- Encrypt-then-MAC
- MAC: HMAC-SHA256
- Cipher: AES-CBC using 256-bit keys
- Key derivation: PBKDF2-HMAC-SHA512

Keys
----

- Master Password
- Derived encryption key.
- Derived MAC key.
- Master encryption key.
- Master MAC key.
- Overview encryption key.
- Overview MAC key.
- Item encryption key (item specific).
- Item MAC key (item specific).

- Master password ->  derived keys
- derived keys encrypt/mac master keys
- master keys encrypt/mac item keys
- item keys encrypt/mac items

How to decrypt an item
----------------------

1. Derive encryption and mac keys based on master password
2. Use derived mac key to verify encrypted master keys
3. Assuming (2) succeeds, use derived encryption key to decrypt master keys
4. Use master mac key to verify encrypted item keys
5. Assuming (4) succeeds, use decrypted mac key to verify encrypted item
6. Assuming (5) succeeds, use decrypted enc key to decrypt item data


DB Structure
============

- Master and overview keys are associated with a profile and are stored in
  the profiles table.
