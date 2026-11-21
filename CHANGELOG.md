Changelog
=========

4.0.0
-----

### Changed behaviour

- MD5 ($1$), SHA-256 ($5$) and SHA-512 ($6$) hashes of passwords
  containing non-ASCII characters are now computed from the UTF-8
  bytes of the password as glibc, libxcrypt and OpenSSL do.
  Previously the length dependent steps used the length of the
  JavaScript string instead of its UTF-8 encoding, so such hashes
  were incompatible with every other implementation. A hash that an
  earlier version created from a non-ASCII password does not verify
  with this version. Hashes of plain ASCII passwords are unchanged.

### Fixed

- check() returned false for every legacy DES and extended DES hash,
  because crypt() copied the whole hash given as the salt to the
  result. crypt() now also accepts a complete DES hash as the salt.

### Other

- Tests for check() and mkpass(), and test vectors for non-ASCII
  passwords.
- The tests are run before publishing.
