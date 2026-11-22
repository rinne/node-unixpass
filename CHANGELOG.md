Changelog
=========

4.0.1
-----

### Fixed

- An extended DES salt or hash with an iteration count of zero
  (`_....`) is refused. Such a hash is the same for every password,
  so check() accepted any password for it.
- bcrypt truncated the password to 72 characters before UTF-8
  encoding it instead of to 72 bytes after. The result differed from
  other implementations when the cut fell inside a character outside
  the Basic Multilingual Plane. Other passwords hash as before.
- check() compares the hash in constant time.
- crypt() and check() no longer print errors with console.log.
- Typos: `'use stict'` in bcrypt.js, `TYpeError` in pb64.js.

### Other

- The tests are no longer included in the published package.

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
