# Change log for [raaz].

## [0.1.0] - 28th February, 2017

* Stream cipher chacha20 added.
* Added a PRG that uses chacha20, seeded with system entropy
* Sha1 highly depreciated in view of reported collision.
* We now have supper command `raaz` with subcommands
  - `checksum`: as a replacement for the old checksum executable
  - `rand`: for generating random bytes.

Low level changes

* Reworked alignment considerations.

  - New Alignment type

  - Ways for implementations to demand that the input buffer be aligned
	(mainly to facilitate more efficient SIMD implementations).


* Num instance from LengthUnit removed, Monoid instance added (See
  issue:#247)


## [0.0.2] - July 25, 2016.

This release comes with very little changes.

* Encoding: translation between formats using the `translate`
  combinator
* Encoding formats: base64
* Bug fix in base16 character verification (Commit: d6eca4c37b0b)
* Dropped `isSuccessful` from export list of Equality.

## [0.0.1] - June 21, 2016.

* Basic cryptographic types.
* Hashes: sha1, sha256, sha512, sha224, sha384 and their HMACs
* Ciphers: AES-CBC with key-sizes 128, 192 and 256
* Encoding formats: base16

[0.0.1]: <http://github.com/raaz-crypto/raaz/releases/tag/v0.0.1>
[0.0.2]: <http://github.com/raaz-crypto/raaz/releases/tag/v0.0.2>
[raaz]:  <http://github.com/raaz-crypto/raaz/>
