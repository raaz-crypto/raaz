# Change log for [raaz].

## [0.2.0] - Pending

* BLAKE2b added.
* system entropy: Experimental support for linux getrandom call
* removed depreciated `liftSubMT` from Memory.
* Got rid of the class `MemoryMonad`, instead introduced a more specific
  `MemoryThread`. This allows to treat monads like `RT mem` much like
  `MT mem`, including possibility of running an action on a sub-memory.
* combinator to randomise memory cells.
* hardened the prg so that a compromise on the current prg state will
  not expose previously generated data.
* OpenBSD/NetBSD: fix incorrect arc4random call.
* Basic Unix man-page for the raaz command.

## [0.1.1] - 2nd  March, 2017

* Failing build on big endian machines (#306) fixed.

## [0.1.0] - 28th February, 2017

* Stream cipher chacha20 added.
* Added a PRG that uses chacha20, seeded with system entropy
* Sha1 highly depreciated in view of reported collision.
* We now have super command `raaz` with subcommands
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
[0.1.0]: <http://github.com/raaz-crypto/raaz/releases/tag/v0.1.0>
[0.1.1]: <http://github.com/raaz-crypto/raaz/releases/tag/v0.1.1>
[raaz]:  <http://github.com/raaz-crypto/raaz/>
