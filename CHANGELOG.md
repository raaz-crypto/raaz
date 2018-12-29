# Change log for [raaz].

## [0.3.0] - Pending

* Major changes are

    1. Use libverse for the low level FFI implementations. From now on
       newer primitives will be coded up in verse instead of hand
       written C/assembly.

    2. Complete rewrite of the interface using backpack where modules
       and signatures now replace classes related to
       implementation. Simplifies the library and allows easy plugging
       in of custom implementations.

    3. GHC below 8.2 not supported anymore because of backpack.

* Uses a host-endian variant of chacha20 keystream for csprg.
* Block size moved to type level. Allows better type safety.
* Use Data.Proxy.Proxy to get rid of some uses of undefined.
* Linux: getrandom now uses syscall directly, so works even when glibc
  is old.  By default on Linux getrandom is the entropy source unless
  disabled by flags.
* raaz command expose an entropy command for checking the quality of
  system entropy source.
* Dropped support for SHA1, SHA224, SHA384, HMAC, and AES-CBC, mainly
  to concentrate efforts and reach stable release soon.
* From BSD-3-Clause to dual license Apache-2.0 OR BSD-3-Clause.

## [0.2.0] - 24 August, 2017

* Some cpu detection builtin for GCC. Would come handy in future for
  selection of primitives are runtime.
* BLAKE2b, BLAKE2s added.
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
* Windows support is now included. The missing pieces were system
  entropy and memory locking which is now available.

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
[0.2.0]: <http://github.com/raaz-crypto/raaz/releases/tag/v0.2.0>
[raaz]:  <http://github.com/raaz-crypto/raaz/>
