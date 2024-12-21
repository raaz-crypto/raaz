# Change log for [raaz].

## [0.3.11] - Dec 21, 2024

Release that supports ghc-9.12 (base 4.21)

## [0.3.10] - Feb 1, 2024

Release that supports ghc-9.10 (base 4.20)

## [0.3.9] - Feb 1, 2024

Release that supports ghc-9.8 (base 4.19)

## [0.3.8] - Oct 6, 2023

Release that supports ghc-9.6 (base 4.18)

## [0.3.7] - Nov 14, 2022

Release that supports ghc-9.4 (base 4.17).

## [0.3.6] - Dec 3, 2021

Release that supports ghc-9.2 (base 4.16).

## [0.3.5] - Oct 10, 2021

Make things more friendly for serialisation.

- Enforce Encodable instance on Digest, AuthTag, and Nounce.

- Exppose unsafeToNounce for conversion from AEAD token to Nounce.


## [0.3.4] - Oct 7, 2021

This is yet another release trying to work out the cabal-install
+ c-files interaction.

## [0.3.3] - Oct 7, 2021

The core and libverse files need to be in the install include.
Unfortunately there is no easy way to check this out.

## [0.3.2] - Oct 6, 2021

Yet another missing header file sets.

## [0.3.1] - Oct 6, 2021

This release ensures that missing verse.h C header files. Without that
the version on hackage was unbuildable.


## [0.3.0] - May 20, 2021

  This is a major rewrite of the raaz library with significant change in the
  API and internals.

* Platform requirements

  - Cabal >= 3.0.0.0
  - GHC   >= 8.4

* User facing interface

  - Top level `Raaz` module centred around cryptographic operation
    instead of specific primitives. This release supports the
    following operations

	- message digest provided via Blake2b
	- message authentication provided via Blake2b
	- authenticated encryption via XChaCha20Poly1305

  - Explicit primitive based interface meant only for interworking
    with other library.

  - Dropped support for SHA1, SHA224, SHA384, HMAC, and AES-CBC,
	mainly to concentrate efforts and reach stable release soon.

  - Pluggable interface for primitive implementations and entropy
    source (recommended only for advanced users)

* Internal changes.

  - Use libverse for the low level FFI implementations. From now on
    newer primitives will be coded up in verse instead of hand written
    C/assembly. (See <https://github.com/raaz-crypto/libverse/>)

  - Backpack based modules and signatures instead of classes for
    primitive implementation. Simplifies the library and allows easy
    plugging in of custom implementations.

* CSPRG and Entropy

  - Entropy on linux: uses getrandom by default with flag to fall back
	to `/dev/urandom`.

  - The raaz command now exposes the sub-command entropy (just like
	rand) mainly for system entropy quality checking.

  - A host-endian variant of chacha20 keystream for csprg.

  - Backpack based pluggable entropy source (recommended only for
	advanced users).

* Type level improvements.

  - Using Data.Proxy.Proxy to get rid of some uses of undefined.

  - Primitives block sizes to type level.

  - Aligned pointer with alignment at type level.

* Other changes.

  - Cross testing implementations with the monocypher library

  - Licensing changed to Apache-2.0 OR BSD-3-Clause dual licensing.

## [0.2.3] - 25 April, 2021

This is a minor release just update package dependencies.


## [0.2.2] - 13 December, 2020

This is a minor release just update package dependencies.

* Get raaz to work with the latest ghcs.

## [0.2.1] - 25 March, 2019

This is a minor release just to get the latest ghc.

* Get raaz to work with latest ghcs.

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
[0.2.1]: <http://github.com/raaz-crypto/raaz/releases/tag/v0.2.1>
[0.2.2]: <http://github.com/raaz-crypto/raaz/releases/tag/v0.2.2>
[0.2.3]: <http://github.com/raaz-crypto/raaz/releases/tag/v0.2.3>
[0.3.0]: <http://github.com/raaz-crypto/raaz/releases/tag/v0.3.0>
[0.3.1]: <http://github.com/raaz-crypto/raaz/releases/tag/v0.3.1>
[0.3.2]: <http://github.com/raaz-crypto/raaz/releases/tag/v0.3.2>
[0.3.3]: <http://github.com/raaz-crypto/raaz/releases/tag/v0.3.3>
[0.3.4]: <http://github.com/raaz-crypto/raaz/releases/tag/v0.3.4>
[0.3.5]: <http://github.com/raaz-crypto/raaz/releases/tag/v0.3.5>
[0.3.6]: <http://github.com/raaz-crypto/raaz/releases/tag/v0.3.6>
[0.3.7]: <http://github.com/raaz-crypto/raaz/releases/tag/v0.3.7>
[0.3.8]: <http://github.com/raaz-crypto/raaz/releases/tag/v0.3.8>
[0.3.9]: <http://github.com/raaz-crypto/raaz/releases/tag/v0.3.9>
[0.3.10]: <http://github.com/raaz-crypto/raaz/releases/tag/v0.3.10>
[0.3.11]: <http://github.com/raaz-crypto/raaz/releases/tag/v0.3.11>
[raaz]:  <http://github.com/raaz-crypto/raaz/>
