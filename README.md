Raaz: A secure cryptographic library
====================================

[![Build Staus][travis-status]][travis-raaz]
[![Build Windows][appveyor-status]][appveyor-raaz]
[![In Progress][waffle-inprogress]][waffle-raaz]
[![Stackage LTS][stackage-lts-raaz-badge]][stackage-lts-raaz]
[![Stackage Nightly][stackage-nightly-raaz-badge]][stackage-nightly-raaz]
[![Hackage][hackage-badge]][hackage]
[![Hackage Dependencies][hackage-deps-badge]][hackage-deps]

The Raaz cryptographic library is a collection of Haskell packages
whose goal is to provide high level access to cryptographic
operations. The type system of Haskell plays a crucial role in
avoiding some of common bugs in cryptographic implementations. The
library is intended to be used for standalone cryptographic
applications as well as implementing network protocols.  Besides, we
put a lot of emphasis on better API design and good documentation
which, we believe, makes the usage of the library secure.

Some of the features that are unique to raaz are the following

1. Pervasive use of types for better safety.
2. Default choice of primitives and implementations are safe.
3. Multiple implementations of cryptographic primitives that make use
   of platform specific features. An advanced user who has an indepth
   knowledge of the platform should be able to plugin the desired
   implementation
4. Strong emphasis on API design with through documentation.


Backpack and Pluggable implementations
--------------------------------------

Depending on the platform specific features, certain cryptographic
primitives can have better (in terms of safety and performance)
implementations. For example, if it is known that the underlying
processor supports vector extensions like `avx2`, some primitives like
chacha20 can be made upto 2x times faster. Raaz cryptographic library
uses the backpack system to provide a pluggable architecture for its
primitives. To provide such an interface the raaz cryptographic library
is divided into the following packages.

1. `raaz-core`: contains the basic types and utility functions
2. `raaz-core-indef`: signature package used by primitive implementations
3. `raaz-implementation`: Modules that give low-level implementations
   for cryptographic primitives.
4. `raaz`: the main package that provides the user level API for
   cryptographic primitives.

An advanced user can mix and match primitives by making use of the
signature `Raaz.Primitive.Implementation` with actual implementations
available in raaz-implementation.

Installing and Building
-----------------------

We used to support both stack and cabal-install for building
raaz. However, starting from version 0.3, `raaz` uses backpack and as
a result only cabal-install (>=2.2) is supported. Backpack support is
still [work in progress for stack][stack-backpack] and it should be
possible to use stack once this issue is resolved. If you are inside
the raaz repository you could build raaz with the following command.

    cabal new-build


Hacking and Discussion
----------------------

* For hacking see our [github repository][repo].

* For discussion see our [google groups][emailgroups] mailing list.

* Hangout on irc.freenode.net (channel: #haskell-raaz).

For details please refer to [our wiki][wiki].

## Releasing and reviewing.

The repository also contains the file Releasing.md which contains
checklist for releasing a new version of the library. Any crypto
library should undergo through review by multiple people. In the file
Reviewing.md, we collect some common pitfalls to look for while
reviewing the code. It is good to actively look for some of the
problems suggested there but of course one should also look for other
problems.

About the name
--------------

The word `Raaz` (&#x0930;&#x093E;&#x095B;) stands for secret in Hindi.


[wiki]: <https://github.com/raaz-crypto/raaz/wiki> "Raaz Wiki"
[repo]: <https://github.com/raaz-crypto/raaz> "Raaz on github"

[emailgroups]: <https://groups.google.com/forum/#!forum/hraaz> "Raaz on Google groups"
[waffle-raaz]:   <https://waffle.io/raaz-crypto/raaz>
[waffle-inprogress]: <https://badge.waffle.io/raaz-crypto/raaz.svg?label=waffle%3Ain%20progress&title=In%20Progress>
[travis-status]: <https://secure.travis-ci.org/raaz-crypto/raaz.png> "Build status"
[travis-raaz]: <https://travis-ci.org/raaz-crypto/raaz>
[stackage-lts-raaz]: <https://www.stackage.org/lts/package/raaz>
[stackage-nightly-raaz]: <https://www.stackage.org/nightly/package/raaz>

[stackage-lts-raaz-badge]: <https://www.stackage.org/package/raaz/badge/lts>
[stackage-nightly-raaz-badge]: <https://www.stackage.org/package/raaz/badge/nightly>

[hackage]:       <https://hackage.haskell.org/package/raaz>
[hackage-badge]: <https://img.shields.io/hackage/v/raaz.svg>
[hackage-deps-badge]: <https://img.shields.io/hackage-deps/v/raaz.svg>
[hackage-deps]: <https://packdeps.haskellers.com/feed?needle=raaz>
[appveyor-status]: <https://ci.appveyor.com/api/projects/status/github/raaz-crypto/raaz?branch=master&svg=true>
[appveyor-raaz]: <https://ci.appveyor.com/project/raaz-crypto/raaz>
[stack-backpack]: <https://github.com/commercialhaskell/stack/issues/2540>
