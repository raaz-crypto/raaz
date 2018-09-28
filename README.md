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
3. Mechanism to have multiple implementations for any given
   cryptographic primitives. An advanced user who has an indepth
   knowledge of the platform should be able to plugin the desired
   implementation
4. Strong emphasis on API design with through documentation.


Building
--------

Ensure that you have a ghc >= 8.2 and cabal version >= 2.2. These are
necessary due to the crucial role played by backpack in the design.
Having met these pre-requisites, the recommended approach towards
building raaz using the following command.

    cabal new-build

Backpack support is still [work in progress for stack][stack-backpack]
and it should be possible to use stack once this issue is resolved.

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

Backpack based pluggable implementations
----------------------------------------

**NOTE:** The interface that we describe now needs the ability for a
single package (`raaz` in our case) to expose multiple
components. This is still work in progress but is expected to be
merged in soon (See
<https://github.com/haskell/cabal/issues/4206>). Without this feature
the interface described below cannot be used.

Certain cryptographic primitives can have better (both in terms of
safety and performance) implementations that exploit specific hardware
features. For example, if the underlying processor supports vector
extensions like `avx2`, some primitives like chacha20 can be made up
to 2x faster. Production quality cryptographic libraries are expected
to provide implementations tuned for such specific hardware. Even when
they don't give one for the hardware in hand, it should be possible
for the downstream user of the library to plugin a custom
implementations. We want make it possible to plug-in such
implementations and yet not disturb the high-level interface of
raaz. Mixin-style modules provided by backpack is what we use to give
such a pluggable interface.

The raaz cryptographic library is organised as a single package
containing multiple component. A user who only cares about a high
level interface can just ignore these individual components and use
only the top level library `raaz` much like any other package. For
users who does care about changing the underlying implementation,
having an overall picture of these components is helpful.

1. The component `raaz:core` contains core types and utility
   functions. You would most likely need this component to begin with.

2. The component `raaz:indef` exports a signature `Implementation` and
   a module `Utils` that depends on the signature. The
   `Implementation` signature captures the Haskell interface to the
   low level implementation of a cryptographic block primitive. To
   complement this indefinite package the component
   `raaz:implementation` provides implementations that can be
   "mixed-in" in place the signature `Implementation`. A user can
   select one such implementation from `raaz:implementation`, or can
   code up her own as long as it satisfies the `Implementation`
   signature.

3. For each block primitive `foo` that is supported by `raaz` there is
   a component `raaz:foo-indef`, that captures the various
   implementations of the primitive `foo`. It reexports (a restricted
   version of) the signature `Implementation` and the module `Utils`
   as `Foo.Implementation` and `Foo.Utils` respectively.  For example,
   `raaz:chacha20-indef` component captures low-level implementations
   of the ChaCha20 stream cipher and exposes them as the signature
   `ChaCha20.Implementation` and `ChaCha20.Utils`


4. Any library `bar` that wants to use a primitive `foo` while giving
   the flexibility for the downstream user to plugin different
   implementations of `foo` should define an indefinite package
   `bar:indef`. The downstream user will then be able to `mixin` the
   appropriate implementation using the following in her cabal file

   ```

     build-depends: raaz:chacha20-indef
                  , bar:indef
                  , raaz:implementation
     mixin: bar:indef (Bar as Bar.Portable)
               requires (ChaCha20.Implementations as ChaCha20.Portable)
                 -- This makes use of the portable c implementation of
                 -- ChaCha20 from raaz:implementation
   ```

For an example of this usage check out the component `raaz:hash-indef`
and its use in the main library.


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
