Raaz: A secure cryptographic library
====================================

[![Build Staus][travis-status]][travis-raaz]
[![Build Windows][appveyor-status]][appveyor-raaz]
[![Hackage][hackage-badge]][hackage]
[![Hackage Dependencies][hackage-deps-badge]][hackage-deps]

Raaz is a cryptographic library in Haskell that provide a high level
and safe access to a lot of cryptographic operations. The library can
be used for standalone cryptographic applications as well as for
implementing other network protocols. Some of the features that are
unique to raaz are the following

1. Pervasive use of types for better safety.
2. Default choice of primitives and implementations are safe.
3. Mechanism to have multiple implementations for any given
   cryptographic primitives. An advanced user who has an in-depth
   knowledge of the platform should be able to plugin the desired
   implementation.
4. Strong emphasis on API design with through documentation.

Building
--------

The recommended way to install raaz is through `cabal-install` version
3.0 or above. We also require `ghc` version 8.4 or above.

    cabal build
	cabal test
	cabal install

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

One of the biggest safety feature of the raaz cryptographic library is
that the implementations are fast and safe by default. However, there
are some rare cases when the user might want to rework the internals
of the raaz library. This could be for performance reasons --- certain
cryptographic primitives can have better (both in terms of safety and
performance) implementations that exploit specific hardware features
--- or due to safety reasons -- the default entropy source might not
be the best on certain virtualised system.  While we *do not*
recommend such tinkering in general, it is nonetheless possible to
tweak each and every implementations of primitives or tweak the
underlying entropy source using backpack style modules and signatures.

The raaz cryptographic library is organised as a single package
containing multiple component. A user who only cares about the high
level interface can just ignore these individual components and use
only the top level library `raaz` much like any other package. For
users who do care about changing the underlying implementation, having
an overall picture of these components is helpful. We assume some
familiarity with the backpack system of mixin style modules for
Haskell for the rest of this section.

The overall picture can be simplified as follows: Any primitive that
raaz supports is exposed through its `Interface` module which in turn
depends on an appropriate `Implementation` module. This dependency is
satisfied by the `mixin` mechanism of backpack.

1. The package `raaz:prim-indef` exposes an `Interface` module, one
   for each primitive that raaz supports. For example, the
   `Blake2b.Interface` provides access to [blake2b][blake2] hashing.
   However, this package cannot be used as such because it is a
   _package with a hole_. One needs to actually _mixin_ a module with
   name `Blake2b.Implementation` for this to work.

2. The component `raaz:implementation` provides the needed
   `Implementation` modules and by listing both `raaz:prim-indef` and
   `raaz:implementation` in the `build-depends` the implementation
   modules needed by `raaz:prim-indef` are satisfied by the default
   implementations from `raaz:implementation`. This is how the raaz
   library provides you with the interface.

```
   build-depends: raaz:prim-indef
                , raaz:implementation

```

### Overiding the default implementation

The `raaz:implementation` often provide multiple implementation for
the same primitives but for a particular primitives selects one as the
default implementation. If we stick to the `Blake2b` example,
`raaz:implementation` exposes `Blake2b.CPortable` and
`Blake2b.CHandWritten` of which `Blake2b.CPortable` is made the
default implementation by re-exporting it under the name
`Blake2b.Implementation`. This means that when we add both
`raaz:prim-indef` and the `raaz:implementation` to the build depends
field, the demand for the module `Blake2b.Implementation` from the
former component is satisfied by the `Blakd2b.CPortable`. We can
selectively override this using the following cabal stanza.



```
build-depends: raaz:raaz-indef
             , raaz:implementation
mixins: raaz:raaz-indef requires (Blake2b.Implementation as Blake2b.CHandWritten)
```

You can also mix-in custom implementations (i.e implementations that
are not exposed by raaz) using this technique.


```
build-depends: raaz:raaz-indef
             , raaz-implementation
             , my-custom-blake2

mixins: raaz:prim-indef requires (Blake2b.Implementation as MyCustom.Blake2b.Implementation)

```


The above stanza ensures all primitives except blake2b uses the
default implementation from `raaz:implementation` but `Blake2b` alone
uses `MyCustom.Blake2b.Implementation` (exposed from
`my-custom-blake2`).

### Overriding the Entropy source.


The raaz library expects entropy to be supplied through and interface
captured by the signature `Entropy` exposed by the `raaz:random-api`
component. We can override the entropy source by using the following
cabal stanza

```
build-depends: raaz:raaz-indef
             , raaz:implementation
             , my-custom-blake2
			 , my-custom-entropy

mixins: raaz:raaz-indef requires (Blake2b.Implementation as MyCustom.Blake2b.Implementation,
                                  Entropy as MyCustom.Entropy)

```


About the name
--------------

The word `Raaz` (&#x0930;&#x093E;&#x095B;) stands for secret in Hindi.


Legal
-----

Copyright 2012 Piyush P Kurur

The library is licensed under

* Apache License, Version 2.0
  <http://www.apache.org/licenses/LICENSE-2.0>
* BSD 3-Clause license
  <https://opensource.org/licenses/BSD-3-Clause>

You may not use this software except in compliance with one of the
above Licenses (*at your option*).

SPDX-License-Identifier: (Apache-2.0 OR  BSD-3-Clause)

Unless required by applicable law or agreed to in writing, software
distributed under these Licenses is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied. For the exact terms and conditions see the accompanying
LICENSE file.


[wiki]: <https://github.com/raaz-crypto/raaz/wiki> "Raaz Wiki"
[repo]: <https://github.com/raaz-crypto/raaz> "Raaz on github"
[blake2]: <https://blake2.net/> "Blake2 hash function"
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
