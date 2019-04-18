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
to provide implementations tuned for such specific hardware. In
addition, it should be possible for users of esoteric platforms to
override the default implementation with their own custom
implementations. We use mixin-style modules provided by backpack to
achieve this goal.

The raaz cryptographic library is organised as a single package
containing multiple component. A user who only cares about the high
level interface can just ignore these individual components and use
only the top level library `raaz` much like any other package. For
users who do care about changing the underlying implementation, having
an overall picture of these components is helpful.

Any primitive that raaz supports is supported through its `Interface`
module. Typically such Interface module needs to be _mixed in_ with an
appropriate `Implementation` module for it to be useful. Two packages
are of at most importance here.

1. The package `raaz:prim-indef` exposes an `Interface` module for
   each primitive that raaz supports. For example, the
   `Blake2b.Interface` provides access to [blake2b][blake2] hashing.
   However, this package cannot be used as such because it is a
   _package with a hole_. One needs to actually mixin implementations
   of blake2 to make it usable.

2. The `Implementation` modules are provided by the component
   `raaz:implementation`. By listing both `raaz:prim-indef` and
   `raaz:implementation` in the `build-depends` the Implementations
   needed by `raaz:prim-indef` are satisfied by the default
   implementations from `raaz:implementation`. This is how the raaz
   library provides you with the interface.

```
   build-depends: raaz:prim-indef
                , raaz:implementation

```

### Overiding default implementations

The `raaz:implementation` often provide multiple implementation for
the same primitives but for a particular primitives selects one as the
default implementation. If we stick to the Blakd2b example,
`raaz:implementation` exposes `Blake2b.CPortable` and
`Blake2b.CHandWritten` of which `Blake2b.CPortable` is made the
default implementation by re-exporting it also under the name
`Blakd2b.Implementation`. This means that when we add both
`raaz:prim-indef` and the `raaz:implementation` to the build depends
field, the demand for the module Blake2b.Implementation from the
former component is satisfied by the `Blakd2b.CPortable`. We can selectively override this
using the following cabal stanza.


```
build-depends: raaz:prim-indef
             , raaz:implementation
mixins: raaz:prim-indef requires (Blake2b.Implementation as Blake2b.CHandWritten)
```

You can also mixin custom implementations (i.e implementations that
are not exposed by raaz) using this technique.


```
build-depends: raaz:prim-indef
             , raaz:implementation
             , my-custom-blake2

mixins: raaz:prim-indef requires (Blake2b.Implementation as MyCustom.Blake2b.Implementation)

```

The above stanza ensures all primitives except blake2b uses the
default implementation from raaz-implementations but Blakd2b alone
uses `MyCustom.Blake2b.Implementation` (exposed from
my-custom-blake2).


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
