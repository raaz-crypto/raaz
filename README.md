Raaz: A secure cryptographic library
====================================

[![Apache-2.0 OR BSD-3-Clause][shields-license]](#legal)
[![][ci-build]][github-actions]
[![][ci-checks]][github-actions]
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

About the name
--------------

The word `Raaz` (&#x0930;&#x093E;&#x095B;) stands for secret in Hindi.


Legal
-----

<a name="legal"></a>

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
[hackage]:       <https://hackage.haskell.org/package/raaz>
[hackage-badge]: <https://img.shields.io/hackage/v/raaz.svg>
[hackage-deps-badge]: <https://img.shields.io/hackage-deps/v/raaz.svg>
[hackage-deps]: <https://packdeps.haskellers.com/feed?needle=raaz>
[appveyor-status]: <https://ci.appveyor.com/api/projects/status/github/raaz-crypto/raaz?branch=master&svg=true>
[appveyor-raaz]: <https://ci.appveyor.com/project/raaz-crypto/raaz>
[shields-license]: <https://img.shields.io/badge/License-Apache--2.0%20OR%20BSD--3--Clause-informational.svg>
[ci-build]: <https://github.com/raaz-crypto/raaz/workflows/Build/badge.svg> "Building source"
[ci-checks]: <https://github.com/raaz-crypto/raaz/workflows/Checks/badge.svg> "Source code checks"
[github-actions]: <https://github.com/raaz-crypto/raaz/actions> "Github actions"
