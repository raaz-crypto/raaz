Raaz: A secure cryptographic library
====================================

[![Apache-2.0 OR BSD-3-Clause][shields-license]](#legal)
[![][ci-build]][github-actions]
[![][ci-checks]][github-actions]
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
3.0 or above. We also need a version of GHC that supports backpack
(for details on which version of GHC is supported, refer to our
[CI-builds][github-actions]).

    cabal build
    cabal test
    cabal install

Online documentation
--------------------

- [Latest release][doc-latest]
- [Release candidate][doc-candidate]

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
[hackage]:       <https://hackage.haskell.org/package/raaz>
[hackage-badge]: <https://img.shields.io/hackage/v/raaz.svg>
[hackage-deps-badge]: <https://img.shields.io/hackage-deps/v/raaz.svg>
[hackage-deps]: <https://packdeps.haskellers.com/feed?needle=raaz>
[shields-license]: <https://img.shields.io/badge/License-Apache--2.0%20OR%20BSD--3--Clause-informational.svg>
[ci-build]: <https://github.com/raaz-crypto/raaz/workflows/Build/badge.svg> "Building source"
[ci-checks]: <https://github.com/raaz-crypto/raaz/workflows/Checks/badge.svg> "Source code checks"
[github-actions]: <https://github.com/raaz-crypto/raaz/actions> "Github actions"
[doc-latest]: <https://hackage.haskell.org/package/raaz>
[doc-candidate]: <https://hackage.haskell.org/package/raaz-0.3.0/candidate>
