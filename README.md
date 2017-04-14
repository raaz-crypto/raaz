Raaz: A secure cryptographic library
------------------------------------

[![Build Staus][travis-status]][travis-raaz]
[![In Progress][waffle-inprogress]][waffle-raaz]
[![Stackage LTS][stackage-lts-raaz-badge]][stackage-lts-raaz]
[![Stackage Nightly][stackage-nightly-raaz-badge]][stackage-nightly-raaz]
[![Hackage][hackage-badge]][hackage]
[![Hackage Dependencies][hackage-deps-badge]][hackage-deps]


This is the repository of `raaz`, a Haskell library that implements
some standard cryptographic primitives. This library is the basis on
which we plan to build a cryptographic framework in Haskell. For
example, there are plans to implement some common cryptographic
protocols like `ssh`. Thus applications that require cryptographic
security, in particular secure networking applications can be built
out of this.

Raaz is also an attempt to provide better security guarantees by
making use of Haskell's strong typing. Besides, we put a lot of
emphasis on better API design and good documentation which, we
believe, makes the usage of the library secure.

The word `Raaz` (&#x0930;&#x093E;&#x095B;) stands for secret in Hindi.

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




[wiki]: <https://github.com/raaz-crypto/raaz/wiki> "Raaz Wiki"
[repo]: <https://github.com/raaz-crypto/raaz> "Raaz on github"

[emailgroups]: <https://groups.google.com/forum/#!forum/hraaz> "Raaz on Google groups"
[waffle-raaz]:   <http://waffle.io/raaz-crypto/raaz>
[waffle-inprogress]: <https://badge.waffle.io/raaz-crypto/raaz.svg?label=waffle%3Ain%20progress&title=In%20Progress>
[travis-status]: <https://secure.travis-ci.org/raaz-crypto/raaz.png> "Build status"
[travis-raaz]: <https://travis-ci.org/raaz-crypto/raaz>
[stackage-lts-raaz]: <http://stackage.org/lts/package/raaz>
[stackage-nightly-raaz]: <http://stackage.org/nightly/package/raaz>

[stackage-lts-raaz-badge]: <http://stackage.org/package/raaz/badge/lts>
[stackage-nightly-raaz-badge]: <http://stackage.org/package/raaz/badge/nightly>

[hackage]:       <https://hackage.haskell.org/package/raaz>
[hackage-badge]: <https://img.shields.io/hackage/v/raaz.svg>
[hackage-deps-badge]: <https://img.shields.io/hackage-deps/v/raaz.svg>
[hackage-deps]: <http://packdeps.haskellers.com/feed?needle=raaz>
