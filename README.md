Raaz: A secure networking library in Haskell
--------------------------------------------

[![Build Staus][travis-status]][travis-raaz]
[![In Progress][waffle-inprogress]][waffle-raaz]
[![Stackage LTS][stackage-lts-raaz-badge]][stackage-lts-raaz]
[![Stackage Nightly][stackage-nightly-raaz-badge]][stackage-nightly-raaz]


Raaz is a library for secure network programming. The word `Raaz`
(&#x0930;&#x093E;&#x095B;) stands for secret in Hindi. The aim of this library
is to provide a haskell interface to existing protocols like ssh and
tls together with fast implementation of primitives.

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
