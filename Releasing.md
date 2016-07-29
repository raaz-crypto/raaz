# Checklist for releasing.

## Pre-release checklist.

Suppose that the release that one wants to do is version A.B.C. We
assume that the current master has all the necessary changes except
the release specific ones. The workflow is to start with a release
branch which we will call release-A.B.C.

* The first step is to update travis.yml to start building on the
  release-A.B.C This should be done before actually creating the
  release branch because we what all the release specific changes that
  are pushed to be built by travis. This is done on the master branch.
  push this change to the main repository

* Create a fresh branch titled release-A.B.C.

* Bump up the version in the cabal file.

* Go over the bug-tracker for bugs to be addressed for this release.
  mark them.

* A pending change log entry should already be there for this entry.
  Please review it.

* Hack and get the project to shape.

* When ready merge to the master as a non-ff merge.


## Post release

* Upload the release on hackage.

* Tag the release branch. Put the change log in the tag message.

* Create a pending entry for the next release in the Change log.
