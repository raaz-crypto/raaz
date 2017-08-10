# Checklist for releasing.

## Pre-release checklist.

Suppose that the release that one wants to do is version A.B.C. We
assume that the current master has all the necessary changes except
the release specific ones. The workflow is to start with a release
branch which we will call release-A.B.C.

* The first step is to update travis.yml to start building on the
  release-A.B.C This should be done before actually creating the
  release branch because we want all the release specific changes that
  are pushed to be built by travis. This is done on the master branch.
  push this change to the main repository

* Create a fresh branch titled release-A.B.C.

* Go over the bug-tracker for bugs to be addressed for this release.
  mark them.

* A pending change log entry should already be there for this entry.
  Please review it.

* Hack and get the project to shape.

* When ready merge to the master as a non-ff merge.

## Candidate release.

Hackage supports candidate releases which we should be making use of.
Here is a set of steps that can be done with a candidate release that
can help in doing a high quality release

1. Make sure to trigger a documentation build for the candidate on
   hackage.  This is currently not automated but would likely be the
   case.

2. The package build matrix is likely to be operational for candidate
   packages as well. This gives good package compatibility hints for
   high quality release.


3. Get down-stream packagers to make an experimental upload of the
   package into their CI system. Distributions like Debian often do
   have multi-arch builds and also add builds across other platforms
   like Hurd, kFreeBSD etc. Successful builds


## Post release

* Upload the release on hackage.

* Tag the release branch. Put the change log in the tag message.

* Bump up the release version.

* Create a pending entry for the next release in the Change log.
