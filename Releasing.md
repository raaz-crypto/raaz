# Checklist for releasing.

## Pre-release checklist.

* Create a fresh branch for a release. For the version A.B.C the
  branch should be release.A.B.C.

* Update travis.yml to start building on this branch.

* Go over the bug-tracker for bugs to be addressed for this release.
  mark them.

* A pending change log entry should already be there for this entry.
  Please review it.

* Hack and get the project to shape.

* When ready merge to the master as a non-ff merge.


## Post release

* Upload the release on hackage.

* Tag the release branch.

* Create a pending entry for the next release in the Change log.
