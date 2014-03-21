#
# Unlike other stuff in the Haskell world cabal-install's
# documentation is sparse even reaching the limit of OpenSSL (the gold
# standard of documentation obscurity). This is what I figured out
# after many trial and error.
#
# The source tarballs are arranged in the following directory
# structure.
#
# foo/3.145/foo-3.145.tar.gz
# bar/2.718/bar-2.718.tar.gz
#
# This is followed by an index that is stored in the file
# 00-index.tar.  The tricky thing to figure out is that if you want to
# build a repository for serving from the web you should have the
# gziped version of it, i.e you should have 00-index.tar.gz instead of
# 00-index.tar. Are we reaching the inconsistency of OpenSSL as well?
#
# The script in ../scripts/raaz-repo.hs generates this directory structure
#

.PHONY: index

CABALS=$(wildcard */*/*.cabal)

index: 00-index.tar.gz 00-index.tar

00-index.tar.gz: 00-index.tar
	gzip -c 00-index.tar > 00-index.tar.gz

00-index.tar: ${CABALS}
	tar c ${CABALS} -f 00-index.tar
clean:
	rm -f 00-index.tar 00-index.tar.gz
	$(foreach pkg, ${PACKAGES},\
		rm -rf ${pkg};\
	)
