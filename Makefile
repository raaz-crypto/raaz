PACKAGES=primitives ssh hash-sha

BRANCHES=${PACKAGES}
X_BRANCHES=$(addprefix x-,${BRANCHES})

TEST_PATH=dist/build/tests/tests

.PHONY: ${PACKAGES}

install: ${PACKAGES}

${PACKAGES}:
	cd raaz-$@; cabal install --enable-tests

tests:
	$(foreach pkg, ${PACKAGES}, raaz-${pkg}/${TEST_PATH})

merge:
	git checkout master
	if git branch | grep -q 'x-merge'; then git branch -D x-merge ; fi
	git checkout -B x-merge
	git merge --no-ff ${X_BRANCHES} -m `date +'snapshot-%F-%T'`

release:
	git checkout master
	git merge --no-ff ${BRANCES}
