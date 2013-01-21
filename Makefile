PACKAGES=primitives ssh hash-sha tests


hash-sha: primitives tests

BRANCHES=${PACKAGES}
X_BRANCHES=$(addprefix x-,${BRANCHES})

TEST_PATH=dist/build/tests/tests

.PHONY: ${PACKAGES} install merge release travis-tests

install: ${PACKAGES}

${PACKAGES}:
	cd raaz-$@;\
	cabal install --enable-documentation\
	              --enable-tests\
		      --force-reinstall

travis-tests:

	$(foreach pkg, ${PACKAGES},\
		cd raaz-${pkg};\
		cabal test;\
		cd ..;\
		)

merge:
	git checkout master
	if git branch | grep -q 'x-merge'; then git branch -D x-merge ; fi
	git checkout -B x-merge
	git merge --no-ff ${X_BRANCHES} -m `date -u +'snapshot-%F-%T-%Z'`

release:
	git checkout master
	git merge --no-ff ${BRANCES}
