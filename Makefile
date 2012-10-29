PACKAGES=primitives ssh hash-sha


hash-sha: primitives

BRANCHES=${PACKAGES}
X_BRANCHES=$(addprefix x-,${BRANCHES})

TEST_PATH=dist/build/tests/tests

.PHONY: ${PACKAGES} install merge release tests

install: ${PACKAGES}
	git checkout master


${PACKAGES}:
	git checkout x-$@
	cd raaz-$@;\
	cabal install --enable-documentation\
	              --enable-tests\
		      --force-reinstall

tests:

	$(foreach pkg, ${PACKAGES},\
		git checkout x-${pkg};\
		cd raaz-${pkg};\
		cabal test;\
		cd ..;\
		)
	git checkout master

merge:
	git checkout master
	if git branch | grep -q 'x-merge'; then git branch -D x-merge ; fi
	git checkout -B x-merge
	git merge --no-ff ${X_BRANCHES} -m `date -u +'snapshot-%F-%T-%Z'`

release:
	git checkout master
	git merge --no-ff ${BRANCES}
