PACKAGES=primitives ssh hash-sha tests
INSTALL_OPTS=

hash-sha: primitives tests

BRANCHES=${PACKAGES}
X_BRANCHES=$(addprefix x-,${BRANCHES})

TEST_PATH=dist/build/tests/tests

.PHONY: ${PACKAGES} install merge release travis-tests
.PHONY: fast-forward fast-forward-all

install: ${PACKAGES}

${PACKAGES}:
	cd raaz-$@;\
	cabal install ${INSTALL_OPTS}

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

fast-forward:
	$(foreach br, ${X_BRANCHES},\
		git checkout ${br}; \
		git merge --ff-only master; \
		)


fast-forward-all:
	$(foreach br, ${BRANCHES} ${X_BRANCHES},\
		git checkout ${br}; \
		git merge --ff-only master; \
		)
