INSTALL_OPTS=
PACKAGES=primitives ssh hash-sha tests # Add new packages here

# Dependencies of packages goes here.

hash-sha: primitives tests

# End of package dependency

BRANCHES=${PACKAGES}
X_BRANCHES=$(addprefix x-,${BRANCHES})

TEST_PATH=dist/build/tests/tests

.PHONY: ${PACKAGES} install travis-tests clean
.PHONY: fast-forward fast-forward-all merge release



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

clean:
	$(foreach pkg, ${PACKAGES},\
		ghc-pkg unregister --force raaz-${pkg}; \
		cd raaz-${pkg}; \
		./Setup.lhs clean;\
		cd ..)
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
