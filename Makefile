INSTALL_OPTS=

# Add new packages here
PACKAGES=primitives ssh hash-sha tests executables

# Dependencies of packages goes here.

tests: primitives
hash-sha: primitives tests
executables: hash-sha

# End of package dependency

BRANCHES=
X_BRANCHES=

TEST_PATH=dist/build/tests/tests

.PHONY: travis-install travis-tests
.PHONY: ${PACKAGES} install clean
.PHONY: fast-forward fast-forward-all merge release


travis-install:
	make install INSTALL_OPTS='-O0 --enable-documentation --enable-tests'

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
