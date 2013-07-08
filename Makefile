INSTALL_OPTS=

# Add new packages here.

PACKAGES=primitives hash-sha executables ssh tests

# Dependencies of packages goes here.

tests: primitives
hash-sha: primitives tests
executables: hash-sha

# End of package dependency. Edit the rest only if you know what your
# are doing.

PACKAGE_CLEAN=$(foreach pkg, ${PACKAGES}, ${pkg}-clean)
TEST_PATH=dist/build/tests/tests

BRANCHES=
X_BRANCHES=

.PHONY: install clean ${PACKAGES} ${PACKAGES_UNREGISTER}

install: ${PACKAGES}
clean: ${PACKAGE_CLEAN}
	$(foreach pkg, ${PACKAGES},\
		cd raaz-${pkg};\
		./Setup.lhs clean;\
		cd ..;)

${PACKAGES}:
	cd raaz-$@;\
	cabal install ${INSTALL_OPTS}

${PACKAGE_CLEAN}:
	-ghc-pkg unregister  raaz-$(patsubst %-clean,%,$@) --force



.PHONY: travis-install travis-tests

.PHONY: fast-forward fast-forward-all merge release


travis-install:
	make install INSTALL_OPTS='-O0 --enable-documentation --enable-tests'

travis-tests:
	$(foreach pkg, ${PACKAGES},\
		cd raaz-${pkg};\
		cabal test;\
		cd ..;\
		)
