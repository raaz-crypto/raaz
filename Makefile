INSTALL_OPTS=

# Add new packages here.

PACKAGES=raaz raaz-config raaz-primitives raaz-hash-sha raaz-ssh raaz-tests

# Dependencies of packages goes here.

raaz-primitives: raaz-config
raaz-tests: raaz-primitives
raaz-hash-sha: raaz-primitives raaz-tests
raaz: raaz-hash-sha raaz-primitives

# End of package dependency. Edit the rest only if you know what your
# are doing.

PACKAGE_CLEAN=$(foreach pkg, ${PACKAGES}, ${pkg}-clean)
TEST_PATH=dist/build/tests/tests

BRANCHES=
X_BRANCHES=

.PHONY: install clean ${PACKAGES} ${PACKAGES_UNREGISTER}

install: ${PACKAGES} raaz
clean: ${PACKAGE_CLEAN}
	$(foreach pkg, ${PACKAGES},\
		cd ${pkg};\
		./Setup.lhs clean;\
		cd ..;)
${PACKAGES}:
	cd $@;\
	cabal install ${INSTALL_OPTS}

${PACKAGE_CLEAN}:
	-ghc-pkg unregister  $(patsubst %-clean,%,$@) --force



.PHONY: travis-install travis-tests

.PHONY: fast-forward fast-forward-all merge release


travis-install:
	make install INSTALL_OPTS='-O0 --enable-documentation --enable-tests'

travis-tests:
	$(foreach pkg, ${PACKAGES},\
		cd ${pkg};\
		cabal test;\
		cd ..;\
		)
