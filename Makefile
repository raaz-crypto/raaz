INSTALL_OPTS=

# Add new packages here. Make sure that raaz-config is the last in
# this list. We unregister package according to this order and
# raaz-config is typically used by the Setup.lhs of packages. Cleaning
# will fail otherwise.

PACKAGES=raaz raaz-primitives raaz-hash-sha raaz-ssh raaz-tests \
	 raaz-config

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
${PACKAGES}:
	cd $@;\
	cabal install ${INSTALL_OPTS}

${PACKAGE_CLEAN}:
	cd $(patsubst %-clean,%,$@);\
	./Setup.lhs clean;\
	cd ..
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
