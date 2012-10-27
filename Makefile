PACKAGES=
TEST_PATH=dist/build/tests/tests

.PHONY: ${PACKAGES}

install: ${PACKAGES}

${PACKAGES}:
	cd raaz-$@; cabal install --enable-tests

tests:
	$(foreach pkg, ${PACKAGES}, raaz-${pkg}/${TEST_PATH})

