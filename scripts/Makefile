GHC ?= ghc
PROGS=raaz-repo platform
.PHONY: all clean

all: ${PROGS}

${PROGS}:
	${GHC} --make -Wall  $@.hs
clean:
	rm -f ${PROGS} *.o *.hi
