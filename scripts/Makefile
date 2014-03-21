GHC ?= ghc
PROGS=raaz-repo cabal-config
.PHONY: all clean

all: ${PROGS}

raaz-repo: raaz-repo.hs
	${GHC} --make -Wall raaz-repo.hs

cabal-config: cabal-config.hs
	${GHC} --make -Wall cabal-config.hs

clean:
	rm -f raaz-repo cabal-config *.o *.hi
