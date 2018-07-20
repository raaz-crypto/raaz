#!/bin/bash

FOLDER="$HOME/liquidhaskell"

rm -rf "$FOLDER"

cd "$HOME"
git clone --recursive --depth 1 git://github.com/ucsd-progsys/liquidhaskell.git

cd "$FOLDER"

cabal sandbox init
cabal sandbox add-source ./liquid-fixpoint
cabal install
