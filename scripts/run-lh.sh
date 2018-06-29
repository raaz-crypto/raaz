#!/bin/bash

LIQUID="$HOME/liquidhaskell/.cabal-sandbox/bin/liquid"
$LIQUID --version
echo "-------------------------------------------------"
pwd
echo "-------------------------------------------------"
cd ./raaz-core
pwd
echo "-------------------------------------------------"
find . -name '*.hs' -print0 | xargs -n 1 -0 -I{} sh -c "echo ---- {}; $LIQUID {}"
cd ..
pwd
echo "-------------------------------------------------"
cd raaz-implementation
pwd
echo "-------------------------------------------------"
find . -name '*.hs' -print0 | xargs -n 1 -0 -I{} sh -c "echo ---- {}; $LIQUID {}"
