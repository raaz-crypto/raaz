#!/bin/bash


LIQUID="$HOME/liquidhaskell/.cabal-sandbox/bin/liquid"
$LIQUID --version

echo "-------------------------------------------------"


"$LIQUID" `find raaz-core -name "*.hs" | grep -v Entropy`
"$LIQUID"`find raaz-implementation -name "*.hs" | grep -v Entropy`
