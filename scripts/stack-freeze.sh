#!/bin/sh

STACKAGE_URL=https://www.stackage.org/"$1"/cabal.config
rm -f cabal.config
wget "$STACKAGE_URL" -c
sed -n /raaz/!p < cabal.config > cabal.project.freeze
