#!/bin/sh

STACKAGE_URL=https://www.stackage.org/"$1"/cabal.config
TARGET=cabal.project.freeze
if [ -n "$2" ]
then
   TARGET="$2"
fi

rm -f cabal.config
wget "$STACKAGE_URL" -c
sed -n /raaz/!p < cabal.config > "$TARGET"
