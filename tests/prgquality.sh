#!/bin/sh
cabal new-exec raaz rand | dieharder -a -g 200
