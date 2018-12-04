#!/bin/sh
cabal new-exec raaz entropy | dieharder -a -g 200
