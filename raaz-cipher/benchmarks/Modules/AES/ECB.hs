module Modules.AES.ECB (benchmarks, benchmarksTiny) where

import Criterion.Main

import Raaz.Primitives.Cipher

import Raaz.Cipher.AES

import Modules.AES.Defaults

ecb :: AES ECB KEY128
ecb = undefined

benchmarks :: [Benchmark]
benchmarks = benchmarksDefault ecb

benchmarksTiny :: [Benchmark]
benchmarksTiny = benchmarksTinyDefault ecb
