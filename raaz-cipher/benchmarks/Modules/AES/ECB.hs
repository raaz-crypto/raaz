module Modules.AES.ECB (benchmarks, benchmarksTiny) where

import Criterion.Main

import Raaz.Core.Primitives.Cipher

import Raaz.Cipher.AES

import Modules.AES.Defaults

ecb :: AES ECB KEY128
ecb = undefined

benchmarks :: IO [Benchmark]
benchmarks = benchmarksDefault ecb (fst testKey128) (fst testKey192) (fst testKey256)

benchmarksTiny :: IO [Benchmark]
benchmarksTiny = benchmarksTinyDefault ecb (fst testKey128) (fst testKey192) (fst testKey256)
