module Modules.AES.ECB (benchmarks, benchmarksTiny) where

import Criterion.Main

import Raaz.Core.Primitives.Cipher

import Raaz.Cipher.AES

import Modules.AES.Defaults

ecb :: AES ECB KEY128
ecb = undefined

benchmarks :: IO [Benchmark]
benchmarks = benchmarksDefault ecb

benchmarksTiny :: IO [Benchmark]
benchmarksTiny = benchmarksTinyDefault ecb
