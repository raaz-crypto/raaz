module Modules.AES.ECB (benchmarks, benchmarksTiny) where

import Criterion.Main

import Raaz.Primitives.Cipher

import Raaz.Cipher.AES.ECB

import Modules.AES.Defaults

benchmarks :: [Benchmark]
benchmarks = benchmarksDefault (undefined :: ECB)

benchmarksTiny :: [Benchmark]
benchmarksTiny = benchmarksTinyDefault (undefined :: ECB)
