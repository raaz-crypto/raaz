module Modules.AES.CTR (benchmarks, benchmarksTiny) where

import Criterion.Main

import Raaz.Primitives.Cipher

import Raaz.Cipher.AES.CTR

import Modules.AES.Defaults

benchmarks :: [Benchmark]
benchmarks = benchmarksDefault (undefined :: CTR)

benchmarksTiny :: [Benchmark]
benchmarksTiny = benchmarksTinyDefault (undefined :: CTR)
