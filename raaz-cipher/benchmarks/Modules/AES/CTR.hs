module Modules.AES.CTR (benchmarks, benchmarksTiny) where

import Criterion.Main

import Raaz.Core.Primitives.Cipher

import Raaz.Cipher.AES

import Modules.AES.Defaults

ctr :: AES CTR KEY128
ctr = undefined

benchmarks :: IO [Benchmark]
benchmarks = benchmarksDefault ctr

benchmarksTiny :: IO [Benchmark]
benchmarksTiny = benchmarksTinyDefault ctr
