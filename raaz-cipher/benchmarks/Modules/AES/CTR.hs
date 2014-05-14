module Modules.AES.CTR (benchmarks, benchmarksTiny) where

import Criterion.Main

import Raaz.Primitives.Cipher

import Raaz.Cipher.AES

import Modules.AES.Defaults

ctr :: AES CTR KEY128
ctr = undefined

benchmarks :: [Benchmark]
benchmarks = benchmarksDefault ctr

benchmarksTiny :: [Benchmark]
benchmarksTiny = benchmarksTinyDefault ctr
