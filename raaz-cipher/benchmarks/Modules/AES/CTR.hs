module Modules.AES.CTR (benchmarks, benchmarksTiny) where

import Criterion.Main

import Raaz.Core.Primitives.Cipher

import Raaz.Cipher.AES

import Modules.AES.Defaults

ctr :: AES CTR KEY128
ctr = undefined

benchmarks :: IO [Benchmark]
benchmarks = benchmarksDefault ctr testKey128 testKey192 testKey256

benchmarksTiny :: IO [Benchmark]
benchmarksTiny = benchmarksTinyDefault ctr testKey128 testKey192 testKey256
