module Modules.AES.CBC (benchmarks, benchmarksTiny) where

import Criterion.Main
import Raaz.Benchmark.Gadget
import Raaz.Core.Primitives.Cipher

import Raaz.Cipher.AES

import Modules.AES.Defaults

cbc :: AES CBC KEY128
cbc = undefined

benchmarks :: IO [Benchmark]
benchmarks = benchmarksDefault cbc testKey128 testKey192 testKey256

benchmarksTiny :: IO [Benchmark]
benchmarksTiny = benchmarksTinyDefault cbc testKey128 testKey192 testKey256
