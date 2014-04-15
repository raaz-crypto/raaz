module Modules.AES.CBC (benchmarks, benchmarksTiny) where

import Criterion.Main
import Raaz.Benchmark.Gadget
import Raaz.Primitives.Cipher

import Raaz.Cipher.AES

import Modules.AES.Defaults

cbc :: Cipher (AES CBC) KEY128 EncryptMode
cbc = undefined

benchmarks :: [Benchmark]
benchmarks = benchmarksDefault cbc

benchmarksTiny :: [Benchmark]
benchmarksTiny = benchmarksTinyDefault cbc
