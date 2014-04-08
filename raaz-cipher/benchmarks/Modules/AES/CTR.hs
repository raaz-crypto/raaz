module Modules.AES.CTR (benchmarks, benchmarksTiny) where

import Criterion.Main

import Raaz.Primitives.Cipher

import Raaz.Cipher.AES

import Modules.AES.Defaults

ctr :: Cipher (AES CTR) KEY128 EncryptMode
ctr = undefined

ctrd :: Cipher (AES CTR) KEY128 DecryptMode
ctrd = undefined

benchmarks :: [Benchmark]
benchmarks = benchmarksDefault ctr ++ benchmarksDefault ctrd

benchmarksTiny :: [Benchmark]
benchmarksTiny = benchmarksTinyDefault ctr
