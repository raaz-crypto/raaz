module Modules.AES.ECB (benchmarks, benchmarksTiny) where

import Criterion.Main

import Raaz.Primitives.Cipher

import Raaz.Cipher.AES

import Modules.AES.Defaults

ecb :: Cipher (AES ECB) KEY128 EncryptMode
ecb = undefined

ecbd :: Cipher (AES ECB) KEY128 DecryptMode
ecbd = undefined

benchmarks :: [Benchmark]
benchmarks = benchmarksDefault ecb ++ benchmarksDefault ecbd

benchmarksTiny :: [Benchmark]
benchmarksTiny = benchmarksTinyDefault ecb
