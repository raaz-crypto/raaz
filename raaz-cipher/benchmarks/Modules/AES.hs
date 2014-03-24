module Modules.AES
       ( benchmarks
       , benchmarksTiny
       ) where

import           Criterion       (bgroup)

import qualified Modules.AES.ECB as ECB
import qualified Modules.AES.CBC as CBC
import qualified Modules.AES.CTR as CTR


-- | Performs benchmark for CTR tiny only
benchmarksTiny = [ bgroup "Raaz.Cipher.AES.ECB" ECB.benchmarksTiny ]

-- | Performs all the benchmarks
benchmarks = [ bgroup "Raaz.Cipher.AES.ECB" ECB.benchmarks
             , bgroup "Raaz.Cipher.AES.CBC" CBC.benchmarks
             , bgroup "Raaz.Cipher.AES.CTR" CTR.benchmarks
             ]
