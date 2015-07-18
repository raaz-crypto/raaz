module Modules.AES
       ( benchmarks
       , benchmarksTiny
       ) where

import           Criterion       (bgroup)

-- import qualified Modules.AES.ECB as ECB
import qualified Modules.AES.CBC as CBC
import qualified Modules.AES.CTR as CTR


-- | Performs benchmark for CTR tiny only
benchmarksTiny = do
  ctr <- CTR.benchmarks
  return [bgroup "Raaz.Cipher.AES.CTR" ctr]

-- | Performs all the benchmarks
benchmarks = do
  -- ecb <- ECB.benchmarks
  cbc <- CBC.benchmarks
  ctr <- CTR.benchmarks
  return [ bgroup "Raaz.Cipher.AES.CBC" cbc
         -- , bgroup "Raaz.Cipher.AES.ECB" ecb
         , bgroup "Raaz.Cipher.AES.CTR" ctr
         ]
