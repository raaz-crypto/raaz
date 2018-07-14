{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE FlexibleInstances   #-}
{-# LANGUAGE CPP                 #-}
{-# LANGUAGE RecordWildCards     #-}

-- | This module benchmarks all block function and shows the

import Control.Monad

import Text.PrettyPrint

import           Benchmark.Types
import qualified Benchmark.Blake2b.CPortable  as Blake2bCP
import qualified Benchmark.Blake2s.CPortable  as Blake2sCP
import qualified Benchmark.ChaCha20.CPortable as ChaCha20CP
import qualified Benchmark.Sha256.CPortable   as Sha256CP
import qualified Benchmark.Sha512.CPortable   as Sha512CP


main :: IO ()
main = mapM_ printBench [ Blake2bCP.bench
                        , Blake2sCP.bench
                        , ChaCha20CP.bench
                        , Sha256CP.bench
                        , Sha512CP.bench
                        ]

  where printBench = runRaazBench >=> pure . render >=> putStrLn
