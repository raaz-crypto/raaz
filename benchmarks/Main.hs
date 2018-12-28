{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE FlexibleInstances   #-}
{-# LANGUAGE CPP                 #-}
{-# LANGUAGE RecordWildCards     #-}

-- | This module benchmarks all block function and shows the

import Control.Monad

import System.IO
import Text.PrettyPrint

import           Benchmark.Types
import qualified Benchmark.Blake2b.CPortable     as Blake2bCP
import qualified Benchmark.Blake2b.CHandWritten  as Blake2bCHW

import qualified Benchmark.Blake2s.CHandWritten  as Blake2sCHW

import qualified Benchmark.ChaCha20.CPortable    as ChaCha20CP
import qualified Benchmark.ChaCha20.CHandWritten as ChaCha20CHW

import qualified Benchmark.Poly1305.CPortable    as Poly1305CP

import qualified Benchmark.Sha256.CPortable      as Sha256CP
import qualified Benchmark.Sha256.CHandWritten   as Sha256CHW

import qualified Benchmark.Sha512.CPortable      as Sha512CP
import qualified Benchmark.Sha512.CHandWritten   as Sha512CHW

import qualified Benchmark.CSPRG.CPortable       as CSPRGCP
import qualified Benchmark.CSPRG.CHandWritten    as CSPRGHW


main :: IO ()
main = do
  hSetEncoding stdout utf8
  putStrLn $ render header
  mapM_ printBench [ Blake2bCP.bench
                   , Blake2bCHW.bench

                   , Blake2sCHW.bench

                   , Poly1305CP.bench

                   , ChaCha20CP.bench
                   , ChaCha20CHW.bench

                   , CSPRGCP.bench
                   , CSPRGHW.bench

                   , Sha256CP.bench
                   , Sha256CHW.bench

                   , Sha512CP.bench
                   , Sha512CHW.bench
                   ]

  where printBench = runRaazBench >=> pure . render >=> putStrLn
