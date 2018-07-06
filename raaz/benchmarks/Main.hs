{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE FlexibleInstances   #-}
{-# LANGUAGE CPP                 #-}
{-# LANGUAGE RecordWildCards     #-}

-- | This module benchmarks all block function and shows the

import Control.Monad
import Criterion

import Text.PrettyPrint

import Raaz.Core
import Raaz.Random
import Raaz.Random.Internal

import           Benchmark.Types
import qualified Benchmark.Blake2b.CPortable  as Blake2bCP
import qualified Benchmark.Blake2s.CPortable  as Blake2sCP
import qualified Benchmark.ChaCha20.CPortable as ChaCha20CP
import qualified Benchmark.Sha256.CPortable   as Sha256CP
import qualified Benchmark.Sha512.CPortable   as Sha512CP


allBench :: [RaazBench]
allBench = [ Blake2bCP.bench
           , Blake2sCP.bench
           , ChaCha20CP.bench
           , Sha256CP.bench
           , Sha512CP.bench
           ]

main :: IO ()
main = do putStrLn $ "Buffer Size = " ++ show (fromIntegral nBytes :: Int)
          putStrLn $ "Iterations  = " ++ show nRuns
          putStrLn $ "Memset (for comparison)"
          printBench memsetBench
          putStrLn $ "Randomness"
          mapM_ printBench [ randomnessBench, entropyBench ]
          putStrLn $ "Supported Primitives"
          mapM_ printBench allBench
  where printBench bnch = do x <- runRaazBench bnch
                             putStrLn $ render $ nest 4 x

-------------  All benchmarks ---------------------------------------------

memsetBench :: RaazBench
memsetBench = ("memset", toBenchmarkable $ memBench . fromIntegral )
  where memBench count = allocaBuffer nBytes $ \ ptr -> replicateM_ count (memset ptr 42 nBytes)

randomnessBench :: RaazBench
randomnessBench = ("random", toBenchmarkable $ rand . fromIntegral)
  where rand count = allocaBuffer nBytes $ insecurely . replicateM_ count . fillIt
        fillIt :: Pointer -> RandM ()
        fillIt = fillRandomBytes nBytes

entropyBench :: RaazBench
entropyBench = ("entropy", toBenchmarkable $ rand . fromIntegral)
  where rand count = allocaBuffer nBytes $ replicateM_ count . fillIt
        fillIt :: Pointer -> IO ()
        fillIt ptr = void (fillSystemEntropy nBytes ptr)
