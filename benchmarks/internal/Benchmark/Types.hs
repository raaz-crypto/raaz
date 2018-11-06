{-# LANGUAGE RecordWildCards #-}

module Benchmark.Types
       ( RaazBench
       , toBenchmarkable
       , nBytes
       , nRuns
       , runRaazBench
       , header
       ) where

import Criterion.Measurement
import Criterion.Measurement.Types hiding (measure)

import Data.Int
import Text.PrettyPrint

import Raaz.Core

-- | The total data processed in each benchmark.
nBytes :: BYTES Int
nBytes = 32 * 1024

-- | How many times to run each benchmark
nRuns :: Int64
nRuns = 10000

type RaazBench         = (String, Benchmarkable)

header :: Doc
header = hsep $ punctuate comma $ map text
         [ "Implementation"
         , "time"
         , "cycles"
         , "rate (bits/sec)"
         , "secs/byte"
         , "cycles/byte"
         ]

-- | Execute a benchmark and writeout the results.
runRaazBench :: RaazBench -> IO Doc
runRaazBench (nm, bm) = do
  (memt,_) <- measure bm nRuns
  return $ hsep $ punctuate comma $ text nm : pprMeasured memt


------------------------ Helper functions ------------------------


pprMeasured :: Measured -> [Doc]
pprMeasured (Measured{..}) =
  [ text (secs tm) -- time
  , double cy      -- cycles
  , text rt        -- rate
  , text secB      -- secs/byte
  , double cycB    -- cycles/byte
  ]
  where tm    = measTime   / fromIntegral nRuns
        cy    = fromIntegral measCycles / fromIntegral nRuns
        bytes = fromIntegral nBytes
        secB  = humanise $ tm / bytes
        cycB  = cy    / bytes
        rt    = humanise $ 8 * bytes / tm


-- | Humanise the output units.
humanise :: Double -> String
humanise u | u < 1     = goL 0 u
           | otherwise = goU 0 u
  where goL e x | x > 1 || e == -3  = restrictDecimals 2  x ++ unitPrefix e
                | otherwise         = goL (e  - 1) (x * 1000)

        goU e x | x < 100 || e == 5 = restrictDecimals 2 x  ++ unitPrefix e
                | otherwise         = goU (e  + 1) (x / 1000)


restrictDecimals :: Int -> Double -> String
restrictDecimals n x = u ++ take (n+1) v
  where (u,v) = span (/= '.') $ show x


-- | @Unit prefix n@ gives proper prefix every 10^{3n} exponent
unitPrefix :: Int -> String
unitPrefix ex
  | ex <  -3   = error "exponent too small name"
  | ex == -3   = "n"
  | ex == -2   = "μ"
  | ex == -1   = "m"
  | ex == 0    = ""
  | ex == 1    = "K"
  | ex == 2    = "M"
  | ex == 3    = "G"
  | ex == 4    = "T"
  | ex == 5    = "P"
  | otherwise  = error "exponent to large to name"
