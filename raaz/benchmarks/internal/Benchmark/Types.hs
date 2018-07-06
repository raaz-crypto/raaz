{-# LANGUAGE RecordWildCards #-}

module Benchmark.Types
       ( RaazBench
       , toBenchmarkable
       , nBytes
       , nRuns
       , runRaazBench
       ) where

import Criterion.Types hiding (measure)
import Criterion.Measurement
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

-- | Execute a benchmark and writeout the results.
runRaazBench :: RaazBench -> IO Doc
runRaazBench (nm, bm) = do
  (memt,_) <- measure bm nRuns
  return $ text nm $+$ nest 8 (pprMeasured memt)

------------------------ Helper functions ------------------------

pprMeasured :: Measured -> Doc
pprMeasured (Measured{..}) = vcat
  [ text "time       " <+> eqop <+> text (secs tm)
  , text "cycles     " <+> eqop <+> double cy
  , text "rate       " <+> eqop <+> text rt   <> text "bits/sec"
  , text "secs/byte  " <+> eqop <+> text secB <> text "sec/byte"
  , text "cycles/byte" <+> eqop <+> double cycB
  ]
  where tm    = measTime   / fromIntegral nRuns
        cy    = fromIntegral measCycles / fromIntegral nRuns
        bytes = fromIntegral nBytes
        secB  = humanise $ tm / bytes
        cycB  = cy    / bytes
        rt    = humanise $ 8 * bytes / tm
        eqop  = text "="


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
