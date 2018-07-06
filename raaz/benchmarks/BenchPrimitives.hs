{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE FlexibleInstances   #-}
{-# LANGUAGE CPP                 #-}
{-# LANGUAGE RecordWildCards     #-}

-- | This module benchmarks all block function and shows the

import Control.Monad
import Criterion
import Criterion.Types hiding (measure)
import Criterion.Measurement
import Data.Int
import Data.List              (span)

#if MIN_VERSION_base(4,11,0)
import Prelude  hiding ( (<>) )
#endif
import Text.PrettyPrint
import System.IO

import Raaz.Core
import Raaz.Cipher
import Raaz.Cipher.Internal
import Raaz.Hash.Internal
import Raaz.Random
import Raaz.Random.Internal

import qualified Raaz.Hash.Blake2.Implementation.CPortable    as Blake2CP
import qualified Raaz.Hash.Sha256.Implementation.CPortable    as Sha256CP
import qualified Raaz.Hash.Sha512.Implementation.CPortable    as Sha512CP
import qualified Raaz.Cipher.ChaCha20.Implementation.CPortable as ChaCha20CP

#if !MIN_VERSION_criterion(1,2,0)
toBenchmarkable :: (Int64 -> IO ()) -> Benchmarkable
toBenchmarkable = Benchmarkable
#endif

-- The total data processed
nBytes :: BYTES Int
nBytes = 32 * 1024

-- How many times to run each benchmark
nRuns :: Int64
nRuns = 10000

type Result            = (String, Measured)
type RaazBench         = (String, Benchmarkable)

allBench :: [RaazBench]
allBench =    [ memsetBench, randomnessBench, entropyBench ]
           ++ chacha20Benchs
           ++ blake2Benchs
           ++ sha256Benchs
           ++ sha512Benchs

main :: IO ()
main = do putStrLn $ "Buffer Size = " ++ show (fromIntegral nBytes :: Int)
          putStrLn $ "Iterations  = " ++ show nRuns
          mapM_ runRaazBench allBench


pprMeasured :: Measured -> Doc
pprMeasured (Measured{..}) = vcat
  [ text "time       " <+> eq <+> text (secs tm)
  , text "cycles     " <+> eq <+> double cy
  , text "rate       " <+> eq <+> text rt   <> text "bps"
  , text "secs/byte  " <+> eq <+> text secB <> text "sec/byte"
  , text "cycles/byte" <+> eq <+> double cycB
  ]
  where tm    = measTime   / fromIntegral nRuns
        cy    = fromIntegral measCycles / fromIntegral nRuns
        bytes = fromIntegral nBytes
        secB  = humanise $ tm / bytes
        cycB  = cy    / bytes
        rt    = humanise $ 8 * bytes / tm
        eq    = text "="


-------------  All benchmarks ---------------------------------------------

memsetBench :: RaazBench
memsetBench = ("memset", toBenchmarkable $ memBench . fromIntegral )
  where memBench count = allocaBuffer nBytes $ \ ptr -> replicateM_ count (memset ptr 42 nBytes)

sha256Benchs :: [ RaazBench ]
sha256Benchs = [ hashBench Sha256CP.implementation ]

sha512Benchs :: [ RaazBench ]
sha512Benchs = [ hashBench Sha512CP.implementation ]

blake2Benchs :: [ RaazBench ]
blake2Benchs = [ hashBench Blake2CP.implementation2b
               , hashBench Blake2CP.implementation2s
               ]

chacha20Benchs :: [ RaazBench ]
chacha20Benchs = [ encryptBench $ SomeCipherI ChaCha20CP.implementation
#               ifdef HAVE_VECTOR_256
                , encryptBench $ SomeCipherI ChaCha20V256.implementation
#               endif
#               ifdef HAVE_VECTOR_128
                , encryptBench $ SomeCipherI ChaCha20V128.implementation
#               endif
                ]


--------------------------- Helper functions ---------------------------------------------------------------------------

encryptBench :: Cipher c => Implementation c -> RaazBench
encryptBench si@(SomeCipherI impl) = (nm , toBenchmarkable $ encrBench . fromIntegral)
  where encrBench count = allocBufferFor si sz $ \ ptr -> insecurely $ replicateM_ count $ encryptBlocks impl ptr sz
        nm = name si ++ "-encrypt"
        sz = atLeast nBytes


decryptBench :: Cipher c => Implementation c -> RaazBench
decryptBench si@(SomeCipherI impl) = (nm , toBenchmarkable $ decrBench . fromIntegral)
  where decrBench count = allocBufferFor si sz $ \ ptr -> insecurely $ replicateM_ count $ decryptBlocks impl ptr sz
        nm = name si ++ "-decrypt"
        sz = atLeast nBytes

hashBench :: Hash h => Implementation h -> RaazBench
hashBench hi@(SomeHashI impl) = (nm, toBenchmarkable $ compressBench . fromIntegral )
  where compressBench count = allocBufferFor hi sz $ \ ptr -> insecurely $ replicateM_ count $ compress impl ptr sz
        nm = name hi ++ "-compress"
        sz = atLeast nBytes

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


runRaazBench :: RaazBench -> IO ()
runRaazBench (nm, bm) = do
  (memt,x) <- measure bm nRuns
  putStrLn $ render $ text nm $+$ nest 8 (pprMeasured memt)
  hFlush stdout

-------------------------- Humanise output -----------------------------------

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


-- | @prefix n@ gives proper prefix every 10^{3n} exponent
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
