-- | benchmark various randomness source.
{-# LANGUAGE CPP #-}
import Criterion
import Criterion.Main
import Foreign.Marshal.Alloc
import Raaz.Core.Types
import Raaz.Core.Random

#ifdef BENCH_ARC4RANDOM
import Raaz.Core.Random.ARC4Random
#endif

import Raaz.Core.Random.DevUrandom


main :: IO ()
main = do devPrg  <- newDevUrandomPRG
          allocaBytes (fromIntegral bufLength) $ \ ptr -> do
            defaultMain
              [ bgroup "Random sources"
                [  bench "urandom" $ nfIO $ fillBuffer ptr devPrg
# ifdef BENCH_ARC4RANDOM
                , bench "arc4random" $ nfIO $ arc4Random ptr
# endif
                ]
              ]
bufLength :: BYTES Int
bufLength = 32 * 1024

fillBuffer :: PRG prg => Pointer -> prg -> IO ()
fillBuffer = fillRandom bufLength

#ifdef BENCH_ARC4RANDOM
arc4Random :: Pointer -> IO ()
arc4Random ptr = newARC4RandomPRG >>= fillBuffer ptr

#endif
