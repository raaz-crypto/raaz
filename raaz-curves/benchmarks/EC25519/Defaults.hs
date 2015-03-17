module EC25519.Defaults ( benchSecretPublic
                        , benchParamsGivenRandom
                        , benchSharedSecret
                        ) where

import Criterion.Main
import Data.Bits
import Control.DeepSeq

import Raaz.Curves.EC25519
import Raaz.Curves.EC25519.Internal

instance NFData PublicToken25519 where
  rnf (PublicToken25519 pt) = w0 `seq` ()
    where (P25519 w0 w1 w2 w3) = pt

instance NFData Secret25519 where
  rnf (Secret25519 s) = w0 `seq` ()
    where (P25519 w0 w1 w2 w3) = s

instance NFData SharedSecret25519 where
  rnf (SharedSecret25519 ss) = w0 `seq` ()
    where (P25519 w0 w1 w2 w3) = ss

{-# INLINE benchSPref #-}
benchSPref :: IO (Secret25519, PublicToken25519)
benchSPref = do
  random <- getRandomP25519
  let secret = generateSecretEC25519 random
  return (secret, publicToken (undefined :: P25519) secret)

{-# INLINE benchSPRecommended #-}
benchSPRecommended :: IO (Secret25519, PublicToken25519)
benchSPRecommended = do
  random <- getRandomP25519
  params25519Reco random

{-# INLINE benchSPgivenRandomRef #-}
benchSPgivenRandomRef :: P25519 -> (Secret25519, PublicToken25519)
benchSPgivenRandomRef random = (secret, publicToken (undefined :: P25519) secret)
  where secret = generateSecretEC25519 random

{-# INLINE benchSPgivenRandomRecommended #-}
benchSPgivenRandomRecommended :: P25519 -> IO (Secret25519, PublicToken25519)
benchSPgivenRandomRecommended random = do
  params25519Reco random

{-# INLINE benchSSref #-}
benchSSref :: (P25519, P25519) -> SharedSecret25519
benchSSref (r1,r2) = sharedSecret (undefined :: P25519) secret (PublicToken25519 r2)
  where secret = generateSecretEC25519 r1

{-# INLINE benchSSRecommended #-}
benchSSRecommended :: (P25519, P25519) -> IO (SharedSecret25519)
benchSSRecommended (r1,r2) = sharedSecret25519Reco (Secret25519 r1) (PublicToken25519 r2)

benchSecretPublic :: [ Benchmark ]
benchSecretPublic = [ bench "Reference" $ nfIO benchSPref
                    , bench "Recommended" $ nfIO benchSPRecommended
                    ]

benchParamsGivenRandom :: P25519 -> [ Benchmark ]
benchParamsGivenRandom r = [ bench "Reference" $ nf (benchSPgivenRandomRef) r
                           , bench "Recommended" $ nfIO (benchSPgivenRandomRecommended r)
                           ]

benchSharedSecret :: (P25519, P25519) -> [ Benchmark ]
benchSharedSecret pair = [ bench "Reference" $ nf (benchSSref) pair
                         , bench "Recommended" $ nfIO (benchSSRecommended pair)
                         ]
