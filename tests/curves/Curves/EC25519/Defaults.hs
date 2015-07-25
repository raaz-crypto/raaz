{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE Rank2Types #-}

module Curves.EC25519.Defaults where

import Control.Applicative
import Data.Bits
import Data.Word
import Test.Framework                       ( Test, testGroup )
import Test.Framework.Providers.QuickCheck2 ( testProperty    )
import Test.QuickCheck
import Test.QuickCheck.Property as P

import Raaz.Curves.EC25519
import Raaz.Curves.EC25519.Internal         ( integerToP25519 )
import System.IO.Unsafe (unsafePerformIO)

-- | The prime number (2^255 - 19)
curve25519P :: Integer
curve25519P  = 57896044618658097711785492504343953926634992332820282019728792003956564819949
{-# INLINE curve25519P #-}

newtype Param = Param Integer deriving Show

data Param2 = Param2 Integer Integer deriving Show

instance Arbitrary Param where
  arbitrary = do
    w <- choose (1, curve25519P) :: Gen Integer
    return $ Param w

instance Arbitrary Param2 where
  arbitrary = do
    w1 <- choose (1, curve25519P - 1) :: Gen Integer
    w2 <- choose (1, curve25519P - 1) :: Gen Integer
    return $ Param2 w1 w2

prop_genparams25519 :: Param -> Bool
prop_genparams25519 (Param random) = priv1 == priv2 && pub1 == pub2
  where secret        = generateSecretEC25519 (integerToP25519 random)
        (priv1, pub1) = (secret, publicToken (undefined :: P25519) secret)
        (priv2, pub2) = unsafePerformIO $ params25519Reco (integerToP25519 random)

prop_gensharedsecret25519 :: Param2 -> Bool
prop_gensharedsecret25519 (Param2 random1 random2) = priv1 == priv2 && pub1 == pub2 && sharedSecret1 == sharedSecret2
  where secret1       = generateSecretEC25519 (integerToP25519 random1)
        (priv1, pub1) = (secret1, publicToken (undefined :: P25519) secret1)
        (priv2, pub2) = unsafePerformIO $ params25519Reco (integerToP25519 random1)
        secret2       = generateSecretEC25519 (integerToP25519 random2)
        sharedSecret1 = sharedSecret (undefined :: P25519) secret2 pub1
        sharedSecret2 = unsafePerformIO $ sharedSecret25519Reco secret2 pub2

tests = [ testProperty "Generate Params Test" prop_genparams25519
        , testProperty "Generate SharedSecret Test" prop_gensharedsecret25519
        ]
