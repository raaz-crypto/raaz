{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE OverloadedStrings    #-}
{-# LANGUAGE ScopedTypeVariables  #-}
{-# LANGUAGE DataKinds            #-}

module Raaz.Mac.Poly1305Spec where

import           Tests.Core
import           Poly1305.Auth
import           Raaz.Random
import qualified Data.ByteString as BS
import           Raaz.Primitive.Poly1305.Internal (R)

randomClamping :: Spec
randomClamping = it "randomly generated R values should be clamped"
       $ checkClamped `shouldReturn` True
  where randR :: RandM R
        randR = random
        checkClamped = insecurely $ isClamped <$> randR


-- | Check whether the given value of r is clamped.
isClamped :: R -> Bool
isClamped = isClampedStr . toByteString
  where top4Clear w = w < 16
        bot2Clear w = w `mod` 4  == 0
        isClampedStr bs = check top4Clear [3,7,11,15] && check bot2Clear [4,8,12]
          where check pr  = all (pr . BS.index bs)

spec :: Spec
spec = do
  describe "Poly1305" $
    basicEndianSpecs (undefined :: Poly1305)
  describe "R" $ do
    basicEndianSpecs (undefined :: R)
    randomClamping

  describe "S" $
    basicEndianSpecs (undefined :: S)



  with ( "85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8"
       , "01:03:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b"
       ) $ ( "Cryptographic Forum Research Group" :: ByteString)
    `authsTo` ("a8:06:1d:c1:30:51:36:c6:c2:2b:8b:af:0c:01:27:a9" :: Poly1305)
