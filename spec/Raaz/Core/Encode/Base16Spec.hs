{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedStrings   #-}
module Raaz.Core.Encode.Base16Spec where


import Control.Applicative
import Data.ByteString
import Data.String
import Data.Word
import Numeric
import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck

import Raaz.Core.Encode
import Arbitrary()

instance Arbitrary Base16 where
  arbitrary =  (encodeByteString . pack) <$> listOf arbitrary

spec :: Spec
spec = do
  prop "unsafeFromByteString . toByteString = id" $ \ (x :: Base16) ->
    unsafeFromByteString (toByteString x) `shouldBe` x
  let range      = (0x10, 0xff :: Word8)
      genInRange = choose range
      in do
    context ("for bytes in the range " ++ show range) $ do
      it "base16 and showHex should match" $
        forAll genInRange $ \ (x :: Word8) -> show (encodeByteString $ singleton x :: Base16) == fromString (showHex x "")
