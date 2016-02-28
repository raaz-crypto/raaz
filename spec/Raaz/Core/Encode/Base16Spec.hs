{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedStrings   #-}
module Raaz.Core.Encode.Base16Spec where

import Common
import Numeric
import Data.ByteString( singleton )

spec :: Spec
spec = do
  prop "unsafeFromByteString . toByteString = id" $ \ (x :: Base16) ->
    unsafeFromByteString (toByteString x) `shouldBe` x
  let range      = (0x10, 0xff :: Word8)
      genInRange = choose range
      in
   context ("for bytes in the range " ++ show range)
   $ it "base16 and showHex should match"
   $ forAll genInRange $ \ (x :: Word8) -> show (encodeByteString $ singleton x :: Base16) == fromString (showHex x "")
