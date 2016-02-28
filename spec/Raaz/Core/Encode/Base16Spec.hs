{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedStrings   #-}
module Raaz.Core.Encode.Base16Spec where

import Common

spec :: Spec
spec = do
  prop "unsafeFromByteString . toByteString = id" $ \ (x :: Base16) ->
    unsafeFromByteString (toByteString x) `shouldBe` x
  prop "correctly encodes a 64-bit big endian word." $ \ (w :: Word64) ->
    (read $ "0x" ++ showBase16 (bigEndian w))  == w
