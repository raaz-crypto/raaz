{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedStrings   #-}
module Raaz.Core.Encode.Base16Spec where

import           Common
import qualified Data.ByteString as B

shouldBeAMultipleOf :: Int -> Int -> Bool
shouldBeAMultipleOf m x = m `rem` x == 0

spec :: Spec
spec = do

  prop "base16 encoding is always of even length" $ \ (x :: Base16) ->
    B.length (toByteString x) `shouldBeAMultipleOf` 2

  prop "unsafeFromByteString . toByteString = id" $ \ (x :: Base16) ->
    unsafeFromByteString (toByteString x) `shouldBe` x

  prop "correctly encodes a 64-bit big endian word." $ \ (w :: Word64) ->
    (read $ "0x" ++ showBase16 (bigEndian w))  == w
