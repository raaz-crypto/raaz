{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedStrings   #-}
module Raaz.Core.EncodeSpec where

import           Common
import qualified Data.ByteString as B

shouldBeAMultipleOf :: Int -> Int -> Bool
shouldBeAMultipleOf m x = m `rem` x == 0

shouldEncodeTo :: (Format fmt, Eq fmt) => ByteString -> fmt -> Spec
shouldEncodeTo bs e = it msg $ encodeByteString bs `shouldBe` e
  where msg = show bs ++ " should encode to " ++ show e

spec :: Spec
spec = do
  describe "Base16" $ do
    prop "encoded string is always of even length" $ \ (x :: Base16) ->
      B.length (toByteString x) `shouldBeAMultipleOf` 2

    prop "unsafeFromByteString . toByteString = id" $ \ (x :: Base16) ->
      unsafeFromByteString (toByteString x) `shouldBe` x

    prop "correctly encodes a 64-bit big endian word." $ \ (w :: Word64) ->
      read ("0x" ++ showBase16 (bigEndian w))  == w


  describe "Base64" $ do
    prop "encoded string is always divisible by 4" $ \ (x :: Base64) ->
      B.length (toByteString x) `shouldBeAMultipleOf` 4

    prop "unsafeFromByteString . toByteString = id" $ \ (x :: Base16) ->
      unsafeFromByteString (toByteString x) `shouldBe` x

    describe "examples" $ do
      "pleasure." `shouldEncodeTo` ("cGxlYXN1cmUu" :: Base64)
      "leasure."  `shouldEncodeTo` ("bGVhc3VyZS4=" :: Base64)
      "easure."   `shouldEncodeTo` ("ZWFzdXJlLg==" :: Base64)
      "asure."    `shouldEncodeTo` ("YXN1cmUu"     :: Base64)
      "sure."     `shouldEncodeTo` ("c3VyZS4="     :: Base64)
