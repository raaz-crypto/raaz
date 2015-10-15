{-# LANGUAGE ScopedTypeVariables #-}
module Raaz.Core.Types.WordSpec where

import Data.ByteString as B
import Arbitrary()
import Data.Word
import Data.Bits
import Test.Hspec
import Test.Hspec.QuickCheck

import Generic.EndianStore
import Raaz.Core.Types.Word
import Raaz.Core.Encode


msbFirst :: (Bits a, Integral a) => B.ByteString -> a
msbFirst = B.foldl (\ x b -> shiftL x 8 + fromIntegral b) 0
lsbFirst :: (Bits a, Integral a) => B.ByteString -> a
lsbFirst = B.foldr (\ b x -> shiftL x 8 + fromIntegral b) 0


spec :: Spec
spec = do

  describe "little and big endian encodings are opposites" $ do

    prop "for 32-bit quantities" $ \ (x :: Word32) ->
      encode (littleEndian x) `shouldBe` B.reverse (encode $ bigEndian x)

    prop "for 64-bit quantities" $ \ (x :: Word64) ->
      encode (littleEndian x) `shouldBe` B.reverse (encode $ bigEndian x)


  describe "32-bit little endian" $ do

    prop "store followed by load returns original value" $ \ (x :: LE Word32) ->
      storeAndThenLoad x `shouldReturn` x

    prop "size of encodings of is 4 bytes" $ \ (w :: LE Word32) ->
      B.length (encode w) `shouldBe` 4

    prop "encode in lsb first order" $ \ (x :: LE Word32) ->
      lsbFirst (encode x) `shouldBe` x

    prop "decode . encode = id" $ \ (x :: LE Word32) ->
      decode (encode x) `shouldBe` x

  describe "64-bit little endian" $ do

    prop "store followed by load returns original value" $ \ (x :: LE Word64) ->
      storeAndThenLoad x `shouldReturn` x

    prop "size of encodings of is 8 bytes" $ \ (w :: LE Word64) ->
      B.length (encode w) `shouldBe` 8

    prop "encode in lsb first order" $ \ (x :: LE Word64) ->
      lsbFirst (encode x) `shouldBe` x

    prop "decode . encode = id" $ \ (x :: LE Word64) ->
      decode (encode x) `shouldBe` x

  describe "32-bit big endian" $ do

    prop "store followed by load returns original value" $ \ (x :: BE Word32) ->
      storeAndThenLoad x `shouldReturn` x

    prop "size of encodings of is 4 bytes" $ \ (w :: BE Word32) ->
      B.length (encode w) `shouldBe` 4

    prop "encode in lsb first order" $ \ (x :: BE Word32) ->
      msbFirst (encode x) `shouldBe` x

    prop "decode . encode = id" $ \ (x :: BE Word32) ->
      decode (encode x) `shouldBe` x

  describe "64-bit big endian" $ do

    prop "store followed by load returns original value" $ \ (x :: BE Word64) ->
      storeAndThenLoad x `shouldReturn` x

    prop "size of encodings of is 8 bytes" $ \ (w :: BE Word64) ->
      B.length (encode w) `shouldBe` 8

    prop "encode in lsb first order" $ \ (x :: BE Word64) ->
      msbFirst (encode x) `shouldBe` x

    prop "decode . encode = id" $ \ (x :: BE Word64) ->
      decode (encode x) `shouldBe` x
