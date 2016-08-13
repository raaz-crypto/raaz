{-# LANGUAGE ScopedTypeVariables #-}
module Raaz.Core.Types.WordSpec where

import Common
import Data.ByteString as B
import Data.Bits


msbFirst :: (Bits a, Integral a) => B.ByteString -> a
msbFirst = B.foldl (\ x b -> shiftL x 8 + fromIntegral b) 0
lsbFirst :: (Bits a, Integral a) => B.ByteString -> a
lsbFirst = B.foldr (\ b x -> shiftL x 8 + fromIntegral b) 0


spec :: Spec
spec = do

  describe "little and big endian encodings are opposites" $ do

    prop "for 32-bit quantities" $ \ (x :: Word32) ->
      toByteString (littleEndian x) `shouldBe` B.reverse (toByteString $ bigEndian x)

    prop "for 64-bit quantities" $ \ (x :: Word64) ->
      toByteString (littleEndian x) `shouldBe` B.reverse (toByteString $ bigEndian x)


  describe "32-bit little endian" $ do

    basicEndianSpecs (undefined :: LE Word32)

    prop "size of encodings of is 4 bytes" $ \ (w :: LE Word32) ->
      B.length (toByteString w) `shouldBe` 4

    prop "toByteString in lsb first order" $ \ (x :: LE Word32) ->
      lsbFirst (toByteString x) `shouldBe` x

    prop "unsafeFromByteString . toByteString = id" $ \ (x :: LE Word32) ->
      unsafeFromByteString (toByteString x) `shouldBe` x

  describe "64-bit little endian" $ do

    basicEndianSpecs (undefined :: LE Word64)

    prop "size of encodings of is 8 bytes" $ \ (w :: LE Word64) ->
      B.length (toByteString w) `shouldBe` 8

    prop "toByteString in lsb first order" $ \ (x :: LE Word64) ->
      lsbFirst (toByteString x) `shouldBe` x

    prop "unsafeFromByteString . toByteString = id" $ \ (x :: LE Word64) ->
      unsafeFromByteString (toByteString x) `shouldBe` x

  describe "32-bit big endian" $ do

    basicEndianSpecs (undefined :: BE Word32)

    prop "size of encodings of is 4 bytes" $ \ (w :: BE Word32) ->
      B.length (toByteString w) `shouldBe` 4

    prop "toByteString in lsb first order" $ \ (x :: BE Word32) ->
      msbFirst (toByteString x) `shouldBe` x

    prop "unsafeFromByteString . toByteString = id" $ \ (x :: BE Word32) ->
      unsafeFromByteString (toByteString x) `shouldBe` x

  describe "64-bit big endian" $ do

    basicEndianSpecs (undefined :: BE Word64)

    prop "size of encodings of is 8 bytes" $ \ (w :: BE Word64) ->
      B.length (toByteString w) `shouldBe` 8

    prop "toByteString in lsb first order" $ \ (x :: BE Word64) ->
      msbFirst (toByteString x) `shouldBe` x

    prop "unsafeFromByteString . toByteString = id" $ \ (x :: BE Word64) ->
      unsafeFromByteString (toByteString x) `shouldBe` x
