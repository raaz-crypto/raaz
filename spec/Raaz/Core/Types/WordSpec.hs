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

    prop "store followed by load returns original value" $ \ (x :: LE Word32) ->
      storeAndThenLoad x `shouldReturn` x

    prop "store, copy followed by peek should return the original value" $ \ (x :: LE Word32) ->
      storeCopyAndPeek x `shouldReturn` x

    prop "size of encodings of is 4 bytes" $ \ (w :: LE Word32) ->
      B.length (toByteString w) `shouldBe` 4

    prop "toByteString in lsb first order" $ \ (x :: LE Word32) ->
      lsbFirst (toByteString x) `shouldBe` x

    prop "unsafeFromByteString . toByteString = id" $ \ (x :: LE Word32) ->
      unsafeFromByteString (toByteString x) `shouldBe` x

  describe "64-bit little endian" $ do

    prop "store followed by load returns original value" $ \ (x :: LE Word64) ->
      storeAndThenLoad x `shouldReturn` x


    prop "store, copy followed by peek should return the original value" $ \ (x :: LE Word64) ->
      storeCopyAndPeek x `shouldReturn` x

    prop "size of encodings of is 8 bytes" $ \ (w :: LE Word64) ->
      B.length (toByteString w) `shouldBe` 8

    prop "toByteString in lsb first order" $ \ (x :: LE Word64) ->
      lsbFirst (toByteString x) `shouldBe` x

    prop "unsafeFromByteString . toByteString = id" $ \ (x :: LE Word64) ->
      unsafeFromByteString (toByteString x) `shouldBe` x

  describe "32-bit big endian" $ do

    prop "store followed by load returns original value" $ \ (x :: BE Word32) ->
      storeAndThenLoad x `shouldReturn` x

    prop "store, copy followed by peek should return the original value" $ \ (x :: BE Word32) ->
      storeCopyAndPeek x `shouldReturn` x


    prop "size of encodings of is 4 bytes" $ \ (w :: BE Word32) ->
      B.length (toByteString w) `shouldBe` 4

    prop "toByteString in lsb first order" $ \ (x :: BE Word32) ->
      msbFirst (toByteString x) `shouldBe` x

    prop "unsafeFromByteString . toByteString = id" $ \ (x :: BE Word32) ->
      unsafeFromByteString (toByteString x) `shouldBe` x

  describe "64-bit big endian" $ do

    prop "store followed by load returns original value" $ \ (x :: BE Word64) ->
      storeAndThenLoad x `shouldReturn` x

    prop "store, copy followed by peek should return the original value" $ \ (x :: BE Word64) ->
      storeCopyAndPeek x `shouldReturn` x

    prop "size of encodings of is 8 bytes" $ \ (w :: BE Word64) ->
      B.length (toByteString w) `shouldBe` 8

    prop "toByteString in lsb first order" $ \ (x :: BE Word64) ->
      msbFirst (toByteString x) `shouldBe` x

    prop "unsafeFromByteString . toByteString = id" $ \ (x :: BE Word64) ->
      unsafeFromByteString (toByteString x) `shouldBe` x
