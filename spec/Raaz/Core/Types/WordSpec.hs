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

import Raaz.Core

msbFirst :: (Bits a, Integral a) => B.ByteString -> a
msbFirst = B.foldl (\ x b -> shiftL x 8 + fromIntegral b) 0


spec :: Spec
spec = do context "little endian word32" $ storeAndLoadSpec (undefined :: LE Word32)
          context "little endian word64" $ storeAndLoadSpec (undefined :: LE Word64)
          context "big endian word32"    $ storeAndLoadSpec (undefined :: BE Word32)
          context "big ending word64"    $ storeAndLoadSpec (undefined :: BE Word64)

          describe "decode . encode = id" $ do
            prop "for LE Word32" $ \ (x :: LE Word32) -> decode (encode x) == x
            prop "for LE Word64" $ \ (x :: LE Word64) -> decode (encode x) == x
            prop "for BE Word32" $ \ (x :: BE Word32) -> decode (encode x) == x
            prop "for BE Word32" $ \ (x :: BE Word64) -> decode (encode x) == x

          context "Word32" $ do

            prop "size of encodings of little endian is 4" $
              \ (w :: LE Word32) -> B.length (toByteString w) == 4

            prop "size of encodings of big endian is 4" $
              \ (w :: BE Word32) -> B.length (toByteString w) == 4

            prop "big endian encoding is MSB first" $
              \ (w :: BE Word32) -> w == (msbFirst $ toByteString w)

            prop "little endian is reverse of big endian" $
              \ (w :: Word32) -> (toByteString $ littleEndian w) == (B.reverse $ toByteString $ bigEndian w)

          context "Word64" $ do

            prop "size of encodings of little endian is 8" $
              \ (w :: LE Word64) -> B.length (toByteString w) == 8

            prop "size of encodings of big endian is 8" $
              \ (w :: BE Word64) -> B.length (toByteString w) == 8

            prop "big endian encoding is MSB first" $
              \ (w :: BE Word64) -> w == (msbFirst $ toByteString w)

            prop "little endian is reverse of big endian" $
              \ (w :: Word64) -> (toByteString $ littleEndian w) == (B.reverse $ toByteString $ bigEndian w)
