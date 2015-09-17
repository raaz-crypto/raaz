{-# LANGUAGE ScopedTypeVariables #-}

module Raaz.Core.Types.WordSpec where

import Arbitrary()
import Data.Word
import Test.Hspec
import Test.Hspec.QuickCheck

import Generic.EndianStore
import Raaz.Core.Types.Word
import Raaz.Core.Encode

spec :: Spec
spec = do
  describe "Endian Store instance" $ do
    storeAndLoadSpec (undefined :: LE Word32)
    storeAndLoadSpec (undefined :: LE Word64)
    storeAndLoadSpec (undefined :: BE Word32)
    storeAndLoadSpec (undefined :: BE Word64)

  describe "decode . encode = id" $ do
    prop "for LE Word32" $ \ (x :: LE Word32) -> decode (encode x) == x
    prop "for LE Word64" $ \ (x :: LE Word64) -> decode (encode x) == x
    prop "for BE Word32" $ \ (x :: BE Word32) -> decode (encode x) == x
    prop "for BE Word32" $ \ (x :: BE Word64) -> decode (encode x) == x
