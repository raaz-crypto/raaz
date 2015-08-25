module Raaz.Core.Types.WordSpec where

import Arbitrary()
import Data.Word
import Test.Hspec

import Generic.EndianStore
import Raaz.Core.Types.Word

spec :: Spec
spec = describe "Endian Store instance" $ do
  storeAndLoadSpec (undefined :: LE Word32)
  storeAndLoadSpec (undefined :: LE Word64)
  storeAndLoadSpec (undefined :: BE Word32)
  storeAndLoadSpec (undefined :: BE Word64)
