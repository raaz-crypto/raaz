-- This module compares two different implementations of the same
-- digest.
{-# LANGUAGE ScopedTypeVariables #-}
module Tests.Digest.Compare (specCompare) where



import Data.ByteString (ByteString)
import Implementation
import Interface
import Alternate
import AlternateInterface
import Tests.Core

specCompare :: Spec
specCompare
  = describe title $ prop "should hash same strings to same hashes" $
    \ (x :: ByteString) ->
      show (Interface.digest x) `shouldBe` show (AlternateInterface.digest x)
  where title = Implementation.name ++ " vs " ++ Alternate.name
