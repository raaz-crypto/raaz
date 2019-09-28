-- This module compares two different implementations of the same
-- digest.
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE FlexibleContexts    #-}
{-# LANGUAGE MonoLocalBinds      #-}
module Tests.Digest.Compare (specCompare) where



import Data.ByteString (ByteString)
import Implementation
import Interface
import Alternate
import AlternateInterface
import Tests.Core

specCompare :: ( Show Implementation.Prim
               , Show Alternate.Prim
               )
            => Spec
specCompare
  = describe title $ prop "should hash same strings to same hashes" $
    \ (x :: ByteString) ->
      show (Interface.digest x) `shouldBe` show (AlternateInterface.digest x)
  where title = Implementation.name ++ " vs " ++ Alternate.name
