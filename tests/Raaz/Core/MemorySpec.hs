{-# LANGUAGE ScopedTypeVariables #-}
module Raaz.Core.MemorySpec where

import Tests.Core

spec :: Spec
spec = prop "store followed by read gives identical values"
       $ \ (x :: Word) -> securely (storeAndRead x) `shouldReturn` x
  where storeAndRead :: Word -> MT (MemoryCell Word) Word
        storeAndRead x = initialise x >> extract
