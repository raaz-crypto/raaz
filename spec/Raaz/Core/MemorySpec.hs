{-# LANGUAGE ScopedTypeVariables #-}
module Raaz.Core.MemorySpec where

import Common

spec :: Spec
spec = do prop "store followed by read gives identical values"
            $ \ (x :: Word) -> securely (storeAndRead x) `shouldReturn` x
  where storeAndRead :: Word -> MT (MemoryCell Word) Word
        storeAndRead x = initialise x >> extract
