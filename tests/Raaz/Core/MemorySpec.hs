{-# LANGUAGE ScopedTypeVariables #-}
module Raaz.Core.MemorySpec where
import Tests.Core

spec :: Spec
spec = do describe "store and read" $ do
            prop "should return identical values when run securely"
              $ \ (x :: Word) -> withSecureMemory (storeAndRead x) `shouldReturn` x

            prop "should return identical values when run insecurely"
              $ \ (x :: Word) -> withMemory (storeAndRead x) `shouldReturn` x

          describe "store, copy, and read" $ do
            prop "should return identical values when run securely"
              $ \ (x :: Word) -> withSecureMemory (storeCopyRead x) `shouldReturn` x

            prop "should return identical values when run insecurely"
              $ \ (x :: Word) -> withMemory (storeCopyRead x) `shouldReturn` x

  where storeAndRead :: Word -> MemoryCell Word -> IO Word
        storeAndRead x mem = initialise x mem >> extract mem
        storeCopyRead :: Word -> (MemoryCell Word, MemoryCell Word) -> IO Word
        storeCopyRead x mem = let
          src = fst mem
          dst = snd mem
          in do initialise x src
                copyCell (destination dst) (source src)
                extract dst
