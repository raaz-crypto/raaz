{-# LANGUAGE ScopedTypeVariables #-}
module Raaz.Core.MemorySpec where
import Control.Monad.Reader
import Tests.Core

spec :: Spec
spec = do describe "store and read" $ do
            prop "should return identical values when run securely"
              $ \ (x :: Word) -> securely (storeAndRead x) `shouldReturn` x

            prop "should return identical values when run insecurely"
              $ \ (x :: Word) -> insecurely (storeAndRead x) `shouldReturn` x

          describe "store, copy, and read" $ do
            prop "should return identical values when run securely"
              $ \ (x :: Word) -> securely (storeCopyRead x) `shouldReturn` x

            prop "should return identical values when run insecurely"
              $ \ (x :: Word) -> insecurely (storeCopyRead x) `shouldReturn` x

  where storeAndRead :: Word -> MT (MemoryCell Word) Word
        storeAndRead x = initialise x >> extract
        storeCopyRead :: Word -> MT (MemoryCell Word, MemoryCell Word) Word
        storeCopyRead x = do withReaderT fst $ initialise x
                             mem <- ask
                             liftIO $ copyMemory (destination $ snd mem) (source $ fst mem)
                             withReaderT snd $ extract
