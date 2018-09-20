module Raaz.Core.IOCont where

import Control.Monad.IO.Class
import Control.Monad.Reader

-- | Monads that allows lifting IO continuations.
class MonadIO m => MonadIOCont m where
  liftIOCont :: ((a -> IO b) -> IO c) -> (a -> m b) -> m c

instance MonadIOCont IO where
  liftIOCont = id

instance MonadIOCont m => MonadIOCont (ReaderT r m) where
  liftIOCont ioCont rCont = ReaderT $ liftIOCont ioCont . flipR rCont
    where flipR :: (a -> ReaderT r m b) -> r -> a -> m b
          flipR action r a = runReaderT (action a) r
