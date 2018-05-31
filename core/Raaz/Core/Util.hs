{-|

Some useful utility functions and combinators.

-}

module Raaz.Core.Util
       ( module Raaz.Core.Util.ByteString
       , liftToReaderT
       ) where

import Control.Monad.Reader
import Raaz.Core.Util.ByteString

liftToReaderT :: ((a -> m b) -> m c) -> (a -> ReaderT r m b) -> ReaderT r m c
liftToReaderT mLift rCont = ReaderT $ mLift . flipR rCont
  where flipR :: (a -> ReaderT r m b) -> r -> a -> m b
        flipR action r a = runReaderT (action a) r
