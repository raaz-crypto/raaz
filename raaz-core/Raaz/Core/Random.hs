{-# LANGUAGE TypeFamilies     #-}
{-# LANGUAGE KindSignatures   #-}
{-# LANGUAGE FlexibleContexts #-}
module Raaz.Core.Random
  ( PRG(..), fromPRG
  ) where

import Control.Monad   (void)
import Foreign.Ptr     (castPtr)
import Foreign.Storable(Storable, peek)

import Raaz.Core.ByteSource(ByteSource, fillBytes)
import Raaz.Core.Util.Ptr  (byteSize, allocaBuffer)

-- | The class that captures pseudo-random generators. Essentially the
-- a pseudo-random generator (PRG) is a byte sources that can be
-- seeded.
class ByteSource prg => PRG prg where

  -- | Associated type that captures the seed for the PRG.
  type Seed prg :: *

  -- | Creates a new pseudo-random generators
  newPRG :: Seed prg -> IO prg

  -- | Re-seeding the prg.
  reseed :: prg -> Seed prg -> IO ()

-- | Generate a random element of a type which is an instance of `Storable`.
fromPRG :: (PRG prg, Storable a) => prg -> IO a
fromPRG =  go undefined
  where go       :: (PRG prg, Storable a) => a -> prg -> IO a
        go w prg = let sz = byteSize w in
          allocaBuffer sz $ \ ptr -> do
            void $ fillBytes sz prg ptr
            peek $ castPtr ptr
