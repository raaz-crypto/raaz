{-# LANGUAGE GeneralizedNewtypeDeriving #-}
-- | Consider a copy operation that involves copying data between two
-- entities of the same type. If the source and target is confused
-- this can lead to bugs. The types here are to avoid such bugs.

module Raaz.Core.Types.Copying
       ( Src(..), Dest(..), source, destination
       ) where

import Foreign.Storable ( Storable )

-- | The source of a copy operation.
--
-- Note to Developers of Raaz: Since the `Src` type inherits the
-- Storable instance of the base type, one can use this type in
-- foreign functions.
newtype Src  a = Src { unSrc :: a } deriving Storable

-- | smart constructor for source
source :: a -> Src a
source = Src

instance Functor Src where
  fmap f = Src . f . unSrc

-- | The destination of a copy operation.
--
-- Note to Developers of Raaz: Since the `Dest` type inherits the
-- Storable instance of the base type, one can use this type in
-- foreign functions.
newtype Dest a = Dest { unDest :: a } deriving Storable

-- | smart constructor for destionation.
destination :: a -> Dest a
destination = Dest

instance Functor Dest where
  fmap f = Dest . f . unDest
