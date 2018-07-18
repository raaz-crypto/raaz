{-# LANGUAGE GeneralizedNewtypeDeriving #-}
-- | Types to avoid source destination confusion while copying.
module Raaz.Core.Types.Copying
       (
         -- * Copying.
         -- $copyconvention$
         Src(..), Dest(..), source, destination
       ) where

-- $copyconvention$
--
-- Consider a copy operation that involves copying data between two
-- entities of the same type. If the source and target is confused
-- this can lead to bugs. The types `Src` and `Dest` helps in avoiding
-- this confusion. The convention that we follow is that copy function
-- mark its destination and source explicitly at the type level. The
-- actual constructors for the type `Src` and `Dest` are not available
-- to users of the library. Instead they use the smart constructors
-- `source` and `destination` when passing arguments to these
-- functions.
--
-- The developers of the raaz library do have access to the
-- constructors. However, it is unlikely one would need it. Since both
-- `Src` and `Dest` derive the underlying `Storable` instance, one can
-- mark `Src` and `Dest` in calls to `FFI` functions as well.


-- | The source of a copy operation.
newtype Src  a = Src { unSrc :: a }

-- | smart constructor for source
source :: a -> Src a
source = Src

instance Functor Src where
  fmap f = Src . f . unSrc

-- | The destination of a copy operation.
--
-- Note to Developers of Raaz: One can use this type in
-- foreign functions.
newtype Dest a = Dest { unDest :: a }

-- | smart constructor for destionation.
destination :: a -> Dest a
destination = Dest

instance Functor Dest where
  fmap f = Dest . f . unDest
