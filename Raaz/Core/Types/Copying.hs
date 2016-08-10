-- | Consider a copy operation that involves copying data between two
-- entities of the same type. If the source and target is confused
-- this can lead to bugs. The types here are to avoid such bugs.

module Raaz.Core.Types.Copying
       ( Src, Dest, src, dest
       ) where

-- | The source of a copy operation.
newtype Src  a = Src a
-- | smart constructor for source
src :: a -> Src a
src = Src

-- | The destination of a copy operation.
newtype Dest a = Dest a
-- | smart constructor for destionation.
dest :: a -> Dest a
dest = Dest
