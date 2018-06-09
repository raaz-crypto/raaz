-- | This internal module lets you access the constructors of some
-- types that are crucial for for the type safety of Raaz.
--
-- __WARNING:__ There is very little reason for importing this
-- module even if you are a developer of raaz let alone a user. The one
-- place where you enhance type safety by importing this module is where
-- you define FFI calls --- consider this FFI call to memcpy
--
-- >
-- > foreign import ccall unsafe "string.h memcpy" c_memcpy
-- >    :: Dest Pointer -> Src Pointer -> BYTES Int -> IO Pointer
--
-- instead of this
--
-- >
-- > foreign import ccall unsafe "string.h memcpy" c_memcpy
-- >    :: Pointer -> Pointer -> Int -> IO Pointer

module Raaz.Core.Types.Internal
       ( module Raaz.Core.Types.Endian
       , module Raaz.Core.Types.Pointer
       , module Raaz.Core.Types.Copying
       ) where

import Raaz.Core.Types.Endian  ( LE(..), BE(..)          )
import Raaz.Core.Types.Pointer ( Pointer, AlignedPtr(..)
                               , BITS(..), BYTES(..)
                               )
import Raaz.Core.Types.Copying ( Src(..), Dest(..)       )
