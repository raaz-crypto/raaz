{-# OPTIONS_HADDOCK how-extensions #-}
-- |
--
-- Module      : Raaz.Core.Types.Internal
-- Description : Exposes the constructors which are otherwise hidden.
-- Copyright   : (c) Piyush P Kurur, 2018
-- License     : Apache-2.0 OR BSD-3-Clause
-- Maintainer  : Piyush P Kurur <ppk@iitpkd.ac.in>
-- Stability   : experimental
--
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
       ( module Raaz.Core.Primitive
       , module Raaz.Core.Types.Endian
       , module Raaz.Core.Types.Pointer
       , module Raaz.Core.Types.Copying
       , module Raaz.Core.Types.Tuple
       ) where

import Raaz.Core.Primitive     ( BlockCount (..) )
import Raaz.Core.Types.Endian  ( LE(..), BE(..)          )
import Raaz.Core.Types.Pointer ( Pointer, AlignedPtr(..)
                               , BITS(..), BYTES(..)
                               )
import Raaz.Core.Types.Copying ( Src(..), Dest(..)       )
import Raaz.Core.Types.Tuple
