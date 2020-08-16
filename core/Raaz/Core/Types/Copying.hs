{-# OPTIONS_HADDOCK hide show-extensions #-}
-- |
--
-- Module      : Raaz.Core.Types.Copying
-- Description : Avoid confusion between source and destination while copying.
-- Copyright   : (c) Piyush P Kurur, 2016
-- License     : Apache-2.0 OR BSD-3-Clause
-- Maintainer  : Piyush P Kurur <ppk@iitpkd.ac.in>
-- Stability   : experimental
--
module Raaz.Core.Types.Copying
       (
         -- * Copying.
         -- $copyconvention$
         Src(..), Dest(..), source, destination
       ) where

import Raaz.Core.Prelude

-- | The source of a copy operation. Besides the `source` smart
-- constructor, the functor instance allows to transform the internal
-- type using the `fmap` (e.g. given an @sptr :: Src (Ptr Word8)@
-- shift it by an offset).
--
-- For FFI use: One can use this type directly in FFI interface by
-- importing "Raaz.Core.Types.Internal" to get access to the
-- constructor.
newtype Src  a = Src { unSrc :: a }

-- | Smart constructor for `Src`. Copying functions
source :: a -> Src a
source = Src

instance Functor Src where
  fmap f = Src . f . unSrc

-- | The destination of a copy operation. Besides the `destination`
-- smart constructor, the functor instance allows to transform the
-- internal type using the `fmap` (e.g. given an @dptr :: Dest (Ptr
-- Word8)@ shift it by an offset).
--
-- For FFI use: One can use this type directly in FFI interface by
-- importing "Raaz.Core.Types.Internal" to get access to the
-- constructor.

newtype Dest a = Dest { unDest :: a }

-- | Smart constructor for `Dest`.
destination :: a -> Dest a
destination = Dest

instance Functor Dest where
  fmap f = Dest . f . unDest
