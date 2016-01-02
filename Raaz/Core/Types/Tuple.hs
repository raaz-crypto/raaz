{-# LANGUAGE DataKinds             #-}
{-# LANGUAGE KindSignatures        #-}
module Raaz.Core.Types.Tuple where

import GHC.TypeLits
import Data.Vector.Unboxed

newtype Tuple (n :: Nat) a = Tuple { unTuple :: Vector a }
