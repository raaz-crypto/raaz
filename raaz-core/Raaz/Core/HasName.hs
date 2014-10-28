{-# LANGUAGE DefaultSignatures #-}

module Raaz.Core.HasName
       ( HasName(..)
       ) where

import           Data.Typeable            (Typeable, typeOf)

-- | Types which have names. This is mainly used in test cases and
-- benchmarks to get the name of the primitive. A default instance is
-- provided for types with `Typeable` instances.
class HasName a where
  getName :: a -> String
  default getName :: Typeable a => a -> String
  getName = show . typeOf
