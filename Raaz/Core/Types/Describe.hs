-- | This module exposes ways to attach descriptions to types of the
-- library.
module Raaz.Core.Types.Describe
       ( Describable(..)
       ) where

-- | This class captures all types that have some sort of description
-- attached to it.
class Describable d where
  -- | Short name that describes the object.
  name :: d -> String

  -- | Longer description
  description :: d -> String
