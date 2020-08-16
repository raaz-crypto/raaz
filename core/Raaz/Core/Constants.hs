{-# OPTIONS_HADDOCK hide #-}
-- | Some constants used by raaz.
module Raaz.Core.Constants
       ( l1Cache
       ) where
import Raaz.Core.Prelude
import Raaz.Core.Types

-- | Typical size of L1 cache. Used for selecting buffer size etc in crypto operations.
l1Cache :: BYTES Int
l1Cache = 32768
