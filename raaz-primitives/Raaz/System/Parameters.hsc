{-| 

This module exposes some system dependent constants like cache sizes
etc to the Haskell world.


-}

{-# LANGUAGE CPP #-}

module Raaz.System.Parameters
       ( l1Cache
       , l2Cache
       ) where

import Raaz.Types( BYTES(..) )
#include <raaz/system/parameters.h>

-- | The L1 cache size.
l1Cache :: BYTES Int
l1Cache = BYTES #const RAAZ_L1_CACHE

-- | The L2 cache size.
l2Cache :: BYTES Int
l2Cache = #const RAAZ_L2_CACHE
