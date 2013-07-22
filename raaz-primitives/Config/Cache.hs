{-|

This program guesses the L1 and L2 cache of the machine.


-}

module Config.Cache
       ( cache
       ) where
import System.Info

import           Raaz.Config.Monad
import qualified Config.Cache.Linux as Linux

cache :: ConfigM (Int,Int)
cache | os == "linux" = Linux.cache
      | otherwise     = return (0,0)
