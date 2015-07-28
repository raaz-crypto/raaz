{-|

This program guesses the L1 and L2 cache of the machine.


-}

module Config.Cache
       ( getL1CacheSize
       , getL2CacheSize
       ) where
import System.Info

import           Config.Monad
import qualified Config.Cache.Linux as Linux

getL1CacheSize :: ConfigM (Maybe Int)
getL1CacheSize = onOs dontKnow [ ("linux", Linux.getL1CacheSize) ]

getL2CacheSize :: ConfigM (Maybe Int)
getL2CacheSize = onOs dontKnow [ ("linux", Linux.getL2CacheSize) ]

dontKnow :: ConfigM (Maybe a)
dontKnow = return Nothing
