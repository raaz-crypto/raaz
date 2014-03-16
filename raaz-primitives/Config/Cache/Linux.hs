
{-| L1,L2 Cache information on Linux platform. -}
module Config.Cache.Linux
       ( cache
       ) where

import Control.Exception(catch)
import Data.Char(isDigit, isSpace)
import Prelude hiding (catch)

import Config.Monad

-- | Gets the L1 and L2 cache for a linux machine.
cache :: ConfigM (Int, Int)

cache = do
  messageLn "reading L1 and L2 cache sizes from sysfs"
  l1 <- getCache "/sys/devices/system/cpu/cpu0/cache/index1/size"
  l2 <- getCache "/sys/devices/system/cpu/cpu0/cache/index2/size"
  messageLn $ unwords [ "\tL1 = ", show l1
                      , "L2 = ", show l2
                      ]
  return (l1,l2)

getCache :: FilePath -> ConfigM Int
getCache fp = doIO $ fmap readCache (readFile fp) `catch` handler
    where handler :: IOError -> IO Int
          handler e = do print  e
                         return 0

readCache :: String -> Int
readCache str
  | unit == "K" = number * 1024
  | unit == "M" = number * 1024 * 1024
  | otherwise   = error "cache info: bad format for cache string"
  where (n, r) = span isDigit str
        unit   = strip r
        number = read  n

strip :: String -> String
strip = reverse
      . dropWhile isSpace
      . reverse
      . dropWhile isSpace
