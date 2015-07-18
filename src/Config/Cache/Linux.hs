
{-| L1,L2 Cache information on Linux platform. -}
module Config.Cache.Linux
       ( getL1CacheSize
       , getL2CacheSize
       ) where

import Control.Exception(catch)
import Data.Char(isDigit, isSpace)
import Prelude hiding (catch)

import Config.Monad

getL1CacheSize :: ConfigM (Maybe Int)
getL1CacheSize = getCache "/sys/devices/system/cpu/cpu0/cache/index1/size"

getL2CacheSize :: ConfigM (Maybe Int)
getL2CacheSize = getCache "/sys/devices/system/cpu/cpu0/cache/index2/size"

getCache :: FilePath -> ConfigM (Maybe Int)
getCache fp = doIO $ fmap readCache (readFile fp) `catch` handler
    where handler :: IOError -> IO (Maybe Int)
          handler e = do print  e
                         return Nothing

readCache :: String -> Maybe Int
readCache str
  | unit == "K" = Just $ number * 1024
  | unit == "M" = Just $ number * 1024 * 1024
  | otherwise   = Nothing
  where (n, r) = span isDigit str
        unit   = strip r
        number = read  n

strip :: String -> String
strip = reverse
      . dropWhile isSpace
      . reverse
      . dropWhile isSpace
