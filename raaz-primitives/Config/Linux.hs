{-# LANGUAGE OverloadedStrings #-}
module Config.Linux
       ( configure
       ) where

import Control.Exception(catch)
import Config
import Data.Text(Text, strip, span, unpack)
import Data.Text.IO(readFile)
import Data.Char(isDigit)
import Prelude hiding (readFile, span, catch)
import System.Info(os)


configure :: IO Parameters
configure = do inform "platform is linux"
               inform "C compiler is GCC"
               (l1,l2) <- cache
               return $ Parameters { l1Cache = l1
                                   , l2Cache = l2
                                   , isGCC   = True
                                   }
                
                 
-- | Gets the L1 and L2 cache for a linux machine.
cache :: IO (Int, Int)
cache = "reading L1 and L2 cache sizes " <:> do
  l1 <- getCache "/sys/devices/system/cpu/cpu0/cache/index1/size"
  l2 <- getCache "/sys/devices/system/cpu/cpu0/cache/index2/size"
  putStr $ unwords [ "L1 = ", show l1
                   , "L2 = ", show l2
                   ]
  return (l1,l2)

getCache :: FilePath -> IO Int
getCache fp = fmap readCache (readFile fp) `catch` handler
    where handler :: IOError -> IO Int
          handler e = do inform $ show e
                         return 0
                 
readCache :: Text -> Int
readCache str | unit == "K" = number * 1024
              | unit == "M" = number * 1024 * 1024
              | otherwise   = error "cache info: bad format for cache string"
  where (n, r) = span isDigit str
        unit   = strip r
        number = read  $ unpack n
