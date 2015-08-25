{-

Page Size on Linux platform.

-}
{-# LANGUAGE ForeignFunctionInterface #-}

module Config.Page.Linux ( getPageSize ) where

import Config.Monad

foreign import ccall unsafe "unistd.h getpagesize" c_getpagesize :: IO Int

getPageSize :: ConfigM Int
getPageSize = do
  messageLn "Reading Page Size using unistd"
  doIO c_getpagesize
