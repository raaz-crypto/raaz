{-# LANGUAGE ForeignFunctionInterface #-}

import Control.Monad
import Data.Word
import Foreign.Marshal.Alloc
import Foreign.Ptr
import System.Exit

foreign import ccall "sys/mmap.h mlock"   c_mlock :: Ptr Word -> Int -> IO Int
foreign import ccall "sys/mmap.h munlock" c_munlock :: Ptr Word -> Int -> IO Int

size = 1024
wrapper :: Ptr Word -> IO ()
wrapper ptr = do
  lstat  <- c_mlock ptr size
  when (lstat /= 0) $ do
    putStr "mlock failed"
    exitFailure
  ulstat <- c_munlock ptr size
  when (ulstat /= 0) $ do
    putStr "munlock failed"
    exitFailure
  exitSuccess


main :: IO ()
main = allocaBytes size wrapper
