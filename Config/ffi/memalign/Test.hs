{-# LANGUAGE ForeignFunctionInterface #-}

import Control.Monad
import Data.Bits
import Data.Word
import Foreign.Marshal.Alloc
import Foreign.Ptr
import Foreign.Storable
import System.Exit

foreign import ccall "stdlib.h posix_memalign"
  c_memalign :: Ptr (Ptr Word) -> Int -> Int -> IO Int
foreign import ccall "stdlib.h free"
  c_free :: Ptr Word -> IO ()
foreign import ccall "unistd.h getpagesize"
  c_pagesize :: IO Int

size = 16192
wrapper :: Ptr (Ptr Word) -> IO ()
wrapper ptr = do
    psize <- c_pagesize
    out <- c_memalign ptr psize size
    nptr <- peek ptr
    when (out /= 0) $ do
      putStr "mmap failed"
      exitFailure
    c_free nptr
    exitSuccess


main :: IO ()
main = allocaBytes size wrapper
