{-# LANGUAGE ForeignFunctionInterface #-}

import Data.Word
import System.Exit
foreign import ccall "be64" c_be64 :: Word64 -> Word64

main :: IO ()
main = exitSuccess
