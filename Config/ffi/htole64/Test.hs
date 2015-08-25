{-# LANGUAGE ForeignFunctionInterface #-}

import Data.Word
import System.Exit
foreign import ccall "le64" c_le64 :: Word64 -> Word64

main :: IO ()
main = exitSuccess
