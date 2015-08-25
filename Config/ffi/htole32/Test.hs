{-# LANGUAGE ForeignFunctionInterface #-}

import Data.Word
import System.Exit
foreign import ccall "le32" c_le32 :: Word32 -> Word32

main :: IO ()
main = exitSuccess
