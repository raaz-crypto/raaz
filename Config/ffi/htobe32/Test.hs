{-# LANGUAGE ForeignFunctionInterface #-}

import Data.Word
import System.Exit
foreign import ccall "be32" c_be32 :: Word32 -> Word32


main :: IO ()
main = exitSuccess -- Succeed if it compiles
