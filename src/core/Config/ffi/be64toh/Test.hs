{-# LANGUAGE ForeignFunctionInterface #-}

import Data.Word
import System.Exit

foreign import ccall unsafe "be64" c_be64 :: Word64 -> Word64

main :: IO ()
main = exitSuccess -- Succeeds if it compiles
                   -- More sensible test?
