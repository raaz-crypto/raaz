{-# LANGUAGE ForeignFunctionInterface #-}

import Data.Word
import System.Exit

foreign import ccall unsafe "le32" c_le32 :: Word64 -> Word64

main :: IO ()
main = exitSuccess -- Succeeds if it compiles
                   -- More sensible test?
