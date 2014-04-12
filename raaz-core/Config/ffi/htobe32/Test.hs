{-# LANGUAGE ForeignFunctionInterface #-}

import Data.Word
import System.Endian
import Test.Framework(defaultMain, Test)
import Test.Framework.Providers.QuickCheck2(testProperty)

foreign import ccall "be32" c_be32 :: Word32 -> Word32

prop x = c_be32 x == toBE32 x

main :: IO ()
main = defaultMain [testProperty "htobe32" prop]
