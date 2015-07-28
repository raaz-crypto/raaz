{-# LANGUAGE ForeignFunctionInterface #-}

import Data.Word
import System.Endian
import Test.Framework(defaultMain, Test)
import Test.Framework.Providers.QuickCheck2(testProperty)

foreign import ccall "be64" c_be64 :: Word64 -> Word64

prop x = c_be64 x == toBE64 x

main :: IO ()
main = defaultMain [testProperty "htobe64" prop]
