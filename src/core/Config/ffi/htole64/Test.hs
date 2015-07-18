{-# LANGUAGE ForeignFunctionInterface #-}

import Data.Word
import System.Endian
import Test.Framework(defaultMain, Test)
import Test.Framework.Providers.QuickCheck2(testProperty)

foreign import ccall "le64" c_le64 :: Word64 -> Word64

prop x = c_le64 x == toLE64 x

main :: IO ()
main = defaultMain [testProperty "htole64" prop]
