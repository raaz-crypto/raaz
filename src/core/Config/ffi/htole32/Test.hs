{-# LANGUAGE ForeignFunctionInterface #-}

import Data.Word
import System.Endian
import Test.Framework(defaultMain, Test)
import Test.Framework.Providers.QuickCheck2(testProperty)

foreign import ccall "le32" c_le32 :: Word32 -> Word32

prop x = c_le32 x == toLE32 x

main :: IO ()
main = defaultMain [testProperty "htole32" prop]
