{-
This Module contains some test cases for classes in Primitives.
-}

module Raaz.Test.Primitives where

import qualified Data.ByteString as B
import Data.Word
import Test.Framework(Test)
import Test.Framework.Providers.QuickCheck2(testProperty)

import Raaz.Primitives

-- | This performs padding of a message for cryptostore and check if
-- padLength is same as length of bytestring returned by padding.
pad :: (Compressor c) => c -> Word64 ->  Bool
pad c w = padLength c w == fromIntegral (B.length $ padding c w)

testPadding :: (Compressor c) => c -> Test
testPadding c = testProperty "padLength == Length . padding" $ pad c
