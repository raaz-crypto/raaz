{-|

Generic tests for Hash implementations.

-}

module Raaz.Test.Hash
       ( testPadLengthVsPadding
       , testLengthDivisibility
       ) where

import qualified Data.ByteString as B
import Data.Typeable
import Data.Word
import Test.Framework(Test)
import Test.Framework.Providers.QuickCheck2(testProperty)

import Raaz.Primitives
import Raaz.Primitives.Hash
import Raaz.Types


prop_padLengthVsPadding :: Hash h => h -> BITS Word64 ->  Bool
prop_padLengthVsPadding h w = padLength h w ==
                              fromIntegral (B.length $ padding h w)

prop_LengthDivisibility :: Hash h => h -> BITS Word64 -> Bool
prop_LengthDivisibility h w = len `rem` blockSize h == 0
    where len = padLength h w + cryptoCoerce w

-- | For an instance of @`Hash`@, this test checks whether the padding
-- length computed using the function @`padLength`@ is equal to the
-- length of the bytestring returned by the function @`padding`@.
testPadLengthVsPadding :: ( Hash h, Typeable h ) => h -> Test
testPadLengthVsPadding h =  testProperty name
                                     $ prop_padLengthVsPadding h
    where name = show (typeOf h) ++ ": padLength vs length of padding"

-- | For a compressor, this test checks whether the sum of the message
-- length and padding length is a multiple of the block length.
testLengthDivisibility :: ( Hash h, Typeable h ) => h -> Test
testLengthDivisibility h = testProperty name
                           $ prop_LengthDivisibility h
    where name = show (typeOf h) ++ ": padding + message length vs block length"
