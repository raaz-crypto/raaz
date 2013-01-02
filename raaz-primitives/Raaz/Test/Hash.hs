{-|

Generic tests for Hash implementations.

-}

module Raaz.Test.Hash
       ( testPadLengthVsPadding
       , testLengthDivisibility
       , testStandardHashValues
       , allHashTests
       ) where

import qualified Data.ByteString as B
import Data.Typeable
import Data.Word
import Test.Framework(Test)
import Test.Framework.Providers.QuickCheck2(testProperty)
import Test.HUnit ((@?=))
import Test.Framework.Providers.HUnit(testCase)
import Test.QuickCheck(Arbitrary)

import Raaz.Hash
import Raaz.Primitives
import Raaz.Test.CryptoStore
import Raaz.Types
import Raaz.Util.ByteString (toHex)


-- | All generic tests for an instance of `Hash`.
allHashTests :: ( Arbitrary h, Show h, Hash h, Typeable h )
             => h -> [Test]
allHashTests h = [ testStoreLoad h
                 , testPadLengthVsPadding h
                 , testLengthDivisibility h
                 ]

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

-- | For a hash implementation and given prehashed input-output pairs,
-- this function checks if the implementation satisfies those.
testStandardHashValues :: (CryptoStore h, Hash h, Typeable h)
                       => h
                       -> [(B.ByteString,B.ByteString)]
                       -> Test
testStandardHashValues h = testCase msg . sequence_ . map checkHash
  where getHash a = toHex( hashByteString a `asTypeOf` h)
        msg = show (typeOf h) ++ ": StandardHashValues"
        checkHash (a,b) = getHash a @?= b
