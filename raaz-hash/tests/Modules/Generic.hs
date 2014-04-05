{-|

Generic tests for Hashes.

-}
{-# LANGUAGE FlexibleContexts    #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies        #-}

module Modules.Generic
       ( testPadLengthVsPadding
       , testLengthDivisibility
       , testStandardHashValues
       , allHashTests
       , shorten
       ) where

import qualified Data.ByteString                      as B
import           Data.Default
import           Data.Typeable
import           Data.Word
import           Test.Framework                       (Test, testGroup)
import           Test.Framework.Providers.QuickCheck2 (testProperty)
import           Test.HUnit                           ((~?=), test, (~:) )
import           Test.Framework.Providers.HUnit       (hUnitTestToTests)
import           Test.QuickCheck                      (Arbitrary)

import           Raaz.Primitives
import           Raaz.Primitives.Hash
import           Raaz.Types
import           Raaz.Test.EndianStore
import           Raaz.Test.Cipher
import           Raaz.Test.Gadget
import           Raaz.Util.ByteString                 (toHex)


-- | This runs all the test for a given hash. The second argument to
-- the function is a list of pairs of bytestring and their
-- corresponding hash value which is used as a unit testing test
-- suites.
allHashTests :: ( Arbitrary h
                , Show h
                , Hash h
                , Typeable h
                , PrimitiveOf (CGadget h) ~ h
                , PrimitiveOf (HGadget h) ~ h
                , Default (Cxt h)
                , Gadget (HGadget h)
                , Gadget (CGadget h)
                , Eq (Cxt h)
                , HasName h
                )
             => h         -- ^ dummy hash type to satisfy the type checker
             -> [(B.ByteString,B.ByteString)]
                          -- ^ string hash pairs
             -> [Test]
allHashTests h pairs = [ testStoreLoad h
                       , testPadLengthVsPadding h
                       , testLengthDivisibility h
                       , testGroup unitTestName unitTests
                       , testCGadgetvsHGadget h
                       ]
    where unitTestName  = unwords [show $ typeOf h, "Unit tests"]
          unitTests     = testStandardHashValues h pairs

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

-- | The specifications of hash algorithms is usually accompanied with
-- a set of strings and their corresponding hash values so that
-- implementations can be checked. This combinator helps in generating
-- a unit test from such a set of string hash pairs.
--
-- The first argument is ignored and is present only to satisfy the
-- type checker. The second argument is a list which consists of pairs
-- of a string its hash (expressed as a bytestring in hex).

testStandardHashValues :: (EndianStore h, Hash h, Typeable h)
                       => h                             -- ^ hash
                                                        -- value
                                                        -- (ignored)
                       -> [(B.ByteString,B.ByteString)] -- ^ string
                                                        -- hash pairs
                       -> [Test]
testStandardHashValues h = hUnitTestToTests . test . map checkHash
  where getHash a = toHex $ hash a `asTypeOf` h
        label a   = show (typeOf h) ++ " " ++ shorten (show a)
        checkHash (a,b) = label a ~: getHash a ~?= b


testCGadgetvsHGadget :: ( PrimitiveOf (CGadget p) ~ p
                        , PrimitiveOf (HGadget p) ~ p
                        , Default (Cxt p)
                        , Gadget (HGadget p)
                        , Gadget (CGadget p)
                        , Eq (Cxt p)
                        , HasName p
                        ) => p -> Test
testCGadgetvsHGadget p = testGadget (g p) (ref p) def
  where
    g :: p -> CGadget p
    g _ = undefined
    ref :: p -> HGadget p
    ref _ = undefined
