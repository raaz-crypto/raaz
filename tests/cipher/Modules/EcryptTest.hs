{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE TypeFamilies      #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE BangPatterns      #-}
module Modules.EcryptTest (testAll) where

import           Control.Applicative
import           Data.Bits
import           Data.ByteString                ( ByteString,pack      )
import qualified Data.ByteString                as BS
import qualified Data.ByteString.Char8          as B8
import           Data.Char
import           Data.Typeable

import qualified Test.Framework                 as TF
import           Test.Framework                 ( testGroup, buildTest )
import           Test.Framework.Providers.HUnit ( hUnitTestToTests     )
import           Test.HUnit

import           Test                 ()
import           Test.Cipher
import           Test.Gadget          ( testGadget           )
import           Raaz.Core.Primitives
import           Raaz.Core.Primitives.Cipher
import           Raaz.Core.Types
import           Raaz.Core.Util.ByteString

import           Modules.EcryptTestParser

testVector :: ( Gadget g
              , Cipher p
              , HasName g
              , p ~ PrimitiveOf g
              , Key p ~ (k, n)
              , EndianStore k
              , EndianStore n
              ) => g -> EcryptTest -> Test
testVector g (EcryptTest n k iv s digest) = n ~: (testXor : map testExpected s)
    where
        encodedString = applyGadget g kAndIV
                                      (BS.replicate bslen 0)
        kAndIV = (fromByteString k, fromByteString iv)
        bslen = to (last s) + 1
        interval = BS.length digest
        testXor = "xor-digest" ~: TestCase (digest @=? xorDigest encodedString (BS.replicate interval 0))
        xorDigest ""  !out = out
        xorDigest !bs !out = let (l,rest) = BS.splitAt interval bs
                             in xorDigest rest (BS.pack $ BS.zipWith xor out l)
        testExpected (PartialStream f t expected) = concat [show f, " -> ", show t]
                                                      ~: TestCase (expected @=? actual)
            where
              actual = BS.take (t - f + 1) $ BS.drop f encodedString

testAll :: ( Gadget g
           , Cipher p
           , HasName g
           , p ~ PrimitiveOf g
           , Key p ~ (k, n)
           , EndianStore k
           , EndianStore n
           )
        => g
        -> FilePath             -- Path of Testfile
        -> (EcryptTest -> Bool) -- Filtering function
        -> TF.Test
testAll g fp with = buildTest $ do
  vec <- parseTestVector fp
  return $ testGroup msg $ hUnitTestToTests $ test $ map (testVector g) $ filter with vec
  where msg = getName g
