{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE TypeFamilies      #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE BangPatterns      #-}
module Modules.EcryptTest (testAll) where

import           Control.Applicative
import           Data.Bits
import           Data.ByteString                (ByteString,pack)
import qualified Data.ByteString                as BS
import qualified Data.ByteString.Char8          as B8
import           Data.Char
import           Data.Typeable

import qualified Test.Framework                 as TF
import           Test.Framework                 (testGroup,buildTest)
import           Test.Framework.Providers.HUnit (hUnitTestToTests)
import           Test.HUnit

import           Raaz.Test                      ()
import           Raaz.Test.Cipher
import           Raaz.Test.Gadget               (testGadget)
import           Raaz.Primitives
import           Raaz.Primitives.Cipher
import           Raaz.Serialize

import           Modules.EcryptTestParser

testVector :: ( Gadget g
              , Encrypt p
              , HasName g
              , p EncryptMode ~ PrimitiveOf g
              ) => g -> EcryptTest -> Test
testVector g (EcryptTest n k iv s digest) = n ~: (testXor : map testExpected s)
    where
        encodedString = applyGadget g (encryptCxt $ fromByteString kAndIV)
                                      (BS.replicate bslen 0)
        kAndIV = k `BS.append` iv
        bslen = (to $ last s) + 1
        interval = BS.length digest
        testXor = "xor-digest" ~: TestCase (digest @=? xorDigest encodedString (BS.replicate interval 0))
        xorDigest ""  !out = out
        xorDigest !bs !out = let (l,rest) = BS.splitAt interval bs
                             in xorDigest rest (BS.pack $ BS.zipWith xor out l)
        testExpected (PartialStream f t expected) = concat [show f, " -> ", show t]
                                                      ~: TestCase (expected @=? actual)
            where
              actual = (BS.take (t - f + 1) $ BS.drop f $ encodedString)

testAll :: ( Gadget g
           , Encrypt p
           , HasName g
           , p EncryptMode ~ PrimitiveOf g
           )
        => g
        -> FilePath             -- Path of Testfile
        -> (EcryptTest -> Bool) -- Filtering function
        -> TF.Test
testAll g fp with = buildTest $ do
  vec <- parseTestVector fp
  return $ testGroup msg $ hUnitTestToTests $ test $ map (testVector g) $ filter with vec
  where msg = getName g
