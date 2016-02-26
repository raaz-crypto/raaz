
{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE OverloadedStrings    #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Raaz.Hash.Sha1Spec where

import Control.Applicative
import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck

import Data.ByteString.Char8
import Data.String
import Raaz.Core                 as RC
import Raaz.Hash
import Raaz.Hash.Sha1.Internal
import Generic.EndianStore
import qualified Generic.Hash as GH
import Arbitrary
import Generic.Utils


instance Arbitrary SHA1 where
  arbitrary = SHA1 <$> arbitraryVector 5

-- Particular case for SHA1
hashesTo :: ByteString -> SHA1 -> Spec
hashesTo = GH.hashesTo

hmacsTo  :: ByteString -> HMAC SHA1 -> Key (HMAC SHA1) -> Spec
hmacsTo  = GH.hmacsTo

repeated :: Key (HMAC SHA1) -> Int -> Key (HMAC SHA1)
repeated = GH.repeated

spec :: Spec
spec =  do

  prop "store followed by load returns original value" $ \ (x :: SHA1) ->
    storeAndThenLoad x `shouldReturn` x

  --
  -- Some unit tests
  --
  ""    `hashesTo` "da39a3ee5e6b4b0d3255bfef95601890afd80709"
  "abc" `hashesTo` "a9993e364706816aba3e25717850c26c9cd0d89d"
  "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" `hashesTo` "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
  "The quick brown fox jumps over the lazy dog"              `hashesTo` "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
  "The quick brown fox jumps over the lazy cog"              `hashesTo` "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3"
  "The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog"
         `hashesTo` "5957a404e7e74dc746bea2d0d47645ddb387a7de"

  -- Tests for HMAC SHA1
  hmacSpecs

hmacSpecs :: Spec
hmacSpecs = do
  with ("0b" `repeated` 20) $ "Hi There" `hmacsTo` "b617318655057264e28bc0b6fb378c8ef146be00"
  with ("aa" `repeated` 20) $
    RC.replicate (50 :: BYTES Int) 0xdd `hmacsTo` "125d7342b9ac11cd91a39af48aa17b4f63f175d3"
  with ("aa" `repeated` 80)
    $ "Test Using Larger Than Block-Size Key - Hash Key First" `hmacsTo` "aa4ae5e15272d00e95705637ce8a3b55ed402112"
  with ("aa" `repeated` 80) $
    "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data" `hmacsTo` "e8e99d0f45237d786d6bbaa7965c7808bbff1a91"

  let key = fromString $ (show  :: Base16 -> String) $ encodeByteString "Jefe"
    in with key  $ "what do ya want for nothing?" `hmacsTo` "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
