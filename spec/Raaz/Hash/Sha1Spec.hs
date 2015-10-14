
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
import Raaz.Core
import Raaz.Core.Util.ByteString as B
import Raaz.Hash.Sha1.Internal
import Raaz.Hash.HMAC
import Generic.EndianStore
import qualified Generic.Hash as GH
import Arbitrary


import Data.Word
instance Arbitrary SHA1 where
  arbitrary = SHA1 <$> arbitraryVector 5

-- Particular case for SHA1
hashesTo :: ByteString -> SHA1 -> Spec
hashesTo = GH.hashesTo

pad     :: BITS Word64 -> ByteString
padLen  :: BITS Word64 -> BYTES Int
blockSz :: BYTES Int

withKey  :: HMACKey SHA1 -> (HMACKey SHA1 -> Spec) -> Spec
withKey  = GH.withKey

hmacsTo  :: ByteString -> HMAC SHA1 -> HMACKey SHA1 -> Spec
hmacsTo  = GH.hmacsTo

repeated :: HMACKey SHA1 -> Int -> HMACKey SHA1
repeated = GH.repeated



pad     = padding   (undefined :: SHA1)
padLen  = padLength (undefined :: SHA1)
blockSz = blockSize (undefined :: SHA1)

spec :: Spec
spec =  do

  prop "store followed by load returns original value" $ \ (x :: SHA1) ->
    storeAndThenLoad x `shouldReturn` x

  prop "checks that the padding string has the same length as padLength" $
    \ w -> padLen w == (B.length $ pad w)

  prop "length after padding should be an integral multiple of block size" $
    \ w -> (padLen w + bitsQuot w) `rem` blockSz == 0

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
  withKey ("0b" `repeated` 20) $ "Hi There" `hmacsTo` "b617318655057264e28bc0b6fb378c8ef146be00"
  withKey ("aa" `repeated` 20) $
    B.replicate (50 :: BYTES Int) 0xdd `hmacsTo` "125d7342b9ac11cd91a39af48aa17b4f63f175d3"
  withKey ("aa" `repeated` 80)
    $ "Test Using Larger Than Block-Size Key - Hash Key First" `hmacsTo` "aa4ae5e15272d00e95705637ce8a3b55ed402112"
  withKey ("aa" `repeated` 80) $
    "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data" `hmacsTo` "e8e99d0f45237d786d6bbaa7965c7808bbff1a91"

  let key = fromString $ (show  :: Base16 -> String) $ encodeByteString "Jefe"
    in withKey key  $ "what do ya want for nothing?" `hmacsTo` "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
