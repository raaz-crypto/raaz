
{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE OverloadedStrings    #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Raaz.Hash.Sha224Spec where

import Control.Applicative
import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck

import Data.ByteString.Char8
import Raaz.Core
import Raaz.Core.Util.ByteString as B
import Raaz.Hash.Sha224.Internal
import Generic.EndianStore
import qualified Generic.Hash as GH
import Arbitrary

import Data.Word
instance Arbitrary SHA224 where
  arbitrary = SHA224 <$> arbitraryVector 7

hashesTo :: ByteString -> SHA224 -> Spec
hashesTo = GH.hashesTo

pad     :: BITS Word64 -> ByteString
padLen  :: BITS Word64 -> BYTES Int
blockSz :: BYTES Int


pad     = padding   (undefined :: SHA224)
padLen  = padLength (undefined :: SHA224)
blockSz = blockSize (undefined :: SHA224)

spec :: Spec
spec =  do

  prop "store followed by load returns original value" $ \ (x :: SHA224) ->
    storeAndThenLoad x `shouldReturn` x

  prop "checks that the padding string has the same length as padLength" $
    \ w -> padLen w == (B.length $ pad w)

  prop "length after padding should be an integral multiple of block size" $
    \ w -> (padLen w + bitsQuot w) `rem` blockSz == 0

  --
  -- Some unit tests
  --
  "" `hashesTo` "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"

  "abc" `hashesTo` "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"

  "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" `hashesTo`
    "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525"

  "The quick brown fox jumps over the lazy dog" `hashesTo`
    "730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525"

  "The quick brown fox jumps over the lazy cog" `hashesTo`
    "fee755f44a55f20fb3362cdc3c493615b3cb574ed95ce610ee5b1e9b"

  "The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog" `hashesTo`
    "72a1a34c088733e432fa2e61e93a3e69af178870aa6b5ce0864ca60b"
