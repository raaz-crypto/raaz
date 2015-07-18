{-# LANGUAGE OverloadedStrings #-}
module Modules.Sha224
       ( tests
       ) where

import           Control.Applicative
import qualified Data.ByteString       as B
import qualified Data.ByteString.Char8 as C8
import qualified Data.Vector.Unboxed   as VU
import           Test.QuickCheck       ( Arbitrary(..) )
import           Test.QuickCheck.Arbitrary

import Test.Gadget

import Modules.Generic
import Raaz.Hash.Sha224.Internal

instance Arbitrary SHA224 where
  arbitrary = SHA224 . VU.fromList <$> vector 7

tests = allHashTests (undefined :: SHA224) exampleStrings

exampleStrings :: [(B.ByteString,B.ByteString)]
exampleStrings =
  [ ( "abc"
    , "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7" )
  , ( "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    , "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525" )
  , ( "The quick brown fox jumps over the lazy dog"
    , "730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525" )
  , ( "The quick brown fox jumps over the lazy cog"
    , "fee755f44a55f20fb3362cdc3c493615b3cb574ed95ce610ee5b1e9b" )
  , ( ""
    , "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f" )
  , ( "The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog"
    , "72a1a34c088733e432fa2e61e93a3e69af178870aa6b5ce0864ca60b" )
  ]
