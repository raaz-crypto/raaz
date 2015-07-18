{-# LANGUAGE OverloadedStrings #-}
module Modules.Sha1
       ( tests
       ) where

import           Control.Applicative
import qualified Data.ByteString          as B
import qualified Data.ByteString.Char8    as C8
import           Data.String
import qualified Data.Vector.Unboxed      as VU
import           Data.Word
import           Test.QuickCheck          ( Arbitrary(..) )
import           Test.QuickCheck.Arbitrary
import Test.Gadget
import Raaz.Core.Types
import Raaz.Core.Primitives.HMAC
import           Raaz.Core.Primitives
import           Raaz.Core.Types.Word
import           Raaz.Core.Classes

import Modules.Generic
import Raaz.Hash.Sha1.Internal

instance Arbitrary SHA1 where
  arbitrary = SHA1 . VU.fromList <$> vector 5

tests = allHashTests (undefined :: SHA1) exampleStrings
     ++ allHMACTests (undefined :: SHA1) exampleHMAC

exampleStrings :: [(B.ByteString,B.ByteString)]
exampleStrings =
  [ ( "abc"
    , "a9993e364706816aba3e25717850c26c9cd0d89d" )
  , ( "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    , "84983e441c3bd26ebaae4aa1f95129e5e54670f1" )
  , ( "The quick brown fox jumps over the lazy dog"
    , "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12" )
  , ( "The quick brown fox jumps over the lazy cog"
    , "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3" )
  , ( ""
    , "da39a3ee5e6b4b0d3255bfef95601890afd80709" )
  , ( "The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog"
    , "5957a404e7e74dc746bea2d0d47645ddb387a7de" )
  ]

exampleHMAC :: [ (HMACKey SHA1 , B.ByteString, B.ByteString) ]
exampleHMAC =
  [ ( fromString $ replicate 20 '\x0b'
    , "Hi There"
    , "b617318655057264e28bc0b6fb378c8ef146be00"
    )
  , ( "Jefe"
    , "what do ya want for nothing?"
    ,  "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
    )
  , ( fromString $ replicate 20 '\xaa'
    , B.replicate 50 0xdd
    , "125d7342b9ac11cd91a39af48aa17b4f63f175d3"
    )
  , ( fromString $ replicate 80 '\xaa'
    , "Test Using Larger Than Block-Size Key - Hash Key First"
    , "aa4ae5e15272d00e95705637ce8a3b55ed402112"
    )
  , ( fromString $ replicate 80 '\xaa'
    , "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"
    , "e8e99d0f45237d786d6bbaa7965c7808bbff1a91"
    )
  ]
