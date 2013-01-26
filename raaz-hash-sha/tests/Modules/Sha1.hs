module Modules.Sha1
       ( tests
       ) where

import Control.Applicative
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C8
import Test.QuickCheck(Arbitrary(..))

import Raaz.Test(allHashTests)
import Raaz.Hash.Sha()
import Raaz.Hash.Sha.Types(SHA1(..))

instance Arbitrary SHA1 where
  arbitrary = SHA1 <$> arbitrary   -- h0
                   <*> arbitrary   -- h1
                   <*> arbitrary   -- h2
                   <*> arbitrary   -- h3
                   <*> arbitrary   -- h4

tests = allHashTests (undefined ::SHA1) exampleStrings



exampleStrings :: [(B.ByteString,B.ByteString)]
exampleStrings = map convertToByteString
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
 where
   convertToByteString (a,b) = (C8.pack a, C8.pack b)
