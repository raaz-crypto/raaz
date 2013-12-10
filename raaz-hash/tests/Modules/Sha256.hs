module Modules.Sha256
       ( tests
       ) where

import Control.Applicative
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C8
import Test.QuickCheck(Arbitrary(..))

import Raaz.Test.Gadget

import Modules.Generic(allHashTests)
import Raaz.Hash.Sha256.Internal

instance Arbitrary SHA256 where
  arbitrary = SHA256 <$> arbitrary
                     <*> arbitrary
                     <*> arbitrary
                     <*> arbitrary
                     <*> arbitrary
                     <*> arbitrary
                     <*> arbitrary
                     <*> arbitrary

tests = allHashTests (undefined ::SHA256) exampleStrings

exampleStrings :: [(B.ByteString,B.ByteString)]
exampleStrings = map convertToByteString
  [ ( "abc"
    , "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" )
  , ( "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    , "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" )
  , ( "The quick brown fox jumps over the lazy dog"
    , "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592" )
  , ( "The quick brown fox jumps over the lazy cog"
    , "e4c4d8f3bf76b692de791a173e05321150f7a345b46484fe427f6acc7ecc81be" )
  , ( ""
    , "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" )
  , ( "The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog"
    , "86c55ba51d6b4aef51f4ae956077a0f661d0b876c5774fef3172c4f56092cbbd" )
  ]
 where
   convertToByteString (a,b) = (C8.pack a, C8.pack b)
