{-# LANGUAGE OverloadedStrings #-}
module Modules.Sha256
       ( tests
       ) where

import           Control.Applicative
import qualified Data.ByteString       as B
import qualified Data.ByteString.Char8 as C8
import qualified Data.Vector.Unboxed   as VU
import           Data.String
import           Test.QuickCheck       ( Arbitrary(..) )
import           Test.QuickCheck.Arbitrary

import Raaz.Core.Memory
import Raaz.Core.Test.Gadget
import Raaz.Core.Primitives.HMAC

import Modules.Generic
import Raaz.Hash.Sha256.Internal

instance Arbitrary SHA256 where
  arbitrary = SHA256 . VU.fromList <$> vector 8

tests = allHashTests (undefined :: SHA256) (undefined :: (MemoryCell SHA256)) exampleStrings
     ++ allHMACTests (undefined :: SHA256) exampleHMAC

exampleStrings :: [(B.ByteString,B.ByteString)]
exampleStrings =
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

exampleHMAC :: [ (HMACKey SHA256 , B.ByteString, B.ByteString) ]
exampleHMAC =
  [ ( fromString $ replicate 20 '\x0b'
    , "Hi There"
    , "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    )
  , ( "Jefe"
    , "what do ya want for nothing?"
    , "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    )
  , ( fromString $ replicate 20 '\xaa'
    , B.replicate 50 0xdd
    , "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
    )
  , ( fromString $ replicate 131 '\xaa'
    , "Test Using Larger Than Block-Size Key - Hash Key First"
    , "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
    )
  , ( fromString $ replicate 131 '\xaa'
    , "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."
    , "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"
    )
  ]
