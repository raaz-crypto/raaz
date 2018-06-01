
{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE OverloadedStrings    #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Raaz.Hash.Sha256Spec where

import           Prelude hiding (replicate)

import           Common
import qualified Common.Hash as CH

hashesTo :: ByteString -> SHA256 -> Spec
hashesTo = CH.hashesTo

spec :: Spec
spec =  do

  basicEndianSpecs (undefined :: SHA256)

  --
  -- Some unit tests
  --
  ""    `hashesTo` "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

  "abc" `hashesTo` "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

  "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" `hashesTo`
    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"

  "The quick brown fox jumps over the lazy dog" `hashesTo`
    "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"

  "The quick brown fox jumps over the lazy cog" `hashesTo`
    "e4c4d8f3bf76b692de791a173e05321150f7a345b46484fe427f6acc7ecc81be"

  "The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog" `hashesTo`
    "86c55ba51d6b4aef51f4ae956077a0f661d0b876c5774fef3172c4f56092cbbd"
