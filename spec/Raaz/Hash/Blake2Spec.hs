{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE OverloadedStrings    #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Raaz.Hash.Blake2Spec where

import           Prelude hiding (replicate)

import           Common
import qualified Common.Hash as CH
import Raaz.Primitive.Blake2.Internal

{--
hashesTo :: ByteString -> BLAKE2b -> Spec
hashesTo = CH.hashesTo

hmacsTo  :: ByteString -> HMAC BLAKE2b -> Key (HMAC BLAKE2b) -> Spec
hmacsTo  = CH.hmacsTo
--}

spec2b :: Spec
spec2b = describe "blake2b" $ do
  basicEndianSpecs (undefined :: BLAKE2b)

  ------------- Unit tests -------------------------
  "" `hashesTo`
    "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
  "abc" `hashesTo`
    "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"

  where hashesTo :: ByteString -> BLAKE2b -> Spec
        hashesTo = CH.hashesTo


spec2s :: Spec
spec2s = describe "blake2s" $ do
  basicEndianSpecs (undefined :: BLAKE2s)

  ------------- Unit tests -------------------------
  "" `hashesTo` "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"

  "abc" `hashesTo` "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"


  where hashesTo :: ByteString -> BLAKE2s -> Spec
        hashesTo = CH.hashesTo


spec :: Spec
spec =  spec2b >> spec2s



  {-
  --
  -- Some unit tests
  --
  "" `hashesTo`
    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"

  "abc" `hashesTo`
    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"

  "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu" `hashesTo`
    "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"

  "The quick brown fox jumps over the lazy dog" `hashesTo`
    "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6"

  "The quick brown fox jumps over the lazy cog" `hashesTo`
    "3eeee1d0e11733ef152a6c29503b3ae20c4f1f3cda4cb26f1bc1a41f91c7fe4ab3bd86494049e201c4bd5155f31ecb7a3c8606843c4cc8dfcab7da11c8ae5045"

  "The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog" `hashesTo`
    "e489dcc2e8867d0bbeb0a35e6b94951a11affd7041ef39fa21719eb01800c29a2c3522924443939a7848fde58fb1dbd9698fece092c0c2b412c51a47602cfd38"

  -- Some hmac specs
  hmacSpec


-}
