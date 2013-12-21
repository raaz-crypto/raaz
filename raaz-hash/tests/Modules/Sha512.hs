module Modules.Sha512
       ( tests
       ) where

import           Control.Applicative
import qualified Data.ByteString       as B
import qualified Data.ByteString.Char8 as C8
import           Data.Default
import           Test.QuickCheck       (Arbitrary(..))

import Raaz.Test.Gadget

import Modules.Generic(allHashTests)
import Raaz.Hash.Sha512.Internal

instance Arbitrary SHA512 where
  arbitrary = SHA512 <$> arbitrary
                     <*> arbitrary
                     <*> arbitrary
                     <*> arbitrary
                     <*> arbitrary
                     <*> arbitrary
                     <*> arbitrary
                     <*> arbitrary


tests = allHashTests (undefined ::SHA512) exampleStrings ++ [testCPortable]

testCPortable = testGadget g ref def "CPortable vs Reference"
  where
    g :: CPortable
    g = undefined
    ref :: Ref
    ref = undefined

exampleStrings :: [(B.ByteString,B.ByteString)]
exampleStrings = map convertToByteString
  [ ( "abc"
    , "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" )
  , ( "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
    , "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909" )
  , ( "The quick brown fox jumps over the lazy dog"
    , "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6" )
  , ( "The quick brown fox jumps over the lazy cog"
    , "3eeee1d0e11733ef152a6c29503b3ae20c4f1f3cda4cb26f1bc1a41f91c7fe4ab3bd86494049e201c4bd5155f31ecb7a3c8606843c4cc8dfcab7da11c8ae5045" )
  , ( ""
    , "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e" )
  , ( "The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog"
    , "e489dcc2e8867d0bbeb0a35e6b94951a11affd7041ef39fa21719eb01800c29a2c3522924443939a7848fde58fb1dbd9698fece092c0c2b412c51a47602cfd38" )
  ]
 where
   convertToByteString (a,b) = (C8.pack a, C8.pack b)
