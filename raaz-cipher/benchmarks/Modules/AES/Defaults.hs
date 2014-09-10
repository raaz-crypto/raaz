{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE NoMonomorphismRestriction #-}
{-# LANGUAGE OverloadedStrings #-}
module Modules.AES.Defaults ( benchmarksDefault
                            , benchmarksTinyDefault
                            , testKey128, testKey192, testKey256
                            ) where

import           Criterion.Main
import           Control.Applicative
import           Data.ByteString             (ByteString,pack)
import qualified Data.ByteString             as BS
import           Data.Typeable

import           Raaz.Core.Primitives
import           Raaz.Benchmark.Gadget
import           Raaz.Core.Primitives.Cipher
import           Raaz.Core.Util.ByteString

import           Raaz.Cipher.AES.Internal
import           Raaz.Cipher.AES.ECB

import           Modules.Defaults

testKey128 :: (KEY128, STATE)
testKey128 =  ( fromByteString $ unsafeFromHex "2b7e151628aed2a6abf7158809cf4f3c"
              , fromByteString $ unsafeFromHex "000102030405060708090a0b0c0d0e0f"
              )

testKey192 :: (KEY192, STATE)
testKey192 =  ( fromByteString $ unsafeFromHex "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
              , fromByteString $ unsafeFromHex "000102030405060708090a0b0c0d0e0f"

              )


testKey256 :: (KEY256, STATE)
testKey256 =  ( fromByteString $ unsafeFromHex "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
              , fromByteString $ unsafeFromHex "000102030405060708090a0b0c0d0e0f"

              )

benchmarksTinyDefault p s128 s192 s256 = take 2 <$> benchmarksDefault p s128 s192 s256

benchmarksDefault p s128 s192 s256 = sequence
                      [ benchCipher (toH $ prim128 p) s128
                      , benchCipher (toC $ prim128 p) s128
                      , benchCipher (toH $ prim192 p) s192
                      , benchCipher (toC $ prim192 p) s192
                      , benchCipher (toH $ prim256 p) s256
                      , benchCipher (toC $ prim256 p) s256
                      , benchCipher (inverse $ toH $ prim128 p) s128
                      , benchCipher (inverse $ toC $ prim128 p) s128
                      , benchCipher (inverse $ toH $ prim192 p) s192
                      , benchCipher (inverse $ toC $ prim192 p) s192
                      , benchCipher (inverse $ toH $ prim256 p) s256
                      , benchCipher (inverse $ toC $ prim256 p) s256
                      ]
  where
    first (a,_,_) = a
    toH :: AES mode k -> HGadget (AESOp mode k EncryptMode)
    toH _ = undefined
    toC :: AES mode k -> CGadget (AESOp mode k EncryptMode)
    toC _ = undefined
    prim128 :: AES mode key -> AES mode KEY128
    prim128 = undefined
    prim192 :: AES mode key -> AES mode KEY192
    prim192 = undefined
    prim256 :: AES mode key -> AES mode KEY256
    prim256 = undefined
