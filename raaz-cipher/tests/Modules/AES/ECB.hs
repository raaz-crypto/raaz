{-# LANGUAGE OverloadedStrings #-}
module Modules.AES.ECB
       ( tests
       ) where


import Data.ByteString          ( ByteString, pack )
import Data.ByteString.Char8    ()
import Test.Framework           ( Test             )

import Raaz.Core.Primitives
import Raaz.Core.Primitives.Cipher
import Raaz.Core.Util.ByteString

import Raaz.Cipher.AES.Type
import Raaz.Cipher.AES.ECB

import Modules.AES.Defaults

-- From http://www.inconteam.com/software-development/41-encryptMode/55-aes-test-vectors
standard128Vector :: [(KEY128,ByteString,ByteString)]
standard128Vector = map (\(a,b,c) -> (fromByteString a,b,c))
  [ ( unsafeFromHex "2b7e151628aed2a6abf7158809cf4f3c"
    , unsafeFromHex "6bc1bee22e409f96e93d7e117393172a"
    , unsafeFromHex "3ad77bb40d7a3660a89ecaf32466ef97" )
  , ( unsafeFromHex "2b7e151628aed2a6abf7158809cf4f3c"
    , unsafeFromHex "ae2d8a571e03ac9c9eb76fac45af8e51"
    , unsafeFromHex "f5d3d58503b9699de785895a96fdbaaf" )
  , ( unsafeFromHex "2b7e151628aed2a6abf7158809cf4f3c"
    , unsafeFromHex "30c81c46a35ce411e5fbc1191a0a52ef"
    , unsafeFromHex "43b1cd7f598ece23881b00e3ed030688" )
  , ( unsafeFromHex "2b7e151628aed2a6abf7158809cf4f3c"
    , unsafeFromHex "f69f2445df4f9b17ad2b417be66c3710"
    , unsafeFromHex "7b0c785e27e8ad3f8223207104725dd4" )
  ]

standard192Vector :: [(KEY192,ByteString,ByteString)]
standard192Vector = map (\(a,b,c) -> (fromByteString a,b,c))
  [ ( unsafeFromHex "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
    , unsafeFromHex "6bc1bee22e409f96e93d7e117393172a"
    , unsafeFromHex "bd334f1d6e45f25ff712a214571fa5cc" )
  , ( unsafeFromHex "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
    , unsafeFromHex "ae2d8a571e03ac9c9eb76fac45af8e51"
    , unsafeFromHex "974104846d0ad3ad7734ecb3ecee4eef" )
  , ( unsafeFromHex "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
    , unsafeFromHex "30c81c46a35ce411e5fbc1191a0a52ef"
    , unsafeFromHex "ef7afd2270e2e60adce0ba2face6444e" )
  , ( unsafeFromHex "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
    , unsafeFromHex "f69f2445df4f9b17ad2b417be66c3710"
    , unsafeFromHex "9a4b41ba738d6c72fb16691603c18e0e" )
  ]

standard256Vector :: [(KEY256,ByteString,ByteString)]
standard256Vector = map (\(a,b,c) -> (fromByteString a,b,c))
  [ ( unsafeFromHex "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
    , unsafeFromHex "6bc1bee22e409f96e93d7e117393172a"
    , unsafeFromHex "f3eed1bdb5d2a03c064b5a7e3db181f8" )
  , ( unsafeFromHex "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
    , unsafeFromHex "ae2d8a571e03ac9c9eb76fac45af8e51"
    , unsafeFromHex "591ccb10d410ed26dc5ba74a31362870" )
  , ( unsafeFromHex "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
    , unsafeFromHex "30c81c46a35ce411e5fbc1191a0a52ef"
    , unsafeFromHex "b6ed21b99ca6f4f9f153e7b1beafed1d" )
  , ( unsafeFromHex "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
    , unsafeFromHex "f69f2445df4f9b17ad2b417be66c3710"
    , unsafeFromHex "23304b7a39f9f3ff067d8d8f9e24ecc7" )
  ]

ecb :: AES ECB KEY128
ecb = undefined

tests :: [Test]
tests = testsDefault ecb standard128Vector standard192Vector standard256Vector
