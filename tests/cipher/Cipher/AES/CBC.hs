{-# LANGUAGE OverloadedStrings #-}
module Cipher.AES.CBC
       ( tests
       ) where

import Data.ByteString             ( ByteString, pack )
import Data.ByteString.Char8       ( )
import Test.Framework              ( Test             )

import Raaz.Core.Primitives
import Raaz.Core.Primitives.Cipher
import Raaz.Core.Util.ByteString

import Raaz.Cipher.AES.Type
import Raaz.Cipher.AES.CBC
import Raaz.Cipher.AES.Internal

import Cipher.AES.Defaults


-- From http://www.inconteam.com/software-development/41-encryptMode/55-aes-test-vectors
standard128Vector :: [((KEY128, STATE),ByteString,ByteString)]
standard128Vector = map (\(a,b,c,d) -> ((fromByteString a,fromByteString b),c,d))
  [ ( unsafeFromHex "2b7e151628aed2a6abf7158809cf4f3c"
    , unsafeFromHex "000102030405060708090a0b0c0d0e0f"
    , unsafeFromHex "6bc1bee22e409f96e93d7e117393172a"
    , unsafeFromHex "7649abac8119b246cee98e9b12e9197d" )
  , ( unsafeFromHex "2b7e151628aed2a6abf7158809cf4f3c"
    , unsafeFromHex "7649abac8119b246cee98e9b12e9197d"
    , unsafeFromHex "ae2d8a571e03ac9c9eb76fac45af8e51"
    , unsafeFromHex "5086cb9b507219ee95db113a917678b2" )
  , ( unsafeFromHex "2b7e151628aed2a6abf7158809cf4f3c"
    , unsafeFromHex "5086cb9b507219ee95db113a917678b2"
    , unsafeFromHex "30c81c46a35ce411e5fbc1191a0a52ef"
    , unsafeFromHex "73bed6b8e3c1743b7116e69e22229516" )
  , ( unsafeFromHex "2b7e151628aed2a6abf7158809cf4f3c"
    , unsafeFromHex "73bed6b8e3c1743b7116e69e22229516"
    , unsafeFromHex "f69f2445df4f9b17ad2b417be66c3710"
    , unsafeFromHex "3ff1caa1681fac09120eca307586e1a7" )

  ]

standard192Vector :: [((KEY192, STATE),ByteString,ByteString)]
standard192Vector = map (\(a,b,c,d) -> ((fromByteString a,fromByteString b),c,d))
  [ ( unsafeFromHex "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
    , unsafeFromHex "000102030405060708090a0b0c0d0e0f"
    , unsafeFromHex "6bc1bee22e409f96e93d7e117393172a"
    , unsafeFromHex "4f021db243bc633d7178183a9fa071e8" )
  , ( unsafeFromHex "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
    , unsafeFromHex "4f021db243bc633d7178183a9fa071e8"
    , unsafeFromHex "ae2d8a571e03ac9c9eb76fac45af8e51"
    , unsafeFromHex "b4d9ada9ad7dedf4e5e738763f69145a" )
  , ( unsafeFromHex "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
    , unsafeFromHex "b4d9ada9ad7dedf4e5e738763f69145a"
    , unsafeFromHex "30c81c46a35ce411e5fbc1191a0a52ef"
    , unsafeFromHex "571b242012fb7ae07fa9baac3df102e0" )
  , ( unsafeFromHex "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
    , unsafeFromHex "571b242012fb7ae07fa9baac3df102e0"
    , unsafeFromHex "f69f2445df4f9b17ad2b417be66c3710"
    , unsafeFromHex "08b0e27988598881d920a9e64f5615cd" )
  ]

standard256Vector :: [((KEY256, STATE),ByteString,ByteString)]
standard256Vector = map (\(a,b,c,d) -> ((fromByteString a,fromByteString b),c,d))
  [ ( unsafeFromHex "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
    , unsafeFromHex "000102030405060708090a0b0c0d0e0f"
    , unsafeFromHex "6bc1bee22e409f96e93d7e117393172a"
    , unsafeFromHex "f58c4c04d6e5f1ba779eabfb5f7bfbd6" )
  , ( unsafeFromHex "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
    , unsafeFromHex "f58c4c04d6e5f1ba779eabfb5f7bfbd6"
    , unsafeFromHex "ae2d8a571e03ac9c9eb76fac45af8e51"
    , unsafeFromHex "9cfc4e967edb808d679f777bc6702c7d" )
  , ( unsafeFromHex "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
    , unsafeFromHex "9cfc4e967edb808d679f777bc6702c7d"
    , unsafeFromHex "30c81c46a35ce411e5fbc1191a0a52ef"
    , unsafeFromHex "39f23369a9d9bacfa530e26304231461" )
  , ( unsafeFromHex "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
    , unsafeFromHex "39f23369a9d9bacfa530e26304231461"
    , unsafeFromHex "f69f2445df4f9b17ad2b417be66c3710"
    , unsafeFromHex "b2eb05e2c39be9fcda6c19078c6a9d1b" )
  ]

cbc :: AES CBC KEY128
cbc = undefined

tests :: [Test]
tests = testsDefault cbc standard128Vector standard192Vector standard256Vector
