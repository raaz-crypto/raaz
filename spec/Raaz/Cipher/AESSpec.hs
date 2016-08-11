{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE OverloadedStrings    #-}
{-# LANGUAGE ScopedTypeVariables  #-}
{-# LANGUAGE DataKinds            #-}

module Raaz.Cipher.AESSpec where

import           Common
import qualified Common.Cipher as C
import Raaz.Cipher.AES
import Raaz.Cipher.Internal

spec :: Spec
spec =  do describe "128bit CBC" $ aes128cbcSpec
           describe "192bit CBC" $ aes192cbcSpec
           describe "256bit CBC" $ aes256cbcSpec

----------------- AES 128 CBC ------------------------------

aes128cbcSpec :: Spec
aes128cbcSpec = do
  C.encryptVsDecrypt aes128cbc

  with ( "06a9214036b8a15b512e03d534120006"
       , "3dafba429d9eb430b422da802c9fac41")
    $ ("Single block msg" :: ByteString)
    `encryptsTo` ("e353779c1079aeb82708942dbe77181a" :: Base16)

  with ( "c286696d887c9aa0611bbb3e2025a45a"
       , "562e17996d093d28ddb3ba695a2e6f58")$
       ( "000102030405060708090a0b0c0d0e0f" <>
         "101112131415161718191a1b1c1d1e1f" :: Base16)
       `encryptsTo`
       ( "d296cd94c2cccf8a3a863028b5e1dc0a" <>
         "7586602d253cfff91b8266bea6d61ab1" ::Base16)


  with ( "6c3ea0477630ce21a2ce334aa746c2cd"
       , "c782dc4c098c66cbd9cd27d825682c81" )$
       ( "This is a 48-byte message (exactly 3 AES blocks)" :: ByteString)
       `encryptsTo`
       ( "d0a02b3836451753d493665d33f0e886" <>
         "2dea54cdb293abc7506939276772f8d5" <>
         "021c19216bad525c8579695d83ba2684" :: Base16
       )

  with ( "56e47a38c5598974bc46903dba290349"
       , "8ce82eefbea0da3c44699ed7db51b7d9" ) $
       ( "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf" <>
         "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf" <>
         "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf" <>
         "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf" :: Base16 )
       `encryptsTo`
       ( "c30e32ffedc0774e6aff6af0869f71aa" <>
         "0f3af07a9a31a9c684db207eb0ef8e4e" <>
         "35907aa632c3ffdf868bb7b29d3d46ad" <>
         "83ce9f9a102ee99d49a53e87f4c3da55" :: Base16
       )

  with ( "2b7e151628aed2a6abf7158809cf4f3c"
       , "000102030405060708090a0b0c0d0e0f") $
       ( "6bc1bee22e409f96e93d7e117393172a" :: Base16 )
       `encryptsTo`
       ( "7649abac8119b246cee98e9b12e9197d" :: Base16 )

  with ( "2b7e151628aed2a6abf7158809cf4f3c"
       , "7649abac8119b246cee98e9b12e9197d") $
       ( "ae2d8a571e03ac9c9eb76fac45af8e51" :: Base16 )
       `encryptsTo`
       ( "5086cb9b507219ee95db113a917678b2" :: Base16 )

  with ( "2b7e151628aed2a6abf7158809cf4f3c"
       , "5086cb9b507219ee95db113a917678b2") $
       ( "30c81c46a35ce411e5fbc1191a0a52ef" :: Base16 )
       `encryptsTo`
       ( "73bed6b8e3c1743b7116e69e22229516" :: Base16 )

  with ( "2b7e151628aed2a6abf7158809cf4f3c"
       , "73bed6b8e3c1743b7116e69e22229516") $
       ( "f69f2445df4f9b17ad2b417be66c3710" :: Base16 )
       `encryptsTo`
       ( "3ff1caa1681fac09120eca307586e1a7"  :: Base16 )

  where encryptsTo :: (Format fmt1, Format fmt2)
                   => fmt1 -> fmt2 -> Key (AES 128 'CBC) -> Spec
        encryptsTo = C.encryptsTo aes128cbc

------------------ AES 192 CBC ---------------------------

aes192cbcSpec :: Spec
aes192cbcSpec = do
  C.encryptVsDecrypt aes192cbc

  with ( "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
       , "000102030405060708090a0b0c0d0e0f") $
       ( "6bc1bee22e409f96e93d7e117393172a" :: Base16 )
       `encryptsTo`
       ( "4f021db243bc633d7178183a9fa071e8" :: Base16 )

  with ( "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
       , "4f021db243bc633d7178183a9fa071e8" ) $
       ( "ae2d8a571e03ac9c9eb76fac45af8e51" :: Base16 )
       `encryptsTo`
       ( "b4d9ada9ad7dedf4e5e738763f69145a" :: Base16 )

  with ( "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
       , "b4d9ada9ad7dedf4e5e738763f69145a" ) $
       ( "30c81c46a35ce411e5fbc1191a0a52ef" :: Base16 )
       `encryptsTo`
       ( "571b242012fb7ae07fa9baac3df102e0" :: Base16 )

  with ( "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
       , "571b242012fb7ae07fa9baac3df102e0") $
       ( "f69f2445df4f9b17ad2b417be66c3710" :: Base16 )
       `encryptsTo`
       ( "08b0e27988598881d920a9e64f5615cd" :: Base16 )

  where encryptsTo :: (Format fmt1, Format fmt2)
                   => fmt1 -> fmt2 -> Key (AES 192 'CBC) -> Spec
        encryptsTo = C.encryptsTo aes192cbc

------------------ AES 192 CBC ---------------------------

aes256cbcSpec :: Spec
aes256cbcSpec = do
  C.encryptVsDecrypt aes256cbc

  with ( "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
       , "000102030405060708090a0b0c0d0e0f" ) $
       ( "6bc1bee22e409f96e93d7e117393172a" :: Base16)
       `encryptsTo`
       ( "f58c4c04d6e5f1ba779eabfb5f7bfbd6" :: Base16)

  with ( "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
       , "f58c4c04d6e5f1ba779eabfb5f7bfbd6" ) $
       ( "ae2d8a571e03ac9c9eb76fac45af8e51" :: Base16 )
       `encryptsTo`
       ( "9cfc4e967edb808d679f777bc6702c7d" :: Base16 )

  with ( "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
       , "9cfc4e967edb808d679f777bc6702c7d") $
       ( "30c81c46a35ce411e5fbc1191a0a52ef" :: Base16 )
       `encryptsTo`
       ( "39f23369a9d9bacfa530e26304231461" :: Base16 )

  with ( "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
       , "39f23369a9d9bacfa530e26304231461" ) $
       ( "f69f2445df4f9b17ad2b417be66c3710" :: Base16 )
       `encryptsTo`
       ( "b2eb05e2c39be9fcda6c19078c6a9d1b" :: Base16 )

  where encryptsTo :: (Format fmt1, Format fmt2)
                   => fmt1 -> fmt2 -> Key (AES 256 'CBC) -> Spec
        encryptsTo = C.encryptsTo aes256cbc
