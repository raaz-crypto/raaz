{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE OverloadedStrings    #-}
{-# LANGUAGE ScopedTypeVariables  #-}
{-# LANGUAGE DataKinds            #-}

module Raaz.Cipher.AESSpec where

import           Common
import qualified Common.Cipher as C
import Raaz.Cipher.AES
import Raaz.Cipher.Internal

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
  where encryptsTo :: (Format fmt1, Format fmt2)
                   => fmt1 -> fmt2 -> Key (AES 128 CBC) -> Spec
        encryptsTo = C.encryptsTo aes128cbc

spec :: Spec
spec =  describe "128bit AES CBC" $ aes128cbcSpec
