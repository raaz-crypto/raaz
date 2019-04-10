{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE OverloadedStrings    #-}
{-# LANGUAGE ScopedTypeVariables  #-}
{-# LANGUAGE DataKinds            #-}

module Raaz.Cipher.ChaCha20Spec where

import           Tests.Core
import qualified Tests.Cipher as C

keyPrint :: Key ChaCha20 -> String
keyPrint (k,i,c) = "("
                   ++ shortened (show k) ++ ", "
                   ++ shortened (show i) ++ ","
                   ++ show (fromEnum c) ++ ")"

writeZeros :: BYTES Int -> WriteIO
writeZeros = writeBytes 0

zeroIV :: IV
zeroIV = unsafeDecode $ toByteString $ writeZeros 12

zeroKey :: KEY
zeroKey = unsafeDecode $ toByteString $ writeZeros 32

oneKey :: KEY
oneKey = unsafeDecode $ toByteString $ one <> writeZeros 31
  where one = writeBytes 1 (1 :: BYTES Int)

zeroBlocks :: Int -> ByteString
zeroBlocks = C.zeros . (toEnum :: Int -> BLOCKS ChaCha20)

transformsTo :: (Format fmt1, Format fmt2) => fmt1 -> fmt2 -> Key ChaCha20 -> Spec
transformsTo = C.transformsTo keyPrint

keyStreamIs  :: Format fmt => fmt -> Key ChaCha20 -> Spec
keyStreamIs  = C.keyStreamIs keyPrint

spec :: Spec
spec =describe "ChaCha20" $ do
  -- Unit test from RFC7539
  with ("00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f"
       , "00:00:00:00 00:00:00:4a 00:00:00:00"
       , 1
       ) $ ("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it." :: ByteString)
    `transformsTo` ( "6e 2e 35 9a 25 68 f9 80 41 ba 07 28 dd 0d 69 81" <>
                     "e9 7e 7a ec 1d 43 60 c2 0a 27 af cc fd 9f ae 0b" <>
                     "f9 1b 65 c5 52 47 33 ab 8f 59 3d ab cd 62 b3 57" <>
                     "16 39 d6 24 e6 51 52 ab 8f 53 0c 35 9f 08 61 d8" <>
                     "07 ca 0d bf 50 0d 6a 61 56 a3 8e 08 8a 22 b6 5e" <>
                     "52 bc 51 4d 16 cc f8 06 81 8c e9 1a b7 79 37 36" <>
                     "5a f9 0b bf 74 a3 5b e6 b4 0b 8e ed f2 78 5e 42" <>
                     "87 4d" :: Base16)

  with (zeroKey, zeroIV, 0) $ zeroBlocks 2
    `transformsTo` ( "76 b8 e0 ad a0 f1 3d 90 40 5d 6a e5 53 86 bd 28" <>
                     "bd d2 19 b8 a0 8d ed 1a a8 36 ef cc 8b 77 0d c7" <>
                     "da 41 59 7c 51 57 48 8d 77 24 e0 3f b8 d8 4a 37" <>
                     "6a 43 b8 f4 15 18 a1 1c c3 87 b6 69 b2 ee 65 86" <>
                     "9f 07 e7 be 55 51 38 7a 98 ba 97 7c 73 2d 08 0d" <>
                     "cb 0f 29 a0 48 e3 65 69 12 c6 53 3e 32 ee 7a ed" <>
                     "29 b7 21 76 9c e6 4e 43 d5 71 33 b0 74 d8 39 d5" <>
                     "31 ed 1f 28 51 0a fb 45 ac e1 0a 1f 4b 79 4d 6f" :: Base16)


  with (oneKey, zeroIV, 0) $ zeroBlocks 2
    `transformsTo` ( "c5 d3 0a 7c e1 ec 11 93 78 c8 4f 48 7d 77 5a 85" <>
                     "42 f1 3e ce 23 8a 94 55 e8 22 9e 88 8d e8 5b bd" <>
                     "29 eb 63 d0 a1 7a 5b 99 9b 52 da 22 be 40 23 eb" <>
                     "07 62 0a 54 f6 fa 6a d8 73 7b 71 eb 04 64 da c0" <>
                     "10 f6 56 e6 d1 fd 55 05 3e 50 c4 87 5c 99 30 a3" <>
                     "3f 6d 02 63 bd 14 df d6 ab 8c 70 52 1c 19 33 8b" <>
                     "23 08 b9 5c f8 d0 bb 7d 20 2d 21 02 78 0e a3 52" <>
                     "8f 1c b4 85 60 f7 6b 20 f3 82 b9 42 50 0f ce ac" :: Base16)


  with (zeroKey, zeroIV, 0) $ keyStreamIs ( "76 b8 e0 ad a0 f1 3d 90 40 5d 6a e5 53 86 bd 28" <>
                                            "bd d2 19 b8 a0 8d ed 1a a8 36 ef cc 8b 77 0d c7" <>
                                            "da 41 59 7c 51 57 48 8d 77 24 e0 3f b8 d8 4a 37" <>
                                            "6a 43 b8 f4 15 18 a1 1c c3 87 b6 69 b2 ee 65 86" :: Base16)

  with (zeroKey, zeroIV, 1) $ keyStreamIs ( "9f 07 e7 be 55 51 38 7a 98 ba 97 7c 73 2d 08 0d" <>
                                            "cb 0f 29 a0 48 e3 65 69 12 c6 53 3e 32 ee 7a ed" <>
                                            "29 b7 21 76 9c e6 4e 43 d5 71 33 b0 74 d8 39 d5" <>
                                            "31 ed 1f 28 51 0a fb 45 ac e1 0a 1f 4b 79 4d 6f" :: Base16)


  with (oneKey, zeroIV, 0)  $ keyStreamIs ( "c5 d3 0a 7c e1 ec 11 93 78 c8 4f 48 7d 77 5a 85" <>
                                            "42 f1 3e ce 23 8a 94 55 e8 22 9e 88 8d e8 5b bd" <>
                                            "29 eb 63 d0 a1 7a 5b 99 9b 52 da 22 be 40 23 eb" <>
                                            "07 62 0a 54 f6 fa 6a d8 73 7b 71 eb 04 64 da c0" :: Base16)

  with (oneKey, zeroIV, 1) $ keyStreamIs  ( "10 f6 56 e6 d1 fd 55 05 3e 50 c4 87 5c 99 30 a3" <>
                                            "3f 6d 02 63 bd 14 df d6 ab 8c 70 52 1c 19 33 8b" <>
                                            "23 08 b9 5c f8 d0 bb 7d 20 2d 21 02 78 0e a3 52" <>
                                            "8f 1c b4 85 60 f7 6b 20 f3 82 b9 42 50 0f ce ac" :: Base16)
