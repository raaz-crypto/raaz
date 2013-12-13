{-# LANGUAGE FlexibleContexts #-}
module Modules.Defaults (benchmarksDefault, benchmarksTinyDefault) where

import Criterion.Main
import Data.ByteString (pack)

import Raaz.Primitives
import Raaz.Benchmark.Gadget
import Raaz.Primitives.Cipher

import Raaz.Cipher.AES.Internal
import Raaz.Cipher.AES.ECB

testKey128 :: (Initializable g) => IV g
testKey128 =  getIV $ pack [0x2b,0x7e,0x15,0x16
                           ,0x28,0xae,0xd2,0xa6
                           ,0xab,0xf7,0x15,0x88
                           ,0x09,0xcf,0x4f,0x3c
                           ,0x00,0x01,0x02,0x03
                           ,0x04,0x05,0x06,0x07
                           ,0x08,0x09,0x0A,0x0B
                           ,0x0C,0x0D,0x0E,0x0F]

testKey192 :: (Initializable g) => IV g
testKey192 =  getIV $ pack [0x8e,0x73,0xb0,0xf7
                           ,0xda,0x0e,0x64,0x52
                           ,0xc8,0x10,0xf3,0x2b
                           ,0x80,0x90,0x79,0xe5
                           ,0x62,0xf8,0xea,0xd2
                           ,0x52,0x2c,0x6b,0x7b
                           ,0x00,0x01,0x02,0x03
                           ,0x04,0x05,0x06,0x07
                           ,0x08,0x09,0x0A,0x0B
                           ,0x0C,0x0D,0x0E,0x0F]


testKey256 :: (Initializable g) => IV g
testKey256 =  getIV $ pack [0x60,0x3d,0xeb,0x10
                           ,0x15,0xca,0x71,0xbe
                           ,0x2b,0x73,0xae,0xf0
                           ,0x85,0x7d,0x77,0x81
                           ,0x1f,0x35,0x2c,0x07
                           ,0x3b,0x61,0x08,0xd7
                           ,0x2d,0x98,0x10,0xa3
                           ,0x09,0x14,0xdf,0xf4
                           ,0x00,0x01,0x02,0x03
                           ,0x04,0x05,0x06,0x07
                           ,0x08,0x09,0x0A,0x0B
                           ,0x0C,0x0D,0x0E,0x0F]

nBlocks :: (Gadget g) => g -> BLOCKS (PrimitiveOf g)
nBlocks g = 100 * recommendedBlocks g

benchmarksTinyDefault mode = [ benchCipher (r128 mode (undefined :: Encryption)) "AES128 ECB Reference Encryption" testKey128
                             , benchCipher (c128 mode (undefined :: Encryption)) "AES128 ECB CPortable Encryption" testKey128 ]
  where
    benchCipher g gname iv = benchGadgetWith g gname iv (nBlocks g)
    r128 :: (Gadget (Ref128 mode stage)) => mode -> stage -> Ref128 mode stage
    r128 = undefined
    c128 :: (Gadget (CPortable128 mode stage)) => mode -> stage -> CPortable128 mode stage
    c128 = undefined

benchmarksDefault mode = [ benchCipher (r128 mode encr) "AES128 ECB Reference Encryption" testKey128
                         , benchCipher (c128 mode encr) "AES128 ECB CPortable Encryption" testKey128
                         , benchCipher (r128 mode decr) "AES128 ECB Reference Decryption" testKey128
                         , benchCipher (c128 mode decr) "AES128 ECB CPortable Decryption" testKey128
                         , benchCipher (r192 mode encr) "AES192 ECB Reference Encryption" testKey192
                         , benchCipher (c192 mode encr) "AES192 ECB CPortable Encryption" testKey192
                         , benchCipher (r192 mode decr) "AES192 ECB Reference Decryption" testKey192
                         , benchCipher (c192 mode decr) "AES192 ECB CPortable Decryption" testKey192
                         , benchCipher (r256 mode encr) "AES256 ECB Reference Encryption" testKey256
                         , benchCipher (c256 mode encr) "AES256 ECB CPortable Encryption" testKey256
                         , benchCipher (r256 mode decr) "AES256 ECB Reference Decryption" testKey256
                         , benchCipher (c256 mode decr) "AES256 ECB CPortable Decryption" testKey256 ]
  where
    encr :: Encryption
    encr = undefined
    decr :: Decryption
    decr = undefined
    benchCipher g gname iv = benchGadgetWith g gname iv (nBlocks g)
    r128 :: (Gadget (Ref128 mode stage)) => mode -> stage -> Ref128 mode stage
    r128 = undefined
    r192 :: (Gadget (Ref192 mode stage)) => mode -> stage -> Ref192 mode stage
    r192 = undefined
    r256 :: (Gadget (Ref256 mode stage)) => mode -> stage -> Ref256 mode stage
    r256 = undefined
    c128 :: (Gadget (CPortable128 mode stage)) => mode -> stage -> CPortable128 mode stage
    c128 = undefined
    c192 :: (Gadget (CPortable192 mode stage)) => mode -> stage -> CPortable192 mode stage
    c192 = undefined
    c256 :: (Gadget (CPortable256 mode stage)) => mode -> stage -> CPortable256 mode stage
    c256 = undefined
