{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE NoMonomorphismRestriction #-}
module Modules.AES.Defaults (benchmarksDefault, benchmarksTinyDefault) where

import           Criterion.Main
import           Data.ByteString          (ByteString,pack)
import qualified Data.ByteString          as BS
import           Data.Typeable

import           Raaz.Primitives
import           Raaz.Benchmark.Gadget
import           Raaz.Primitives.Cipher
import           Raaz.Serialize

import           Raaz.Cipher.AES.Internal
import           Raaz.Cipher.AES.ECB

import           Modules.Defaults         (nBlocks)

testKey128 :: CryptoSerialize a => a
testKey128 =  fromByteString $
                pack [0x2b,0x7e,0x15,0x16
                     ,0x28,0xae,0xd2,0xa6
                     ,0xab,0xf7,0x15,0x88
                     ,0x09,0xcf,0x4f,0x3c
                     ,0x00,0x01,0x02,0x03
                     ,0x04,0x05,0x06,0x07
                     ,0x08,0x09,0x0A,0x0B
                     ,0x0C,0x0D,0x0E,0x0F]


testKey192 :: CryptoSerialize a => a
testKey192 =  fromByteString $
                pack [0x8e,0x73,0xb0,0xf7
                     ,0xda,0x0e,0x64,0x52
                     ,0xc8,0x10,0xf3,0x2b
                     ,0x80,0x90,0x79,0xe5
                     ,0x62,0xf8,0xea,0xd2
                     ,0x52,0x2c,0x6b,0x7b
                     ,0x00,0x01,0x02,0x03
                     ,0x04,0x05,0x06,0x07
                     ,0x08,0x09,0x0A,0x0B
                     ,0x0C,0x0D,0x0E,0x0F]


testKey256 :: CryptoSerialize a => a
testKey256 =  fromByteString $
                pack [0x60,0x3d,0xeb,0x10
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

benchCipher g iv = benchGadgetWith g iv (nBlocks g)

benchmarksTinyDefault = take 2 . benchmarksDefault

benchmarksDefault p = [ benchCipher (toH $ prim128 p) (encryptCxt testKey128)
                      , benchCipher (toC $ prim128 p) (encryptCxt testKey128)
                      , benchCipher (toH $ prim192 p) (encryptCxt testKey192)
                      , benchCipher (toC $ prim192 p) (encryptCxt testKey192)
                      , benchCipher (toH $ prim256 p) (encryptCxt testKey256)
                      , benchCipher (toC $ prim256 p) (encryptCxt testKey256)
                      , benchCipher (toH $ inv $ prim128 p) (decryptCxt testKey128)
                      , benchCipher (toC $ inv $ prim128 p) (decryptCxt testKey128)
                      , benchCipher (toH $ inv $ prim192 p) (decryptCxt testKey192)
                      , benchCipher (toC $ inv $ prim192 p) (decryptCxt testKey192)
                      , benchCipher (toH $ inv $ prim256 p) (decryptCxt testKey256)
                      , benchCipher (toC $ inv $ prim256 p) (decryptCxt testKey256)
                      ]
  where
    prim128 :: Cipher name k d -> Cipher name KEY128 EncryptMode
    prim128 _ = undefined
    prim192 :: Cipher name k d-> Cipher name KEY192 EncryptMode
    prim192 _ = undefined
    prim256 :: Cipher name k d-> Cipher name KEY256 EncryptMode
    prim256 _ = undefined
    inv :: Cipher name k EncryptMode -> Cipher name k DecryptMode
    inv = undefined
    toH :: p -> HGadget p
    toH _ = undefined
    toC :: p -> CGadget p
    toC _ = undefined
