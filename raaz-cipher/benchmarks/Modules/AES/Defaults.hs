{-# LANGUAGE FlexibleContexts #-}
module Modules.AES.Defaults (benchmarksDefault, benchmarksTinyDefault) where

import           Criterion.Main
import           Data.ByteString          (ByteString,pack)
import qualified Data.ByteString          as BS
import           Data.Typeable

import           Raaz.Primitives
import           Raaz.Benchmark.Gadget
import           Raaz.Primitives.Cipher

import           Raaz.Cipher.AES.Internal
import           Raaz.Cipher.AES.ECB

import           Modules.Defaults         (nBlocks)

genCxt :: Initializable p => ByteString -> Cxt p
genCxt bs = generateCxt undefined bs
  where
    generateCxt :: Initializable p => p -> ByteString -> Cxt p
    generateCxt p = getCxt . BS.take (fromIntegral $ cxtSize p)

testKey128 :: Initializable g => Cxt g
testKey128 =  genCxt $ pack [0x2b,0x7e,0x15,0x16
                            ,0x28,0xae,0xd2,0xa6
                            ,0xab,0xf7,0x15,0x88
                            ,0x09,0xcf,0x4f,0x3c
                            ,0x00,0x01,0x02,0x03
                            ,0x04,0x05,0x06,0x07
                            ,0x08,0x09,0x0A,0x0B
                            ,0x0C,0x0D,0x0E,0x0F]


testKey192 :: Initializable g => Cxt g
testKey192 =  genCxt $ pack [0x8e,0x73,0xb0,0xf7
                            ,0xda,0x0e,0x64,0x52
                            ,0xc8,0x10,0xf3,0x2b
                            ,0x80,0x90,0x79,0xe5
                            ,0x62,0xf8,0xea,0xd2
                            ,0x52,0x2c,0x6b,0x7b
                            ,0x00,0x01,0x02,0x03
                            ,0x04,0x05,0x06,0x07
                            ,0x08,0x09,0x0A,0x0B
                            ,0x0C,0x0D,0x0E,0x0F]


testKey256 :: Initializable g => Cxt g
testKey256 =  genCxt $ pack [0x60,0x3d,0xeb,0x10
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

benchCipher g gname iv = benchGadgetWith g gname iv (nBlocks g)

benchmarksTinyDefault m = [ benchCipher (pr128 m) ("AES128 " ++ mode ++ " Reference Encryption") testKey128
                          , benchCipher (pc128 m) ("AES128 " ++ mode ++ " CPortable Encryption") testKey128 ]
  where
    pr128 :: Gadget (HGadget (Cipher (AES m) KEY128 Encryption)) => m -> HGadget (Cipher (AES m) KEY128 Encryption)
    pr128 = undefined
    pc128 :: Gadget (CGadget (Cipher (AES m) KEY128 Encryption)) => m -> CGadget (Cipher (AES m) KEY128 Encryption)
    pc128 = undefined
    mode = show $ typeOf m

benchmarksDefault m = [ benchCipher (pr128 m encr) ("AES128 " ++ mode ++ " Reference Encryption") testKey128
                      , benchCipher (pc128 m encr) ("AES128 " ++ mode ++ " CPortable Encryption") testKey128
                      , benchCipher (pr128 m decr) ("AES128 " ++ mode ++ " Reference Decryption") testKey128
                      , benchCipher (pc128 m decr) ("AES128 " ++ mode ++ " CPortable Decryption") testKey128
                      , benchCipher (pr192 m encr) ("AES192 " ++ mode ++ " Reference Encryption") testKey192
                      , benchCipher (pc192 m encr) ("AES192 " ++ mode ++ " CPortable Encryption") testKey192
                      , benchCipher (pr192 m decr) ("AES192 " ++ mode ++ " Reference Decryption") testKey192
                      , benchCipher (pc192 m decr) ("AES192 " ++ mode ++ " CPortable Decryption") testKey192
                      , benchCipher (pr256 m encr) ("AES256 " ++ mode ++ " Reference Encryption") testKey256
                      , benchCipher (pc256 m encr) ("AES256 " ++ mode ++ " CPortable Encryption") testKey256
                      , benchCipher (pr256 m decr) ("AES256 " ++ mode ++ " Reference Decryption") testKey256
                      , benchCipher (pc256 m decr) ("AES256 " ++ mode ++ " CPortable Decryption") testKey256 ]
  where
    encr :: Encryption
    encr = undefined
    decr :: Decryption
    decr = undefined
    pr128 :: Gadget (HGadget (Cipher (AES m) KEY128 stage)) => m -> stage -> HGadget (Cipher (AES m) KEY128 stage)
    pr128 = undefined
    pr192 :: Gadget (HGadget (Cipher (AES m) KEY192 stage)) => m -> stage -> HGadget (Cipher (AES m) KEY192 stage)
    pr192 = undefined
    pr256 :: Gadget (HGadget (Cipher (AES m) KEY256 stage)) => m -> stage -> HGadget (Cipher (AES m) KEY256 stage)
    pr256 = undefined
    pc128 :: Gadget (CGadget (Cipher (AES m) KEY128 stage)) => m -> stage -> CGadget (Cipher (AES m) KEY128 stage)
    pc128 = undefined
    pc192 :: Gadget (CGadget (Cipher (AES m) KEY192 stage)) => m -> stage -> CGadget (Cipher (AES m) KEY192 stage)
    pc192 = undefined
    pc256 :: Gadget (CGadget (Cipher (AES m) KEY256 stage)) => m -> stage -> CGadget (Cipher (AES m) KEY256 stage)
    pc256 = undefined
    mode = show $ typeOf m
