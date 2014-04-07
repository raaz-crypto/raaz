{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TypeFamilies      #-}

module Modules.AES.Defaults where

import           Data.ByteString        (ByteString,pack)
import qualified Data.ByteString        as BS
import           Data.Typeable

import           Test.Framework         (Test,testGroup)

import           Raaz.Test              ()
import           Raaz.Test.Cipher
import           Raaz.Test.Gadget       (testGadget)
import           Raaz.Primitives
import           Raaz.Primitives.Cipher


import           Raaz.Cipher.AES.Type

import           Modules.AES.Block      ()
import           Modules.Util

testKey128 :: ByteString
testKey128 =  pack [0x2b,0x7e,0x15,0x16
                   ,0x28,0xae,0xd2,0xa6
                   ,0xab,0xf7,0x15,0x88
                   ,0x09,0xcf,0x4f,0x3c
                   ,0x00,0x01,0x02,0x03
                   ,0x04,0x05,0x06,0x07
                   ,0x08,0x09,0x0A,0x0B
                   ,0x0C,0x0D,0x0E,0x0F]

testKey192 :: ByteString
testKey192 =  pack [0x8e,0x73,0xb0,0xf7
                   ,0xda,0x0e,0x64,0x52
                   ,0xc8,0x10,0xf3,0x2b
                   ,0x80,0x90,0x79,0xe5
                   ,0x62,0xf8,0xea,0xd2
                   ,0x52,0x2c,0x6b,0x7b
                   ,0x00,0x01,0x02,0x03
                   ,0x04,0x05,0x06,0x07
                   ,0x08,0x09,0x0A,0x0B
                   ,0x0C,0x0D,0x0E,0x0F]


testKey256 :: ByteString
testKey256 =  pack [0x60,0x3d,0xeb,0x10
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

testsDefault m s128 s192 s256 =
      [ testStandardCiphers (pr128 m) s128
      , testStandardCiphers (pr192 m) s192
      , testStandardCiphers (pr256 m) s256
      , testStandardCiphers (pc128 m) s128
      , testStandardCiphers (pc192 m) s192
      , testStandardCiphers (pc256 m) s256
      , cportableVsReference (pr128 m) (pc128 m) testKey128
      , cportableVsReference (pr192 m) (pc192 m) testKey192
      , cportableVsReference (pr256 m) (pc256 m) testKey256
      ]
      where
        pr128 :: m -> HGadget (Cipher (AES m) KEY128 Encryption)
        pr128 _ = undefined
        pr192 :: m -> HGadget (Cipher (AES m) KEY192 Encryption)
        pr192 _ = undefined
        pr256 :: m -> HGadget (Cipher (AES m) KEY256 Encryption)
        pr256 _ = undefined
        pc128 :: m -> CGadget (Cipher (AES m) KEY128 Encryption)
        pc128 _ = undefined
        pc192 :: m -> CGadget (Cipher (AES m) KEY192 Encryption)
        pc192 _ = undefined
        pc256 :: m -> CGadget (Cipher (AES m) KEY256 Encryption)
        pc256 _ = undefined
        mode = show $ typeOf m
