{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE NoMonomorphismRestriction #-}
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
testKey128 =  ( fromByteString $ pack [0x2b,0x7e,0x15,0x16
                                      ,0x28,0xae,0xd2,0xa6
                                      ,0xab,0xf7,0x15,0x88
                                      ,0x09,0xcf,0x4f,0x3c]
              , fromByteString $ pack [0x00,0x01,0x02,0x03
                                      ,0x04,0x05,0x06,0x07
                                      ,0x08,0x09,0x0A,0x0B
                                      ,0x0C,0x0D,0x0E,0x0F]
              )

testKey192 :: (KEY192, STATE)
testKey192 =  ( fromByteString $ pack [0x8e,0x73,0xb0,0xf7
                                      ,0xda,0x0e,0x64,0x52
                                      ,0xc8,0x10,0xf3,0x2b
                                      ,0x80,0x90,0x79,0xe5
                                      ,0x62,0xf8,0xea,0xd2
                                      ,0x52,0x2c,0x6b,0x7b]
              , fromByteString $ pack [0x00,0x01,0x02,0x03
                                      ,0x04,0x05,0x06,0x07
                                      ,0x08,0x09,0x0A,0x0B
                                      ,0x0C,0x0D,0x0E,0x0F]
              )


testKey256 :: (KEY256, STATE)
testKey256 =  ( fromByteString $ pack [0x60,0x3d,0xeb,0x10
                                      ,0x15,0xca,0x71,0xbe
                                      ,0x2b,0x73,0xae,0xf0
                                      ,0x85,0x7d,0x77,0x81
                                      ,0x1f,0x35,0x2c,0x07
                                      ,0x3b,0x61,0x08,0xd7
                                      ,0x2d,0x98,0x10,0xa3
                                      ,0x09,0x14,0xdf,0xf4]
              , fromByteString $ pack [0x00,0x01,0x02,0x03
                                      ,0x04,0x05,0x06,0x07
                                      ,0x08,0x09,0x0A,0x0B
                                      ,0x0C,0x0D,0x0E,0x0F]
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
