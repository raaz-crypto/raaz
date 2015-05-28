{-# LANGUAGE FlexibleContexts #-}
module Modules.Salsa20 (benchmarks, benchmarksTiny) where

import           Criterion.Main
import           Control.Applicative
import           Data.ByteString              (ByteString,pack)
import qualified Data.ByteString              as BS
import           Data.Typeable

import           Raaz.Core.Primitives
import           Raaz.Benchmark.Gadget
import           Raaz.Core.Primitives.Cipher
import           Raaz.Core.Util.ByteString

import           Raaz.Cipher.Salsa20.Internal
import           Raaz.Cipher.Salsa20

import           Modules.Defaults

testKey128 :: (KEY128, Nonce)
testKey128 =  (fromByteString  $ pack [1..16], fromByteString $ pack [17..32])

testKey256 :: (KEY256, Nonce)
testKey256 =  (fromByteString  $ pack [1..32], fromByteString $ pack [33..48])

benchmarksTiny = take 2 <$> benchmarks

benchmarks = sequence
             [ benchCipher s20_128  testKey128
             , benchCipher cs20_128 testKey128
             , benchCipher s12_128  testKey128
             , benchCipher cs12_128 testKey128
             , benchCipher s8_128  testKey128
             , benchCipher cs8_128 testKey128
             , benchCipher s20_256  testKey256
             , benchCipher cs20_256 testKey256
             , benchCipher s12_256  testKey256
             , benchCipher cs12_256 testKey256
             , benchCipher s8_256  testKey256
             , benchCipher cs8_256 testKey256
             ]
  where
    s20_128 :: HSalsa20Gadget R20 KEY128
    s20_128 = undefined
    s20_256 :: HSalsa20Gadget R20 KEY256
    s20_256 = undefined
    s12_128 :: HSalsa20Gadget R12 KEY128
    s12_128 = undefined
    s12_256 :: HSalsa20Gadget R12 KEY256
    s12_256 = undefined
    s8_128 :: HSalsa20Gadget R8 KEY128
    s8_128 = undefined
    s8_256 :: HSalsa20Gadget R8 KEY256
    s8_256 = undefined
    cs20_128 :: CSalsa20Gadget R20 KEY128
    cs20_128 = undefined
    cs20_256 :: CSalsa20Gadget R20 KEY256
    cs20_256 = undefined
    cs12_128 :: CSalsa20Gadget R12 KEY128
    cs12_128 = undefined
    cs12_256 :: CSalsa20Gadget R12 KEY256
    cs12_256 = undefined
    cs8_128 :: CSalsa20Gadget R8 KEY128
    cs8_128 = undefined
    cs8_256 :: CSalsa20Gadget R8 KEY256
    cs8_256 = undefined
