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
import           Raaz.Core.Serialize

import           Raaz.Cipher.Salsa20.Internal
import           Raaz.Cipher.Salsa20

import           Modules.Defaults

testKey128 :: ByteString
testKey128 =  pack [1..32]

testKey256 :: ByteString
testKey256 =  pack [1..48]

benchmarksTiny = take 2 <$> benchmarks

benchmarks = sequence
             [ benchCipher s20_128  (cipherCxt $ fromByteString testKey128)
             , benchCipher cs20_128 (cipherCxt $ fromByteString testKey128)
             , benchCipher s12_128  (cipherCxt $ fromByteString testKey128)
             , benchCipher cs12_128 (cipherCxt $ fromByteString testKey128)
             , benchCipher s8_128  (cipherCxt $ fromByteString testKey128)
             , benchCipher cs8_128 (cipherCxt $ fromByteString testKey128)
             , benchCipher s20_256  (cipherCxt $ fromByteString testKey256)
             , benchCipher cs20_256 (cipherCxt $ fromByteString testKey256)
             , benchCipher s12_256  (cipherCxt $ fromByteString testKey256)
             , benchCipher cs12_256 (cipherCxt $ fromByteString testKey256)
             , benchCipher s8_256  (cipherCxt $ fromByteString testKey256)
             , benchCipher cs8_256 (cipherCxt $ fromByteString testKey256)
             ]
  where
    s20_128 :: HGadget (Salsa20 R20 KEY128)
    s20_128 = undefined
    s20_256 :: HGadget (Salsa20 R20 KEY256)
    s20_256 = undefined
    s12_128 :: HGadget (Salsa20 R12 KEY128)
    s12_128 = undefined
    s12_256 :: HGadget (Salsa20 R12 KEY256)
    s12_256 = undefined
    s8_128 :: HGadget (Salsa20 R8 KEY128)
    s8_128 = undefined
    s8_256 :: HGadget (Salsa20 R8 KEY256)
    s8_256 = undefined
    cs20_128 :: CGadget (Salsa20 R20 KEY128)
    cs20_128 = undefined
    cs20_256 :: CGadget (Salsa20 R20 KEY256)
    cs20_256 = undefined
    cs12_128 :: CGadget (Salsa20 R12 KEY128)
    cs12_128 = undefined
    cs12_256 :: CGadget (Salsa20 R12 KEY256)
    cs12_256 = undefined
    cs8_128 :: CGadget (Salsa20 R8 KEY128)
    cs8_128 = undefined
    cs8_256 :: CGadget (Salsa20 R8 KEY256)
    cs8_256 = undefined
