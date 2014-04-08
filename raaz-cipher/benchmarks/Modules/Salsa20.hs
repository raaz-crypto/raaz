{-# LANGUAGE FlexibleContexts #-}
module Modules.Salsa20 (benchmarks, benchmarksTiny) where

import           Criterion.Main
import           Data.ByteString          (ByteString,pack)
import qualified Data.ByteString          as BS
import           Data.Typeable

import           Raaz.Primitives
import           Raaz.Benchmark.Gadget
import           Raaz.Primitives.Cipher

import           Raaz.Cipher.Salsa20.Internal
import           Raaz.Cipher.Salsa20

import           Modules.Defaults         (nBlocks)

testKey128 :: ByteString
testKey128 =  pack [1..32]

testKey256 :: ByteString
testKey256 =  pack [1..48]


benchCipher g iv = benchGadgetWith g iv (nBlocks g)

benchmarksTiny = take 2 benchmarks

benchmarks = [ benchCipher s20_128  (getCxt testKey128)
             , benchCipher cs20_128 (getCxt testKey128)
             , benchCipher s12_128  (getCxt testKey128)
             , benchCipher cs12_128 (getCxt testKey128)
             , benchCipher s8_128  (getCxt testKey128)
             , benchCipher cs8_128 (getCxt testKey128)
             , benchCipher s20_256  (getCxt testKey256)
             , benchCipher cs20_256 (getCxt testKey256)
             , benchCipher s12_256  (getCxt testKey256)
             , benchCipher cs12_256 (getCxt testKey256)
             , benchCipher s8_256  (getCxt testKey256)
             , benchCipher cs8_256 (getCxt testKey256)
             ]
  where
    s20_128 :: HGadget (Cipher (Salsa20 R20) KEY128 EncryptMode)
    s20_128 = undefined
    s20_256 :: HGadget (Cipher (Salsa20 R20) KEY256 EncryptMode)
    s20_256 = undefined
    s12_128 :: HGadget (Cipher (Salsa20 R12) KEY128 EncryptMode)
    s12_128 = undefined
    s12_256 :: HGadget (Cipher (Salsa20 R12) KEY256 EncryptMode)
    s12_256 = undefined
    s8_128 :: HGadget (Cipher (Salsa20 R8) KEY128 EncryptMode)
    s8_128 = undefined
    s8_256 :: HGadget (Cipher (Salsa20 R8) KEY256 EncryptMode)
    s8_256 = undefined
    cs20_128 :: CGadget (Cipher (Salsa20 R20) KEY128 EncryptMode)
    cs20_128 = undefined
    cs20_256 :: CGadget (Cipher (Salsa20 R20) KEY256 EncryptMode)
    cs20_256 = undefined
    cs12_128 :: CGadget (Cipher (Salsa20 R12) KEY128 EncryptMode)
    cs12_128 = undefined
    cs12_256 :: CGadget (Cipher (Salsa20 R12) KEY256 EncryptMode)
    cs12_256 = undefined
    cs8_128 :: CGadget (Cipher (Salsa20 R8) KEY128 EncryptMode)
    cs8_128 = undefined
    cs8_256 :: CGadget (Cipher (Salsa20 R8) KEY256 EncryptMode)
    cs8_256 = undefined
